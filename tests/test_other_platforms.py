"""Agents on other platforms, read by AgentGov's connectors (agentgov.platforms.base)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.platforms.base import Found, Inventory, PlatformError, Risk
from tests.conftest import ADMIN

NO_GUARDRAIL = Risk(
    "platform.no_guardrail",
    "medium",
    "Billing helper has no guardrail",
    "Nothing filters what it says.",
    "Attach a guardrail.",
)
PLAIN_SECRET = Risk(
    "platform.plain_secret",
    "high",
    "Billing helper keeps a secret in its environment",
    details={"variables": ["STRIPE_KEY"]},
)


def found(name: str, part: str = "111122223333/us-east-1", *risks: Risk) -> Found:
    return Found(
        external_id=f"arn:aws:bedrock:{part.split('/')[1]}:{part.split('/')[0]}:agent/{name}",
        name=name,
        kind="Amazon Bedrock agent",
        part=part,
        details={"facts": [{"label": "Region", "value": part.split("/")[1]}]},
        description=f"{name}, for testing",
        external_ids={"aws_arn": f"arn:{name}"},
        risks=list(risks),
    )


class FakeConnector:
    """Hands out whatever inventory the test sets, or fails."""

    def __init__(self) -> None:
        self.next: Inventory | PlatformError = Inventory()
        self.calls = 0

    def inventory(self) -> Inventory:
        self.calls += 1
        if isinstance(self.next, PlatformError):
            raise self.next
        return self.next


@pytest.fixture
def connector() -> FakeConnector:
    return FakeConnector()


@pytest.fixture
def client(settings: Settings, connector: FakeConnector) -> Iterator[TestClient]:
    app = create_app(settings, background=False)
    with TestClient(app) as test_client:
        app.state.rt.platforms["aws"] = connector
        yield test_client


def sync(client: TestClient) -> dict[str, Any]:
    resp = client.post("/v1/platforms/aws/sync", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def agent(client: TestClient, name: str) -> dict[str, Any]:
    resp = client.get(f"/v1/agents/{name}", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def open_findings(client: TestClient, name: str) -> dict[str, dict[str, Any]]:
    view = client.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
    items = view["items"] if isinstance(view, dict) else view
    me = agent(client, name)["id"]
    return {f["type"]: f for f in items if f.get("agent_id") == me}


def test_agents_become_discovered_with_their_platforms_view(client, connector) -> None:
    connector.next = Inventory(
        found=[found("billing-helper", "111122223333/us-east-1", NO_GUARDRAIL)],
        read={"111122223333/us-east-1"},
    )
    assert sync(client) == {"created": 1, "updated": 0, "skipped": 0, "findings": 1}
    billing = agent(client, "billing-helper")
    assert (billing["status"], billing["source"]) == ("discovered", "platform:aws")
    assert billing["platform"] == "Amazon Bedrock agent"
    [view] = billing["platforms"]
    assert view["source"] == "aws" and view["source_name"] == "AWS"
    assert view["kind"] == "Amazon Bedrock agent" and view["in_inventory"] is True
    assert view["facts"] == [{"label": "Region", "value": "us-east-1"}]
    found_types = set(open_findings(client, "billing-helper"))
    assert {"agent.unmanaged", "platform.no_guardrail"} <= found_types
    factors = {f["factor"] for f in billing["risk"]["factors"]}
    assert "No guardrails on what it says" in factors
    # Syncing again updates rather than duplicates.
    assert sync(client)["updated"] == 1


def test_a_fixed_setting_is_resolved_after_two_clean_syncs(client, connector) -> None:
    part = "111122223333/us-east-1"
    connector.next = Inventory(found=[found("billing-helper", part, PLAIN_SECRET)], read={part})
    sync(client)
    assert "platform.plain_secret" in open_findings(client, "billing-helper")
    connector.next = Inventory(found=[found("billing-helper", part)], read={part})
    sync(client)
    assert "platform.plain_secret" in open_findings(client, "billing-helper")  # one odd answer
    sync(client)
    assert "platform.plain_secret" not in open_findings(client, "billing-helper")


def test_agents_gone_from_the_platform_stay_marked_as_gone(client, connector) -> None:
    part = "111122223333/us-east-1"
    connector.next = Inventory(
        found=[found("billing-helper", part, NO_GUARDRAIL), found("triage", part)], read={part}
    )
    sync(client)
    connector.next = Inventory(found=[found("triage", part)], read={part})
    sync(client)
    sync(client)
    [view] = agent(client, "billing-helper")["platforms"]
    assert view["in_inventory"] is False
    assert "platform.no_guardrail" not in open_findings(client, "billing-helper")


def test_a_region_that_failed_leaves_its_agents_alone(client, connector) -> None:
    east, west = "111122223333/us-east-1", "111122223333/us-west-2"
    connector.next = Inventory(
        found=[found("billing-helper", east, NO_GUARDRAIL), found("triage", west, NO_GUARDRAIL)],
        read={east, west},
    )
    sync(client)
    connector.next = Inventory(
        found=[found("billing-helper", east)],
        read={east},
        failed={west: "AccessDeniedException: not authorized"},
    )
    counts = sync(client)
    assert counts["failed"] == 1
    [triage] = agent(client, "triage")["platforms"]
    assert triage["in_inventory"] is True
    finding = open_findings(client, "triage")["platform.no_guardrail"]
    assert finding["verified"] is False
    assert finding["unverified_reason"] == (
        "the last AWS sync couldn't read 111122223333/us-west-2: "
        "AccessDeniedException: not authorized"
    )
    status = {s["source"]: s for s in client.get("/v1/platforms", headers=ADMIN).json()["sources"]}
    assert status["aws"]["last_sync"]["ok"] is False
    assert "us-west-2: AccessDeniedException" in status["aws"]["last_sync"]["message"]


def test_a_sync_that_fails_outright(client, connector) -> None:
    part = "111122223333/us-east-1"
    connector.next = Inventory(found=[found("billing-helper", part, NO_GUARDRAIL)], read={part})
    sync(client)
    connector.next = PlatformError("no AWS credentials")
    resp = client.post("/v1/platforms/aws/sync", headers=ADMIN)
    assert resp.status_code == 502 and "no AWS credentials" in resp.text
    unverified = open_findings(client, "billing-helper")["platform.no_guardrail"]
    assert unverified["verified"] is False
    assert unverified["unverified_reason"] == "the last AWS sync failed: no AWS credentials"
    status = {s["source"]: s for s in client.get("/v1/platforms", headers=ADMIN).json()["sources"]}
    assert status["aws"]["last_sync"]["message"] == "no AWS credentials"
    # Read again: verified, and the reason is gone.
    connector.next = Inventory(found=[found("billing-helper", part, NO_GUARDRAIL)], read={part})
    sync(client)
    verified = open_findings(client, "billing-helper")["platform.no_guardrail"]
    assert verified["verified"] is True and verified["unverified_reason"] is None
    assert "unverified" not in verified["details"]


def test_an_agent_read_in_part_says_what_was_missing(client, connector) -> None:
    part = "111122223333/us-east-1"
    connector.next = Inventory(found=[found("billing-helper", part, NO_GUARDRAIL)], read={part})
    sync(client)
    partial = found("billing-helper", part)
    partial.complete = False
    partial.missing = ["its resource policy couldn't be read"]
    connector.next = Inventory(found=[partial], read={part})
    sync(client)
    sync(client)
    finding = open_findings(client, "billing-helper")["platform.no_guardrail"]
    assert finding["verified"] is False
    assert finding["unverified_reason"] == (
        "the last AWS sync read it in part: its resource policy couldn't be read"
    )


def test_what_the_first_sync_finds_reaches_no_inbox(client, connector, settings) -> None:
    from dataclasses import replace

    from sqlalchemy import select

    from agentgov.models import Notification
    from agentgov.registry import findings, issues, teams

    rt = client.app.state.rt
    with rt.db.session() as s:
        teams.create(
            s, {"name": "ai-gov", "emails": ["gov@example.com"], "default": True}, actor="a:b"
        )
    mail = replace(settings, smtp_url="smtp://mail:25", smtp_from="agentgov@example.com")
    part = "111122223333/us-east-1"
    connector.next = Inventory(found=[found("billing-helper", part, NO_GUARDRAIL)], read={part})
    sync(client)
    found_first = open_findings(client, "billing-helper")
    # All it found about the agents it read: theirs, and AgentGov's own about them.
    assert {"platform.no_guardrail", "agent.unmanaged", "agent.high_risk"} <= set(found_first)
    assert all(f["details"][findings.BASELINE] is True for f in found_first.values())
    first = found_first["platform.no_guardrail"]
    connector.next = Inventory(
        found=[found("billing-helper", part, NO_GUARDRAIL, PLAIN_SECRET)], read={part}
    )
    sync(client)
    later = open_findings(client, "billing-helper")["platform.plain_secret"]
    assert findings.BASELINE not in later["details"]
    with rt.db.session() as s:
        issues.route(s, mail)
        sent = {n.finding_id for n in s.scalars(select(Notification))}
        # Both are with the default team; only the new one is in its inbox.
        assert findings.get(s, first["id"]).level == "team"
        assert sent == {later["id"]}
    # Gone, then back: news like any other.
    with rt.db.session() as s:
        findings.set_status(s, first["id"], "resolved", "admin:test")
    sync(client)
    again = open_findings(client, "billing-helper")["platform.no_guardrail"]
    assert findings.BASELINE not in again["details"]
    with rt.db.session() as s:
        issues.route(s, mail)
        assert first["id"] in {n.finding_id for n in s.scalars(select(Notification))}
    # Or every first sync's findings are sent, if the deployment says so.
    with rt.db.session() as s:
        loud = replace(mail, issues_quiet_first_sync=False)
        assert issues._quiet(loud, findings.get(s, later["id"])) is None


def test_other_sources_findings_of_the_same_type_stay(client, connector) -> None:
    rows = [
        {
            "name": "studio-bot",
            "type": "microsoft.copilotstudio/agents",
            "properties": {
                "displayName": "Studio Bot",
                "sharedWithViewers": {"entireTenant": True},
            },
        }
    ]
    imported = client.post("/v1/platforms/copilot-studio/import", json=rows, headers=ADMIN)
    assert imported.status_code == 200, imported.text
    assert "platform.shared_with_everyone" in open_findings(client, "studio-bot")
    part = "111122223333/us-east-1"
    connector.next = Inventory(found=[found("billing-helper", part)], read={part})
    sync(client)
    sync(client)
    assert "platform.shared_with_everyone" in open_findings(client, "studio-bot")


def test_only_configured_and_turned_on_platforms_sync(client, connector) -> None:
    resp = client.post("/v1/platforms/google-cloud/sync", headers=ADMIN)
    assert resp.status_code == 409 and "not configured" in resp.text
    assert client.post("/v1/platforms/nowhere/sync", headers=ADMIN).status_code == 404
    status = {s["source"]: s for s in client.get("/v1/platforms", headers=ADMIN).json()["sources"]}
    assert status["aws"]["configured"] is True and status["aws"]["turned_on"] is True
    assert "AGENTGOV_AWS_REGIONS" in status["aws"]["needs"]
    assert status["google-cloud"]["configured"] is False
    assert "AGENTGOV_GOOGLE_CLOUD_PROJECTS" in status["google-cloud"]["needs"]
    assert status["databricks"]["configured"] is False


def test_platforms_are_read_on_a_schedule(settings: Settings, connector, monkeypatch) -> None:
    from agentgov import runtime
    from agentgov.registry import features

    started: list[str] = []
    monkeypatch.setattr(runtime._Worker, "start", lambda worker: started.append(worker.name))
    rt = runtime.Runtime(settings.with_overrides(platform_sync_interval_seconds=3600))
    # Connectors may come after the runtime is built, as in these tests.
    rt.platforms["aws"] = connector
    rt.start()
    try:
        assert "platform-sync" in started
        # Each time it runs: every platform that is configured and turned on.
        assert rt._platforms_worker is not None
        rt._platforms_worker.fn()
        assert connector.calls == 1
        with rt.db.session() as s:
            features.set_mode(s, rt.settings, "aws", "off", actor="admin:ada")
        rt._platforms_worker.fn()
        assert connector.calls == 1
    finally:
        rt.stop()

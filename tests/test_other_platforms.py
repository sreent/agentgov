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
    assert open_findings(client, "billing-helper")["platform.no_guardrail"]["verified"] is False
    status = {s["source"]: s for s in client.get("/v1/platforms", headers=ADMIN).json()["sources"]}
    assert status["aws"]["last_sync"]["message"] == "no AWS credentials"


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
    assert "salesforce" not in status  # no connector for it yet

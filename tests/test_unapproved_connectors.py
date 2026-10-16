"""What happens when a Copilot Studio agent uses a connector that isn't on the allowlist
(docs/platforms.md#when-an-agent-uses-a-connector-that-isnt-approved): it is flagged; its
calls through that connector are refused, recorded or not checked, as the
connector-allowlist control says; and a management rule can block it while threat
detection is enforced."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from agentgov import ids
from agentgov.config import Settings
from agentgov.db.models import Finding
from agentgov.registry import features, rules
from tests.conftest import ADMIN, requires_opa
from tests.test_platforms import bot, connector
from tests.test_threat_detection import (
    FakeEntraKeys,
    RealOpa,
    ask,
    call,
    decisions,
    make_client,
    threat_settings,
)

RULE = {
    "name": "unapproved-connectors",
    "conditions": {"findings": ["platform.unapproved_connector"]},
    "action": "block",
    "after_days": 7,
    "mode": "enforce",
}


# Sales Helper uses shared_office365; HR FAQ uses no connector.
BOTS = [
    bot("bot-sales", "Sales Helper", connectors=[connector("shared_office365", "Send")]),
    bot("bot-hr", "HR FAQ"),
]


@pytest.fixture
def keys() -> FakeEntraKeys:
    return FakeEntraKeys()


@pytest.fixture
def opa(tmp_path: Path) -> RealOpa:
    return RealOpa(tmp_path)


def connected(settings: Settings, keys: FakeEntraKeys, opa: RealOpa) -> TestClient:
    """A control plane Copilot Studio asks, with Sales Helper and HR FAQ imported."""
    client = make_client(settings, keys, opa)
    client.__enter__()
    client.post("/v1/platforms/copilot-studio/import", json=BOTS, headers=ADMIN).raise_for_status()
    return client


@pytest.fixture
def studio(settings: Settings, keys: FakeEntraKeys, opa: RealOpa) -> Iterator[TestClient]:
    client = connected(threat_settings(settings), keys, opa)
    yield client
    client.__exit__(None, None, None)


def approve(client: TestClient, connector: str) -> None:
    client.put(
        f"/v1/platforms/connectors/{connector}/approval", json={}, headers=ADMIN
    ).raise_for_status()


def put(client: TestClient, key: str, body: dict[str, Any]) -> Any:
    resp = client.put(f"/v1/features/{key}", json=body, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def feature(client: TestClient, key: str) -> dict[str, Any]:
    listed = client.get("/v1/features", headers=ADMIN).json()["features"]
    return next(f for f in listed if f["key"] == key)


def agent(client: TestClient, name: str) -> dict[str, Any]:
    return client.get(f"/v1/agents/{name}", headers=ADMIN).json()


def run_rules(client: TestClient, now: Any) -> None:
    rt = client.app.state.rt  # type: ignore[attr-defined]
    with rt.db.transaction() as tx:
        rules.evaluate(tx, rt.settings, now)


class TestTheControl:
    def test_it_enforces_by_default_and_takes_exceptions(self, client) -> None:
        found = feature(client, "connector-allowlist")
        assert (found["mode"], found["default"], found["group"]) == (
            "enforce",
            "enforce",
            "microsoft",
        )
        assert found["scopable"] is True
        pilot = [{"mode": "monitor", "scope": {"labels": {"tier": "pilot"}}}]
        assert put(client, "connector-allowlist", {"scopes": pilot})["scopes"][0]["mode"] == (
            "monitor"
        )

    def test_the_features_page_says_whether_it_acts(self, client) -> None:
        # Threat detection off, and nothing approved yet: it checks nothing.
        found = feature(client, "connector-allowlist")
        assert found["status"] == "inactive"
        assert any("threat detection is off" in p for p in found["problems"])
        assert any("no connector yet" in p for p in found["problems"])

    def test_the_monitor_starting_point_monitors_it(self, client) -> None:
        resp = client.post("/v1/feature-presets/monitor", headers=ADMIN)
        assert resp.status_code == 200, resp.text
        assert feature(client, "connector-allowlist")["mode"] == "monitor"


@requires_opa
class TestAtRunTime:
    def test_its_calls_are_refused_recorded_or_not_checked(self, studio, keys) -> None:
        # Sales Helper uses shared_office365; the allowlist names another connector.
        approve(studio, "shared_sql")
        refused = ask(studio, keys, call())
        assert refused["blockAction"] is True
        assert "Connector shared_office365 is not on" in refused["reason"]
        put(studio, "connector-allowlist", {"mode": "monitor"})
        assert ask(studio, keys, call()) == {"blockAction": False}
        latest = decisions(studio)[0]
        assert latest["decision"] == "allow"
        assert latest["reason"].startswith(
            "monitored: connector-allowlist: Connector shared_office365"
        )
        put(studio, "connector-allowlist", {"mode": "off"})
        assert ask(studio, keys, call()) == {"blockAction": False}
        assert decisions(studio)[0]["reason"] is None
        # Either way, the agent is flagged.
        assert any(
            f["type"] == "platform.unapproved_connector"
            for f in studio.get("/v1/findings", params={"status": "open"}, headers=ADMIN).json()
        )

    def test_an_exception_records_them_for_some_agents_only(self, studio, keys) -> None:
        approve(studio, "shared_sql")
        resp = studio.patch(
            "/v1/agents/sales-helper", json={"labels": {"tier": "pilot"}}, headers=ADMIN
        )
        assert resp.status_code == 200, resp.text
        pilot = [{"mode": "monitor", "scope": {"labels": {"tier": "pilot"}}}]
        put(studio, "connector-allowlist", {"scopes": pilot})
        assert ask(studio, keys, call()) == {"blockAction": False}
        assert ask(studio, keys, call("bot-hr"))["blockAction"] is True


class TestRules:
    def _setup(self, client: TestClient) -> None:
        approve(client, "shared_sql")
        put(client, "management-rules", {"mode": "enforce"})
        resp = client.post("/v1/rules", json=RULE, headers=ADMIN)
        assert resp.status_code == 201, resp.text

    def test_a_rule_blocks_the_agent_while_threat_detection_enforces(self, studio) -> None:
        self._setup(studio)
        now = ids.utcnow()
        run_rules(studio, now)
        # Its people are told first; a week later it is blocked.
        assert agent(studio, "sales-helper")["status"] == "discovered"
        run_rules(studio, now + timedelta(days=8))
        assert agent(studio, "sales-helper")["status"] == "blocked"
        # bot-hr uses no connector the allowlist leaves out.
        assert agent(studio, "hr-faq")["status"] == "discovered"

    def test_otherwise_it_says_to_quarantine_it(self, settings: Settings, keys, opa) -> None:
        watching = threat_settings(settings, features="copilot-studio-threat-detection=monitor")
        client = connected(watching, keys, opa)
        try:
            self._setup(client)
            now = ids.utcnow()
            run_rules(client, now)
            run_rules(client, now + timedelta(days=8))
            assert agent(client, "sales-helper")["status"] == "discovered"
            rt = client.app.state.rt  # type: ignore[attr-defined]
            with rt.db.transaction():
                [issue] = Finding.objects.filter(type=rules.MATCHED, status="open")
                assert "quarantine it there" in issue.description
                assert "enforce Copilot Studio threat detection" in issue.description
        finally:
            client.__exit__(None, None, None)

    def test_only_blocking_copilot_studio_agents_while_enforced(self) -> None:
        studio_agent = _Fake(
            source="platform:copilot-studio",
            on_platform=True,
            external_ids={"copilot_studio_agent_id": "bot-sales"},
        )
        aws_agent = _Fake(source="platform:aws", on_platform=True, external_ids={})
        gateway_agent = _Fake(source="registry", on_platform=False, external_ids={})
        block, delete = _Fake(action=rules.BLOCK), _Fake(action=rules.DELETE)
        enforced = {rules.THREAT_DETECTION: features.ENFORCE}
        assert rules._cannot(block, studio_agent, enforced) is None
        assert "quarantine it there" in (rules._cannot(block, studio_agent, {}) or "")
        assert "AWS's admin center" in (rules._cannot(block, aws_agent, enforced) or "")
        # Deleting it in AgentGov would not stop it.
        assert rules._cannot(delete, studio_agent, enforced) is not None
        assert rules._cannot(block, gateway_agent, {}) is None


class _Fake:
    def __init__(self, **values: Any) -> None:
        self.__dict__.update(values)

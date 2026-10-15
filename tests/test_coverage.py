"""What the compliance reports say AgentGov saw of the agents, and controls set up but not
seen working in the period (docs/evidence.md#what-agentgov-saw)."""

from __future__ import annotations

import io
import zipfile
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from starlette.testclient import TestClient

from agentgov import ids, ledger
from agentgov.models import Agent, PlatformAgent, PlatformSync
from tests.conftest import ADMIN, seed
from tests.test_people import import_studio, studio


def report(client: TestClient, framework: str = "nist-ai-rmf") -> dict[str, Any]:
    resp = client.get("/v1/evidence/report", params={"framework": framework}, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def control(r: dict[str, Any], cid: str) -> dict[str, Any]:
    return next(c for c in r["controls"] if c["id"] == cid)


def _rt(client: TestClient) -> Any:
    return client.app.state.rt  # type: ignore[attr-defined]


def seen(client: TestClient) -> tuple[int, int, int, int, int]:
    c = report(client)["coverage"]
    return c["agents"], c["calls_checked"], c["activity_only"], c["inventory_only"], c["not_seen"]


class TestCoverage:
    def test_each_agent_counts_once_by_the_most_seen(self, client) -> None:
        bot = seed(client)  # active, and silent
        import_studio(client, studio("bot-sales", "Sales Helper"))  # its inventory, read now
        assert seen(client) == (2, 0, 0, 1, 1)
        c = report(client)["coverage"]
        assert (c["not_seen_names"], c["platforms_read"]) == (["support-bot"], ["copilot-studio"])
        # Seen at work (its telemetry, say): its calls not checked.
        with _rt(client).db.session() as s:
            s.get(Agent, bot["id"]).last_seen_at = ids.utcnow()
        assert seen(client) == (2, 0, 1, 1, 0)
        # Its calls checked.
        with _rt(client).db.session() as s:
            ledger.append(
                s,
                type="decision.tool.request",
                actor=f"agent:{bot['name']}",
                agent_id=bot["id"],
                decision="allow",
            )
        assert seen(client) == (2, 1, 0, 1, 0)

    def test_a_platform_not_read_in_the_period(self, client) -> None:
        import_studio(client, studio("bot-sales", "Sales Helper"))
        long_ago = ids.utcnow() - timedelta(days=200)
        with _rt(client).db.session() as s:
            s.get(PlatformSync, "copilot-studio").synced_at = long_ago
            for record in s.scalars(select(PlatformAgent)):
                record.synced_at = long_ago
        r = report(client)
        assert r["coverage"]["platforms_not_read"] == ["copilot-studio"]
        assert seen(client) == (1, 0, 0, 0, 1)
        inventory = control(r, "GOVERN 1.6")
        assert inventory["status"] != "in_place"
        assert "Not read in the period" in inventory["gaps"][-1]


class TestConfiguredNotObserved:
    def test_safeguards_no_call_went_through(self, client) -> None:
        seed(client)
        security = control(report(client), "MEASURE 2.7")
        assert security["status"] in ("configured", "not_set_up")
        if security["status"] == "configured":
            assert "No call went through" in security["gaps"][-1]

    def test_posture_checks_that_never_ran(self, client) -> None:
        seed(client)
        monitoring = control(report(client), "MEASURE 2.4")
        assert any("none ran in the period" in g for g in monitoring["gaps"])
        client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        monitoring = control(report(client), "MEASURE 2.4")
        assert not any("none ran" in g for g in monitoring["gaps"])
        evidence = {e["label"]: e["value"] for e in monitoring["evidence"]}
        assert evidence["Last posture scan"] != "none"

    def test_calls_between_agents_never_seen(self, client) -> None:
        seed(client)  # the agent-to-agent gateway is on, as it is by default
        interaction = control(report(client, "eu-ai-act"), "Art. 72")
        assert interaction["status"] == "configured"
        assert "No call between agents" in interaction["gaps"][-1]


def test_in_the_document_and_the_cli(client, monkeypatch) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    seed(client)
    pack = client.get("/v1/evidence/pack", headers=ADMIN)
    assert pack.status_code == 200
    document = zipfile.ZipFile(io.BytesIO(pack.content)).read("report.md").decode()
    assert "## What AgentGov saw" in document
    assert "Of the 1 agent in the inventory" in document
    assert "* 1 weren't seen at all: support-bot." in document
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    out = runner.invoke(cli.app, ["evidence", "report"])
    assert out.exit_code == 0, out.output
    assert "What AgentGov saw of the 1 agent: 0 had their calls checked" in out.output

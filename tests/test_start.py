"""Where an organisation starts (docs/administration.md#start-here): it says where its
agents are, AgentGov turns on only what reads those places, and a checklist leads to a
first useful day."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import ADMIN
from tests.test_platforms import bot, import_inventory


def checklist(client: TestClient) -> dict[str, Any]:
    resp = client.get("/v1/start", headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def steps(client: TestClient) -> dict[str, bool]:
    return {s["key"]: s["done"] for s in checklist(client)["steps"]}


def modes(client: TestClient) -> dict[str, str]:
    listed = client.get("/v1/features", headers=ADMIN).json()["features"]
    return {f["key"]: f["mode"] for f in listed}


def answer(client: TestClient, *places: str) -> dict[str, Any]:
    resp = client.put("/v1/start", json={"places": list(places)}, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestWhereAgentsAre:
    def test_only_what_reads_those_places_is_on(self, client) -> None:
        assert checklist(client)["places"] == []
        answer(client, "copilot-studio", "aws")
        now = modes(client)
        # Copilot Studio is imported, and with it what Microsoft knows about its agents.
        assert (now["aws"], now["purview-audit"], now["defender"]) == ("on", "on", "on")
        assert {now[k] for k in ("google-cloud", "salesforce", "databricks")} == {"off"}
        assert now["microsoft-365"] == "off"
        # No gateway: the inventory starting point.
        assert now["mcp-gateway"] == "off"
        assert checklist(client)["places"] == ["copilot-studio", "aws"]

    def test_agents_through_the_gateway_start_monitored(self, client) -> None:
        answer(client, "gateway")
        now = modes(client)
        assert now["mcp-gateway"] == "on"
        assert now["least-privilege"] == "monitor"
        assert {now[k] for k in ("aws", "microsoft-365", "purview-audit")} == {"off"}

    def test_it_says_what_it_takes(self, client) -> None:
        for body in ({}, {"places": []}, {"places": ["mars"]}, {"places": "aws"}, {"x": 1}):
            resp = client.put("/v1/start", json=body, headers=ADMIN)
            assert resp.status_code == 422, (body, resp.text)
        assert client.put("/v1/start", json={"hidden": "yes"}, headers=ADMIN).status_code == 422

    def test_what_the_deployment_pins_stays(self, client, settings) -> None:
        from dataclasses import replace

        from agentgov.api.app import create_app

        pinned = create_app(replace(settings, features="aws=on"), background=False)
        with TestClient(pinned) as other:
            answer(other, "copilot-studio")
            assert modes(other)["aws"] == "on"

    def test_it_is_recorded(self, client) -> None:
        answer(client, "salesforce")
        [entry] = client.get("/v1/ledger", params={"type": "start.answered"}, headers=ADMIN).json()
        assert entry["details"]["places"] == ["salesforce"]
        assert entry["details"]["starting_point"] == "inventory"


class TestTheChecklist:
    def test_each_step_is_done_by_doing_it(self, client) -> None:
        assert steps(client) == dict.fromkeys(
            ("places", "agents", "team", "review", "owners"), False
        )
        answer(client, "copilot-studio")
        found = checklist(client)
        [how] = next(s for s in found["steps"] if s["key"] == "agents")["how"]
        assert "Import its inventory" in how["how"]
        import_inventory(client, [bot("bot-sales", "Sales Helper")])
        now = steps(client)
        assert (now["places"], now["agents"], now["review"], now["owners"]) == (
            True,
            True,
            False,
            False,
        )
        client.post(
            "/v1/teams", json={"name": "ai-gov", "emails": ["gov@example.com"], "default": True},
            headers=ADMIN,
        ).raise_for_status()  # fmt: skip
        agent = client.get("/v1/agents", headers=ADMIN).json()[0]
        client.post(
            f"/v1/agents/{agent['id']}/adopt",
            json={"owner": "ai-gov", "sponsors": ["dana@example.com"]},
            headers=ADMIN,
        ).raise_for_status()
        assert checklist(client)["done"] is True

    def test_it_can_be_hidden(self, client) -> None:
        resp = client.put("/v1/start", json={"hidden": True}, headers=ADMIN)
        assert resp.status_code == 200 and resp.json()["hidden"] is True
        assert checklist(client)["hidden"] is True

    def test_everyone_who_reads_agentgov_sees_it_and_admins_answer(self, client) -> None:
        from tests.test_api import key

        auditor = key(client, "auditor")
        assert client.get("/v1/start", headers=auditor).status_code == 200
        refused = client.put("/v1/start", json={"places": ["aws"]}, headers=auditor)
        assert refused.status_code == 403


def test_the_cli_says_where_to_start(client, monkeypatch) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    bearer = ADMIN["Authorization"].removeprefix("Bearer ")
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))
    out = runner.invoke(cli.app, ["start", "--place", "copilot-studio"])
    assert out.exit_code == 0, out.output
    assert "[x] Say where your agents are: Copilot Studio" in out.output
    assert "Import its inventory" in out.output


def test_issues_say_when_nobody_takes_what_nobody_else_does(client) -> None:
    """Without a catch-all team, issues no agent's people take reach no one: the Features
    page says so, until one is named."""

    def issues() -> dict[str, Any]:
        listed = client.get("/v1/features", headers=ADMIN).json()["features"]
        return next(f for f in listed if f["key"] == "issues")

    assert issues()["status"] == "limited"
    assert any("No catch-all team" in p for p in issues()["problems"])
    client.post(
        "/v1/teams", json={"name": "ai-gov", "emails": ["gov@example.com"], "default": True},
        headers=ADMIN,
    ).raise_for_status()  # fmt: skip
    assert not any("catch-all" in p for p in issues()["problems"])

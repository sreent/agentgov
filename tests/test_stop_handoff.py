"""Agents blocked in AgentGov that their platform still runs: an issue asks their people to
stop them there, and closes once a sync shows the platform stopped them (docs/platforms.md)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import cli
from agentgov.models import FeatureSetting, Finding
from agentgov.platforms import databricks, foundry
from agentgov.platforms.base import Found, Inventory
from agentgov.registry import platforms
from tests.conftest import ADMIN
from tests.test_cli import _Shared, ok, runner
from tests.test_platforms import (  # noqa: F401 (the m365 fixture, and what it takes)
    agent_named,
    bot,
    import_inventory,
    inventory,
    m365,
    m365_settings,
    microsoft,
)

STILL = platforms.STILL_RUNNING


def issue(client: TestClient, agent_id: str) -> Finding | None:
    with client.app.state.rt.db.session() as s:  # type: ignore[attr-defined]
        found = s.scalar(select(Finding).where(Finding.key == f"{STILL}:{agent_id}"))
        if found is not None:
            s.expunge(found)
        return found


def block(client: TestClient, name: str, action: str = "block") -> dict[str, Any]:
    resp = client.post(f"/v1/agents/{name}/{action}", json={"reason": "test"}, headers=ADMIN)
    assert resp.status_code == 200, resp.text
    return resp.json()


def quarantined(value: bool | None) -> dict[str, Any]:
    return inventory(sales={"isQuarantined": value})


class TestCopilotStudio:
    def test_blocking_hands_the_stop_to_its_people(self, client) -> None:
        import_inventory(client)
        sales = agent_named(client, "sales-helper")
        assert issue(client, sales["id"]) is None
        done = block(client, "sales-helper")
        assert done["status"] == "blocked"
        assert done["still_runs_in"] == "Copilot Studio"
        assert agent_named(client, "sales-helper")["still_runs_in"] == "Copilot Studio"

        found = issue(client, sales["id"])
        assert found is not None and found.status == "open" and found.severity == "high"
        assert found.title == "sales-helper is blocked in AgentGov but still runs in Copilot Studio"
        assert found.description == (
            "Blocking it in AgentGov doesn't stop it in Copilot Studio. Copilot Studio knows it "
            "as bot-sales, in environment env-sales."
        )
        assert "A Power Platform administrator" in found.remediation
        assert "quarantine it" in found.remediation
        assert "AgentGov closes this issue once Copilot Studio reports it quarantined" in (
            found.remediation
        )
        # Admins can't act in Microsoft through this AgentGov: it doesn't offer to.
        assert "from its page in AgentGov" not in found.remediation
        # It isn't in the Microsoft 365 catalog: nothing about blocking it there.
        assert "Microsoft 365" not in found.remediation
        assert found.details["external_id"] == "bot-sales"
        assert found.details["environment_id"] == "env-sales"

    def test_an_import_that_shows_it_quarantined_closes_it(self, client) -> None:
        import_inventory(client)
        sales = agent_named(client, "sales-helper")
        block(client, "sales-helper")
        # Not quarantined yet: still open.
        import_inventory(client, quarantined(False))
        assert issue(client, sales["id"]).status == "open"
        import_inventory(client, quarantined(True))
        closed = issue(client, sales["id"])
        assert closed.status == "resolved" and closed.resolved_by == platforms.SYSTEM_ACTOR
        assert agent_named(client, "sales-helper")["still_runs_in"] is None
        # Released from quarantine while still blocked here: it runs again.
        import_inventory(client, quarantined(False))
        assert issue(client, sales["id"]).status == "open"

    def test_gone_from_copilot_studio_closes_it(self, client) -> None:
        import_inventory(client)
        sales = agent_named(client, "sales-helper")
        block(client, "sales-helper")
        hr_only = {"data": [bot("bot-hr", "HR FAQ")]}
        resp = client.post(
            "/v1/platforms/copilot-studio/import",
            params={"complete": "true"},
            json=hr_only,
            headers=ADMIN,
        )
        assert resp.status_code == 200, resp.text
        assert issue(client, sales["id"]).status == "resolved"

    def test_unblocking_closes_it_whatever_became_of_it(self, client) -> None:
        import_inventory(client)
        sales = agent_named(client, "sales-helper")
        block(client, "sales-helper")
        found = issue(client, sales["id"])
        resp = client.post(
            f"/v1/findings/{found.id}/dismiss",
            json={"reason": "its IAM role is gone"},
            headers=ADMIN,
        )
        assert resp.status_code == 200, resp.text
        # Still blocked, a sync leaves it dismissed.
        import_inventory(client)
        assert issue(client, sales["id"]).status == "dismissed"
        # Unblocking needs a sponsor.
        client.patch(
            f"/v1/agents/{sales['id']}", json={"sponsors": ["sam@example.com"]}, headers=ADMIN
        ).raise_for_status()
        unblocked = block(client, "sales-helper", "unblock")
        assert unblocked["still_runs_in"] is None
        closed = issue(client, sales["id"])
        assert closed.status == "resolved" and closed.resolved_by == "admin:bootstrap"
        # Blocked again: news again.
        block(client, "sales-helper")
        assert issue(client, sales["id"]).status == "open"

    def test_deleting_it_here_closes_it(self, client) -> None:
        import_inventory(client)
        sales = agent_named(client, "sales-helper")
        block(client, "sales-helper")
        block(client, "sales-helper", "delete")
        assert issue(client, sales["id"]).status == "resolved"

    def test_with_threat_detection_enforced_it_makes_no_tool_calls(self, client) -> None:
        import_inventory(client)
        with client.app.state.rt.db.session() as s:
            s.add(
                FeatureSetting(
                    key=platforms.THREAT_DETECTION, mode="enforce", changed_by="admin:test"
                )
            )
        sales = agent_named(client, "sales-helper")
        block(client, "sales-helper")
        assert (
            "it makes none, but it still answers people" in issue(client, sales["id"]).description
        )

    def test_blocked_in_microsoft_365_still_runs_in_copilot_studio(self, m365) -> None:  # noqa: F811
        m365.post("/v1/platforms/microsoft-365/sync", headers=ADMIN).raise_for_status()
        import_inventory(m365, [bot("bot-exp", "Expenses (Copilot Studio)", entra_id="entra-exp")])
        expenses = agent_named(m365, "expense-helper")
        rt = m365.app.state.rt  # type: ignore[attr-defined]
        with rt.db.session() as s:
            record = s.get(platforms.PlatformAgent, "microsoft-365:T_expenses")
            record.data = {**record.data, "blocked": True}
        done = block(m365, "expense-helper")
        assert done["still_runs_in"] == "Copilot Studio"
        found = issue(m365, expenses["id"])
        assert "Microsoft 365 has it blocked, but Copilot Studio still runs it." in (
            found.description
        )
        assert "stops it in Microsoft 365 Copilot and Teams only" in found.remediation


class TestOtherPlatforms:
    def record(self, client: TestClient, *found: Found, read: set[str] | None = None) -> None:
        rt = client.app.state.rt  # type: ignore[attr-defined]
        with rt.db.session() as s:
            platforms.record_inventory(
                s, "aws", Inventory(found=list(found), read=read or {"us-east-1"})
            )
            platforms.refresh_risk(s, rt.settings)

    def agent(self, *, stopped: bool | None = None) -> Found:
        return Found(
            external_id="arn:aws:bedrock:us-east-1:123:agent/claims",
            name="claims-bot",
            kind="Amazon Bedrock agent",
            part="us-east-1",
            details={},
            stopped=stopped,
        )

    def test_a_platform_that_reports_only_what_is_gone(self, client) -> None:
        self.record(client, self.agent())
        claims = agent_named(client, "claims-bot")
        block(client, "claims-bot")
        found = issue(client, claims["id"])
        assert found.title == "claims-bot is blocked in AgentGov but still runs in AWS"
        assert "AgentGov closes this issue once AWS no longer has it, at its next sync." in (
            found.remediation
        )
        assert "dismiss this issue saying how" in found.remediation
        # A region read in part leaves it as it was; read in full without it, it's gone.
        self.record(client, read={"eu-west-1"})
        assert issue(client, claims["id"]).status == "open"
        self.record(client)
        assert issue(client, claims["id"]).status == "resolved"

    def test_a_platform_that_reports_it_stopped(self, client) -> None:
        self.record(client, self.agent(stopped=False))
        claims = agent_named(client, "claims-bot")
        block(client, "claims-bot")
        assert issue(client, claims["id"]).status == "open"
        self.record(client, self.agent(stopped=True))
        assert issue(client, claims["id"]).status == "resolved"
        assert agent_named(client, "claims-bot")["platforms"][0]["stopped"] is True

    def test_connectors_say_when_an_agent_is_stopped(self) -> None:
        def app(state: str | None) -> dict[str, Any]:
            return {"name": "claims", "compute_status": {"state": state} if state else None}

        host = "https://adb-1.azuredatabricks.net"
        assert databricks.app_agent(app("STOPPED"), [], host).stopped is True
        assert databricks.app_agent(app("ACTIVE"), [], host).stopped is False
        assert databricks.app_agent(app(None), [], host).stopped is None

        def agent(state: str | None) -> dict[str, Any]:
            return {"name": "triage", **({"state": state} if state else {})}

        endpoint, part = (
            "https://contoso.services.ai.azure.com/api/projects/support",
            "contoso/support",
        )
        assert foundry.foundry_agent(agent("disabled"), endpoint, part).stopped is True
        assert foundry.foundry_agent(agent("enabled"), endpoint, part).stopped is False
        assert foundry.foundry_agent(agent(None), endpoint, part).stopped is None


class TestCli:
    def test_block_says_it_still_runs_there(self, client, monkeypatch) -> None:
        import_inventory(client)
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        out = ok(runner.invoke(cli.app, ["agents", "block", "sales-helper"]))
        assert "It still runs in Copilot Studio: an issue asks its people to stop it" in out

    def test_blocking_several(self, client, monkeypatch) -> None:
        import_inventory(client)
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        out = ok(runner.invoke(cli.app, ["agents", "block", "hr-faq", "sales-helper"]))
        assert "Those on Copilot Studio still run there" in out
        assert "For each one still running there, an issue asks its people to stop it." in out

"""Many agents and findings at once: each on its own, those it can't do left as they were,
with why (docs/administration.md#many-agents-at-once, docs/issues.md#many-at-once)."""

from __future__ import annotations

import csv
import io
from typing import Any

import httpx
from fastapi.testclient import TestClient

from agentgov.registry import findings
from tests.conftest import ADMIN
from tests.test_api import key
from tests.test_issue_answers import person
from tests.test_issues import _raise, _rt, agent  # noqa: F401 (the agent fixture)
from tests.test_people import import_studio, studio
from tests.test_secops import level


def register(
    client: TestClient,
    name: str,
    *,
    approve: bool = False,
    sponsors: tuple[str, ...] = ("alice@example.com",),
) -> dict[str, Any]:
    resp = client.post(
        "/v1/agents",
        json={"name": name, "owner": "cx", "sponsors": list(sponsors), "approve": approve},
        headers=ADMIN,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def at_once(
    client: TestClient, what: str, body: dict[str, Any], headers: dict[str, str] = ADMIN
) -> httpx.Response:
    return client.post(f"/v1/{what}/bulk", json=body, headers=headers)


def shown(client: TestClient, name: str) -> dict[str, Any]:
    return client.get(f"/v1/agents/{name}", headers=ADMIN).json()


class TestAgents:
    def test_each_on_its_own_and_why_not(self, client) -> None:
        register(client, "a1")
        register(client, "a2")
        register(client, "a3", sponsors=())
        register(client, "a4", approve=True)
        body = {"action": "approve", "agents": ["a1", "a2", "a3", "a4", "nope"], "reason": "Q3"}
        out = at_once(client, "agents", body)
        assert out.status_code == 200, out.text
        assert [(d["agent"], d["status"]) for d in out.json()["done"]] == [
            ("a1", "active"),
            ("a2", "active"),
        ]
        left = {x["agent"]: x["why"] for x in out.json()["left"]}
        assert left["nope"] == "there is no such agent"
        assert "at least one sponsor" in left["a3"]
        assert left["a4"] == "cannot approve an agent that is active"
        assert shown(client, "a3")["status"] == "pending"
        approved = client.get("/v1/ledger", params={"type": "agent.approve"}, headers=ADMIN)
        assert {(e["agent_name"], e["reason"]) for e in approved.json()} >= {
            ("a1", "Q3"),
            ("a2", "Q3"),
        }

    def test_an_edit_to_many(self, client, agent) -> None:  # noqa: F811
        register(client, "b1", sponsors=("alice@example.com", "carol@example.com"))
        fields = {
            "owner": "ai-governance",
            "add_sponsors": ["dana@example.com"],
            "remove_sponsors": ["ALICE@example.com"],
        }
        body = {"action": "update", "agents": ["support-bot", "b1"], "fields": fields}
        out = at_once(client, "agents", {**body, "reason": "Alice left"})
        assert out.status_code == 200 and not out.json()["left"], out.text
        b1, bot = shown(client, "b1"), shown(client, "support-bot")
        assert (b1["owner"], b1["sponsors"]) == (
            "ai-governance",
            ["carol@example.com", "dana@example.com"],
        )
        assert (bot["owner"], bot["sponsors"]) == ("ai-governance", ["bob", "dana@example.com"])
        updated = client.get("/v1/ledger", params={"type": "agent.updated"}, headers=ADMIN).json()
        assert {e["agent_name"] for e in updated if e["reason"] == "Alice left"} == {
            "b1",
            "support-bot",
        }

    def test_an_edit_says_what_it_takes(self, client, agent) -> None:  # noqa: F811
        for fields, code, says in (
            ({}, 422, "say what to change"),
            ({"description": "x"}, 422, "unknown field(s) description"),
            ({"sponsors": ["a"], "add_sponsors": ["b"]}, 422, "not both"),
            ({"team": "nope"}, 422, "team 'nope' not found"),
            ({"blueprint": "nope"}, 404, "nope"),
        ):
            out = at_once(
                client, "agents", {"action": "update", "agents": ["support-bot"], "fields": fields}
            )
            assert out.status_code == code and says in out.json()["detail"], (fields, out.text)
        for body, says in (
            ({"action": "approve", "agents": []}, "one at least"),
            ({"action": "approve", "agents": ["x"] * 2 + [str(n) for n in range(500)]}, "500"),
            ({"action": "adopt", "agents": ["support-bot"]}, "action is"),
            ({"action": "approve", "agents": ["support-bot"], "fields": {"owner": "x"}}, "update"),
            ({"action": "approve", "agents": ["support-bot"], "who": "me"}, "unknown field"),
        ):
            out = at_once(client, "agents", body)
            assert out.status_code == 422 and says in out.json()["detail"], (body, out.text)

    def test_who_may(self, client, agent) -> None:  # noqa: F811
        soc, approver = key(client, "secops", "soc"), key(client, "approver", "dana")
        block = {"action": "block", "agents": ["support-bot"], "reason": "Incident 42"}
        assert at_once(client, "agents", block, soc).status_code == 403
        level(client, "contain")
        assert at_once(client, "agents", block, soc).json()["done"][0]["status"] == "blocked"
        for body in (
            {"action": "delete", "agents": ["support-bot"]},
            {"action": "update", "agents": ["support-bot"], "fields": {"owner": "x"}},
        ):
            assert at_once(client, "agents", body, soc).status_code == 403
        assert at_once(client, "agents", block, approver).status_code == 403

    def test_it_says_which_run_on_platforms(self, client) -> None:
        import_studio(client, studio("bot-sales", "Sales Helper"))
        register(client, "gw-bot", approve=True)
        to_review = {"type": "platform.agents_to_review"}
        assert len(client.get("/v1/findings", params=to_review, headers=ADMIN).json()) == 1
        out = at_once(client, "agents", {"action": "block", "agents": ["sales-helper", "gw-bot"]})
        assert {d["agent"]: d["platform"] for d in out.json()["done"]} == {
            "sales-helper": "copilot-studio",
            "gw-bot": None,
        }
        # Blocked, it doesn't wait to be reviewed any more.
        assert client.get("/v1/findings", params=to_review, headers=ADMIN).json() == []


def _finding(client: TestClient, agent_id: str, type_: str, title: str) -> str:
    with _rt(client).db.session() as s:
        raised, _ = findings.raise_finding(
            s, type=type_, severity="medium", subject=agent_id, agent_id=agent_id, title=title
        )
        return raised.id


class TestFindings:
    def test_each_on_its_own_and_why_not(self, client, agent) -> None:  # noqa: F811
        a = _raise(client, agent["id"])
        b = _finding(client, agent["id"], "agent.attestation_overdue", "Attestation overdue")
        dismissed = at_once(
            client,
            "findings",
            {
                "action": "dismiss",
                "findings": [a, b, "nope"],
                "reason": "A test agent",
                "until": 30,
            },
        )
        assert dismissed.status_code == 200, dismissed.text
        assert sorted(d["finding"] for d in dismissed.json()["done"]) == sorted([a, b])
        assert dismissed.json()["left"] == [
            {"finding": "nope", "title": "", "why": "there is no such finding"}
        ]
        again = at_once(
            client, "findings", {"action": "dismiss", "findings": [a], "reason": "Again"}
        )
        assert again.json()["left"][0]["why"] == "finding is dismissed already"
        reopened = at_once(client, "findings", {"action": "reopen", "findings": [a, b]})
        assert {d["status"] for d in reopened.json()["done"]} == {"open"}

    def test_it_says_what_it_takes(self, client, agent) -> None:  # noqa: F811
        a = _raise(client, agent["id"])
        for body, says in (
            ({"action": "dismiss", "findings": [a]}, "say why they are wrong"),
            ({"action": "accept", "findings": [a], "reason": "ok"}, "until when"),
            ({"action": "accept", "findings": [a], "reason": "ok", "until": 400}, "a year"),
            ({"action": "resolve", "findings": [a], "reason": "fixed"}, "takes no reason"),
            ({"action": "recheck", "findings": [a]}, "action is"),
            ({"action": "resolve", "findings": a}, "is a list"),
        ):
            out = at_once(client, "findings", body)
            assert out.status_code == 422 and says in out.json()["detail"], (body, out.text)

    def test_people_acknowledge_theirs(self, client, agent) -> None:  # noqa: F811
        mine = _raise(client, agent["id"])
        other = register(client, "other-bot", approve=True)
        client.patch("/v1/agents/other-bot", json={"owner": "ops"}, headers=ADMIN)
        theirs = _finding(client, other["id"], "agent.attestation_overdue", "Overdue")
        _rt(client).run_issues()
        cx = person(client, "cx-team@example.com")
        out = at_once(client, "findings", {"action": "acknowledge", "findings": [mine, theirs]}, cx)
        assert out.status_code == 200, out.text
        assert [d["finding"] for d in out.json()["done"]] == [mine]
        assert out.json()["left"] == [
            {"finding": theirs, "title": "Overdue", "why": "it isn't yours"}
        ]
        refused = at_once(client, "findings", {"action": "resolve", "findings": [mine]}, cx)
        assert refused.status_code == 403

    def test_those_accountable_dont_accept_their_risks(self, client, agent) -> None:  # noqa: F811
        a = _raise(client, agent["id"])
        alice = person(client, "alice@example.com", role="approver")
        body = {"action": "accept", "findings": [a], "reason": "Retiring it", "until": 30}
        out = at_once(client, "findings", body, alice).json()
        assert out["done"] == [] and "sponsor" in out["left"][0]["why"]
        soc = key(client, "secops", "soc")
        assert at_once(client, "findings", body, soc).status_code == 403
        level(client, "triage")
        assert at_once(client, "findings", body, soc).json()["done"][0]["status"] == "accepted"


class TestTheCli:
    def test_agents(self, client, agent, monkeypatch) -> None:  # noqa: F811
        from agentgov import cli
        from tests.test_cli import _Shared, runner

        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        # More than the control plane takes a call: sent in turns.
        monkeypatch.setattr(cli, "AT_ONCE", 2)
        register(client, "c1")
        register(client, "c2")
        out = runner.invoke(cli.app, ["agents", "approve", "c1", "c2", "nope", "--reason", "Q3"])
        assert out.exit_code == 1, out.output
        assert "agent/c1: active" in out.output and "agent/c2: active" in out.output
        assert "agent/nope: left as it was: there is no such agent" in out.output
        out = runner.invoke(
            cli.app, ["agents", "update", "c1", "c2", "--add-sponsor", "dana@example.com"]
        )
        assert out.exit_code == 0 and "agent/c1: updated" in out.output, out.output
        assert shown(client, "c2")["sponsors"] == ["alice@example.com", "dana@example.com"]
        out = runner.invoke(cli.app, ["agents", "update", "c1", "c2", "--description", "x"])
        assert out.exit_code != 0 and "description one agent at a time" in out.output
        out = runner.invoke(cli.app, ["agents", "block", "c1", "c2", "--in-platform"])
        assert out.exit_code != 0 and "one agent at a time" in out.output
        listed = runner.invoke(cli.app, ["agents", "list", "-q"])
        assert listed.stdout.split() == ["c1", "c2", "support-bot"]
        sheet = list(
            csv.DictReader(io.StringIO(runner.invoke(cli.app, ["agents", "list", "--csv"]).stdout))
        )
        assert [(r["name"], r["status"], r["sponsors"]) for r in sheet][:2] == [
            ("c1", "active", "alice@example.com; dana@example.com"),
            ("c2", "active", "alice@example.com; dana@example.com"),
        ]

    def test_findings(self, client, agent, monkeypatch) -> None:  # noqa: F811
        from agentgov import cli
        from tests.test_cli import _Shared, runner

        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        a = _raise(client, agent["id"])
        b = _finding(client, agent["id"], "agent.attestation_overdue", '=HYPERLINK("x")')
        ids_ = runner.invoke(cli.app, ["findings", "list", "-q"]).stdout.split()
        assert sorted(ids_) == sorted([a, b])
        sheet = runner.invoke(cli.app, ["findings", "--csv"]).stdout
        # A title a spreadsheet would take for a formula stays text.
        assert "'=HYPERLINK" in sheet
        out = runner.invoke(cli.app, ["findings", "dismiss", a, b, "--reason", "A test agent"])
        assert out.exit_code == 0 and f"issue/{a}: dismissed" in out.output, out.output
        out = runner.invoke(cli.app, ["findings", "reopen", a, b])
        assert out.exit_code == 0 and f"issue/{b}: open" in out.output, out.output

"""Roles for one team's agents (approver@sales): from the identity provider, given in
AgentGov, or an API key's; what they read and change, and that nothing organisation-wide
takes them (docs/administration.md#roles-for-one-team)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentgov import cli, ids
from agentgov.config import Settings
from agentgov.identity import sso as sso_svc
from agentgov.models import ApprovalRequest, ModelUsage
from agentgov.registry import findings
from tests.conftest import ADMIN
from tests.test_cli import _Shared, ok, runner
from tests.test_sso import (  # noqa: F401 (fixtures)
    CSRF,
    TestOnlyPeopleWithARole,
    provider,
    sign_in,
    sso,
    sso_settings,
)


def _rt(client: TestClient) -> Any:
    return client.app.state.rt  # type: ignore[attr-defined]


def key(client: TestClient, role: str, team: str | None = "sales") -> dict[str, str]:
    body: dict[str, Any] = {"name": f"{role}-{team}", "role": role, "team": team}
    resp = client.post("/v1/apikeys", json=body, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def agent(client: TestClient, name: str, **fields: Any) -> dict[str, Any]:
    body = {"name": name, "owner": "cx@example.com", "sponsors": ["cx@example.com"],
            "approve": True, **fields}  # fmt: skip
    resp = client.post("/v1/agents", json=body, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()


def finding(client: TestClient, agent_id: str, title: str) -> str:
    with _rt(client).db.session() as s:
        raised, _ = findings.raise_finding(
            s, type="test.thing", severity="medium", subject=agent_id, agent_id=agent_id,
            title=title,
        )  # fmt: skip
        return raised.id


def request(client: TestClient, agent: dict[str, Any]) -> str:
    """An approval request from ``agent``, waiting for an approver."""
    now = ids.utcnow()
    with _rt(client).db.session() as s:
        s.add(ApprovalRequest(id=f"apr_{agent['name']}", agent_id=agent["id"],
                              agent_name=agent["name"], action="tools/call", resource="crm/x",
                              arguments_hash="h", status="pending", requested_at=now,
                              expires_at=now + timedelta(hours=1)))  # fmt: skip
    return f"apr_{agent['name']}"


def names(rows: list[dict[str, Any]], field: str = "name") -> set[str]:
    return {r[field] for r in rows}


@pytest.fixture
def org(client: TestClient) -> dict[str, dict[str, Any]]:
    """Teams sales, hr and ops (the default team); agents with each, one by its blueprint."""
    for name in ("sales", "hr", "ops"):
        client.post("/v1/teams", json={"name": name}, headers=ADMIN).raise_for_status()
    client.patch("/v1/teams/ops", json={"default": True}, headers=ADMIN).raise_for_status()
    client.post(
        "/v1/blueprints", json={"name": "sales-bp", "team": "sales"}, headers=ADMIN
    ).raise_for_status()
    return {
        "sales": agent(client, "sales-bot", team="sales"),
        "by-blueprint": agent(client, "quote-bot", blueprint="sales-bp"),
        "hr": agent(client, "hr-bot", team="hr"),
        # No team of its own, nor a blueprint's: the default team's.
        "loose": agent(client, "loose-bot"),
    }


class TestIdentity:
    def test_the_provider_names_roles_for_a_team(self) -> None:
        claims = {"groups": ["agentgov-approver@sales", "agentgov-auditor", "agentgov-person@x"]}
        found = sso_svc.roles_from_claims(claims, "groups", "agentgov-", {})
        assert found == ["auditor", "approver@sales"]
        mapped = sso_svc.roles_from_claims(
            {"groups": ["g1"]}, "groups", "agentgov-", {"g1": {"secops@hr"}}
        )
        assert mapped == ["secops@hr"]
        assert Settings(oidc_role_map="Sales approvers=approver@sales").oidc_role_pairs() == {
            "Sales approvers": {"approver@sales"}
        }
        for wrong in ("x=person@sales", "x=service@sales", "x=approver@"):
            with pytest.raises(ValueError, match="AGENTGOV_OIDC_ROLE_MAP"):
                Settings(oidc_role_map=wrong).oidc_role_pairs()

    def test_signed_in_with_roles_for_a_team(self, sso, provider) -> None:  # noqa: F811
        resp = sign_in(sso, provider, roles=["agentgov-approver@sales", "agentgov-auditor@hr"])
        assert resp.headers["location"] == "/ui/"
        me = sso.get("/v1/me").json()
        assert me["roles"] == ["approver@sales", "auditor@hr"]
        assert me["teams"] == {"approver": ["sales"], "auditor": ["hr"]}
        # Nothing organisation-wide.
        assert sso.get("/v1/overview").status_code == 403
        assert sso.get("/v1/agents").status_code == 200

    def test_a_role_for_a_team_is_a_role(self, sso_settings, provider) -> None:  # noqa: F811
        """Where only people with a role may sign in, a role for one team is one."""
        with TestOnlyPeopleWithARole.client(
            sso_settings, provider, oidc_require_role=True
        ) as client:
            resp = sign_in(client, provider, roles=["agentgov-auditor@sales"])
            assert resp.headers["location"] == "/ui/"
            assert client.get("/v1/me").json()["roles"] == ["auditor@sales"]


class TestGiving:
    def test_a_role_for_a_team_given_in_agentgov(self, client, org) -> None:
        resp = client.post(
            "/v1/access/grants",
            json={"email": "Bo@Example.com", "role": "approver", "team": "sales"},
            headers=ADMIN,
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["role"] == "approver@sales"
        grants = client.get("/v1/access", headers=ADMIN).json()["grants"]
        assert [(g["email"], g["role"]) for g in grants] == [("bo@example.com", "approver@sales")]
        for body, words in (
            ({"role": "approver", "team": "nope"}, "team 'nope' not found"),
            ({"role": "person", "team": "sales"}, "the person role is for every team"),
        ):
            bad = client.post(
                "/v1/access/grants", json={"email": "c@example.com", **body}, headers=ADMIN
            )
            assert bad.status_code == 422 and words in bad.json()["detail"], bad.text
        taken = client.delete("/v1/access/grants/bo@example.com/approver@sales", headers=ADMIN)
        assert taken.status_code == 200, taken.text

    def test_an_api_key_for_a_team(self, client, org) -> None:
        resp = client.post(
            "/v1/apikeys",
            json={"name": "sales-ci", "role": "auditor", "team": "sales"},
            headers=ADMIN,
        )
        assert resp.status_code == 201 and resp.json()["role"] == "auditor@sales"
        me = client.get("/v1/me", headers={"Authorization": f"Bearer {resp.json()['token']}"})
        assert (me.json()["actor"], me.json()["teams"]) == (
            "auditor@sales:sales-ci",
            {"auditor": ["sales"]},
        )
        bad = client.post(
            "/v1/apikeys", json={"name": "x", "role": "service", "team": "sales"}, headers=ADMIN
        )
        assert bad.status_code == 422

    def test_the_cli(self, client, org, monkeypatch) -> None:
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        result = runner.invoke(
            cli.app, ["access", "grant", "bo@example.com", "secops", "--team", "hr"]
        )
        assert result.exit_code == 0, result.output
        assert "secops@hr" in ok(runner.invoke(cli.app, ["access", "grants"]))
        result = runner.invoke(
            cli.app, ["apikeys", "create", "hr-siem", "--role", "secops", "--team", "hr"]
        )
        assert result.exit_code == 0 and "(secops@hr)" in result.stderr, result.output
        result = runner.invoke(
            cli.app, ["access", "revoke", "bo@example.com", "secops", "--team", "hr"]
        )
        assert result.exit_code == 0, result.output


class TestReading:
    def test_their_teams_agents_only(self, client, org) -> None:
        sales = key(client, "auditor")
        listed = client.get("/v1/agents", headers=sales).json()
        assert names(listed) == {"sales-bot", "quote-bot"}
        assert {tuple(a["your_roles"]) for a in listed} == {("auditor",)}
        assert client.get("/v1/agents/sales-bot", headers=sales).status_code == 200
        for path in ("", "/a2a", "/risk", "/instructions", "/access-packages", "/rules"):
            assert client.get(f"/v1/agents/quote-bot{path}", headers=sales).status_code == 200
            out = client.get(f"/v1/agents/hr-bot{path}", headers=sales)
            assert out.status_code in (403, 404), (path, out.text)
        assert client.get("/v1/agents/hr-bot", headers=sales).json()["detail"] == (
            "agent hr-bot not found"
        )
        # The default team's.
        ops = key(client, "auditor", "ops")
        assert names(client.get("/v1/agents", headers=ops).json()) == {"loose-bot"}

    def test_what_hangs_off_them(self, client, org) -> None:
        mine = finding(client, org["sales"]["id"], "Sales thing")
        finding(client, org["hr"]["id"], "HR thing")
        request(client, org["sales"])
        request(client, org["hr"])
        with _rt(client).db.session() as s:
            day = ids.utcnow().strftime("%Y-%m-%d")
            for a in (org["sales"], org["hr"]):
                s.add(ModelUsage(agent_id=a["id"], day=day, provider="p", model="m", calls=1))
        sales = key(client, "auditor")
        issues = client.get("/v1/findings", headers=sales)
        assert [f["id"] for f in issues.json()] == [mine]
        assert issues.headers["X-Total-Count"] == "1"
        assert client.get(f"/v1/findings/{mine}", headers=sales).status_code == 200
        assert names(client.get("/v1/approvals", headers=sales).json(), "agent_name") == {
            "sales-bot"
        }
        assert names(client.get("/v1/ledger", headers=sales).json(), "agent_name") <= {
            "sales-bot",
            "quote-bot",
        }
        usage = client.get("/v1/models/usage", headers=sales).json()
        assert {r["agent_name"] for r in usage["rows"]} == {"sales-bot"}
        assert (
            client.get("/v1/ledger", params={"agent": "hr-bot"}, headers=sales).status_code == 404
        )
        assert names(client.get("/v1/teams", headers=sales).json()) == {"sales"}
        assert client.get("/v1/teams/hr", headers=sales).status_code == 404
        assert "sales-bp" in names(client.get("/v1/blueprints", headers=sales).json())

    def test_nothing_organisation_wide(self, client, org) -> None:
        admin = key(client, "admin")
        for path in (
            "/v1/overview",
            "/v1/features",
            "/v1/toolservers",
            "/v1/apikeys",
            "/v1/access",
            "/v1/ledger/verify",
            "/v1/ledger/export",
            "/v1/finding-types",
            "/v1/models/providers",
            "/v1/platforms",
        ):
            assert client.get(path, headers=admin).status_code == 403, path
        assert client.post("/v1/teams", json={"name": "x"}, headers=admin).status_code == 403
        assert client.post("/v1/posture/scan", headers=admin).status_code == 403
        # Gone for good: administrators for every team.
        client.post("/v1/agents/sales-bot/delete", json={}, headers=admin).raise_for_status()
        assert client.delete("/v1/agents/sales-bot", headers=admin).status_code == 403


class TestActing:
    def test_an_administrator_for_a_team(self, client, org) -> None:
        admin = key(client, "admin")
        edited = client.patch("/v1/agents/sales-bot", json={"description": "Quotes"}, headers=admin)
        assert edited.status_code == 200, edited.text
        moved = client.patch("/v1/agents/sales-bot", json={"team": "hr"}, headers=admin)
        assert moved.status_code == 403
        assert "would no longer be with your teams (sales)" in moved.json()["detail"]
        assert client.get("/v1/agents/sales-bot", headers=ADMIN).json()["team"] == "sales"
        assert (
            client.patch("/v1/agents/hr-bot", json={"description": "x"}, headers=admin).status_code
            == 404
        )
        # Registered into their one team.
        made = client.post("/v1/agents", json={"name": "new-bot", "owner": "cx"}, headers=admin)
        assert made.status_code == 201 and made.json()["team"] == "sales", made.text
        elsewhere = client.post(
            "/v1/agents", json={"name": "hr-new", "owner": "cx", "team": "hr"}, headers=admin
        )
        assert elsewhere.status_code == 403
        assert client.get("/v1/agents/hr-new", headers=ADMIN).status_code == 404
        for action in ("block", "unblock", "delete", "restore"):
            out = client.post(f"/v1/agents/quote-bot/{action}", json={}, headers=admin)
            assert out.status_code == 200, (action, out.text)
        assert client.post("/v1/agents/hr-bot/block", json={}, headers=admin).status_code == 404

    def test_exemptions_stay_with_administrators_for_every_team(self, client, org) -> None:
        admin = key(client, "admin")
        exempt = {"agentgov/exempt-rules": "true"}
        out = client.patch("/v1/agents/sales-bot", json={"labels": exempt}, headers=admin)
        assert out.status_code == 403, out.text
        assert "administrators for every team" in out.json()["detail"]
        client.patch(
            "/v1/agents/sales-bot", json={"labels": exempt}, headers=ADMIN
        ).raise_for_status()
        # Their own labels, with the exemption as it is.
        kept = client.patch(
            "/v1/agents/sales-bot", json={"labels": {**exempt, "app": "crm"}}, headers=admin
        )
        assert kept.status_code == 200, kept.text
        gone = client.patch("/v1/agents/sales-bot", json={"labels": {}}, headers=admin)
        assert gone.status_code == 403
        made = client.post(
            "/v1/agents",
            json={"name": "x-bot", "owner": "cx", "labels": {"agentgov/exempt-controls": "x"}},
            headers=admin,
        )
        assert made.status_code == 422, made.text

    def test_registered_and_approved_by_an_administrator_for_the_team(self, client, org) -> None:
        body = {"owner": "cx", "sponsors": ["cx@example.com"], "approve": True}
        made = client.post(
            "/v1/agents", json={"name": "fast-bot", **body}, headers=key(client, "admin")
        )
        assert made.json()["status"] == "active", made.text
        asked = client.post(
            "/v1/agents", json={"name": "slow-bot", **body}, headers=key(client, "registrar")
        )
        assert (asked.json()["status"], asked.json()["team"]) == ("pending", "sales")

    def test_secops_for_a_team_as_far_as_the_hand_off_lets_it(self, client, org) -> None:
        secops = key(client, "secops")
        out = client.post("/v1/agents/sales-bot/block", json={}, headers=secops)
        assert out.status_code == 403 and "hand-off" in out.json()["detail"]
        client.put(
            "/v1/features/security-operations", json={"mode": "contain"}, headers=ADMIN
        ).raise_for_status()
        assert client.get("/v1/me", headers=secops).json()["handoff"]["level"] == "contain"
        assert client.post("/v1/agents/sales-bot/block", json={}, headers=secops).status_code == 200
        assert (
            client.post("/v1/agents/sales-bot/delete", json={}, headers=secops).status_code == 403
        )
        assert client.post("/v1/agents/hr-bot/block", json={}, headers=secops).status_code == 404

    def test_many_at_once(self, client, org) -> None:
        approver = key(client, "approver")
        out = client.post(
            "/v1/agents/bulk",
            json={
                "action": "classify",
                "agents": ["sales-bot", "hr-bot"],
                "fields": {"category": "minimal", "role": "deployer", "basis": "b", "purpose": "p"},
            },
            headers=approver,
        )
        assert out.status_code == 200, out.text
        assert [d["agent"] for d in out.json()["done"]] == ["sales-bot"]
        assert out.json()["left"] == [{"agent": "hr-bot", "why": "there is no such agent"}]
        admin = key(client, "admin")
        moved = client.post(
            "/v1/agents/bulk",
            json={"action": "update", "agents": ["sales-bot"], "fields": {"team": "hr"}},
            headers=admin,
        )
        assert "would no longer be with your teams" in moved.json()["left"][0]["why"]
        assert client.get("/v1/agents/sales-bot", headers=ADMIN).json()["team"] == "sales"
        assert (
            client.post(
                "/v1/agents/bulk",
                json={"action": "block", "agents": ["sales-bot"]},
                headers=approver,
            ).status_code
            == 403
        )

    def test_many_at_once_by_the_roles_held_where_each_agent_is(self, client, org) -> None:
        def at_once(headers: dict[str, str], action: str, *refs: str) -> dict[str, Any]:
            out = client.post(
                "/v1/agents/bulk", json={"action": action, "agents": list(refs)}, headers=headers
            )
            assert out.status_code == 200, out.text
            return out.json()

        # An administrator for sales approves and deletes sales agents, and no others.
        pending = client.post(
            "/v1/agents",
            json={"name": "wait-bot", "owner": "cx", "sponsors": ["cx@example.com"]},
            headers=key(client, "registrar"),
        ).json()
        assert pending["status"] == "pending"
        admin = key(client, "admin")
        done = at_once(admin, "approve", "wait-bot", "hr-bot")
        assert [d["agent"] for d in done["done"]] == ["wait-bot"]
        assert done["left"] == [{"agent": "hr-bot", "why": "there is no such agent"}]
        assert [d["agent"] for d in at_once(admin, "delete", "wait-bot")["done"]] == ["wait-bot"]
        # Secops for sales, as far as the hand-off lets it.
        secops = key(client, "secops")
        held = at_once(secops, "block", "sales-bot")
        assert held["done"] == [] and "hand-off" in held["left"][0]["why"]
        client.put(
            "/v1/features/security-operations", json={"mode": "contain"}, headers=ADMIN
        ).raise_for_status()
        assert [d["agent"] for d in at_once(secops, "block", "sales-bot")["done"]] == ["sales-bot"]
        assert "nothing else" in at_once(secops, "delete", "sales-bot")["left"][0]["why"]
        unknown = client.post(
            "/v1/agents/bulk", json={"action": "fly", "agents": ["sales-bot"]}, headers=secops
        )
        assert unknown.status_code == 422

    def test_issues_and_approvals(self, client, org) -> None:
        mine = finding(client, org["sales"]["id"], "Sales thing")
        theirs = finding(client, org["hr"]["id"], "HR thing")
        approver = key(client, "approver")
        assert client.post(f"/v1/findings/{mine}/resolve", headers=approver).status_code == 200
        assert client.post(f"/v1/findings/{theirs}/resolve", headers=approver).status_code == 403
        out = client.post(
            "/v1/findings/bulk",
            json={"action": "reopen", "findings": [mine, theirs]},
            headers=approver,
        )
        assert [d["finding"] for d in out.json()["done"]] == [mine]
        assert out.json()["left"][0]["why"] == "it isn't yours"
        listed = client.get("/v1/findings", headers=approver).json()
        assert [tuple(f["your_roles"]) for f in listed] == [("approver",)]
        sales, hr = request(client, org["sales"]), request(client, org["hr"])
        waiting = client.get("/v1/inbox", headers=approver).json()
        calls = next(k for k in waiting["kinds"] if k["kind"] == "calls")
        assert [r["id"] for r in calls["items"]] == [sales]
        assert calls["items"][0]["your_roles"] == ["approver"]
        assert client.post(f"/v1/approvals/{sales}/approve", headers=approver).status_code == 200
        assert client.post(f"/v1/approvals/{hr}/approve", headers=approver).status_code == 403
        # An auditor for the team reads them, and decides nothing.
        auditor = key(client, "auditor")
        assert client.get(f"/v1/approvals/{sales}", headers=auditor).status_code == 200
        assert client.get(f"/v1/approvals/{hr}", headers=auditor).status_code == 403
        assert client.post(f"/v1/findings/{mine}/resolve", headers=auditor).status_code == 403

    def test_a_blueprints_team(self, client, org) -> None:
        # quote-bot is the sales team's by its blueprint: given another, it would leave.
        client.post("/v1/blueprints", json={"name": "hr-bp", "team": "hr"}, headers=ADMIN)
        admin = key(client, "admin")
        out = client.patch("/v1/agents/quote-bot", json={"blueprint": "hr-bp"}, headers=admin)
        assert out.status_code == 403, out.text
        # Its own team keeps it with sales, whatever its blueprint.
        ok_ = client.patch(
            "/v1/agents/quote-bot", json={"blueprint": "hr-bp", "team": "sales"}, headers=admin
        )
        assert ok_.status_code == 200, ok_.text


def test_signed_in_ui_reaches_their_pages(sso, provider) -> None:  # noqa: F811
    """What the admin UI is told: roles for a team, and who they are where each agent is."""
    sign_in(sso, provider, roles=["agentgov-admin@sales"])
    me = sso.get("/v1/me").json()
    assert me["teams"] == {"admin": ["sales"]}
    sso.post("/v1/teams", json={"name": "sales"}, headers=ADMIN).raise_for_status()
    made = sso.post("/v1/agents", json={"name": "s-bot", "owner": "cx"}, headers=CSRF)
    assert made.status_code == 201 and made.json()["team"] == "sales", made.text
    [row] = sso.get("/v1/agents").json()
    assert row["your_roles"] == ["admin"]

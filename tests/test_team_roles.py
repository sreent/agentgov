"""Roles for one team's agents (approver@sales): from the identity provider, given in
AgentGov, or an API key's; what they read and change, and that nothing organisation-wide
takes them (docs/administration.md#roles-for-one-team)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from starlette.testclient import TestClient

from agentgov import cli, ids
from agentgov.config import Settings
from agentgov.identity import sso as sso_svc
from agentgov.models import ApprovalRequest, ModelUsage
from agentgov.registry import discovery, findings
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
            assert out.status_code == 404, (path, out.text)
        # In the same words as for an agent there isn't.
        assert client.get("/v1/agents/hr-bot", headers=sales).json()["detail"] == (
            "agent 'hr-bot' not found"
        )
        for path in ("", "/access-packages", "/rules"):
            out = client.get(f"/v1/agents/{org['hr']['id']}{path}", headers=sales).json()
            assert out["detail"] == f"agent {org['hr']['id']!r} not found", path
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


class TestReserved:
    def test_entitlements_are_for_administrators_for_every_team(self, client, org) -> None:
        """pii-access lets an agent have personal data unmasked (the policies read it): set,
        changed and removed, as the agentgov/ labels, by administrators for every team."""
        pii = {"pii-access": "true"}
        admin = key(client, "admin")
        out = client.patch("/v1/agents/sales-bot", json={"labels": pii}, headers=admin)
        assert out.status_code == 403 and "pii-access" in out.json()["detail"], out.text
        for registrar in (key(client, "registrar"), key(client, "registrar", None)):
            made = client.post(
                "/v1/agents",
                json={"name": "pii-bot", "owner": "cx", "labels": pii},
                headers=registrar,
            )
            assert made.status_code == 422 and "pii-access" in made.json()["detail"], made.text
        client.patch("/v1/agents/sales-bot", json={"labels": pii}, headers=ADMIN).raise_for_status()
        for labels in ({}, None, {"pii-access": "false"}):
            out = client.patch("/v1/agents/sales-bot", json={"labels": labels}, headers=admin)
            assert out.status_code == 403, labels
        kept = client.patch(
            "/v1/agents/sales-bot", json={"labels": {**pii, "app": "crm"}}, headers=admin
        )
        assert kept.status_code == 200, kept.text
        assert client.get("/v1/agents/sales-bot", headers=ADMIN).json()["labels"] == {
            **pii,
            "app": "crm",
        }

    def test_no_labels_is_labels_too(self, client, org) -> None:
        exempt = {"agentgov/exempt-rules": "true"}
        client.patch(
            "/v1/agents/sales-bot", json={"labels": exempt}, headers=ADMIN
        ).raise_for_status()
        out = client.patch(
            "/v1/agents/sales-bot", json={"labels": None}, headers=key(client, "admin")
        )
        assert out.status_code == 403, out.text
        assert client.get("/v1/agents/sales-bot", headers=ADMIN).json()["labels"] == exempt

    def test_nor_from_a_blueprint(self, client, org) -> None:
        """A blueprint's labels are its agents' too, as the policies read them."""
        client.post(
            "/v1/blueprints",
            json={"name": "pii-bp", "team": "sales", "labels": {"pii-access": "true"}},
            headers=ADMIN,
        ).raise_for_status()
        out = client.patch(
            "/v1/agents/sales-bot", json={"blueprint": "pii-bp"}, headers=key(client, "admin")
        )
        assert out.status_code == 403 and "pii-access" in out.json()["detail"], out.text
        assert client.get("/v1/agents/sales-bot", headers=ADMIN).json()["blueprint"] is None


class TestLoosening:
    """A role for one team changes its agents, but doesn't loosen what governs them: a
    control's mode, the management rules that look at them, what they may call."""

    def test_not_into_a_controls_weaker_mode(self, client, org) -> None:
        scopes = [{"mode": "monitor", "scope": {"environments": ["dev"]}}]
        client.put(
            "/v1/features/data-protection",
            json={"mode": "enforce", "scopes": scopes},
            headers=ADMIN,
        ).raise_for_status()
        admin = key(client, "admin")
        out = client.patch("/v1/agents/sales-bot", json={"environment": "dev"}, headers=admin)
        assert out.status_code == 403, out.text
        assert "data-protection" in out.json()["detail"]
        assert client.get("/v1/agents/sales-bot", headers=ADMIN).json()["environment"] is None
        at_once = client.post(
            "/v1/agents/bulk",
            json={"action": "update", "agents": ["sales-bot"], "fields": {"environment": "dev"}},
            headers=admin,
        ).json()
        assert at_once["done"] == [] and "data-protection" in at_once["left"][0]["why"]
        # What isn't weaker is theirs to change; an administrator for every team does either.
        assert (
            client.patch(
                "/v1/agents/sales-bot", json={"environment": "test"}, headers=admin
            ).status_code
            == 200
        )
        client.patch(
            "/v1/agents/sales-bot", json={"environment": "dev"}, headers=ADMIN
        ).raise_for_status()
        back = client.patch("/v1/agents/sales-bot", json={"environment": "prod"}, headers=admin)
        assert back.status_code == 200, back.text

    def test_not_out_of_a_management_rules_scope(self, client, org) -> None:
        client.post(
            "/v1/rules",
            json={
                "name": "prod-owners",
                "conditions": {"missing": ["owner"]},
                "scope": {"labels": {"tier": "prod"}},
                "action": "issue",
            },
            headers=ADMIN,
        ).raise_for_status()
        client.patch(
            "/v1/agents/sales-bot", json={"labels": {"tier": "prod"}}, headers=ADMIN
        ).raise_for_status()
        admin = key(client, "admin")
        out = client.patch("/v1/agents/sales-bot", json={"labels": {}}, headers=admin)
        assert out.status_code == 403 and "prod-owners" in out.json()["detail"], out.text
        # Into a rule's scope is theirs to choose.
        joined = client.patch(
            "/v1/agents/quote-bot", json={"labels": {"tier": "prod"}}, headers=admin
        )
        assert joined.status_code == 200, joined.text

    def test_grants_only_narrow(self, client, org) -> None:
        client.patch(
            "/v1/agents/sales-bot",
            json={
                "permissions": [{"server": "crm", "tools": ["get_*", "update_customer"]}],
                "model_access": [{"provider": "openai", "models": ["gpt-4*"]}],
                "agent_access": ["billing-*"],
            },
            headers=ADMIN,
        ).raise_for_status()
        admin = key(client, "admin")

        def edit(**body: Any) -> Any:
            return client.patch("/v1/agents/sales-bot", json=body, headers=admin)

        for wider in (
            {"permissions": [{"server": "crm", "tools": ["*"]}]},
            {"permissions": [{"server": "*", "tools": ["get_*"]}]},
            {"permissions": [{"server": "hr-db", "tools": ["get_*"]}]},
            {"model_access": [{"provider": "openai", "models": ["*"]}]},
            {"model_access": [{"provider": "azure", "models": ["gpt-4o"]}]},
            {"agent_access": ["*"]},
            {"agent_access": ["hr-bot"]},
        ):
            out = edit(**wider)
            assert out.status_code == 403, (wider, out.text)
            assert "access package" in out.json()["detail"]
        for narrower in (
            {"permissions": [{"server": "crm", "tools": ["get_customer", "update_customer"]}]},
            {"model_access": [{"provider": "openai", "models": ["gpt-4o"]}]},
            {"agent_access": ["billing-eu"]},
            {"permissions": [], "model_access": [], "agent_access": []},
        ):
            assert edit(**narrower).status_code == 200, narrower
        # A blueprint is its agents' grants too.
        client.post(
            "/v1/blueprints",
            json={
                "name": "wide-bp",
                "team": "sales",
                "permissions": [{"server": "*", "tools": ["*"]}],
            },
            headers=ADMIN,
        ).raise_for_status()
        assert edit(blueprint="wide-bp").status_code == 403
        at_once = client.post(
            "/v1/agents/bulk",
            json={"action": "update", "agents": ["quote-bot"], "fields": {"blueprint": "wide-bp"}},
            headers=admin,
        ).json()
        assert at_once["done"] == [] and "access package" in at_once["left"][0]["why"]
        wider = {"permissions": [{"server": "*", "tools": ["*"]}]}
        assert client.patch("/v1/agents/sales-bot", json=wider, headers=ADMIN).status_code == 200

    def test_not_for_more_people(self, client, org) -> None:
        """Whom an agent acts for is its blueprint's to say: one for some teams only doesn't
        switch it to one that acts for more."""
        for name, acts_for, groups in (
            ("support-only", "people", ["/support"]),
            ("support-too", "people", ["support"]),
            ("all-people", "people", []),
            ("self-only", "itself", []),
            ("either-support", "either", ["support"]),
            ("support-sales", "people", ["support", "sales"]),
        ):
            client.post(
                "/v1/blueprints",
                json={"name": name, "team": "sales", "acts_for": acts_for, "people_groups": groups},
                headers=ADMIN,
            ).raise_for_status()
        client.patch(
            "/v1/agents/sales-bot", json={"blueprint": "support-only"}, headers=ADMIN
        ).raise_for_status()
        admin = key(client, "admin")
        for wider, said in (
            ("all-people", "it would act for anyone, not only people in support"),
            ("self-only", "it would act on its own behalf"),
            ("either-support", "it would act on its own behalf"),
            ("support-sales", "it would act for people in sales, support"),
            (None, "it would act on its own behalf"),
        ):
            out = client.patch("/v1/agents/sales-bot", json={"blueprint": wider}, headers=admin)
            assert out.status_code == 403, (wider, out.text)
            assert said in out.json()["detail"], (wider, out.text)
        at_once = client.post(
            "/v1/agents/bulk",
            json={
                "action": "update",
                "agents": ["sales-bot"],
                "fields": {"blueprint": "all-people"},
            },
            headers=admin,
        ).json()
        assert at_once["done"] == [] and "anyone" in at_once["left"][0]["why"]
        # The same groups, however they are written, and fewer people, are theirs to choose.
        same = client.patch(
            "/v1/agents/sales-bot", json={"blueprint": "support-too"}, headers=admin
        )
        assert same.status_code == 200, same.text
        client.patch(
            "/v1/agents/sales-bot", json={"blueprint": "all-people"}, headers=ADMIN
        ).raise_for_status()
        fewer = client.patch(
            "/v1/agents/sales-bot", json={"blueprint": "support-only"}, headers=admin
        )
        assert fewer.status_code == 200, fewer.text
        # Adopting it, too.
        with _rt(client).db.session() as s:
            assert discovery.observe(s, source="test", name="found-bot") is not None
        client.patch(
            "/v1/agents/found-bot",
            json={"team": "sales", "blueprint": "support-only"},
            headers=ADMIN,
        ).raise_for_status()
        body = {"owner": "cx", "sponsors": ["cx@example.com"], "blueprint": "all-people"}
        out = client.post("/v1/agents/found-bot/adopt", json=body, headers=admin)
        assert out.status_code == 403 and "anyone" in out.json()["detail"], out.text
        body["blueprint"] = "support-only"
        adopted = client.post("/v1/agents/found-bot/adopt", json=body, headers=admin)
        assert adopted.json()["status"] == "pending", adopted.text


class TestPuttingToWork:
    """A role for one team puts an agent to work with what its blueprint grants, no more:
    beyond that, an access package, or an administrator for every team approves it."""

    WITHIN = {
        "permissions": [{"server": "crm", "tools": ["get_customer"]}],
        "model_access": [{"provider": "openai", "models": ["gpt-4o"]}],
        "agent_access": ["billing-eu"],
    }
    BEYOND = (
        ({"permissions": [{"server": "crm", "tools": ["*"]}]}, "tool crm/*"),
        (
            {"model_access": [{"provider": "openai", "models": ["big-model"]}]},
            "model openai/big-model",
        ),
        ({"agent_access": ["hr-*"]}, "calls to agents hr-*"),
    )

    @pytest.fixture(autouse=True)
    def blueprint(self, client, org) -> None:
        client.post(
            "/v1/blueprints",
            json={
                "name": "crm-bp",
                "team": "sales",
                "permissions": [{"server": "crm", "tools": ["get_*"]}],
                "model_access": [{"provider": "openai", "models": ["gpt-4*"]}],
                "agent_access": ["billing-*"],
            },
            headers=ADMIN,
        ).raise_for_status()

    @staticmethod
    def body(name: str, **fields: Any) -> dict[str, Any]:
        return {"name": name, "owner": "cx", "sponsors": ["cx@example.com"],
                "blueprint": "crm-bp", **fields}  # fmt: skip

    @staticmethod
    def refused(out: Any, gained: str) -> None:
        assert out.status_code == 403, out.text
        detail = out.json()["detail"]
        assert gained in detail and "access package" in detail, detail
        assert "an administrator for every team approves it" in detail, detail

    def test_registered_and_approved_at_once(self, client) -> None:
        admin = key(client, "admin")
        fits = client.post(
            "/v1/agents",
            json={**self.body("fit-bot", **self.WITHIN), "approve": True},
            headers=admin,
        )
        assert fits.status_code == 201 and fits.json()["status"] == "active", fits.text
        for i, (beyond, gained) in enumerate(self.BEYOND):
            body = {**self.body(f"wide-bot-{i}", **beyond), "approve": True}
            self.refused(client.post("/v1/agents", json=body, headers=admin), gained)
            assert client.get(f"/v1/agents/wide-bot-{i}", headers=ADMIN).status_code == 404
        # Not approved, it waits for approval.
        waits = client.post(
            "/v1/agents", json=self.body("wide-bot", **self.BEYOND[0][0]), headers=admin
        )
        assert waits.json()["status"] == "pending", waits.text

    def test_approved_after(self, client) -> None:
        client.post(
            "/v1/agents", json=self.body("wide-bot", **self.BEYOND[0][0]), headers=ADMIN
        ).raise_for_status()
        admin = key(client, "admin")
        self.refused(
            client.post("/v1/agents/wide-bot/approve", json={}, headers=admin), "tool crm/*"
        )
        at_once = client.post(
            "/v1/agents/bulk", json={"action": "approve", "agents": ["wide-bot"]}, headers=admin
        ).json()
        assert at_once["done"] == [] and "tool crm/*" in at_once["left"][0]["why"]
        assert client.get("/v1/agents/wide-bot", headers=ADMIN).json()["status"] == "pending"
        # With no more than its blueprint grants, it is theirs to approve.
        client.patch(
            "/v1/agents/wide-bot", json={"permissions": []}, headers=admin
        ).raise_for_status()
        approved = client.post("/v1/agents/wide-bot/approve", json={}, headers=admin)
        assert approved.json()["status"] == "active", approved.text
        # An administrator for every team approves what goes beyond it.
        client.post(
            "/v1/agents", json=self.body("big-bot", **self.BEYOND[1][0]), headers=ADMIN
        ).raise_for_status()
        big = client.post("/v1/agents/big-bot/approve", json={}, headers=ADMIN)
        assert big.json()["status"] == "active", big.text

    def test_registered_while_registration_approval_is_off(self, client) -> None:
        client.put(
            "/v1/features/registration-approval", json={"mode": "off"}, headers=ADMIN
        ).raise_for_status()
        registrar = key(client, "registrar")
        fits = client.post(
            "/v1/agents", json=self.body("fit-bot", **self.WITHIN), headers=registrar
        )
        assert fits.json()["status"] == "active", fits.text
        wide = self.body("wide-bot", **self.BEYOND[2][0])
        self.refused(
            client.post("/v1/agents", json=wide, headers=registrar), "calls to agents hr-*"
        )
        # A registrar for every team, as before.
        anyone = client.post("/v1/agents", json=wide, headers=key(client, "registrar", None))
        assert anyone.json()["status"] == "active", anyone.text


class TestHidden:
    """What another team's agents are, a role for one team isn't told."""

    def test_in_what_names_its_team_and_its_agents_calls(self, client, org) -> None:
        client.patch(
            "/v1/agents/hr-bot",
            json={
                "owner": "sales",
                "agent_access": ["sales-*"],
                "a2a_url": "https://hr.example.com/a2a",
            },
            headers=ADMIN,
        ).raise_for_status()
        client.patch(
            "/v1/agents/sales-bot",
            json={"agent_access": ["hr-*"], "a2a_url": "https://sales.example.com/a2a"},
            headers=ADMIN,
        ).raise_for_status()
        sales = key(client, "auditor")
        assert "agent hr-bot" not in client.get("/v1/teams/sales", headers=sales).json()["named_by"]
        a2a = client.get("/v1/agents/sales-bot/a2a", headers=sales).json()
        assert "hr-bot" not in a2a["called_by"] + a2a["may_call"]
        assert "agent hr-bot" in client.get("/v1/teams/sales", headers=ADMIN).json()["named_by"]
        a2a = client.get("/v1/agents/sales-bot/a2a", headers=ADMIN).json()
        assert "hr-bot" in a2a["called_by"] and "hr-bot" in a2a["may_call"]

    def test_their_access_packages_arent_there(self, client, org) -> None:
        client.put("/v1/features/access-packages", json={"mode": "on"}, headers=ADMIN)
        client.post(
            "/v1/access-packages",
            json={"name": "crm-write", "permissions": [{"server": "crm", "tools": ["update"]}]},
            headers=ADMIN,
        ).raise_for_status()
        asked = client.post(
            "/v1/access-assignments",
            json={"agent": "hr-bot", "package": "crm-write", "reason": "x"},
            headers=ADMIN,
        ).json()
        for role in ("approver", "registrar"):
            sales = key(client, role)
            body = {"agent": "hr-bot", "package": "crm-write", "reason": "x"}
            assert (
                client.post("/v1/access-assignments", json=body, headers=sales).status_code == 404
            )
            assert (
                client.get(f"/v1/access-assignments/{asked['id']}", headers=sales).status_code
                == 404
            )
            out = client.post(f"/v1/access-assignments/{asked['id']}/approve", headers=sales)
            assert out.status_code == 404, (role, out.text)

    def test_nor_who_holds_a_workload_identity(self, client, org) -> None:
        client.put("/v1/features/workload-identity", json={"mode": "on"}, headers=ADMIN)
        client.post(
            "/v1/identity-issuers",
            json={"name": "cluster", "kind": "kubernetes", "issuer": "https://k8s.example.com"},
            headers=ADMIN,
        ).raise_for_status()
        held = {"issuer": "cluster", "subject": "system:serviceaccount:hr:bot"}
        client.patch(
            "/v1/agents/hr-bot", json={"workload_identity": held}, headers=ADMIN
        ).raise_for_status()
        out = client.patch(
            "/v1/agents/sales-bot", json={"workload_identity": held}, headers=key(client, "admin")
        )
        assert out.status_code == 409 and "hr-bot" not in out.json()["detail"], out.text
        out = client.patch("/v1/agents/loose-bot", json={"workload_identity": held}, headers=ADMIN)
        assert out.status_code == 409 and "hr-bot" in out.json()["detail"], out.text


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

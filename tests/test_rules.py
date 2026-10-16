"""Management rules: what to do about agents that meet some conditions for long enough
(docs/management-rules.md)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from agentgov import ids
from agentgov.db.models import AccessAssignment, Agent, Finding, RuleMatch
from agentgov.models import LedgerEntry
from agentgov.platforms import connections
from agentgov.registry import access_packages, features, findings, issues, rules
from agentgov.registry.errors import Conflict, ValidationError
from tests.conftest import ADMIN, seed

INACTIVE = {
    "name": "inactive-agents",
    "description": "Agents nobody uses",
    "conditions": {"inactive_days": 30},
    "action": "block",
    "after_days": 7,
}


def _rt(client: TestClient):  # type: ignore[no-untyped-def]
    return client.app.state.rt  # type: ignore[attr-defined]


@pytest.fixture
def agent(client: TestClient) -> dict[str, Any]:
    """support-bot, last seen 40 days ago."""
    created = seed(client)
    _seen(client, "support-bot", days_ago=40)
    return created


def _seen(client: TestClient, name: str, *, days_ago: float) -> None:
    with _rt(client).db.transaction():
        Agent.objects.filter(name=name).update(last_seen_at=ids.utcnow() - timedelta(days=days_ago))


def _rule(client: TestClient, mode: str = "enforce", **spec: Any) -> str:
    with _rt(client).db.session() as s:
        return rules.create(s, {**INACTIVE, "mode": mode, **spec}, actor="admin:test").name


def _feature(client: TestClient, key: str, mode: str) -> None:
    rt = _rt(client)
    with rt.db.session() as s:
        features.set_mode(s, rt.settings, key, mode, actor="admin:test")


def _run(client: TestClient, at: datetime) -> dict[str, Any]:
    rt = _rt(client)
    with rt.db.session() as s:
        return rules.evaluate(s, rt.settings, at)


def _status(client: TestClient, name: str = "support-bot") -> str:
    with _rt(client).db.transaction():
        return Agent.objects.filter(name=name).values_list("status", flat=True).first()


def _issues(client: TestClient, type_: str = rules.MATCHED) -> list[Finding]:
    with _rt(client).db.transaction():
        return list(Finding.objects.filter(type=type_))


def _ledger(client: TestClient, type_: str) -> list[LedgerEntry]:
    with _rt(client).db.session() as s:
        return list(s.scalars(select(LedgerEntry).where(LedgerEntry.type == type_)))


class TestValidation:
    @pytest.mark.parametrize(
        ("spec", "message"),
        [
            ({"conditions": {}}, "at least one condition"),
            ({"conditions": {"idle": 3}}, "unknown condition"),
            ({"conditions": {"inactive_days": 0}}, "inactive_days is a whole number"),
            ({"conditions": {"missing": ["boss"]}}, "missing is a list of owner"),
            ({"conditions": {"finding_severity": "high"}}, "goes with findings"),
            ({"conditions": {"findings": ["rule.*"]}}, "rules' own issues"),
            ({"conditions": {"risk_level": "extreme"}}, "risk_level must be one of"),
            ({"after_days": 0}, "a day's notice"),
            ({"action": "purge"}, "action must be one of"),
            ({"mode": "on"}, "mode must be one of"),
            ({"max_actions": 0}, "max_actions is a whole number"),
            ({"params": {"owner": "cx"}}, "takes no params"),
            ({"action": "assign_owner"}, "needs params.owner"),
            ({"action": "assign_owner", "params": {"owner": "nobody"}}, "neither a team"),
            ({"scope": {"teams": "cx"}}, "scope.teams must be a list"),
            ({"scope": {"owners": ["cx"]}}, "unknown scope key"),
            ({"colour": "red"}, "unknown field"),
        ],
    )
    def test_what_a_rule_must_say(self, client, spec, message) -> None:
        with pytest.raises(ValidationError, match=message), _rt(client).db.session() as s:
            rules.create(s, {**INACTIVE, **spec}, actor="admin:test")

    def test_names_are_unique_and_fixed(self, client) -> None:
        _rule(client)
        with pytest.raises(Conflict), _rt(client).db.session() as s:
            rules.create(s, INACTIVE, actor="admin:test")
        with pytest.raises(ValidationError, match="can't change"), _rt(client).db.session() as s:
            rules.update(s, rules.get(s, "inactive-agents"), {"name": "x"}, actor="admin:test")

    def test_issues_need_no_notice_and_owners_may_be_teams(self, client) -> None:
        client.post("/v1/teams", json={"name": "cx-platform"}, headers=ADMIN).raise_for_status()
        with _rt(client).db.session() as s:
            rule = rules.create(
                s,
                {
                    "name": "ownerless",
                    "conditions": {"missing": ["owner"]},
                    "action": "assign_owner",
                    "params": {"owner": "cx-platform"},
                },
                actor="admin:test",
            )
            assert rule.params == {"owner": "cx-platform"}
            # Changing the action checks its params again.
            with pytest.raises(ValidationError, match="takes no params"):
                rules.update(s, rule, {"action": "block"}, actor="admin:test")
            rules.update(s, rule, {"action": "issue", "params": {}, "after_days": 0}, actor="t")
            assert (rule.action, rule.after_days) == ("issue", 0)


class TestMonitor:
    def test_monitored_rules_tell_nobody_and_record_what_they_would_do(self, client, agent) -> None:
        name = _rule(client, mode="monitor")
        now = ids.utcnow()
        assert _run(client, now)[name]["matching"] == 1
        assert _issues(client) == []  # nobody is told
        assert _run(client, now + timedelta(days=8))[name]["would_act"] == 1
        assert _status(client) == "active"
        (entry,) = _ledger(client, "rule.would_act")
        assert entry.actor == "system:rule:inactive-agents"
        assert "no activity for 48 days" in entry.reason  # by then
        # Once per match.
        _run(client, now + timedelta(days=9))
        assert len(_ledger(client, "rule.would_act")) == 1

    def test_the_feature_caps_every_rule(self, client, agent) -> None:
        name = _rule(client, mode="enforce")  # the feature is monitored by default
        now = ids.utcnow()
        _run(client, now)  # its days start when it first matches
        out = _run(client, now + timedelta(days=8))
        assert out[name]["would_act"] == 1
        assert _status(client) == "active"


class TestEnforce:
    @pytest.fixture(autouse=True)
    def _enforced(self, client: TestClient) -> None:
        _feature(client, rules.FEATURE, "enforce")

    def test_it_tells_first_then_acts(self, client, agent) -> None:
        _rule(client)
        now = ids.utcnow()
        _run(client, now)
        (issue,) = _issues(client)
        assert issue.title.startswith("Rule inactive-agents will block support-bot on ")
        assert issue.agent_id == agent["id"] and issue.status == "open"
        assert "no activity for 40 days" in issue.description
        assert "agentgov/exempt-rules: inactive-agents" in issue.remediation
        _run(client, now + timedelta(days=6))
        assert _status(client) == "active"
        _run(client, now + timedelta(days=7, minutes=1))
        assert _status(client) == "blocked"
        (issue,) = _issues(client)
        assert issue.title.startswith("Rule inactive-agents blocked support-bot on ")
        assert "unblocks it" in issue.remediation
        assert issue.round == 1 and issue.level is None  # sent to its people again
        (blocked,) = _ledger(client, "agent.block")
        assert blocked.actor == "system:rule:inactive-agents"
        assert "management rule inactive-agents" in blocked.reason
        assert [e.actor for e in _ledger(client, "finding.acted")] == [blocked.actor]
        # Its issue stays while the agent is blocked.
        _run(client, now + timedelta(days=8))
        assert _issues(client)[0].status == "open"

    def test_it_doesnt_argue_with_people(self, client, agent) -> None:
        _rule(client)
        now = ids.utcnow()
        _run(client, now)
        _run(client, now + timedelta(days=8))
        assert _status(client) == "blocked"
        client.post("/v1/agents/support-bot/unblock", json={}, headers=ADMIN).raise_for_status()
        _run(client, now + timedelta(days=20))
        assert _status(client) == "active"  # still inactive, but someone decided
        # Used again, it no longer matches: the match and its issue go.
        _seen(client, "support-bot", days_ago=0)
        _run(client, ids.utcnow() + timedelta(days=1))
        assert _issues(client)[0].status == "resolved"
        with _rt(client).db.transaction():
            assert not RuleMatch.objects.exists()

    def test_an_agent_that_stops_matching_is_left_alone(self, client, agent) -> None:
        _rule(client)
        now = ids.utcnow()
        _run(client, now)
        _seen(client, "support-bot", days_ago=0)
        _run(client, now + timedelta(days=8))
        assert _status(client) == "active"
        (issue,) = _issues(client)
        assert (issue.status, issue.resolved_by) == ("resolved", rules.SYSTEM)

    def test_an_accepted_risk_holds_it_back_then_the_notice_starts_again(
        self, client, agent
    ) -> None:
        _rule(client)
        now = ids.utcnow()
        _run(client, now)
        rt = _rt(client)
        with rt.db.session() as s:
            issue = Finding.objects.get(type=rules.MATCHED)
            issues.accept(s, issue, reason="Seasonal agent", until=30, actor="approver:ann")
        _run(client, now + timedelta(days=8))
        assert _status(client) == "active"
        assert "risk is accepted until" in _issues(client)[0].title
        with rt.db.session() as s:
            assert RuleMatch.objects.get().warned_at is None
            issues.reopen_accepted(s, now + timedelta(days=31))
        _run(client, now + timedelta(days=31))
        assert _status(client) == "active"  # told again: a full week's notice
        assert "will block" in _issues(client)[0].title
        _run(client, now + timedelta(days=38, minutes=1))
        assert _status(client) == "blocked"

    def test_a_dismissed_issue_keeps_the_rule_off_the_agent(self, client, agent) -> None:
        _rule(client)
        now = ids.utcnow()
        _run(client, now)
        issue_id = _issues(client)[0].id
        client.post(
            f"/v1/findings/{issue_id}/dismiss", json={"reason": "Kept on purpose"}, headers=ADMIN
        ).raise_for_status()
        _run(client, now + timedelta(days=8))
        assert _status(client) == "active"
        assert _issues(client)[0].status == "dismissed"

    def test_too_many_at_once_and_it_acts_on_none(self, client, agent) -> None:
        for name in ("bot-a", "bot-b"):
            client.post(
                "/v1/agents",
                json={
                    "name": name,
                    "blueprint": "support",
                    "owner": "cx",
                    "sponsors": ["alice@example.com"],
                    "approve": True,
                },
                headers=ADMIN,
            ).raise_for_status()
            _seen(client, name, days_ago=40)
        name = _rule(client, max_actions=2)
        now = ids.utcnow()
        _run(client, now)
        out = _run(client, now + timedelta(days=8))
        assert out[name]["held_back"] == 3
        assert {_status(client, n) for n in ("support-bot", "bot-a", "bot-b")} == {"active"}
        (held,) = _issues(client, rules.TOO_MANY)
        assert held.status == "open" and held.agent_id is None  # to the default team
        assert "more than its limit of 2" in held.title
        # The agents' people were told a date: their issues say why nothing happened.
        assert all("is held back" in i.title for i in _issues(client))
        _run(client, now + timedelta(days=9))
        assert len(_ledger(client, "rule.held_back")) == 1
        with _rt(client).db.session() as s:
            rules.update(s, rules.get(s, name), {"max_actions": 3}, actor="admin:test")
        _run(client, now + timedelta(days=10))
        assert {_status(client, n) for n in ("support-bot", "bot-a", "bot-b")} == {"blocked"}
        assert _issues(client, rules.TOO_MANY)[0].status == "resolved"

    def test_agents_on_other_platforms(self, client, agent) -> None:
        rt = _rt(client)
        now = ids.utcnow()
        with rt.db.transaction():
            Agent.objects.create(
                id=ids.new_id(ids.AGENT),
                name="m365-helper",
                status="active",
                source="platform:microsoft-365",
                platform="Microsoft 365",
                owner="cx",
                sponsors=["alice@example.com"],
                created_at=now - timedelta(days=90),
            )
        name = _rule(client)
        with rt.db.session() as s:
            shown = rules.preview(s, rules.get(s, name), now)
            # Without its usage, nobody can tell that it's inactive.
            assert [u["agent"] for u in shown["unknown"]] == ["m365-helper"]
            assert "purview-audit" in shown["unknown"][0]["why"]
            connections.save_state(
                s,
                "purview-audit",
                {
                    "usage_from": ids.isoformat(now - timedelta(days=60)),
                    "usage_until": ids.isoformat(now - timedelta(hours=1)),
                },
            )
        _run(client, now)
        titles = sorted(i.title for i in _issues(client))
        assert titles[0] == "Rule inactive-agents can't block m365-helper"
        _run(client, now + timedelta(days=8))
        assert _status(client, "m365-helper") == "active"
        m365 = next(i for i in _issues(client) if "m365-helper" in i.title)
        assert "block it in Microsoft 365's admin center" in m365.description
        with rt.db.session() as s:
            # Usage read last week, not since: it can't tell any more.
            connections.save_state(
                s,
                "purview-audit",
                {
                    "usage_from": ids.isoformat(now - timedelta(days=60)),
                    "usage_until": ids.isoformat(now - timedelta(days=7)),
                },
            )
            shown = rules.preview(s, rules.get(s, name), now)
            assert [u["agent"] for u in shown["unknown"]] == ["m365-helper"]

    def test_a_rule_names_teams_and_blueprints_there_are(self, client, agent) -> None:
        typo = client.post(
            "/v1/rules", json={**INACTIVE, "scope": {"teams": ["cx-typo"]}}, headers=ADMIN
        )
        assert typo.status_code == 422 and "there is no team cx-typo" in typo.json()["detail"]
        client.post("/v1/teams", json={"name": "cx-ops"}, headers=ADMIN).raise_for_status()
        made = client.post(
            "/v1/rules",
            json={**INACTIVE, "action": "assign_owner", "params": {"owner": "cx-ops"}},
            headers=ADMIN,
        )
        assert made.status_code == 201, made.text
        # The team it gives agents stays while it does.
        refused = client.delete("/v1/teams/cx-ops", headers=ADMIN)
        assert refused.status_code == 409
        assert "management rule inactive-agents" in refused.json()["detail"]

    def test_who_a_rule_looks_at(self, client, agent) -> None:
        client.post("/v1/blueprints", json={"name": "other"}, headers=ADMIN).raise_for_status()
        name = _rule(client, scope={"blueprints": ["other"]})
        with _rt(client).db.session() as s:
            assert rules.preview(s, rules.get(s, name))["matching"] == 0
            rules.update(
                s, rules.get(s, name), {"scope": {"platforms": ["gateway"]}}, actor="admin:test"
            )
            assert rules.preview(s, rules.get(s, name))["matching"] == 1
        client.patch(
            "/v1/agents/support-bot",
            json={"labels": {rules.EXEMPT_LABEL: "other-rule, inactive-agents"}},
            headers=ADMIN,
        ).raise_for_status()
        with _rt(client).db.session() as s:
            assert rules.preview(s, rules.get(s, name))["matching"] == 0

    def test_assigning_an_owner(self, client, agent) -> None:
        client.post("/v1/teams", json={"name": "cx-platform"}, headers=ADMIN).raise_for_status()
        client.patch("/v1/agents/support-bot", json={"owner": None}, headers=ADMIN)
        _rule(
            client,
            name="ownerless",
            conditions={"missing": ["owner"]},
            action="assign_owner",
            params={"owner": "cx-platform"},
            after_days=3,
        )
        now = ids.utcnow()
        _run(client, now)
        (issue,) = _issues(client)
        assert issue.title.startswith("Rule ownerless will make cx-platform the owner of ")
        _run(client, now + timedelta(days=4))
        with _rt(client).db.transaction():
            assert Agent.objects.get(name="support-bot").owner == "cx-platform"
        (updated,) = _ledger(client, "agent.updated")[-1:]
        assert updated.actor == "system:rule:ownerless"
        # It has an owner now: the rule is done with it.
        _run(client, now + timedelta(days=5))
        assert _issues(client)[0].status == "resolved"

    def test_revoking_access_packages(self, client, agent) -> None:
        client.post(
            "/v1/access-packages",
            json={"name": "crm-write", "permissions": [{"server": "crm", "tools": ["update_*"]}]},
            headers=ADMIN,
        ).raise_for_status()
        client.post(
            "/v1/access-assignments",
            json={
                "agent": "support-bot",
                "package": "crm-write",
                "reason": "CX-1",
                "approve": True,
            },
            headers=ADMIN,
        ).raise_for_status()
        _rule(client, name="idle-access", action="revoke_access", after_days=1)
        now = ids.utcnow()
        _run(client, now)
        _run(client, now + timedelta(days=2))
        with _rt(client).db.session() as s:
            assert AccessAssignment.objects.get().status == "revoked"
            assert access_packages.held(s) == {}
        (revoked,) = _ledger(client, "access.revoked")
        assert revoked.actor == "system:rule:idle-access"
        assert _status(client) == "active"

    def test_deleting_stale_registrations(self, client, agent) -> None:
        client.post(
            "/v1/agents",
            json={
                "name": "forgotten",
                "blueprint": "support",
                "owner": "cx",
                "sponsors": ["alice@example.com"],
            },
            headers=ADMIN,
        ).raise_for_status()
        _rule(
            client,
            name="stale-requests",
            conditions={"status": ["pending"]},
            action="delete",
            after_days=30,
        )
        now = ids.utcnow()
        _run(client, now)
        _run(client, now + timedelta(days=31))
        assert _status(client, "forgotten") == "deleted"
        assert _status(client) == "active"
        (issue,) = _issues(client)
        assert "restores it before" in issue.remediation
        _run(client, now + timedelta(days=32))
        assert _issues(client)[0].status == "open"  # deleted, and restorable: it stays
        client.delete("/v1/agents/forgotten", headers=ADMIN).raise_for_status()
        _run(client, now + timedelta(days=33))
        assert _issues(client)[0].status == "resolved"

    def test_issues_are_raised_once_they_are_due(self, client, agent) -> None:
        name = _rule(
            client,
            name="no-team",
            conditions={"missing": ["team"]},
            action="issue",
            after_days=0,
            severity="low",
        )
        now = ids.utcnow()
        assert _run(client, now)[name]["acted"] == 1
        (issue,) = _issues(client)
        assert issue.title == "support-bot matches rule no-team: no team"
        assert issue.severity == "low"
        # Resolved by someone, it stays so while the agent still matches.
        client.post(f"/v1/findings/{issue.id}/resolve", headers=ADMIN).raise_for_status()
        _run(client, now + timedelta(days=1))
        assert _issues(client)[0].status == "resolved"

    def test_findings_and_risk(self, client, agent) -> None:
        name = _rule(
            client,
            name="stale",
            conditions={"findings": ["agent.st*"], "finding_severity": "medium"},
            action="issue",
            after_days=0,
        )
        rt = _rt(client)
        with rt.db.session() as s:
            finding, _ = findings.raise_finding(
                s,
                type="agent.stale",
                severity="low",
                subject=agent["id"],
                agent_id=agent["id"],
                title="Agent support-bot is stale",
            )
        assert _run(client, ids.utcnow())[name]["matching"] == 0  # not severe enough
        with rt.db.transaction():
            Finding.objects.filter(pk=finding.id).update(severity="medium")
        assert _run(client, ids.utcnow())[name]["acted"] == 1
        assert "open issue: Agent support-bot is stale" in _issues(client)[0].title
        with rt.db.transaction():
            # A finding a failed sync can't vouch for doesn't count.
            Finding.objects.filter(pk=finding.id).update(verified=False)
        _run(client, ids.utcnow())
        assert _issues(client)[0].status == "resolved"

    def test_off_resolves_their_issues(self, client, agent) -> None:
        _rule(client)
        _run(client, ids.utcnow())
        assert _issues(client)[0].status == "open"
        _feature(client, rules.FEATURE, "off")
        assert _run(client, ids.utcnow())["off"] is True
        assert _issues(client)[0].status == "resolved"
        with _rt(client).db.transaction():
            assert not RuleMatch.objects.exists()

    def test_nothing_runs_without_posture_checks(self, client, agent) -> None:
        _rule(client)
        _run(client, ids.utcnow())
        _feature(client, "posture-checks", "off")
        assert "posture checks are off" in _run(client, ids.utcnow())["skipped"]
        assert _issues(client)[0].status == "open"  # left as it was
        _run(client, ids.utcnow() + timedelta(days=8))
        assert _status(client) == "active"

    def test_deleting_a_rule_resolves_its_issues(self, client, agent) -> None:
        name = _rule(client)
        _run(client, ids.utcnow())
        with _rt(client).db.session() as s:
            rules.delete(s, rules.get(s, name), actor="admin:test")
            assert not RuleMatch.objects.exists()
        assert _issues(client)[0].status == "resolved"
        assert _ledger(client, "rule.deleted")


def test_previewing_a_rule_before_saving_it(client, agent) -> None:
    rt = _rt(client)
    with rt.db.session() as s:
        draft = rules.draft(s, {**INACTIVE, "mode": "enforce"})
        shown = rules.preview(s, draft)
        assert shown["rule"] is None and shown["matching"] == 1
        (entry,) = shown["agents"]
        assert entry["agent"] == "support-bot" and entry["state"] == "waiting"
        assert entry["reasons"][0].startswith("no activity for 40 days")
        # Monitored by the feature: it would only record it.
        assert shown["mode"] == "monitor" and entry["detail"].startswith("would block it on")
        assert rules.list_all(s) == []


class TestApiCliManifests:
    def test_the_api(self, client, agent) -> None:
        approver = client.post(
            "/v1/apikeys", json={"name": "ann", "role": "approver"}, headers=ADMIN
        ).json()
        ann = {"Authorization": f"Bearer {approver['token']}"}
        assert client.post("/v1/rules", json=INACTIVE, headers=ann).status_code == 403
        bad = client.post("/v1/rules", json={**INACTIVE, "after_days": 0}, headers=ADMIN)
        assert bad.status_code == 422 and "blocks agents gives a day" in bad.text
        created = client.post("/v1/rules", json=INACTIVE, headers=ADMIN)
        assert created.status_code == 201, created.text
        rule = created.json()
        assert (rule["mode"], rule["effective_mode"], rule["after_days"]) == (
            "monitor",
            "monitor",
            7,
        )
        assert [r["name"] for r in client.get("/v1/rules", headers=ann).json()] == [
            "inactive-agents"
        ]
        # Previews, for a draft and for the saved rule.
        draft = client.post(
            "/v1/rules/preview", json={"conditions": {"missing": ["team"]}}, headers=ann
        ).json()
        assert draft["matching"] == 1 and draft["agents"][0]["reasons"] == ["no team"]
        shown = client.get("/v1/rules/inactive-agents/preview", headers=ann).json()
        assert shown["rule"] == "inactive-agents" and shown["agents"][0]["state"] == "waiting"
        # Run now; the agent's rules, for its sponsor too.
        ran = client.post("/v1/rules/evaluate", headers=ADMIN).json()
        assert ran["inactive-agents"]["matching"] == 1
        mine = client.get("/v1/agents/support-bot/rules", headers=ADMIN).json()
        assert mine[0]["rule"] == "inactive-agents" and mine[0]["state"] == "waiting"
        updated = client.patch(
            "/v1/rules/inactive-agents", json={"mode": "enforce"}, headers=ADMIN
        ).json()
        assert (updated["mode"], updated["effective_mode"]) == ("enforce", "monitor")
        _feature(client, "posture-checks", "off")
        assert client.post("/v1/rules/evaluate", headers=ADMIN).status_code == 409
        assert client.delete("/v1/rules/inactive-agents", headers=ADMIN).json() == {
            "deleted": "inactive-agents"
        }
        assert client.get("/v1/rules/inactive-agents", headers=ADMIN).status_code == 404

    def test_rules_round_trip(self, client, agent) -> None:
        manifest = """
apiVersion: agentgov/v1alpha1
kind: Team
metadata: {name: cx-platform}
spec: {members: [alice@example.com]}
---
apiVersion: agentgov/v1alpha1
kind: ManagementRule
metadata: {name: ownerless-agents}
spec:
  description: Agents nobody owns go to the platform team
  conditions: {missing: [owner]}
  scope: {platforms: [gateway]}
  action: assign_owner
  params: {owner: cx-platform}
  after_days: 14
"""
        headers = {**ADMIN, "Content-Type": "application/yaml"}
        applied = client.post("/v1/apply", content=manifest, headers=headers).json()
        assert applied["results"][1] == {
            "kind": "ManagementRule",
            "name": "ownerless-agents",
            "action": "created",
        }
        again = client.post("/v1/apply", content=manifest, headers=headers).json()
        assert again["results"][1]["action"] == "unchanged"
        exported = client.get("/v1/export", headers=ADMIN).text
        doc = exported[exported.index("kind: ManagementRule") :]
        assert "after_days" not in doc.split("---")[0]  # the default is left out
        assert "params:\n    owner: cx-platform" in doc
        assert exported.index("kind: Team") < exported.index("kind: ManagementRule")
        assert exported.index("kind: ManagementRule") < exported.index("kind: Agent")

    def test_from_the_cli(self, client, agent, monkeypatch) -> None:
        from agentgov import cli
        from tests.test_cli import _Shared, runner

        bearer = ADMIN["Authorization"].removeprefix("Bearer ")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))

        def run(*args: str) -> str:
            result = runner.invoke(cli.app, list(args))
            assert result.exit_code == 0, result.output
            return result.output

        dry = run("rules", "create", "idle", "--inactive-days", "30", "--action", "block",
                  "--after-days", "7", "--dry-run")  # fmt: skip
        assert dry.startswith("1 agent(s) match, 0 due now (monitor)")
        assert "support-bot" in dry and "no activity for 40 days" in dry
        assert run("rules", "list").count("idle") == 0  # not saved
        out = run("rules", "create", "idle", "--inactive-days", "30", "--action", "block",
                  "--after-days", "7", "--scope-label", "tier=gold")  # fmt: skip
        assert out.strip() == "rule/idle: created (monitor)"
        assert "inactive_days=30" in run("rules", "list")
        run("rules", "update", "idle", "--mode", "enforce", "--platform", "gateway")
        got = run("rules", "get", "idle")
        assert '"platforms": [\n      "gateway"\n    ]' in got and '"mode": "enforce"' in got
        assert "rule/idle: 1 matching" in run("rules", "evaluate")
        assert "idle" in run("rules", "agent", "support-bot")
        assert "waiting" in run("rules", "preview", "idle")
        assert run("rules", "delete", "idle", "--yes").strip() == "rule/idle: deleted"

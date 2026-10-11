"""Issues: findings routed to the people responsible for them (docs/issues.md)."""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import cli, ids
from agentgov.models import Finding, LedgerEntry, Notification
from agentgov.notify import MAX_ATTEMPTS, Notifier
from agentgov.registry import destinations, features, findings, issues, teams
from agentgov.secops.delivery import Delivery
from tests.conftest import ADMIN, seed
from tests.test_cli import _Shared, runner


def _rt(client: TestClient):  # type: ignore[no-untyped-def]
    return client.app.state.rt  # type: ignore[attr-defined]


def _types(session) -> list[str]:  # type: ignore[no-untyped-def]
    return [e.type for e in session.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))]


@pytest.fixture
def agent(client: TestClient) -> dict[str, Any]:
    """support-bot: owner cx (a team), sponsors alice and bob, blueprint support."""
    created = seed(client, sponsors=["alice@example.com", "bob"])
    with _rt(client).db.session() as s:
        teams.create(
            s,
            {"name": "cx", "emails": ["cx-team@example.com"], "destinations": []},
            actor="admin:test",
        )
        teams.create(
            s,
            {"name": "ai-governance", "emails": ["gov@example.com"], "default": True},
            actor="admin:test",
        )
    return created


def _raise(client: TestClient, agent_id: str, severity: str = "medium") -> str:
    with _rt(client).db.session() as s:
        finding, _ = findings.raise_finding(
            s,
            type="agent.no_owner",
            severity=severity,
            subject=agent_id,
            agent_id=agent_id,
            title="Agent support-bot has no owner",
        )
        return finding.id


class TestChains:
    def test_an_agents_chain_goes_owner_sponsors_team(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            steps = issues.chain(s, findings.get(s, fid))
            assert [level for level, _ in steps] == ["owner", "sponsors", "team"]
            owner, sponsors, team = (people for _, people in steps)
            # The owner names a team; the sponsors are a person with an address and one
            # reached in AgentGov only; the team is the default one.
            assert owner == [issues.Recipient("team", "cx", ("cx-team@example.com",))]
            assert [(p.name, p.emails) for p in sponsors] == [
                ("alice@example.com", ("alice@example.com",)),
                ("bob", ()),
            ]
            assert [p.name for p in team] == ["ai-governance"]

    def test_the_blueprints_team_comes_before_the_default(self, client, agent) -> None:
        client.patch("/v1/blueprints/support", json={"team": "cx"}, headers=ADMIN)
        fid = _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            # The team step would repeat the owner's, so it is left out.
            assert [level for level, _ in issues.chain(s, findings.get(s, fid))] == [
                "owner",
                "sponsors",
            ]

    def test_findings_about_agentgov_itself_go_to_the_default_team(self, client, agent) -> None:
        with _rt(client).db.session() as s:
            finding, _ = findings.raise_finding(
                s,
                type="destination.failing",
                severity="high",
                subject="dst_1",
                title="Destination soc is failing",
            )
            steps = issues.chain(s, finding)
            assert [(level, [p.name for p in people]) for level, people in steps] == [
                ("team", ["ai-governance"])
            ]


class TestRouting:
    def test_it_goes_to_the_first_step_then_up_the_chain(self, client, agent) -> None:
        rt = _rt(client)
        settings = dataclasses.replace(rt.settings, smtp_url="smtp://mail:25", smtp_from="a@b.c")
        fid = _raise(client, agent["id"])
        now = ids.utcnow()
        with rt.db.session() as s:
            assert issues.route(s, settings, now) == {"assigned": 1, "escalated": 0}
            f = findings.get(s, fid)
            assert (f.level, f.assignees) == ("owner", ["team cx"])
            # Medium findings wait 72 hours at each step.
            assert f.escalate_at == now + timedelta(hours=72)
            queued = s.scalars(select(Notification).where(Notification.finding_id == fid)).all()
            assert [(n.channel, n.recipient) for n in queued] == [("email", "cx-team@example.com")]
        with rt.db.session() as s:
            # Not yet due; then due.
            assert issues.route(s, settings, now + timedelta(hours=1))["escalated"] == 0
            assert issues.route(s, settings, now + timedelta(hours=73))["escalated"] == 1
            f = findings.get(s, fid)
            assert (f.level, f.assignees) == ("sponsors", ["alice@example.com", "bob"])
            assert issues.route(s, settings, now + timedelta(hours=146))["escalated"] == 1
            assert findings.get(s, fid).level == "team"
            # The last step: it stays there.
            assert findings.get(s, fid).escalate_at is None
            assert issues.route(s, settings, now + timedelta(days=30))["escalated"] == 0
        with rt.db.session() as s:
            assert "finding.assigned" in _types(s) and _types(s).count("finding.escalated") == 2

    def test_acknowledging_stops_it_going_further(self, client, agent) -> None:
        rt = _rt(client)
        fid = _raise(client, agent["id"])
        now = ids.utcnow()
        with rt.db.session() as s:
            issues.route(s, rt.settings, now)
            issues.acknowledge(s, findings.get(s, fid), actor="person:cx-team@example.com")
            assert issues.route(s, rt.settings, now + timedelta(days=10))["escalated"] == 0
            f = findings.get(s, fid)
            assert (f.level, f.acknowledged_by) == ("owner", "person:cx-team@example.com")
        # Without a mail server, nobody is emailed; the issue is in AgentGov.
        with rt.db.session() as s:
            assert s.scalars(select(Notification)).all() == []

    def test_an_accepted_risk_opens_again_when_its_time_runs_out(self, client, agent) -> None:
        rt = _rt(client)
        fid = _raise(client, agent["id"])
        with rt.db.session() as s:
            issues.route(s, rt.settings)
            f = findings.get(s, fid)
            with pytest.raises(Exception, match="why"):
                issues.accept(s, f, reason="", until=30, actor="admin:test")
            with pytest.raises(Exception, match="a year at most"):
                issues.accept(s, f, reason="ok", until=400, actor="admin:test")
            issues.accept(s, f, reason="Pilot until the new owner joins", until=30, actor="admin:a")
            assert (f.status, f.escalate_at) == ("accepted", None)
            # While accepted, the condition holding doesn't open it again.
            findings.raise_finding(
                s,
                type="agent.no_owner",
                severity="medium",
                subject=agent["id"],
                agent_id=agent["id"],
                title="Agent support-bot has no owner",
            )
            assert f.status == "accepted"
        with rt.db.session() as s:
            assert issues.reopen_accepted(s, ids.utcnow() + timedelta(days=31)) == 1
            f = findings.get(s, fid)
            # It starts its chain over.
            assert (f.status, f.level, f.round) == ("open", None, 1)
            issues.route(s, rt.settings)
            assert findings.get(s, fid).level == "owner"

    def test_a_finding_raised_again_starts_its_chain_over(self, client, agent) -> None:
        rt = _rt(client)
        fid = _raise(client, agent["id"])
        with rt.db.session() as s:
            issues.route(s, rt.settings)
            findings.set_status(s, fid, "resolved", "admin:test")
        _raise(client, agent["id"])
        with rt.db.session() as s:
            f = findings.get(s, fid)
            assert (f.status, f.level, f.assignees, f.round) == ("open", None, [], 1)


class TestChecks:
    def test_findings_from_syncs_close_after_two_clean_checks(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            types = {"agent.no_owner"}
            assert findings.resolve_absent(s, types=types, present_keys=set(), clean=2) == 0
            assert findings.get(s, fid).status == "open"
            assert findings.resolve_absent(s, types=types, present_keys=set(), clean=2) == 1
            assert findings.get(s, fid).status == "resolved"

    def test_a_check_that_finds_it_again_starts_the_count_over(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            findings.resolve_absent(s, types={"agent.no_owner"}, present_keys=set(), clean=2)
        _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            findings.resolve_absent(s, types={"agent.no_owner"}, present_keys=set(), clean=2)
            assert findings.get(s, fid).status == "open"

    def test_a_failed_sync_leaves_its_findings_open_and_unverified(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            assert findings.mark_unverified(s, types={"agent.no_owner"}) == 1
            assert findings.to_dict(findings.get(s, fid))["verified"] is False
        _raise(client, agent["id"])
        with _rt(client).db.session() as s:
            assert findings.get(s, fid).verified is True


class _SMTP:
    """Stands in for the mail server."""

    def __init__(self, outbox: list[Any], fail: bool = False) -> None:
        self.outbox, self.fail = outbox, fail

    def __enter__(self) -> _SMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def send_message(self, message: Any) -> None:
        if self.fail:
            raise OSError("connection refused")
        self.outbox.append(message)


class TestSending:
    def _notifier(self, client: TestClient, **kw: Any) -> tuple[Any, Notifier]:
        rt = _rt(client)
        settings = dataclasses.replace(
            rt.settings, smtp_url="smtp://mail:25", smtp_from="agentgov@example.com"
        )
        notifier = Notifier(rt.db, settings, Delivery(rt.db, settings, http=kw.get("http")), **kw)
        return settings, notifier

    def test_emails_go_out_and_are_in_the_ledger(self, client, agent) -> None:
        rt = _rt(client)
        outbox: list[Any] = []
        settings, notifier = self._notifier(client, smtp=lambda: _SMTP(outbox))
        fid = _raise(client, agent["id"])
        with rt.db.session() as s:
            issues.route(s, settings)
        assert notifier.run() == {"sent": 1, "failed": 0}
        (message,) = outbox
        assert message["To"] == "cx-team@example.com"
        assert message["Subject"] == (
            "[AgentGov] Medium issue about agent support-bot: Agent support-bot has no owner"
        )
        assert f"/ui/#/findings/{fid}" in message.get_content()
        assert "as the team it escalates to" not in message.get_content()
        with rt.db.session() as s:
            assert "finding.notified" in _types(s)
            assert issues.notifications(s, findings.get(s, fid))[0]["status"] == "sent"
        # Sent once.
        assert notifier.run() == {"sent": 0, "failed": 0}

    def test_failures_are_retried_then_given_up_on(self, client, agent) -> None:
        rt = _rt(client)
        settings, notifier = self._notifier(client, smtp=lambda: _SMTP([], fail=True))
        fid = _raise(client, agent["id"])
        with rt.db.session() as s:
            issues.route(s, settings)
        assert notifier.run() == {"sent": 0, "failed": 1}
        for _ in range(MAX_ATTEMPTS - 1):
            with rt.db.session() as s:
                for n in s.scalars(select(Notification)):
                    n.next_attempt_at = ids.utcnow()  # its backoff is over
            notifier.run()
        with rt.db.session() as s:
            (n,) = s.scalars(select(Notification)).all()
            assert (n.status, n.attempts) == ("failed", MAX_ATTEMPTS)
            assert "connection refused" in (n.last_error or "")
            assert "finding.notification_failed" in _types(s)
            assert issues.notifications(s, findings.get(s, fid))[0]["status"] == "failed"

    def test_teams_chats_get_a_message(self, client, agent, tmp_path: Path) -> None:
        rt = _rt(client)
        posted: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            posted.append(request)
            return httpx.Response(200, text="ok")

        http = httpx.Client(transport=httpx.MockTransport(handler))
        rt.settings = dataclasses.replace(rt.settings, destination_secrets_dir=str(tmp_path))
        (tmp_path / "cx-slack").write_text("https://hooks.slack.example/T/B/x")
        with rt.db.session() as s:
            destinations.create(s, {"name": "cx-slack", "kind": "slack"}, actor="admin:test")
            teams.update_team(
                s, teams.get(s, "cx"), {"destinations": ["cx-slack"]}, actor="admin:test"
            )
        settings = dataclasses.replace(rt.settings, smtp_url=None)
        notifier = Notifier(rt.db, settings, Delivery(rt.db, settings, http=http))
        _raise(client, agent["id"])
        with rt.db.session() as s:
            issues.route(s, settings)
        assert notifier.run() == {"sent": 1, "failed": 0}
        (request,) = posted
        assert str(request.url) == "https://hooks.slack.example/T/B/x"
        assert b"Acknowledge in AgentGov" in request.content

    def test_nothing_is_sent_while_issues_are_off(self, client, agent) -> None:
        rt = _rt(client)
        outbox: list[Any] = []
        settings, notifier = self._notifier(client, smtp=lambda: _SMTP(outbox))
        _raise(client, agent["id"])
        with rt.db.session() as s:
            issues.route(s, settings)
            features.set_mode(s, rt.settings, "issues", "off", actor="admin:test")
        assert notifier.run() == {}
        assert outbox == []


class TestWhoSeesWhat:
    def test_people_see_the_issues_that_reached_them(self, client, agent) -> None:
        rt = _rt(client)
        fid = _raise(client, agent["id"])
        now = ids.utcnow()
        with rt.db.session() as s:
            issues.route(s, rt.settings, now)
            # The owner team's address; not the sponsors, yet.
            assert [f.id for f in issues.for_person(s, "CX-Team@example.com")] == [fid]
            assert issues.for_person(s, "alice@example.com") == []
            issues.route(s, rt.settings, now + timedelta(hours=73))
            assert [f.id for f in issues.for_person(s, "alice@example.com")] == [fid]
            assert [f.id for f in issues.for_person(s, "bob")] == [fid]
            # The owner still sees it after it went further.
            assert [f.id for f in issues.for_person(s, "cx-team@example.com")] == [fid]
            assert issues.for_person(s, "mallory@example.com") == []

    def test_issues_route_only_while_the_feature_is_on(self, client, agent) -> None:
        rt = _rt(client)
        fid = _raise(client, agent["id"])
        with rt.db.session() as s:
            features.set_mode(s, rt.settings, "issues", "off", actor="admin:test")
        assert "assigned" not in rt.run_issues()
        with rt.db.session() as s:
            assert s.get(Finding, fid).level is None
            features.set_mode(s, rt.settings, "issues", "on", actor="admin:test")
        assert rt.run_issues()["assigned"] == 1


def _key(client: TestClient, role: str) -> dict[str, str]:
    resp = client.post("/v1/apikeys", json={"name": f"{role}-key", "role": role}, headers=ADMIN)
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestApi:
    def test_teams_are_managed_and_kept_while_named(self, client) -> None:
        seed(client)
        made = client.post(
            "/v1/teams",
            json={"name": "cx", "members": ["Alice@Example.com", "bob"], "default": True},
            headers=ADMIN,
        )
        assert made.status_code == 201, made.text
        assert made.json()["members"] == ["alice@example.com", "bob"]
        auditor = _key(client, "auditor")
        assert client.get("/v1/teams", headers=auditor).json()[0]["name"] == "cx"
        assert client.post("/v1/teams", json={"name": "x"}, headers=auditor).status_code == 403
        bad = client.post("/v1/teams", json={"name": "y", "emails": ["nope"]}, headers=ADMIN)
        assert bad.status_code == 422 and "email addresses" in bad.json()["detail"]
        typo = client.patch("/v1/agents/support-bot", json={"team": "cx-typo"}, headers=ADMIN)
        assert typo.status_code == 422 and "not found" in typo.json()["detail"]
        client.patch("/v1/agents/support-bot", json={"team": "cx"}, headers=ADMIN)
        assert client.get("/v1/teams/cx", headers=ADMIN).json()["named_by"] == ["agent support-bot"]
        refused = client.delete("/v1/teams/cx", headers=ADMIN)
        assert refused.status_code == 409 and "agent support-bot" in refused.json()["detail"]
        # Its owner names the team too.
        client.patch("/v1/agents/support-bot", json={"team": None}, headers=ADMIN)
        assert client.delete("/v1/teams/cx", headers=ADMIN).status_code == 409
        client.patch("/v1/agents/support-bot", json={"owner": "carol@example.com"}, headers=ADMIN)
        assert client.delete("/v1/teams/cx", headers=ADMIN).status_code == 200
        types = [e["type"] for e in client.get("/v1/ledger?type=team.*", headers=ADMIN).json()]
        assert types == ["team.deleted", "team.created"]

    def test_a_destination_a_team_posts_to_is_kept(self, client, tmp_path: Path) -> None:
        client.post("/v1/destinations", json={"name": "cx-chat", "kind": "teams"}, headers=ADMIN)
        client.post(
            "/v1/teams", json={"name": "cx", "destinations": ["cx-chat"]}, headers=ADMIN
        ).raise_for_status()
        refused = client.delete("/v1/destinations/cx-chat", headers=ADMIN)
        assert refused.status_code == 409 and "cx" in refused.json()["detail"]
        siem = client.post(
            "/v1/destinations",
            json={"name": "siem", "kind": "otlp", "url": "http://x"},
            headers=ADMIN,
        )
        assert siem.status_code == 201
        wrong = client.patch("/v1/teams/cx", json={"destinations": ["siem"]}, headers=ADMIN)
        assert wrong.status_code == 422 and "Teams or Slack" in wrong.json()["detail"]

    def test_a_finding_shows_who_it_goes_to(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        _rt(client).run_issues()
        f = client.get(f"/v1/findings/{fid}", headers=ADMIN).json()
        assert (f["level"], f["assignees"], f["agent_name"]) == (
            "owner",
            ["team cx"],
            "support-bot",
        )
        assert [(s["level"], s["current"], s["reached"]) for s in f["chain"]] == [
            ("owner", True, True),
            ("sponsors", False, False),
            ("team", False, False),
        ]
        assert [e["type"] for e in f["history"]] == ["finding.assigned", "finding.raised"]
        mine = client.get("/v1/me/issues", headers=ADMIN).json()
        assert mine == []  # the bootstrap administrator is nobody's owner

    def test_approvers_acknowledge_and_accept(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        _rt(client).run_issues()
        approver, auditor = _key(client, "approver"), _key(client, "auditor")
        assert client.post(f"/v1/findings/{fid}/acknowledge", headers=auditor).status_code == 403
        acked = client.post(f"/v1/findings/{fid}/acknowledge", headers=approver).json()
        assert acked["acknowledged_by"] == "approver:approver-key"
        assert acked["escalate_at"] is None
        body = {"reason": "Pilot ends in May", "until": "2099-01-01"}
        too_late = client.post(f"/v1/findings/{fid}/accept", json=body, headers=approver)
        assert too_late.status_code == 422 and "a year at most" in too_late.json()["detail"]
        odd = client.post(f"/v1/findings/{fid}/accept", json={**body, "x": 1}, headers=approver)
        assert odd.status_code == 422
        body["until"] = 30
        assert (
            client.post(f"/v1/findings/{fid}/accept", json=body, headers=auditor).status_code == 403
        )
        accepted = client.post(f"/v1/findings/{fid}/accept", json=body, headers=approver).json()
        assert (accepted["status"], accepted["accepted_reason"]) == (
            "accepted",
            "Pilot ends in May",
        )
        listed = client.get("/v1/findings?status=accepted", headers=auditor).json()
        assert [f["id"] for f in listed] == [fid]
        # Reopened by hand, it starts over.
        reopened = client.post(f"/v1/findings/{fid}/reopen", headers=approver).json()
        assert (reopened["status"], reopened["level"], reopened["accepted_until"]) == (
            "open",
            None,
            None,
        )

    def test_the_secops_role_triages_issues_from_triage_on(self, client, agent) -> None:
        fid = _raise(client, agent["id"])
        _rt(client).run_issues()
        secops = _key(client, "secops")
        client.put(
            "/v1/features/security-operations", json={"mode": "inform"}, headers=ADMIN
        ).raise_for_status()
        body = {"reason": "Known", "until": 7}
        assert (
            client.post(f"/v1/findings/{fid}/accept", json=body, headers=secops).status_code == 403
        )
        assert client.post(f"/v1/findings/{fid}/acknowledge", headers=secops).status_code == 403
        client.put("/v1/features/security-operations", json={"mode": "triage"}, headers=ADMIN)
        assert client.post(f"/v1/findings/{fid}/acknowledge", headers=secops).status_code == 200
        assert (
            client.post(f"/v1/findings/{fid}/accept", json=body, headers=secops).status_code == 200
        )


class TestManifests:
    def test_teams_round_trip(self, client, agent) -> None:
        client.patch("/v1/blueprints/support", json={"team": "cx"}, headers=ADMIN)
        exported = client.get("/v1/export", headers=ADMIN).text
        assert "kind: Team" in exported
        assert exported.index("kind: Team") < exported.index("kind: Blueprint")
        manifest = """
apiVersion: agentgov/v1alpha1
kind: Agent
metadata: {name: kb-bot}
spec: {blueprint: support, owner: platform, sponsors: [carol@example.com], team: platform}
---
apiVersion: agentgov/v1alpha1
kind: Team
metadata: {name: platform}
spec: {members: [carol@example.com], emails: [platform@example.com]}
"""
        resp = client.post(
            "/v1/apply", content=manifest, headers={**ADMIN, "Content-Type": "application/yaml"}
        )
        assert resp.status_code == 200, resp.text
        assert [(r["kind"], r["action"]) for r in resp.json()["results"]] == [
            ("Team", "created"),
            ("Agent", "created"),
        ]
        again = client.post(
            "/v1/apply", content=manifest, headers={**ADMIN, "Content-Type": "application/yaml"}
        )
        assert {r["action"] for r in again.json()["results"]} == {"unchanged"}


class TestCli:
    @pytest.fixture
    def agentgov(self, client: TestClient, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
        bearer = ADMIN["Authorization"].removeprefix("Bearer ")

        def run(*args: str):  # type: ignore[no-untyped-def]
            monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))
            result = runner.invoke(cli.app, list(args))
            assert result.exit_code == 0, result.output
            return result.output

        return run

    def test_teams_and_issues_from_the_cli(self, client, agent, agentgov) -> None:
        out = agentgov(
            "teams", "create", "platform", "--member", "carol@example.com,dan",
            "--email", "platform@example.com", "--description", "Platform engineering",
        )  # fmt: skip
        assert out.strip() == "team/platform: created"
        assert "platform@example.com" in agentgov("teams", "list")
        agentgov("teams", "update", "platform", "--default")
        assert "yes" in agentgov("teams", "list").splitlines()[-1]
        agentgov("blueprints", "update", "support", "--team", "platform")
        agentgov("agents", "update", "support-bot", "--team", "")
        fid = _raise(client, agent["id"])
        _rt(client).run_issues()
        listing = agentgov("findings", "list")
        assert fid in listing and "team cx (owner)" in listing
        shown = agentgov("findings", "get", fid)
        assert "-> owner: team cx" in shown and "team: team platform" in shown
        assert "acknowledged by admin:bootstrap" in agentgov("findings", "acknowledge", fid)
        out = agentgov("findings", "accept", fid, "--reason", "Pilot", "--until", "30")
        assert "risk accepted until" in out
        assert fid in agentgov("findings", "list", "--status", "accepted")
        assert fid not in agentgov("findings", "list", "--mine")

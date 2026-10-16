"""Finding types: which kinds of findings are raised here, and how severe each is
(docs/issues.md#kinds-of-issues)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from agentgov import cli, ids
from agentgov.db.models import Finding, FindingType
from agentgov.models import LedgerEntry
from agentgov.registry import finding_types, findings, issues, teams
from tests.conftest import ADMIN, seed
from tests.test_api import key
from tests.test_cli import _Shared, ok, runner

TYPE = "agent.no_owner"


def _rt(client: TestClient):  # type: ignore[no-untyped-def]
    return client.app.state.rt  # type: ignore[attr-defined]


def put(client: TestClient, type_: str, body: Any, headers=ADMIN) -> Any:
    return client.put(f"/v1/finding-types/{type_}", json=body, headers=headers)


def raise_(client: TestClient, subject: str, severity: str = "medium", type_: str = TYPE):
    with _rt(client).db.session() as s:
        finding, new = findings.raise_finding(
            s,
            type=type_,
            severity=severity,
            subject=subject,
            title=f"{subject} has no owner",
        )
        return finding.id, new, finding.status, finding.severity


def status(client: TestClient, fid: str) -> tuple[str, str]:
    with _rt(client).db.session() as s:
        f = findings.get(s, fid)
        return f.status, f.severity


@pytest.fixture
def team(client: TestClient) -> None:
    """The default team: it takes the findings about nothing else."""
    with _rt(client).db.session() as s:
        teams.create(s, {"name": "ai-governance", "default": True}, actor="admin:test")


def entries(client: TestClient, type_: str) -> list[LedgerEntry]:
    with _rt(client).db.session() as s:
        rows = s.scalars(select(LedgerEntry).where(LedgerEntry.type == type_)).all()
        s.expunge_all()
        return list(rows)


class TestChoosing:
    def test_the_types_raised_are_listed_with_their_counts(self, client) -> None:
        raise_(client, "a")
        raise_(client, "b")
        raise_(client, "c", type_="agent.stale")
        listed = {t["type"]: t for t in client.get("/v1/finding-types", headers=ADMIN).json()}
        assert listed[TYPE] == {
            "type": TYPE,
            "mode": "on",
            "severity": None,
            "open": 2,
            "total": 2,
            "changed_by": None,
            "changed_at": None,
        }
        assert listed["agent.stale"]["open"] == 1
        # A type can be set up before anything of it is raised.
        assert put(client, "platform.public_agent", {"mode": "off"}).status_code == 200
        listed = {t["type"]: t for t in client.get("/v1/finding-types", headers=ADMIN).json()}
        assert listed["platform.public_agent"]["mode"] == "off"
        assert listed["platform.public_agent"]["changed_by"] == "admin:bootstrap"

    @pytest.mark.parametrize(
        ("type_", "body", "message"),
        [
            ("no-dot", {"mode": "off"}, "isn't a finding type"),
            (TYPE, {}, "give the type's mode"),
            (TYPE, {"mode": "maybe"}, "mode is on or off"),
            (TYPE, {"severity": "urgent"}, "severity is one of"),
            (TYPE, {"mode": "off", "owner": "x"}, "give the type's mode"),
            (TYPE, ["off"], "valid dictionary"),
        ],
    )
    def test_changes_are_checked(self, client, type_: str, body: Any, message: str) -> None:
        resp = put(client, type_, body)
        assert resp.status_code == 422, resp.text
        assert message in resp.text

    def test_only_administrators_change_them(self, client) -> None:
        auditor = key(client, "auditor")
        assert client.get("/v1/finding-types", headers=auditor).status_code == 200
        assert put(client, TYPE, {"mode": "off"}, auditor).status_code == 403


class TestOff:
    @pytest.mark.parametrize("type_", ["ledger.rewound", "ledger.archive_failed"])
    def test_the_ledgers_own_cant_be_turned_off(self, client, type_: str) -> None:
        """They say the evidence ledger lost entries or can't be archived: an administrator
        covering what happened must not be able to quiet them."""
        resp = put(client, type_, {"mode": "off"})
        assert resp.status_code == 422 and "can't be turned off" in resp.text
        # One turned off before this, in the database: it still raises its issues.
        with _rt(client).db.transaction():
            FindingType.objects.create(type=type_, mode="off", changed_by="admin:before")
        _, new, state, _ = raise_(client, "ledger", type_=type_)
        assert (new, state) == (True, "open")

    def test_turning_a_type_off_dismisses_what_it_found(self, client) -> None:
        fid, *_ = raise_(client, "a")
        other, *_ = raise_(client, "b", type_="agent.stale")
        resp = put(client, TYPE, {"mode": "off"})
        assert resp.status_code == 200, resp.text
        assert (resp.json()["mode"], resp.json()["open"]) == ("off", 0)
        assert status(client, fid)[0] == "dismissed"
        assert status(client, other)[0] == "open"
        [dismissed] = entries(client, "finding.dismissed")
        assert dismissed.actor == "admin:bootstrap"
        assert dismissed.details["reason"] == "its type is off"
        [changed] = entries(client, "finding_type.changed")
        # Fewer findings for some: a warning.
        assert changed.severity == "warning" and changed.details["dismissed"] == 1
        # Unchanged: nothing more is recorded.
        put(client, TYPE, {"mode": "off"})
        assert len(entries(client, "finding_type.changed")) == 1

    def test_while_off_what_it_finds_is_kept_dismissed(self, client, team) -> None:
        put(client, TYPE, {"mode": "off"})
        fid, new, state, _ = raise_(client, "a")
        assert (new, state) == (False, "dismissed")
        assert entries(client, "finding.raised") == []
        # Found again: still dismissed, and seen.
        _, new, state, _ = raise_(client, "a")
        assert (new, state) == (False, "dismissed")
        with _rt(client).db.session() as s:
            f = findings.get(s, fid)
            assert f.resolved_by == finding_types.ACTOR
            assert f.details[finding_types.SUPPRESSED] is True
            assert issues.route(s, _rt(client).settings) == {"assigned": 0, "escalated": 0}

    def test_on_again_what_its_checks_find_again_comes_back(self, client, team) -> None:
        kept, *_ = raise_(client, "a")
        gone, *_ = raise_(client, "b")
        by_hand, *_ = raise_(client, "c")
        with _rt(client).db.session() as s:
            findings.set_status(s, by_hand, "dismissed", "admin:test")
        put(client, TYPE, {"mode": "off"})
        put(client, TYPE, {"mode": "on"})
        # Nothing comes back until its check finds it again.
        assert status(client, kept)[0] == "dismissed"
        _, reopened, state, _ = raise_(client, "a")
        assert (reopened, state) == (True, "open")
        with _rt(client).db.session() as s:
            assert finding_types.SUPPRESSED not in findings.get(s, kept).details
        assert status(client, gone)[0] == "dismissed"
        # Dismissed by a person: that stands.
        _, reopened, state, _ = raise_(client, "c")
        assert (reopened, state) == (False, "dismissed")
        # It goes to the people responsible again.
        with _rt(client).db.session() as s:
            assert issues.route(s, _rt(client).settings)["assigned"] == 1

    def test_a_resolved_finding_back_while_off_is_kept_dismissed(self, client) -> None:
        fid, *_ = raise_(client, "a")
        with _rt(client).db.session() as s:
            findings.set_status(s, fid, "resolved", "admin:test")
        put(client, TYPE, {"mode": "off"})
        _, reopened, state, _ = raise_(client, "a")
        assert (reopened, state) == (False, "dismissed")

    def test_reopened_by_hand_while_off_it_goes_to_nobody(self, client, team) -> None:
        put(client, TYPE, {"mode": "off"})
        fid, *_ = raise_(client, "a")
        with _rt(client).db.session() as s:
            findings.set_status(s, fid, "open", "admin:test")
            assert issues.route(s, _rt(client).settings)["assigned"] == 0
            assert findings.get(s, fid).level is None

    def test_an_accepted_risk_of_a_type_off_stays_closed(self, client) -> None:
        seed(client)
        fid, *_ = raise_(client, "a")
        with _rt(client).db.session() as s:
            issues.accept(s, findings.get(s, fid), reason="pilot", until=30, actor="admin:a")
        put(client, TYPE, {"mode": "off"})
        with _rt(client).db.session() as s:
            assert issues.reopen_accepted(s, ids.utcnow() + timedelta(days=31)) == 0
            assert findings.get(s, fid).status == "dismissed"


class TestSeverity:
    def test_a_types_severity_applies_to_open_and_new_findings(self, client) -> None:
        fid, *_ = raise_(client, "a", severity="medium")
        resp = put(client, TYPE, {"severity": "low"})
        assert resp.json()["severity"] == "low"
        assert status(client, fid) == ("open", "low")
        assert raise_(client, "b", severity="high")[3] == "low"
        # Found again, it keeps the type's severity.
        assert raise_(client, "a", severity="critical")[3] == "low"
        # Lower than it was set: a warning.
        put(client, TYPE, {"severity": "high"})
        put(client, TYPE, {"severity": "info"})
        assert [e.severity for e in entries(client, "finding_type.changed")] == [
            "info",
            "info",
            "warning",
        ]
        # Back to its checks' own.
        put(client, TYPE, {"severity": None})
        assert raise_(client, "a", severity="critical")[3] == "critical"


class TestManifestsAndCli:
    def test_finding_types_round_trip(self, client) -> None:
        manifest = """
apiVersion: agentgov/v1alpha1
kind: FindingType
metadata: {name: agent.no_owner}
spec: {mode: "off"}
---
apiVersion: agentgov/v1alpha1
kind: FindingType
metadata: {name: agent.stale}
spec: {severity: low}
"""
        headers = {**ADMIN, "Content-Type": "application/yaml"}
        resp = client.post("/v1/apply", content=manifest, headers=headers)
        assert resp.status_code == 200, resp.text
        assert [(r["name"], r["action"]) for r in resp.json()["results"]] == [
            ("agent.no_owner", "configured"),
            ("agent.stale", "configured"),
        ]
        again = client.post("/v1/apply", content=manifest, headers=headers)
        assert {r["action"] for r in again.json()["results"]} == {"unchanged"}
        exported = client.get("/v1/export", headers=ADMIN).text
        assert exported.count("kind: FindingType") == 2
        assert "severity: low" in exported and "mode: 'off'" in exported
        bad = "apiVersion: agentgov/v1alpha1\nkind: FindingType\nmetadata: {name: x.y}\nspec: {}\n"
        resp = client.post("/v1/apply", content=bad, headers=headers)
        assert resp.status_code == 422 and "needs mode, severity or both" in resp.text

    def test_finding_types_from_the_cli(self, client, monkeypatch) -> None:
        raise_(client, "a")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
        out = ok(runner.invoke(cli.app, ["findings", "types"]))
        assert TYPE in out and "(its checks')" in out
        out = ok(runner.invoke(cli.app, ["findings", "type", TYPE, "--off", "--yes"]))
        assert out.strip() == f"finding-type/{TYPE}: off, its checks' severity"
        out = ok(runner.invoke(cli.app, ["findings", "type", TYPE, "--on", "--severity", "low"]))
        assert out.strip() == f"finding-type/{TYPE}: on, severity low"
        out = ok(runner.invoke(cli.app, ["findings", "type", TYPE, "--severity", "default"]))
        assert out.strip() == f"finding-type/{TYPE}: on, its checks' severity"
        result = runner.invoke(cli.app, ["findings", "type", TYPE])
        assert result.exit_code != 0 and "give --on, --off or --severity" in result.output
        with _rt(client).db.transaction():
            assert Finding.objects.get(type=TYPE).status == "dismissed"

"""Access packages: grants agents hold for a while once approved (docs/access-packages.md)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import ids
from agentgov.models import AccessAssignment, LedgerEntry
from agentgov.registry import access_packages, features, findings
from tests.conftest import ADMIN, requires_opa, seed
from tests.test_opa import _decide


def _rt(client: TestClient):  # type: ignore[no-untyped-def]
    return client.app.state.rt  # type: ignore[attr-defined]


def _key(client: TestClient, role: str, name: str | None = None) -> dict[str, str]:
    resp = client.post(
        "/v1/apikeys", json={"name": name or f"{role}-key", "role": role}, headers=ADMIN
    )
    return {"Authorization": f"Bearer {resp.json()['token']}"}


CRM_WRITE = {
    "name": "crm-write",
    "description": "Change customer records",
    "permissions": [{"server": "crm", "tools": ["update_customer"]}],
    "duration_days": 30,
}


@pytest.fixture
def agent(client: TestClient) -> dict[str, Any]:
    """support-bot (owner cx, sponsor alice@example.com), and the crm-write package."""
    created = seed(client)
    resp = client.post("/v1/access-packages", json=CRM_WRITE, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return created


def _ask(client: TestClient, headers: dict[str, str], **body: Any) -> Any:
    payload = {"agent": "support-bot", "package": "crm-write", "reason": "Ticket CX-1", **body}
    return client.post("/v1/access-assignments", json=payload, headers=headers)


def _held(client: TestClient, agent_id: str) -> list[dict[str, Any]]:
    with _rt(client).db.session() as s:
        return access_packages.held(s).get(agent_id, [])


def _types(client: TestClient) -> list[str]:
    with _rt(client).db.session() as s:
        return [e.type for e in s.scalars(select(LedgerEntry).order_by(LedgerEntry.seq))]


class TestPackages:
    def test_packages_are_managed_by_administrators(self, client, agent) -> None:
        auditor = _key(client, "auditor")
        listed = client.get("/v1/access-packages", headers=auditor).json()
        assert [p["name"] for p in listed] == ["crm-write"]
        assert listed[0]["assignments"] == {"requested": 0, "active": 0, "expired": 0}
        assert client.post("/v1/access-packages", json={}, headers=auditor).status_code == 403
        empty = client.post("/v1/access-packages", json={"name": "nothing"}, headers=ADMIN)
        assert empty.status_code == 422 and "grants something" in empty.json()["detail"]
        long = client.post(
            "/v1/access-packages",
            json={**CRM_WRITE, "name": "x", "duration_days": 400},
            headers=ADMIN,
        )
        assert long.status_code == 422 and "1 to 365" in long.json()["detail"]
        nowhere = client.patch(
            "/v1/access-packages/crm-write", json={"blueprints": ["nope"]}, headers=ADMIN
        )
        assert nowhere.status_code == 422 and "not found" in nowhere.json()["detail"]
        changed = client.patch(
            "/v1/access-packages/crm-write", json={"review_days": 30}, headers=ADMIN
        ).json()
        assert changed["review_days"] == 30
        assert "access_package.updated" in _types(client)

    def test_a_package_agents_hold_is_kept(self, client, agent) -> None:
        _ask(client, ADMIN, approve=True).raise_for_status()
        refused = client.delete("/v1/access-packages/crm-write", headers=ADMIN)
        assert refused.status_code == 409


class TestRequests:
    def test_approvers_decide_what_others_ask_for(self, client, agent) -> None:
        registrar, approver = _key(client, "registrar"), _key(client, "approver", "ann")
        asked = _ask(client, registrar, days=14)
        assert asked.status_code == 201, asked.text
        row = asked.json()
        assert (row["status"], row["days"], row["requested_by"]) == (
            "requested",
            14,
            "registrar:registrar-key",
        )
        assert _held(client, agent["id"]) == []  # nothing until approved
        again = _ask(client, registrar)
        assert again.status_code == 409  # one request at a time
        assert (
            client.post(
                f"/v1/access-assignments/{row['id']}/approve", headers=registrar
            ).status_code
            == 403
        )
        approved = client.post(
            f"/v1/access-assignments/{row['id']}/approve", json={"note": "ok"}, headers=approver
        ).json()
        assert (approved["status"], approved["decided_by"]) == ("active", "approver:ann")
        (held,) = _held(client, agent["id"])
        assert held["name"] == "crm-write"
        assert held["grants"] == [{"server": "crm", "tools": ["update_customer"]}]
        assert [t for t in _types(client) if t.startswith("access.")] == [
            "access.requested",
            "access.approved",
        ]

    def test_nobody_approves_their_own_request(self, client, agent) -> None:
        approver = _key(client, "approver", "ann")
        row = _ask(client, approver).json()
        refused = client.post(f"/v1/access-assignments/{row['id']}/approve", headers=approver)
        assert refused.status_code == 403 and "someone other" in refused.json()["detail"]

    def test_packages_without_approval_are_granted_at_once(self, client, agent) -> None:
        client.patch("/v1/access-packages/crm-write", json={"approval": False}, headers=ADMIN)
        row = _ask(client, _key(client, "registrar")).json()
        assert (row["status"], row["decided_by"]) == ("active", "system:access-packages")

    def test_what_a_request_must_say(self, client, agent) -> None:
        assert _ask(client, ADMIN, reason="").status_code == 422
        too_long = _ask(client, ADMIN, days=31)
        assert too_long.status_code == 422 and "30 days at most" in too_long.json()["detail"]
        client.patch(
            "/v1/access-packages/crm-write", json={"blueprints": ["support"]}, headers=ADMIN
        )
        client.post(
            "/v1/agents",
            json={"name": "other-bot", "approve": True, "sponsors": ["x"]},
            headers=ADMIN,
        )
        elsewhere = _ask(client, ADMIN, agent="other-bot")
        assert (
            elsewhere.status_code == 422 and "for agents on support" in elsewhere.json()["detail"]
        )
        auditor = _key(client, "auditor")
        assert _ask(client, auditor).status_code == 403
        not_admin = _ask(client, _key(client, "approver"), approve=True)
        assert not_admin.status_code == 403

    def test_the_agents_owner_and_sponsors_may_ask(self, client, agent) -> None:
        with _rt(client).db.session() as s:
            from agentgov.registry import agents

            bot = agents.get(s, "support-bot")
            assert access_packages.may_request(s, frozenset({"person"}), "Alice@Example.com", bot)
            assert not access_packages.may_request(s, frozenset({"person"}), "mallory", bot)

    def test_nothing_is_asked_for_while_packages_are_off(self, client, agent) -> None:
        client.put("/v1/features/access-packages", json={"mode": "off"}, headers=ADMIN)
        assert _ask(client, ADMIN).status_code == 409


class TestLifecycle:
    def _active(self, client: TestClient, **body: Any) -> str:
        row = _ask(client, ADMIN, approve=True, **body).json()
        assert row["status"] == "active"
        return row["id"]

    def test_reminders_then_expiry(self, client, agent) -> None:
        rt = _rt(client)
        assignment_id = self._active(client, days=30)
        now = ids.utcnow()
        with rt.db.session() as s:
            assert access_packages.check(s, rt.settings, now) == {
                "expired": 0,
                "expiring": 0,
                "reviews": 0,
            }
            assert access_packages.check(s, rt.settings, now + timedelta(days=20))["expiring"] == 1
            reminder = findings.get(s, s.scalar(select(findings.Finding.id)))
            assert (reminder.type, reminder.severity) == ("access.expiring", "low")
            access_packages.check(s, rt.settings, now + timedelta(days=29, hours=12))
            assert findings.get(s, reminder.id).severity == "high"
            assert access_packages.check(s, rt.settings, now + timedelta(days=31))["expired"] == 1
            row = s.get(AccessAssignment, assignment_id)
            assert row.status == "expired"
            assert findings.get(s, reminder.id).status == "resolved"
            expired = s.scalar(
                select(findings.Finding).where(findings.Finding.type == "access.expired")
            )
            assert "still uses" in expired.description  # monitored by default
        assert "access.expired" in _types(client)
        # Held still: OPA decides what an expired package grants, as the feature says.
        assert [p["name"] for p in _held(client, agent["id"])] == ["crm-write"]

    def test_renewing_carries_on_and_never_ends_sooner(self, client, agent) -> None:
        rt = _rt(client)
        first = self._active(client, days=30)
        renewal = _ask(client, _key(client, "registrar"), days=7).json()
        approver = _key(client, "approver", "ann")
        client.post(f"/v1/access-assignments/{renewal['id']}/approve", headers=approver)
        with rt.db.session() as s:
            old, new = s.get(AccessAssignment, first), s.get(AccessAssignment, renewal["id"])
            assert (old.status, new.status) == ("renewed", "active")
            assert new.expires_at == old.expires_at  # 7 days from now would be sooner
        assert len(_held(client, agent["id"])) == 1

    def test_a_deleted_agents_packages_wait_for_it(self, client, agent) -> None:
        rt = _rt(client)
        assignment_id = self._active(client, days=30)
        pending = _ask(client, _key(client, "registrar"), days=7).json()
        deleted = client.post("/v1/agents/support-bot/delete", json={}, headers=ADMIN)
        assert deleted.status_code == 200, deleted.text
        later = ids.utcnow() + timedelta(days=31)
        with rt.db.session() as s:
            # No reminders, expiry or reviews about an agent that is gone.
            assert access_packages.check(s, rt.settings, later) == {
                "expired": 0,
                "expiring": 0,
                "reviews": 0,
            }
            assert s.scalar(select(findings.Finding.id)) is None
        approver = _key(client, "approver", "ann")
        refused = client.post(f"/v1/access-assignments/{pending['id']}/approve", headers=approver)
        assert refused.status_code == 409 and "restore it first" in refused.text
        assert (
            client.post(f"/v1/access-assignments/{pending['id']}/deny", headers=approver).json()[
                "status"
            ]
            == "denied"
        )
        assert _ask(client, ADMIN, approve=True).status_code == 409
        # Restored, they are checked again.
        client.post("/v1/agents/support-bot/restore", json={}, headers=ADMIN)
        with rt.db.session() as s:
            assert access_packages.check(s, rt.settings, later)["expired"] == 1
            assert s.get(AccessAssignment, assignment_id).status == "expired"
        # Purged, they go with it, and the package can be deleted.
        client.post("/v1/agents/support-bot/delete", json={}, headers=ADMIN)
        assert client.delete("/v1/agents/support-bot", headers=ADMIN).status_code in (200, 204)
        assert _held(client, agent["id"]) == []
        assert client.delete("/v1/access-packages/crm-write", headers=ADMIN).status_code in (
            200,
            204,
        )

    def test_revoking_takes_it_away(self, client, agent) -> None:
        assignment_id = self._active(client)
        approver = _key(client, "approver")
        out = client.post(
            f"/v1/access-assignments/{assignment_id}/revoke",
            json={"reason": "No longer needed"},
            headers=approver,
        ).json()
        assert out["status"] == "revoked" and out["ended_at"]
        assert _held(client, agent["id"]) == []
        again = client.post(f"/v1/access-assignments/{assignment_id}/revoke", headers=approver)
        assert again.status_code == 409

    def test_the_secops_role_revokes_from_contain_on(self, client, agent) -> None:
        assignment_id = self._active(client)
        secops = _key(client, "secops")
        url = f"/v1/access-assignments/{assignment_id}/revoke"
        assert client.post(url, headers=secops).status_code == 403
        client.put("/v1/features/security-operations", json={"mode": "contain"}, headers=ADMIN)
        assert client.post(url, headers=secops).status_code == 200

    def test_reviews_keep_or_remove(self, client, agent) -> None:
        rt = _rt(client)
        client.patch("/v1/access-packages/crm-write", json={"review_days": 7}, headers=ADMIN)
        assignment_id = self._active(client, days=30)
        with rt.db.session() as s:
            assert (
                access_packages.check(s, rt.settings, ids.utcnow() + timedelta(days=8))["reviews"]
                == 1
            )
        url = f"/v1/access-assignments/{assignment_id}/review"
        approver = _key(client, "approver")
        assert client.post(url, json={}, headers=approver).status_code == 422
        kept = client.post(url, json={"keep": True}, headers=approver).json()
        assert kept["status"] == "active" and kept["reviewed_at"]
        with rt.db.session() as s:
            due = s.scalar(
                select(findings.Finding).where(findings.Finding.type == "access.review_due")
            )
            assert due.status == "resolved"
        removed = client.post(url, json={"keep": False}, headers=approver).json()
        assert removed["status"] == "revoked"

    def test_an_agents_packages(self, client, agent) -> None:
        self._active(client)
        rows = client.get("/v1/agents/support-bot/access-packages", headers=ADMIN).json()
        assert [(r["package"], r["status"]) for r in rows] == [("crm-write", "active")]
        listed = client.get(
            "/v1/access-assignments", params={"status": "active"}, headers=_key(client, "auditor")
        ).json()
        assert [r["agent_name"] for r in listed] == ["support-bot"]


@requires_opa
def test_opa_applies_expiry_as_the_feature_says(rt, settings, tmp_path: Path) -> None:
    from tests.test_opa import _seed

    _seed(rt, settings)
    with rt.db.session() as s:
        from agentgov.registry import agents

        package = access_packages.create(
            s,
            {"name": "crm-write", "permissions": [{"server": "crm", "tools": ["update_*"]}]},
            actor="t",
        )
        row = access_packages.request(
            s,
            agent=agents.get(s, "bot"),
            package=package,
            days=30,
            reason="r",
            actor="admin:t",
            approve=True,
        )
        assignment_id = row.id
    call = {
        "phase": "request",
        "method": "tools/call",
        "agent": {"client_id": "agent-bot"},
        "resource": {"server": "crm", "name": "update_customer"},
        "detections": {"categories": []},
    }
    assert _decide(rt, tmp_path, call)["effect"] == "allow"
    with rt.db.session() as s:
        s.get(AccessAssignment, assignment_id).expires_at = ids.utcnow() - timedelta(minutes=1)
    rt.bundles.notify()
    monitored = _decide(rt, tmp_path, call)
    assert monitored["effect"] == "allow" and monitored["monitored"] == [
        "access-packages: crm/update_customer was granted to agent bot by access package "
        "crm-write, which has expired"
    ]
    with rt.db.session() as s:
        features.set_mode(s, settings, "access-packages", "enforce", actor="t")
    rt.bundles.notify()
    assert _decide(rt, tmp_path, call)["effect"] == "deny"


class TestManifestsAndCli:
    def test_packages_round_trip(self, client, agent) -> None:
        manifest = """
apiVersion: agentgov/v1alpha1
kind: AccessPackage
metadata: {name: analytics-models}
spec:
  description: Bigger models for the quarterly analysis
  model_access: [{provider: openai, models: [gpt-4.1]}]
  duration_days: 14
  approval: false
  blueprints: [support]
"""
        headers = {**ADMIN, "Content-Type": "application/yaml"}
        applied = client.post("/v1/apply", content=manifest, headers=headers).json()
        assert applied["results"] == [
            {"kind": "AccessPackage", "name": "analytics-models", "action": "created"}
        ]
        again = client.post("/v1/apply", content=manifest, headers=headers).json()
        assert again["results"][0]["action"] == "unchanged"
        exported = client.get("/v1/export", headers=ADMIN).text
        assert "kind: AccessPackage" in exported
        assert exported.index("kind: Blueprint") < exported.index("kind: AccessPackage")
        assert exported.index("kind: AccessPackage") < exported.index("kind: Agent")

    def test_from_the_cli(self, client, agent, monkeypatch) -> None:
        from agentgov import cli
        from tests.test_cli import _Shared, runner

        bearer = ADMIN["Authorization"].removeprefix("Bearer ")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))

        def run(*args: str) -> str:
            result = runner.invoke(cli.app, list(args))
            assert result.exit_code == 0, result.output
            return result.output

        run(
            "access-packages", "create", "kb-read", "--grant", "kb:search",
            "--model-access", "openai:gpt-4.1", "--days", "7", "--no-approval",
        )  # fmt: skip
        listing = run("access-packages", "list")
        assert "kb-read" in listing and "kb:search; openai:gpt-4.1" in listing
        out = run("access-packages", "request", "support-bot", "kb-read", "--reason", "Pilot")
        assert out.startswith("access/asg_") and "active until" in out
        assignment_id = out.split(":")[0].removeprefix("access/")
        assert assignment_id in run("access-packages", "assignments", "--status", "active")
        assert "revoked" in run("access-packages", "revoke", assignment_id, "--yes")
        run("access-packages", "update", "kb-read", "--review-days", "30")
        assert '"review_days": 30' in run("access-packages", "get", "kb-read")

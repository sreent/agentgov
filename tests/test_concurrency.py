"""People working at once: edits made from an older copy, and decisions taken together.

The races need PostgreSQL (AGENTGOV_TEST_POSTGRES_URL): SQLite runs one write
transaction at a time, so it can't have them.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from agentgov import db, ledger
from agentgov.config import Settings
from agentgov.models import LedgerEntry
from agentgov.registry import access_packages, agents, approvals
from agentgov.registry.errors import InvalidTransition
from agentgov.runtime import Runtime
from tests.conftest import ADMIN, POSTGRES, seed

postgres = pytest.mark.skipif(not POSTGRES, reason="needs AGENTGOV_TEST_POSTGRES_URL")


# ------------------------------------------------------------------- edit conflicts


def test_an_edit_from_an_older_copy_is_refused(client: TestClient) -> None:
    seed(client)
    loaded = client.get("/v1/agents/support-bot", headers=ADMIN).json()
    version = loaded["version"]
    # Someone else saves first.
    first = client.patch(
        "/v1/agents/support-bot",
        json={"description": "Answers support tickets"},
        headers={**ADMIN, "If-Match": f'"{version}"'},
    )
    assert first.status_code == 200 and first.json()["version"] == version + 1
    # The second save was made from the copy before it.
    second = client.patch(
        "/v1/agents/support-bot",
        json={"owner": "billing"},
        headers={**ADMIN, "If-Match": f'"{version}"'},
    )
    assert second.status_code == 412
    assert "changed since you loaded it" in second.json()["detail"]
    agent = client.get("/v1/agents/support-bot", headers=ADMIN).json()
    assert agent["owner"] == "cx" and agent["description"] == "Answers support tickets"
    # Made again on top of the newer copy, it goes through (a weak tag too).
    third = client.patch(
        "/v1/agents/support-bot",
        json={"owner": "billing"},
        headers={**ADMIN, "If-Match": f'W/"{version + 1}"'},
    )
    assert third.status_code == 200 and third.json()["owner"] == "billing"
    # Without If-Match, an edit changes what it gives, whatever the version.
    loose = client.patch("/v1/agents/support-bot", json={"owner": "cx"}, headers=ADMIN)
    assert loose.status_code == 200 and loose.json()["version"] == version + 3
    bad = client.patch(
        "/v1/agents/support-bot", json={}, headers={**ADMIN, "If-Match": "yesterday"}
    )
    assert bad.status_code == 400


def test_what_the_scheduled_work_changes_isnt_an_edit(client: TestClient) -> None:
    seed(client)
    version = client.get("/v1/agents/support-bot", headers=ADMIN).json()["version"]
    # Blocking, unblocking and a new risk score don't move the version: a form open
    # meanwhile still saves.
    client.post("/v1/agents/support-bot/block", json={}, headers=ADMIN).raise_for_status()
    client.post("/v1/agents/support-bot/unblock", json={}, headers=ADMIN).raise_for_status()
    rt = client.app.state.rt  # type: ignore[attr-defined]
    with rt.db.session() as s:
        agents.refresh_risk(s, rt.settings, agents.get(s, "support-bot"))
    resp = client.patch(
        "/v1/agents/support-bot",
        json={"description": "Still mine"},
        headers={**ADMIN, "If-Match": f'"{version}"'},
    )
    assert resp.status_code == 200, resp.text
    # Nor does a save that changes nothing.
    same = client.patch(
        "/v1/agents/support-bot",
        json={"description": "Still mine"},
        headers={**ADMIN, "If-Match": f'"{version + 1}"'},
    )
    assert same.status_code == 200 and same.json()["version"] == version + 1


EDITABLE = [
    ("/v1/blueprints/support", "patch", {"description": "Support agents"}),
    ("/v1/toolservers/crm", "patch", {"description": "The CRM"}),
    ("/v1/teams/cx", "patch", {"description": "Customer experience"}),
    ("/v1/models/providers/demo", "patch", {"description": "The demo model"}),
    ("/v1/identity-issuers/cluster", "patch", {"description": "The cluster"}),
    ("/v1/destinations/siem", "patch", {"description": "The SIEM"}),
    ("/v1/access-packages/crm-read", "patch", {"description": "Read customers"}),
    ("/v1/rules/idle", "patch", {"description": "Idle agents"}),
    ("/v1/policies/extra", "put", {"description": "Extra rules"}),
]


def _make_all(client: TestClient) -> None:
    seed(client)
    for path, body in [
        ("/v1/teams", {"name": "cx", "members": ["alice@example.com"]}),
        (
            "/v1/models/providers",
            {"name": "demo", "kind": "openai-compatible", "base_url": "http://demo-model:9100/v1"},
        ),
        (
            "/v1/identity-issuers",
            {
                "name": "cluster",
                "kind": "kubernetes",
                "issuer": "https://cluster.example.com",
                "jwks_url": "https://cluster.example.com/keys",
            },
        ),
        (
            "/v1/destinations",
            {"name": "siem", "kind": "webhook", "url": "https://siem.example.com"},
        ),
        (
            "/v1/access-packages",
            {
                "name": "crm-read",
                "permissions": [{"server": "crm", "tools": ["get_*"]}],
                "duration_days": 7,
            },
        ),
        (
            "/v1/rules",
            {
                "name": "idle",
                "conditions": {"inactive_days": 90},
                "action": "issue",
            },
        ),
        ("/v1/policies", {"name": "extra", "rego": "package agentgov.custom.extra\n"}),
    ]:
        resp = client.post(path, json=body, headers=ADMIN)
        assert resp.status_code in (200, 201), (path, resp.text)


@pytest.mark.parametrize(("path", "method", "body"), EDITABLE)
def test_every_kind_refuses_an_edit_from_an_older_copy(
    client: TestClient, path: str, method: str, body: dict[str, Any]
) -> None:
    _make_all(client)
    version = client.get(path, headers=ADMIN).json()["version"]
    send = getattr(client, method)
    resp = send(path, json=body, headers={**ADMIN, "If-Match": f'"{version}"'})
    assert resp.status_code == 200, resp.text
    assert resp.json()["version"] == version + 1
    stale = send(
        path, json={"description": "Too late"}, headers={**ADMIN, "If-Match": f'"{version}"'}
    )
    assert stale.status_code == 412, stale.text


def test_manifests_raise_the_version(client: TestClient) -> None:
    seed(client)
    version = client.get("/v1/blueprints/support", headers=ADMIN).json()["version"]
    manifest = (
        "apiVersion: agentgov/v1alpha1\nkind: Blueprint\nmetadata: {name: support}\n"
        "spec:\n  risk_tier: medium\n  description: From Git\n"
        "  permissions: [{server: crm, tools: ['get_*', delete_customer]}]\n"
    )
    resp = client.post(
        "/v1/apply", content=manifest, headers={**ADMIN, "Content-Type": "application/yaml"}
    )
    assert resp.status_code == 200, resp.text
    assert client.get("/v1/blueprints/support", headers=ADMIN).json()["version"] == version + 1


# --------------------------------------------------------------------------- races


def together(*decisions: Callable[[], Any]) -> list[str]:
    """Run the decisions at once, each in its own transaction, and say how each went:
    "ok" or "refused"."""
    start = threading.Barrier(len(decisions))
    outcomes: list[str] = []
    lock = threading.Lock()

    def run(decision: Callable[[], Any]) -> None:
        start.wait()
        try:
            decision()
            outcome = "ok"
        except InvalidTransition:
            outcome = "refused"
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=run, args=(d,)) for d in decisions]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    return sorted(outcomes)


@pytest.fixture
def pg(settings: Settings) -> Runtime:
    rt = Runtime(settings)
    rt.init_db()
    yield rt
    rt.db.dispose()


def _agent(rt: Runtime) -> str:
    with rt.db.session() as s:
        agent = agents.register(
            s,
            rt.settings,
            {"name": "support-bot", "owner": "cx", "sponsors": ["alice@example.com"]},
            actor="admin:test",
            approve=True,
        )
        return agent.id


def _entries(rt: Runtime, type_: str) -> int:
    with rt.db.session() as s:
        return s.scalar(
            select(func.count()).select_from(LedgerEntry).where(LedgerEntry.type == type_)
        )


@postgres
def test_two_approvers_decide_one_request(pg: Runtime) -> None:
    agent_id = _agent(pg)
    with pg.db.session() as s:
        _, req = approvals.check_or_request(
            s,
            agent=agents.get(s, agent_id),
            action="tools/call",
            resource="crm/delete_customer",
            arguments={"customer_id": "c-1"},
            reasons=["destructive"],
            ttl_seconds=600,
        )
        request_id = req.id

    def decide(approve: bool) -> Callable[[], Any]:
        def run() -> None:
            with pg.db.session() as s:
                req = approvals.get(s, request_id)  # both read it pending
                approvals.decide(s, req, approve=approve, actor=f"approver:{approve}")

        return run

    assert together(decide(True), decide(False)) == ["ok", "refused"]
    assert _entries(pg, "approval.approved") + _entries(pg, "approval.denied") == 1


@postgres
def test_one_approval_is_used_once(pg: Runtime) -> None:
    agent_id = _agent(pg)
    call = {
        "action": "tools/call",
        "resource": "crm/delete_customer",
        "arguments": {"customer_id": "c-1"},
        "reasons": ["destructive"],
        "ttl_seconds": 600,
    }
    with pg.db.session() as s:
        _, req = approvals.check_or_request(s, agent=agents.get(s, agent_id), **call)
        approvals.decide(s, req, approve=True, actor="approver:test")
    used: list[str] = []

    def again() -> None:
        with pg.db.session() as s:
            outcome, _ = approvals.check_or_request(s, agent=agents.get(s, agent_id), **call)
            used.append(outcome)

    together(again, again)
    assert sorted(used) == ["approved", "created"]


@postgres
def test_two_people_decide_one_access_request(pg: Runtime) -> None:
    agent_id = _agent(pg)
    with pg.db.session() as s:
        package = access_packages.create(
            s,
            {
                "name": "crm-write",
                "permissions": [{"server": "crm", "tools": ["update_customer"]}],
                "duration_days": 30,
            },
            actor="admin:test",
        )
        row = access_packages.request(
            s,
            agent=agents.get(s, agent_id),
            package=package,
            days=None,
            reason="Ticket CX-1",
            actor="alice@example.com",
        )
        row_id = row.id

    def decide(approve: bool) -> Callable[[], Any]:
        def run() -> None:
            with pg.db.session() as s:
                row = access_packages.assignment(s, row_id)
                access_packages.decide(s, row, approve=approve, actor=f"approver:{approve}")

        return run

    assert together(decide(True), decide(False)) == ["ok", "refused"]


@postgres
def test_two_blocks_at_once(pg: Runtime) -> None:
    agent_id = _agent(pg)

    def block() -> None:
        with pg.db.session() as s:
            agents.transition(s, pg.settings, agents.get(s, agent_id), "block", actor="a")

    assert together(block, block) == ["ok", "refused"]
    assert _entries(pg, "agent.block") == 1


@postgres
def test_the_chain_head_is_locked_last(pg: Runtime) -> None:
    """One transaction appends to the ledger, then locks a row; another locks the row, then
    appends. Were the chain's head locked as each appended, each would wait for the other
    (a deadlock: PostgreSQL fails one); it is locked as each commits, so they take turns."""
    agent_id = _agent(pg)
    appended, locked = threading.Event(), threading.Event()
    failed: list[BaseException] = []

    def append_then_lock() -> None:
        try:
            with pg.db.session() as s:
                ledger.append(s, type="test.first", actor="test")
                appended.set()
                assert locked.wait(5)
                db.lock(s, agents.get(s, agent_id))  # waits for the other to commit
        except BaseException as exc:
            failed.append(exc)

    def lock_then_append() -> None:
        try:
            with pg.db.session() as s:
                assert appended.wait(5)
                db.lock(s, agents.get(s, agent_id))
                locked.set()
                time.sleep(0.3)  # the other is waiting for the row by now
                ledger.append(s, type="test.second", actor="test")
        except BaseException as exc:
            failed.append(exc)

    threads = [threading.Thread(target=append_then_lock), threading.Thread(target=lock_then_append)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert failed == []
    with pg.db.session() as s:
        types = list(s.scalars(select(LedgerEntry.type).order_by(LedgerEntry.seq)))
        assert types[-2:] == ["test.second", "test.first"]  # in the order they committed
        assert ledger.verify(s)["valid"] is True


def test_the_cli_names_the_version_too(client: TestClient, monkeypatch) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    seed(client)
    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    version = client.get("/v1/agents/support-bot", headers=ADMIN).json()["version"]
    update = ["agents", "update", "support-bot", "--if-version", str(version)]
    ok = runner.invoke(cli.app, [*update, "--description", "From the CLI"])
    assert ok.exit_code == 0, ok.output
    stale = runner.invoke(cli.app, [*update, "--description", "Too late"])
    assert stale.exit_code == 1 and "error 412" in stale.output
    replicas = runner.invoke(cli.app, ["replicas"])
    assert replicas.exit_code == 0 and "this one" in replicas.output

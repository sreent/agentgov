"""What waits for a decision, in one place, each kind for those who may decide it
(agentgov.registry.inbox, GET /v1/inbox)."""

from __future__ import annotations

from typing import Any

from starlette.testclient import TestClient

from agentgov.registry import agents, approvals, findings, issues
from tests.conftest import ADMIN, seed
from tests.test_access_packages import CRM_WRITE, _key
from tests.test_platforms import import_inventory


def inbox(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    resp = client.get("/v1/inbox", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def counts(view: dict[str, Any]) -> dict[str, int]:
    return {k["kind"]: k["count"] for k in view["kinds"]}


def waiting(client: TestClient) -> None:
    """One of each kind: a held call, an access request, a risk someone asked to be
    accepted, an agent and a tool server to approve, a changed tool definition, and two
    Copilot Studio agents nobody has reviewed."""
    seed(client)
    client.post("/v1/access-packages", json=CRM_WRITE, headers=ADMIN).raise_for_status()
    registrar = _key(client, "registrar")
    client.post(
        "/v1/access-assignments",
        json={"agent": "support-bot", "package": "crm-write", "reason": "Ticket CX-1"},
        headers=registrar,
    ).raise_for_status()
    client.post(
        "/v1/agents",
        json={"name": "new-bot", "blueprint": "support", "owner": "cx", "sponsors": ["a@x.io"]},
        headers=ADMIN,
    ).raise_for_status()
    client.post(
        "/v1/toolservers", json={"name": "wiki", "url": "http://wiki:9000/mcp"}, headers=registrar
    ).raise_for_status()
    import_inventory(client)
    rt = client.app.state.rt  # type: ignore[attr-defined]
    with rt.db.transaction() as tx:
        agent = agents.get(tx, "support-bot")
        approvals.check_or_request(
            tx,
            agent=agent,
            action="tools/call",
            resource="crm/delete_customer",
            arguments={"id": 7},
            reasons=["destructive"],
            ttl_seconds=600,
        )
        finding, _ = findings.raise_finding(
            tx,
            type="agent.no_sponsor",
            severity="medium",
            subject=agent.id,
            agent_id=agent.id,
            title="support-bot has no sponsor",
        )
        issues.ask_exception(
            tx, finding, actor="user:sam", name="sam", reason="A pilot, ends soon", until=30
        )
        findings.raise_finding(
            tx,
            type="toolserver.tool_drift",
            severity="high",
            subject="crm/delete_customer",
            category=findings.THREAT,
            title="Tool definition changed: crm/delete_customer",
        )


def test_an_administrator_sees_every_kind(client: TestClient) -> None:
    waiting(client)
    view = inbox(client, ADMIN)
    assert counts(view) == {
        "calls": 1,
        "access": 1,
        "risks": 1,
        "agents": 1,
        "toolservers": 1,
        "definitions": 1,
        "platform_agents": 2,
    }
    assert view["total"] == 8
    by = {k["kind"]: k["items"] for k in view["kinds"]}
    assert by["calls"][0]["resource"] == "crm/delete_customer"
    assert by["access"][0]["package"] == "crm-write"
    assert by["risks"][0]["asked"]["by"] == "sam"
    assert by["risks"][0]["agent_name"] == "support-bot"
    assert [a["name"] for a in by["agents"]] == ["new-bot"]
    assert [t["name"] for t in by["toolservers"]] == ["wiki"]
    assert by["definitions"] == [
        {
            "finding_id": by["definitions"][0]["finding_id"],
            "server": "crm",
            "tool": "delete_customer",
            "since": by["definitions"][0]["since"],
        }
    ]
    assert by["platform_agents"] == [{"platform": "Copilot Studio", "count": 2}]


def test_each_role_sees_what_it_decides(client: TestClient) -> None:
    waiting(client)
    approver = _key(client, "approver", "ann")
    assert counts(inbox(client, approver)) == {"calls": 1, "access": 1, "risks": 1}
    # Whoever asked for a package doesn't decide it.
    assert counts(inbox(client, _key(client, "registrar", "registrar-key"))) == {"calls": 0}
    auditor = _key(client, "auditor")
    view = inbox(client, auditor)
    assert counts(view) == {"calls": 0} and view["total"] == 0


def test_decided_is_gone_from_it(client: TestClient) -> None:
    waiting(client)
    view = inbox(client, ADMIN)
    call = next(k for k in view["kinds"] if k["kind"] == "calls")["items"][0]
    client.post(f"/v1/approvals/{call['id']}/approve", json={}, headers=ADMIN).raise_for_status()
    client.post("/v1/agents/new-bot/approve", json={}, headers=ADMIN).raise_for_status()
    after = counts(inbox(client, ADMIN))
    assert after["calls"] == 0 and after["agents"] == 0


def test_the_findings_asked_to_be_accepted_are_only_those(client: TestClient) -> None:
    """On SQLite too: a JSON key that isn't there is no match."""
    waiting(client)
    asked = client.get("/v1/findings", params={"asked": "true"}, headers=ADMIN)
    assert [f["type"] for f in asked.json()] == ["agent.no_sponsor"]
    assert asked.headers["X-Total-Count"] == "1"


def test_the_cli(client: TestClient, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
    out = runner.invoke(cli.app, ["inbox"])
    assert out.exit_code == 0 and "Nothing waits" in out.output, out.output
    waiting(client)
    out = runner.invoke(cli.app, ["inbox"])
    assert out.exit_code == 0, out.output
    assert "8 waiting for a decision of yours" in out.output
    assert "Agents waiting for approval (1): agentgov agents lifecycle NAME" in out.output
    assert "  new-bot  owner cx, sponsors a@x.io" in out.output
    assert "  crm/delete_customer" in out.output

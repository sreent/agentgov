"""The CLI against the real API, in process: every command goes through the HTTP layer."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from agentgov import cli
from tests.conftest import ADMIN, SERVICE, requires_opa, seed

runner = CliRunner()


class _Shared:
    """Stands in for ``cli._client()``: the test's client, with a bearer token."""

    def __init__(self, client: TestClient, token: str) -> None:
        self.client, self.token = client, token

    def __enter__(self) -> TestClient:
        self.client.headers["Authorization"] = f"Bearer {self.token}"
        return self.client

    def __exit__(self, *exc: object) -> None:
        self.client.headers.pop("Authorization", None)


@pytest.fixture
def agentgov(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """Run ``agentgov <args>`` as the bootstrap admin (or ``token=``)."""

    def run(*args: str, token: str | None = None, input: str | None = None):
        bearer = token or ADMIN["Authorization"].removeprefix("Bearer ")
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, bearer))
        return runner.invoke(cli.app, list(args), input=input)

    yield run


def ok(result) -> str:  # type: ignore[no-untyped-def]
    assert result.exit_code == 0, result.output
    return result.output


class TestAgents:
    def test_register_edit_and_retire_an_agent(self, client, agentgov) -> None:
        seed(client)
        out = ok(
            agentgov(
                "agents", "create", "triage-bot",
                "--blueprint", "support", "--owner", "cx",
                "--sponsor", "alice@example.com,bob@example.com",
                "--grant", "crm:search_customers", "--label", "team=cx", "--approve",
            )
        )  # fmt: skip
        assert out.strip() == "agent/triage-bot: active"
        agent = client.get("/v1/agents/triage-bot", headers=ADMIN).json()
        assert agent["sponsors"] == ["alice@example.com", "bob@example.com"]
        assert agent["permissions"] == [{"server": "crm", "tools": ["search_customers"]}]
        assert agent["labels"] == {"team": "cx"}

        ok(agentgov("agents", "update", "triage-bot", "--owner", "", "--clear-grants"))
        agent = client.get("/v1/agents/triage-bot", headers=ADMIN).json()
        assert (agent["owner"], agent["permissions"]) == (None, [])
        assert "attested" in ok(agentgov("agents", "attest", "triage-bot", "--note", "still used"))
        assert "low risk" in ok(agentgov("agents", "risk", "triage-bot", "--refresh"))

        assert ok(agentgov("agents", "delete", "triage-bot")).strip() == "agent/triage-bot: deleted"
        assert "pending" in ok(agentgov("agents", "restore", "triage-bot"))
        ok(agentgov("agents", "delete", "triage-bot"))
        assert agentgov("agents", "purge", "triage-bot", input="n\n").exit_code == 1  # aborted
        ok(agentgov("agents", "purge", "triage-bot", "--yes"))
        assert client.get("/v1/agents/triage-bot", headers=ADMIN).status_code == 404

    def test_list_shows_the_inventory(self, client, agentgov) -> None:
        seed(client)
        out = ok(agentgov("agents", "list"))
        assert out.splitlines()[0].split()[:3] == ["NAME", "STATUS", "BLUEPRINT"]
        assert "support-bot  active" in out

    def test_bad_input_is_explained_before_any_request(self, agentgov) -> None:
        result = agentgov("agents", "create", "x", "--grant", "crm")
        assert result.exit_code == 2 and "server:tool,tool" in result.output
        result = agentgov("agents", "update", "x")
        assert result.exit_code == 2 and "nothing to change" in result.output

    def test_api_errors_are_reported(self, agentgov) -> None:
        result = agentgov("agents", "get", "missing")
        assert result.exit_code == 1 and "error 404" in result.output


class TestRegistry:
    def test_blueprints(self, client, agentgov) -> None:
        out = ok(
            agentgov(
                "blueprints", "create", "research",
                "--grant", "search:*", "--grant", "crm:get_*,list_*",
                "--risk-tier", "low", "--review-days", "30", "--no-sponsor",
            )
        )  # fmt: skip
        assert out.strip() == "blueprint/research: created"
        bp = client.get("/v1/blueprints/research", headers=ADMIN).json()
        assert bp["permissions"][1] == {"server": "crm", "tools": ["get_*", "list_*"]}
        assert (bp["attestation_days"], bp["require_sponsor"]) == (30, False)
        ok(agentgov("blueprints", "update", "research", "--no-review", "--require-sponsor"))
        bp = client.get("/v1/blueprints/research", headers=ADMIN).json()
        assert (bp["attestation_days"], bp["require_sponsor"]) == (None, True)
        assert "research" in ok(agentgov("blueprints", "list"))
        # Who its agents act for.
        ok(
            agentgov(
                "blueprints", "update", "research", "--acts-for", "people",
                "--people-groups", "support,/emea/sales", "--approvals-by", "person",
            )
        )  # fmt: skip
        bp = client.get("/v1/blueprints/research", headers=ADMIN).json()
        assert (bp["acts_for"], bp["people_groups"], bp["approvals_by"]) == (
            "people",
            ["support", "/emea/sales"],
            "person",
        )
        ok(agentgov("blueprints", "update", "research", "--all-people"))
        assert client.get("/v1/blueprints/research", headers=ADMIN).json()["people_groups"] == []
        bad = agentgov("blueprints", "update", "research", "--acts-for", "anyone")
        assert bad.exit_code == 1 and "acts_for must be one of" in bad.output
        ok(agentgov("blueprints", "delete", "research", "--yes"))
        assert client.get("/v1/blueprints/research", headers=ADMIN).status_code == 404

    def test_toolservers(self, client, agentgov) -> None:
        out = ok(
            agentgov(
                "toolservers", "create", "wiki", "--url", "http://wiki:9000/mcp",
                "--trust", "verified", "--classification", "public",
            )
        )  # fmt: skip
        assert out.startswith("toolserver/wiki: approved")
        ok(agentgov("toolservers", "update", "wiki", "--description", "Team wiki"))
        assert ok(agentgov("toolservers", "block", "wiki")).strip() == "toolserver/wiki: blocked"
        assert ok(agentgov("toolservers", "unblock", "wiki")).strip() == "toolserver/wiki: approved"
        assert "wiki" in ok(agentgov("toolservers", "list"))
        ok(agentgov("toolservers", "delete", "wiki", "--yes"))
        assert client.get("/v1/toolservers/wiki", headers=ADMIN).status_code == 404

    @requires_opa
    def test_policies(self, client, agentgov, tmp_path: Path) -> None:
        source = tmp_path / "no-deletes.rego"
        source.write_text(
            "package agentgov.custom.no_deletes\n\n"
            'deny contains "no deletes" if input.resource.name == "delete_customer"\n'
        )
        ok(agentgov("policies", "create", "no-deletes", "--file", str(source)))
        assert ok(agentgov("policies", "disable", "no-deletes")).strip() == (
            "policy/no-deletes: disabled"
        )
        ok(agentgov("policies", "enable", "no-deletes"))
        broken = tmp_path / "broken.rego"
        broken.write_text("package agentgov.custom.no_deletes\n\ndeny contains if {\n")
        result = agentgov("policies", "update", "no-deletes", "--file", str(broken))
        assert result.exit_code == 1 and "does not compile" in result.output
        assert "no_deletes" in ok(agentgov("policies", "get", "no-deletes", "--rego"))
        ok(agentgov("policies", "delete", "no-deletes", "--yes"))

    def test_findings(self, client, agentgov) -> None:
        ok(agentgov("agents", "create", "nobody-owns-me"))  # pending, without an owner
        client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        rows = ok(agentgov("findings")).splitlines()[1:]
        assert rows, "the posture scan should have raised a finding"
        finding_id = rows[0].split()[0]
        assert "resolved" in ok(agentgov("findings", "resolve", finding_id))
        assert finding_id in ok(agentgov("findings", "list", "--status", "resolved"))


class TestLedger:
    def test_tail_filters_and_export(self, client, agentgov) -> None:
        seed(client)
        tail = ok(agentgov("ledger", "tail", "--agent", "support-bot", "--type", "agent.*"))
        assert "agent.registered" in tail and "toolserver.registered" not in tail
        lines = ok(agentgov("ledger", "export")).splitlines()
        assert len(lines) == len(client.get("/v1/ledger", headers=ADMIN).json())
        assert all(line.startswith("{") for line in lines)
        assert '"valid": true' in ok(agentgov("ledger", "verify"))

    def test_what_agents_did_for_a_person(self, client, agentgov) -> None:
        agent = seed(client)
        record = {
            "phase": "request",
            "resource": "crm/get_customer",
            "agent": {"id": agent["id"]},
            "effect": "allow",
            "user": {"id": "u-1", "username": "alice", "via": "exchange"},
        }
        client.post("/v1/internal/decisions", json={"records": [record]}, headers=SERVICE)
        tail = ok(agentgov("ledger", "tail", "--user", "alice"))
        assert "decision.request" in tail and "alice" in tail
        assert "agent.registered" not in tail


class TestApprovals:
    def test_list_decide_and_mine(self, client, agentgov) -> None:
        agent = seed(client)
        check = {
            "agent_id": agent["id"],
            "action": "tools/call",
            "resource": "crm/delete_customer",
            "arguments": {"id": "c-1"},
            "reasons": ["destructive"],
            "user": {"id": "u-1", "username": "alice", "via": "exchange"},
        }
        held = client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).json()
        approval_id = held["approval"]["id"]
        out = ok(agentgov("approvals", "list"))
        assert approval_id in out and "alice" in out
        # The bootstrap administrator is nobody agents act for.
        assert approval_id not in ok(agentgov("approvals", "list", "--mine"))
        assert "approved" in ok(agentgov("approvals", "approve", approval_id, "--note", "ok"))
        assert approval_id in ok(agentgov("approvals", "list", "--status", "all"))


class TestApiKeys:
    def test_create_use_and_revoke(self, client, agentgov) -> None:
        result = agentgov("apikeys", "create", "ci", "--role", "auditor")
        token = ok(result).strip().splitlines()[-1]
        assert token.startswith("agk_")
        assert '"role": "auditor"' in ok(agentgov("whoami", token=token))
        listing = ok(agentgov("apikeys", "list", token=token))  # auditors can review keys
        key_id = next(line.split()[0] for line in listing.splitlines() if " ci " in line)
        ok(agentgov("apikeys", "revoke", key_id, "--yes"))
        assert agentgov("whoami", token=token).exit_code == 1


def test_the_server_keeps_idle_connections_longer_than_load_balancers(monkeypatch) -> None:
    import uvicorn

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.append(kwargs))
    monkeypatch.delenv("AGENTGOV_HTTP_KEEPALIVE_SECONDS", raising=False)
    ok(runner.invoke(cli.app, ["server"]))
    monkeypatch.setenv("AGENTGOV_HTTP_KEEPALIVE_SECONDS", "3700")
    ok(runner.invoke(cli.app, ["server"]))
    # Google Cloud's load balancers keep connections to backends for 600 seconds.
    assert [c["timeout_keep_alive"] for c in calls] == [620, 3700]

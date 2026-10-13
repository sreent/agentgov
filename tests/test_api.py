"""The control plane HTTP API: authentication, roles and endpoint behaviour."""

from __future__ import annotations

import gzip
import json

import pytest
from fastapi.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.opa import WHAT_IF
from agentgov.registry import findings
from tests.conftest import ADMIN, SERVICE, seed


def key(client, role: str, name: str | None = None) -> dict[str, str]:
    resp = client.post(
        "/v1/apikeys", json={"name": name or f"{role}-key", "role": role}, headers=ADMIN
    )
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestAuth:
    def test_requires_a_token(self, client) -> None:
        resp = client.get("/v1/agents")
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == "Bearer"

    def test_rejects_unknown_tokens(self, client) -> None:
        assert client.get("/v1/agents", headers={"Authorization": "Bearer nope"}).status_code == 401

    def test_service_token_cannot_read_the_registry(self, client) -> None:
        assert client.get("/v1/agents", headers=SERVICE).status_code == 403

    def test_admin_cannot_be_impersonated_by_internal_endpoints(self, client) -> None:
        assert (
            client.post(
                "/v1/internal/decisions", json={"records": []}, headers=key(client, "auditor")
            ).status_code
            == 403
        )

    def test_revoked_keys_stop_working(self, client) -> None:
        resp = client.post(
            "/v1/apikeys", json={"name": "temp", "role": "auditor"}, headers=ADMIN
        ).json()
        headers = {"Authorization": f"Bearer {resp['token']}"}
        assert client.get("/v1/agents", headers=headers).status_code == 200
        client.delete(f"/v1/apikeys/{resp['id']}", headers=ADMIN).raise_for_status()
        assert client.get("/v1/agents", headers=headers).status_code == 401

    def test_health_is_public(self, client) -> None:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json()["status"] == "ready"

    def test_whoami(self, client) -> None:
        me = client.get("/v1/me", headers=ADMIN).json()
        assert me == {
            "name": "bootstrap",
            "role": "admin",
            "roles": ["admin"],
            "actor": "admin:bootstrap",
            "via": "token",
            "microsoft": False,
            # What is sent to people themselves (docs/issues.md, docs/acting-for-people.md).
            "inbox": {"issues": True, "approvals": False},
        }
        ci = client.get("/v1/me", headers=key(client, "registrar", "ci")).json()
        assert (ci["actor"], ci["via"]) == ("registrar:ci", "api_key")
        assert client.get("/v1/me").status_code == 401

    def test_validation_errors_use_the_common_error_shape(self, client) -> None:
        resp = client.get("/v1/ledger", params={"limit": "many"}, headers=ADMIN)
        assert resp.status_code == 422
        assert resp.json()["detail"].startswith("query.limit: ")
        assert resp.json()["errors"][0]["loc"] == ["query", "limit"]

    def test_ui_is_served_with_a_restrictive_csp(self, client) -> None:
        resp = client.get("/", follow_redirects=True)
        assert resp.status_code == 200
        assert resp.url.path == "/ui/"
        csp = resp.headers["content-security-policy"]
        assert "script-src 'self';" in csp
        assert "frame-ancestors 'none'" in csp
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert "content-security-policy" not in client.get("/healthz").headers


class TestRoles:
    def test_registrar_requests_are_pending(self, client) -> None:
        seed(client)
        registrar = key(client, "registrar")
        resp = client.post(
            "/v1/agents", json={"name": "new-bot", "approve": True}, headers=registrar
        )
        assert resp.status_code == 201
        assert resp.json()["status"] == "pending"
        ts = client.post(
            "/v1/toolservers", json={"name": "byo", "url": "http://byo/mcp"}, headers=registrar
        )
        assert ts.json()["status"] == "pending"

    def test_registrar_requests_activate_when_approval_is_not_required(self, settings) -> None:
        from fastapi.testclient import TestClient

        from agentgov.api.app import create_app

        open_settings = settings.with_overrides(features="registration-approval=off")
        with TestClient(create_app(open_settings, background=False)) as c:
            registrar = key(c, "registrar")
            resp = c.post("/v1/agents", json={"name": "auto", "sponsors": ["a"]}, headers=registrar)
            assert resp.json()["status"] == "active"

    def test_approver_decides_but_cannot_block(self, client) -> None:
        seed(client)
        approver = key(client, "approver", "bob@example.com")
        assert (
            client.post("/v1/agents/support-bot/block", json={}, headers=approver).status_code
            == 403
        )

    def test_only_sponsors_or_admins_attest(self, client) -> None:
        seed(client, sponsors=["alice@example.com"])
        assert (
            client.post(
                "/v1/agents/support-bot/attest", json={}, headers=key(client, "approver", "mallory")
            ).status_code
            == 403
        )
        resp = client.post(
            "/v1/agents/support-bot/attest",
            json={"note": "still needed"},
            headers=key(client, "approver", "alice@example.com"),
        )
        assert resp.status_code == 200
        assert resp.json()["attestation"]["attested_by"] == "approver:alice@example.com"

    def test_auditor_reads_ledger(self, client) -> None:
        seed(client)
        auditor = key(client, "auditor")
        assert client.get("/v1/ledger/verify", headers=auditor).json()["valid"] is True
        assert (
            client.post("/v1/agents/support-bot/delete", json={}, headers=auditor).status_code
            == 403
        )


class TestAgents:
    def test_lifecycle_endpoints(self, client) -> None:
        seed(client)
        for action, status in [
            ("block", "blocked"),
            ("unblock", "active"),
            ("delete", "deleted"),
            ("restore", "pending"),
            ("approve", "active"),
        ]:
            resp = client.post(
                f"/v1/agents/support-bot/{action}", json={"reason": "test"}, headers=ADMIN
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["status"] == status

    def test_errors_are_json(self, client) -> None:
        seed(client)
        resp = client.post("/v1/agents/support-bot/approve", json={}, headers=ADMIN)
        assert resp.status_code == 409
        assert "cannot approve" in resp.json()["detail"]
        assert client.get("/v1/agents/nope", headers=ADMIN).status_code == 404
        assert (
            client.post("/v1/agents", json={"name": "Bad Name"}, headers=ADMIN).status_code == 422
        )

    def test_activation_needs_a_sponsor(self, client) -> None:
        resp = client.post("/v1/agents", json={"name": "lonely", "approve": True}, headers=ADMIN)
        assert resp.status_code == 409
        assert "sponsor" in resp.json()["detail"]
        # Registration and approval are one transaction: nothing half-created remains.
        assert client.get("/v1/agents/lonely", headers=ADMIN).status_code == 404

    def test_purge(self, client) -> None:
        seed(client)
        assert client.delete("/v1/agents/support-bot", headers=ADMIN).status_code == 409
        client.post("/v1/agents/support-bot/delete", json={}, headers=ADMIN)
        assert client.delete("/v1/agents/support-bot", headers=ADMIN).status_code == 200
        assert client.get("/v1/agents/support-bot", headers=ADMIN).status_code == 404

    def test_credentials_need_identity_integration(self, client) -> None:
        seed(client)
        assert (
            client.post("/v1/agents/support-bot/credentials", json={}, headers=ADMIN).status_code
            == 409
        )

    def test_filters(self, client) -> None:
        seed(client)
        client.post("/v1/agents", json={"name": "other"}, headers=ADMIN)

        def names(**params: str) -> list[str]:
            agents = client.get("/v1/agents", params=params, headers=ADMIN).json()
            return [a["name"] for a in agents]

        assert names(status="pending") == ["other"]
        assert names(q="supp") == ["support-bot"]
        assert names(blueprint="support") == ["support-bot"]


class TestGovernance:
    def test_approval_flow_over_http(self, client) -> None:
        agent = seed(client)
        check = {
            "agent_id": agent["id"],
            "action": "tools/call",
            "resource": "crm/delete_customer",
            "arguments": {"id": "c-1"},
            "reasons": ["destructive"],
        }
        first = client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).json()
        assert first["outcome"] == "created"
        pending = client.get("/v1/approvals", params={"status": "pending"}, headers=ADMIN).json()
        assert [a["id"] for a in pending] == [first["approval"]["id"]]
        approver = key(client, "approver", "bob")
        decided = client.post(
            f"/v1/approvals/{first['approval']['id']}/approve",
            json={"note": "ok"},
            headers=approver,
        ).json()
        assert decided["status"] == "approved"
        second = client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).json()
        assert second["outcome"] == "approved"

    def test_an_approval_is_for_the_person_the_agent_acted_for(self, client) -> None:
        agent = seed(client)
        check = {
            "agent_id": agent["id"],
            "action": "tools/call",
            "resource": "crm/delete_customer",
            "arguments": {"id": "c-1"},
            "reasons": ["destructive"],
        }

        def held(**extra):  # type: ignore[no-untyped-def]
            body = {**check, **extra}
            return client.post("/v1/internal/approvals/check", json=body, headers=SERVICE).json()

        alice = {"id": "u-1", "username": "alice", "via": "exchange"}
        for_alice = held(user=alice)
        assert for_alice["approval"]["on_behalf_of"] == "alice"
        assert for_alice["approval"]["deciders"] == "approvers"  # the default
        client.post(
            f"/v1/approvals/{for_alice['approval']['id']}/approve", json={}, headers=ADMIN
        ).raise_for_status()
        # The same call for bob, or for no one, needs an approval of its own.
        assert held(user={"id": "u-2", "username": "bob"})["outcome"] == "created"
        assert held()["outcome"] == "created"
        assert held(user=alice)["outcome"] == "approved"

    def test_decision_records_feed_ledger_risk_and_findings(self, client) -> None:
        agent = seed(client)
        record = {
            "phase": "request",
            "method": "tools/call",
            "resource": "crm/add_note",
            "agent": {"id": agent["id"]},
            "effect": "deny",
            "reasons": ["credentials"],
            "detections": {"categories": ["secret"], "entities": ["AWS_ACCESS_KEY_ID"]},
        }
        resp = client.post("/v1/internal/decisions", json={"records": [record]}, headers=SERVICE)
        assert resp.json() == {"stored": 1}
        entries = client.get(
            "/v1/ledger", params={"agent": "support-bot", "type": "decision.*"}, headers=ADMIN
        ).json()
        assert entries[0]["decision"] == "deny"
        found = client.get("/v1/findings", headers=ADMIN).json()
        assert any(f["type"] == "agent.credential_exfiltration_attempt" for f in found)
        risk = client.get("/v1/agents/support-bot/risk", headers=ADMIN).json()
        assert risk["score"] > 10

    def test_decisions_record_who_the_agent_acted_for(self, client) -> None:
        agent = seed(client)
        alice = {"id": "u-1", "username": "alice", "groups": ["/support"], "via": "exchange"}
        records = [
            {"phase": "request", "resource": "crm/get_customer", "agent": {"id": agent["id"]},
             "effect": "allow", "user": alice},
            {"phase": "request", "resource": "crm/get_customer", "agent": {"id": agent["id"]},
             "effect": "allow"},
        ]  # fmt: skip
        client.post("/v1/internal/decisions", json={"records": records}, headers=SERVICE)
        entries = client.get("/v1/ledger", params={"type": "decision.*"}, headers=ADMIN).json()
        assert "on_behalf_of" not in entries[0]
        assert entries[1]["on_behalf_of"] == "alice"
        assert entries[1]["details"]["user"] == alice
        for_alice = client.get("/v1/ledger", params={"user": "alice"}, headers=ADMIN).json()
        assert [e["seq"] for e in for_alice] == [entries[1]["seq"]]
        assert client.get("/v1/ledger/verify", headers=ADMIN).json()["valid"] is True

    def test_blueprints_say_who_their_agents_act_for(self, client) -> None:
        seed(client)
        assert client.get("/v1/agents/support-bot", headers=ADMIN).json()["acts_for"] == "either"
        changed = client.patch(
            "/v1/blueprints/support",
            json={"acts_for": "people", "people_groups": ["support", "/emea/sales"],
                  "approvals_by": "person"},
            headers=ADMIN,
        )  # fmt: skip
        assert changed.status_code == 200, changed.text
        agent = client.get("/v1/agents/support-bot", headers=ADMIN).json()
        assert (agent["acts_for"], agent["people_groups"], agent["approvals_by"]) == (
            "people",
            ["support", "/emea/sales"],
            "person",
        )
        for body in ({"acts_for": "anyone"}, {"people_groups": ["/"]},
                     {"people_groups": "support"}, {"approvals_by": "the-person"}):  # fmt: skip
            assert (
                client.patch("/v1/blueprints/support", json=body, headers=ADMIN).status_code == 422
            )

    def test_gateway_decisions_link_to_their_trace(self, settings, tmp_path) -> None:
        settings = settings.with_overrides(trace_url="https://traces.example/t/{trace_id}")
        with TestClient(create_app(settings, background=False)) as client:
            agent = seed(client)
            trace = "4bf92f3577b34da6a3ce929d0e0e4736"
            records = [
                {"phase": "request", "resource": "crm/get_customer", "agent": {"id": agent["id"]},
                 "effect": "allow", "trace_id": trace},
                {"phase": "request", "resource": "crm/get_customer", "agent": {"id": agent["id"]},
                 "effect": "allow", "trace_id": "not-a-trace-id"},
            ]  # fmt: skip
            client.post("/v1/internal/decisions", json={"records": records}, headers=SERVICE)
            entries = client.get("/v1/ledger", params={"type": "decision.*"}, headers=ADMIN).json()
        assert entries[0]["trace_id"] is None and "trace_url" not in entries[0]
        assert entries[1]["trace_id"] == trace
        assert entries[1]["trace_url"] == f"https://traces.example/t/{trace}"

    def test_trace_url_needs_a_placeholder(self) -> None:
        with pytest.raises(ValueError, match="trace_id"):
            Settings(trace_url="https://traces.example/").validate()

    def test_risk_reads_are_read_only_and_refresh_is_for_admins(self, client) -> None:
        seed(client)
        auditor = key(client, "auditor")
        risk = client.get("/v1/agents/support-bot/risk", headers=auditor)
        assert risk.status_code == 200
        assert set(risk.json()) == {"score", "level", "factors"}
        refresh = "/v1/agents/support-bot/risk/refresh"
        assert client.post(refresh, headers=auditor).status_code == 403
        assert client.post(refresh, headers=ADMIN).json()["level"] == risk.json()["level"]

    def test_blocking_an_agent_cancels_its_open_approvals(self, client) -> None:
        agent = seed(client)
        check = {
            "agent_id": agent["id"],
            "action": "tools/call",
            "resource": "crm/delete_customer",
            "arguments": {"id": "c-1"},
            "reasons": ["destructive"],
        }
        created = client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).json()
        approval_id = created["approval"]["id"]
        client.post(
            "/v1/agents/support-bot/block", json={"reason": "incident"}, headers=ADMIN
        ).raise_for_status()
        assert client.get(f"/v1/approvals/{approval_id}", headers=ADMIN).json()["status"] == (
            "cancelled"
        )
        resp = client.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=ADMIN)
        assert resp.status_code == 409
        cancelled = client.get("/v1/ledger", params={"type": "approval.cancelled"}, headers=ADMIN)
        assert cancelled.json()[0]["details"]["approval_id"] == approval_id

    def test_finding_status_changes_are_recorded_in_the_ledger(self, client) -> None:
        seed(client)
        client.post("/v1/agents", json={"name": "ownerless"}, headers=ADMIN).raise_for_status()
        client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        finding = client.get("/v1/findings", headers=ADMIN).json()[0]
        for action in ("resolve", "resolve", "reopen"):
            client.post(f"/v1/findings/{finding['id']}/{action}", headers=ADMIN).raise_for_status()
        entries = [
            e
            for e in client.get("/v1/ledger", params={"type": "finding.*"}, headers=ADMIN).json()
            if e["details"]["finding_id"] == finding["id"]
        ]
        # Raised by the scan, resolved once (the second resolve changes nothing), reopened.
        assert [e["type"] for e in entries] == [
            "finding.reopened",
            "finding.resolved",
            "finding.raised",
        ]
        assert entries[0]["actor"] == "admin:bootstrap"
        assert entries[-1]["actor"] == "system:agentgov"
        assert entries[-1]["details"]["category"] == "posture"

    def test_overview_lists_each_held_call_once(self, client) -> None:
        agent = seed(client)
        check = {
            "agent_id": agent["id"],
            "action": "tools/call",
            "resource": "crm/delete_customer",
            "arguments": {"id": "c-1"},
            "reasons": ["destructive"],
        }
        client.post("/v1/internal/approvals/check", json=check, headers=SERVICE).raise_for_status()
        record = {
            "phase": "request",
            "method": "tools/call",
            "resource": "crm/delete_customer",
            "agent": {"id": agent["id"]},
            "effect": "require_approval",
            "reasons": ["destructive"],
        }
        client.post(
            "/v1/internal/decisions", json={"records": [record]}, headers=SERVICE
        ).raise_for_status()
        overview = client.get("/v1/overview", headers=ADMIN).json()
        assert [e["type"] for e in overview["recent_blocks"]] == ["decision.request"]
        assert overview["ledger"]["valid"] is True

    def test_findings_actions(self, client) -> None:
        seed(client)
        client.post("/v1/agents", json={"name": "ownerless"}, headers=ADMIN).raise_for_status()
        client.post("/v1/posture/scan", headers=ADMIN).raise_for_status()
        finding = client.get("/v1/findings", headers=ADMIN).json()[0]
        approver = key(client, "approver")
        # Dismissing says why it is wrong.
        bare = client.post(f"/v1/findings/{finding['id']}/dismiss", headers=approver)
        assert bare.status_code == 422 and "say why it is wrong" in bare.json()["detail"]
        dismissed = client.post(
            f"/v1/findings/{finding['id']}/dismiss",
            json={"reason": "A test agent", "until": 30},
            headers=approver,
        ).json()
        assert dismissed["status"] == "dismissed"
        assert dismissed["details"]["dismissal"]["reason"] == "A test agent"
        assert dismissed["details"]["dismissal"]["until"]
        assert (
            client.post(f"/v1/findings/{finding['id']}/reopen", headers=approver).json()["status"]
            == "open"
        )

    def test_findings_come_a_page_at_a_time_with_their_total(self, client) -> None:
        seed(client)
        rt = client.app.state.rt
        with rt.db.session() as s:
            for n in range(3):
                findings.raise_finding(
                    s, type="destination.failing", severity="high", subject=f"d{n}", title=f"d{n}"
                )
            findings.raise_finding(
                s, type="opa.bundle_error", severity="low", subject="o", title="o"
            )
        first = client.get("/v1/findings", params={"limit": 2}, headers=ADMIN)
        assert (len(first.json()), first.headers["x-total-count"]) == (2, "4")
        rest = client.get("/v1/findings", params={"limit": 2, "offset": 2}, headers=ADMIN).json()
        assert {f["id"] for f in first.json()}.isdisjoint(f["id"] for f in rest)
        assert len(rest) == 2
        failing = client.get("/v1/findings", params={"type": "destination.failing"}, headers=ADMIN)
        assert (len(failing.json()), failing.headers["x-total-count"]) == (3, "3")
        assert client.get("/v1/findings", params={"limit": 0}, headers=ADMIN).status_code == 422
        assert client.get("/v1/findings", params={"offset": -1}, headers=ADMIN).status_code == 422

    def test_the_overview_counts_imported_agents_without_owners(self, client) -> None:
        """Agents found on platforms arrive without an owner: the overview says so, and
        says they were found there rather than seen in traffic."""
        seed(client)  # support-bot, which has an owner
        imported = [
            {"name": f"bot-{n}", "type": "microsoft.copilotstudio/agents", "properties": {}}
            for n in (1, 2)
        ]
        client.post(
            "/v1/platforms/copilot-studio/import", json=imported, headers=ADMIN
        ).raise_for_status()
        agents = client.get("/v1/overview", headers=ADMIN).json()["agents"]
        assert (agents["without_owner"], agents["unmanaged"], agents["on_platforms"]) == (2, 2, 2)

    def test_overview_and_graph(self, client) -> None:
        agent = seed(client)
        client.post(
            "/v1/internal/decisions",
            json={
                "records": [
                    {
                        "phase": "request",
                        "method": "tools/call",
                        "resource": "crm/get_customer",
                        "agent": {"id": agent["id"]},
                        "effect": "allow",
                    }
                ]
            },
            headers=SERVICE,
        )
        overview = client.get("/v1/overview", headers=ADMIN).json()
        assert overview["agents"]["total"] == 1
        assert overview["activity"][-1]["tool_calls"] == 1
        assert len(overview["activity"]) == 14
        assert overview["ledger"]["valid"] is True
        graph = client.get("/v1/graph", headers=ADMIN).json()
        kinds = {
            (e["from"].split(":")[0], e["kind"], e["to"].split(":")[0]) for e in graph["edges"]
        }
        assert ("person", "sponsor", "agent") in kinds
        assert ("agent", "granted", "server") in kinds
        edge = next(e for e in graph["edges"] if e["kind"] == "granted")
        assert edge["calls"] == 1

    def test_ledger_export_is_jsonl(self, client) -> None:
        seed(client)
        lines = client.get("/v1/ledger/export", headers=ADMIN).text.strip().splitlines()
        entries = [json.loads(line) for line in lines]
        assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))


class TestIntegrations:
    def test_bundle_etag_and_304(self, client) -> None:
        seed(client)
        first = client.get("/v1/opa/bundles/agentgov.tar.gz", headers=SERVICE)
        assert first.headers["content-type"] == "application/vnd.openpolicyagent.bundles"
        again = client.get(
            "/v1/opa/bundles/agentgov.tar.gz",
            headers={**SERVICE, "If-None-Match": first.headers["etag"]},
        )
        assert again.status_code == 304

    def test_bundle_long_poll_returns_on_timeout(self, client) -> None:
        seed(client)
        etag = client.get("/v1/opa/bundles/agentgov.tar.gz", headers=SERVICE).headers["etag"]
        resp = client.get(
            "/v1/opa/bundles/agentgov.tar.gz",
            headers={**SERVICE, "If-None-Match": etag, "Prefer": "modes=snapshot,delta;wait=2"},
        )
        assert resp.status_code == 304

    def test_bundle_requires_service_role(self, client) -> None:
        assert (
            client.get(
                "/v1/opa/bundles/agentgov.tar.gz", headers=key(client, "auditor")
            ).status_code
            == 403
        )

    def test_opa_decision_logs_gzip(self, client) -> None:
        seed(client)
        events = [
            {
                "decision_id": "d1",
                "path": "agentos/allow",
                "result": False,
                "input": {
                    "agent_id": "support-bot",
                    "action_type": "tool_call",
                    "tool_name": "shell",
                },
                "timestamp": "2026-10-09T10:00:00Z",
            }
        ]
        resp = client.post(
            "/v1/opa/logs",
            content=gzip.compress(json.dumps(events).encode()),
            headers={**SERVICE, "Content-Encoding": "gzip", "Content-Type": "application/json"},
        )
        assert resp.json() == {"stored": 1, "skipped": 0}
        entry = client.get(
            "/v1/ledger", params={"type": "decision.inprocess"}, headers=ADMIN
        ).json()[0]
        assert (entry["agent_name"], entry["decision"], entry["resource"]) == (
            "support-bot",
            "deny",
            "shell",
        )

    def test_decision_records_a_processor_lost_are_in_the_ledger(self, client) -> None:
        resp = client.post(
            "/v1/internal/decisions", json={"records": [], "dropped": 7}, headers=SERVICE
        )
        assert resp.status_code == 200, resp.text
        [entry] = client.get(
            "/v1/ledger", params={"type": "decisions.dropped"}, headers=ADMIN
        ).json()
        assert (entry["severity"], entry["details"]["count"]) == ("warning", 7)
        odd = client.post(
            "/v1/internal/decisions", json={"records": [], "dropped": "x"}, headers=SERVICE
        )
        assert odd.status_code == 422

    def test_opa_decision_logs_keep_only_agents_own_decisions(self, client) -> None:
        """OPA can still send the decisions the processor and the control plane asked for
        (a bundle from before it dropped them), and what-if questions: none is an agent's
        own decision, and an AuthZEN permit is no denial."""
        seed(client)
        tool_call = {"agent_id": "support-bot", "action_type": "tool_call", "tool_name": "shell"}
        events = [
            {"path": "agentgov/authzen/evaluation", "result": {"decision": True}, "input": {}},
            {"path": "agentgov/copilotstudio/decision", "result": {"allow": False}},
            {"path": "registry/features", "result": {"data-protection": "enforce"}},
            {"path": "agentos/allow", "result": False, "input": {**tool_call, WHAT_IF: True}},
            {"decision_id": "d2", "path": "agentos/allow", "result": True, "input": tool_call},
        ]
        resp = client.post("/v1/opa/logs", json=events, headers=SERVICE)
        assert resp.json() == {"stored": 1, "skipped": 4}
        entries = client.get(
            "/v1/ledger", params={"type": "decision.inprocess"}, headers=ADMIN
        ).json()
        assert [e["decision"] for e in entries] == ["allow"]

    def test_opa_status_errors_raise_a_finding(self, client) -> None:
        status = {
            "labels": {"id": "opa-1"},
            "bundles": {"agentgov": {"code": "bundle_error", "message": "compile failed"}},
        }
        client.post("/v1/opa/status", json=status, headers=SERVICE).raise_for_status()
        found = client.get("/v1/findings", headers=ADMIN).json()
        assert any(f["type"] == "opa.bundle_error" for f in found)
        client.post(
            "/v1/opa/status", json={"bundles": {"agentgov": {}}}, headers=SERVICE
        ).raise_for_status()
        assert not any(
            f["type"] == "opa.bundle_error"
            for f in client.get("/v1/findings", headers=ADMIN).json()
        )

    def test_catalog_and_observe(self, client) -> None:
        seed(client)
        resp = client.post(
            "/v1/internal/catalog",
            json={"server": "crm", "tools": [{"name": "get_customer"}]},
            headers=SERVICE,
        )
        assert resp.json()["added"] == ["get_customer"]
        observed = client.post(
            "/v1/internal/observe",
            json={"source": "gateway", "client_id": "rogue-client"},
            headers=SERVICE,
        ).json()
        assert (
            client.get(f"/v1/agents/{observed['agent']}", headers=ADMIN).json()["status"]
            == "discovered"
        )

    def test_otlp_json(self, client) -> None:
        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [{"key": "service.name", "value": {"stringValue": "shadow"}}]
                    },
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "chat x",
                                    "attributes": [
                                        {
                                            "key": "gen_ai.operation.name",
                                            "value": {"stringValue": "chat"},
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        resp = client.post("/v1/otlp/v1/traces", json=payload, headers=SERVICE)
        assert resp.status_code == 200
        assert client.get("/v1/agents/shadow", headers=ADMIN).json()["status"] == "discovered"

    def test_discovery_import(self, client) -> None:
        resp = client.post(
            "/v1/discovery/import",
            json={"source": "agt", "items": [{"name": "found-bot"}]},
            headers=key(client, "registrar"),
        )
        assert resp.json() == {"created": 1, "matched": 0}


class TestManifestsOverHttp:
    MANIFEST = """
apiVersion: agentgov/v1alpha1
kind: Agent
metadata: {name: bot}
spec: {blueprint: bp, sponsors: [a], owner: team}
---
apiVersion: agentgov/v1alpha1
kind: Blueprint
metadata: {name: bp}
spec:
  permissions: [{server: crm, tools: ["*"]}]
"""

    def test_apply_is_idempotent_and_ordered(self, client) -> None:
        headers = {**ADMIN, "Content-Type": "application/yaml"}
        first = client.post("/v1/apply", content=self.MANIFEST, headers=headers).json()["results"]
        assert first == [
            {"kind": "Blueprint", "name": "bp", "action": "created"},
            {"kind": "Agent", "name": "bot", "action": "created"},
        ]
        second = client.post("/v1/apply", content=self.MANIFEST, headers=headers).json()["results"]
        assert {r["action"] for r in second} == {"unchanged"}
        assert client.get("/v1/agents/bot", headers=ADMIN).json()["status"] == "active"

    def test_export_round_trips(self, client) -> None:
        client.post(
            "/v1/apply",
            content=self.MANIFEST,
            headers={**ADMIN, "Content-Type": "application/yaml"},
        )
        exported = client.get("/v1/export", headers=ADMIN).text
        again = client.post(
            "/v1/apply", content=exported, headers={**ADMIN, "Content-Type": "application/yaml"}
        ).json()["results"]
        assert {r["action"] for r in again} == {"unchanged"}

    def test_public_clients_and_servers_outside_the_gateway_round_trip(self, client) -> None:
        manifest = (
            self.MANIFEST
            + """---
apiVersion: agentgov/v1alpha1
kind: ToolServer
metadata: {name: wiki}
spec:
  url: https://wiki.example.com/mcp
  gateway: false
  authorization_server: https://id.wiki.example.com/realms/wiki
  oauth_client_id: agentgov-agents
---
apiVersion: agentgov/v1alpha1
kind: Agent
metadata: {name: vscode}
spec: {blueprint: bp, sponsors: [a], client_type: public, redirect_uris: ["http://127.0.0.1/*"]}
"""
        )
        headers = {**ADMIN, "Content-Type": "application/yaml"}
        client.post("/v1/apply", content=manifest, headers=headers).raise_for_status()
        exported = client.get("/v1/export", headers=ADMIN).text
        assert "authorization_server: https://id.wiki.example.com/realms/wiki" in exported
        assert "client_type: public" in exported
        # Defaults stay out: the other agent's client type, and servers' missing fields.
        assert exported.count("client_type:") == 1
        assert exported.count("authorization_server:") == 1
        again = client.post("/v1/apply", content=exported, headers=headers).json()["results"]
        assert {r["action"] for r in again} == {"unchanged"}

    @pytest.mark.parametrize(
        "doc",
        [
            "apiVersion: v1\nkind: Agent\nmetadata: {name: x}\n",
            "apiVersion: agentgov/v1alpha1\nkind: Robot\nmetadata: {name: x}\n",
            "apiVersion: agentgov/v1alpha1\nkind: Agent\nmetadata: {}\n",
            "{{not yaml",
        ],
    )
    def test_invalid_manifests(self, client, doc) -> None:
        resp = client.post(
            "/v1/apply", content=doc, headers={**ADMIN, "Content-Type": "application/yaml"}
        )
        assert resp.status_code == 422

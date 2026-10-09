"""The control plane HTTP API: authentication, roles and endpoint behaviour."""

from __future__ import annotations

import gzip
import json

import pytest

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
        assert me == {"name": "bootstrap", "role": "admin", "actor": "admin:bootstrap"}
        assert client.get("/v1/me", headers=key(client, "registrar", "ci")).json()["actor"] == (
            "registrar:ci"
        )
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

        open_settings = settings.with_overrides(registration_requires_approval=False)
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
        entries = client.get("/v1/ledger", params={"type": "finding.*"}, headers=ADMIN).json()
        assert [e["type"] for e in entries] == ["finding.reopened", "finding.resolved"]
        assert entries[0]["actor"] == "admin:bootstrap"
        assert entries[0]["details"]["finding_id"] == finding["id"]

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
        assert (
            client.post(f"/v1/findings/{finding['id']}/dismiss", headers=approver).json()["status"]
            == "dismissed"
        )
        assert (
            client.post(f"/v1/findings/{finding['id']}/reopen", headers=approver).json()["status"]
            == "open"
        )

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
        assert resp.json() == {"stored": 1}
        entry = client.get(
            "/v1/ledger", params={"type": "decision.inprocess"}, headers=ADMIN
        ).json()[0]
        assert (entry["agent_name"], entry["decision"], entry["resource"]) == (
            "support-bot",
            "deny",
            "shell",
        )

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

"""Calls around the gateway (agentgov.registry.reachability): what agents' owners say stops
them, the test that calls an agent's A2A URL itself, and calls seen in telemetry."""

from __future__ import annotations

import http.server
import json
import ssl
import threading
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from agentgov import cli, telemetry
from agentgov.models import Finding, LedgerEntry
from agentgov.registry import agents, features, posture, reachability
from agentgov.secops import ocsf
from tests.conftest import ADMIN
from tests.test_cli import _Shared, ok, runner


def _agent(s, settings, name: str = "billing", **data: Any):
    return agents.register(
        s,
        settings,
        {
            "name": name,
            "owner": "finance",
            "sponsors": ["bob@example.com"],
            "a2a_url": f"http://{name}:9600",
            **data,
        },
        actor="test",
        approve=True,
    )


def _mode(rt, mode: str) -> None:
    with rt.db.session() as s:
        features.set_mode(s, rt.settings, reachability.FEATURE, mode, actor="admin:t")


def _open(rt) -> dict[str, Finding]:
    with rt.db.session() as s:
        found = s.scalars(select(Finding).where(Finding.status == "open")).all()
        return {f.type: f for f in found if f.type.startswith("agent.a2a_")}


def _answer(status: int, body: Any = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-agentgov-check"] == "calls-around-gateway"
        assert "x-agentgov-delegation" not in request.headers
        assert json.loads(request.content)["method"] == "GetTask"
        return httpx.Response(status, json=body) if body is not None else httpx.Response(status)

    return httpx.MockTransport(handler)


def _test(url: str, transport: httpx.BaseTransport) -> dict[str, Any]:
    with httpx.Client(transport=transport) as client:
        return reachability.call(url, client)


# ------------------------------------------------------------------------ the test


class TestTheTest:
    def test_an_agent_that_refuses_calls_without_a_delegation(self) -> None:
        body = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Refused"}}
        got = _test("http://billing:9600", _answer(401, body))
        assert (got["state"], got["status"]) == ("refused", 401)
        assert got["detail"] == "it refused a call without credentials (HTTP 401): Refused"
        assert got["url"] == "http://billing:9600" and got["checked_at"]

    def test_an_agent_that_takes_the_call(self) -> None:
        body = {"jsonrpc": "2.0", "id": "x", "error": {"code": -32001, "message": "No task"}}
        got = _test("http://billing:9600", _answer(200, body))
        assert got["state"] == "accepted"
        assert got["detail"] == (
            "it took a call that didn't come through the gateway (HTTP 200, answering 'No task')"
        )

    @pytest.mark.parametrize(
        ("status", "detail"),
        [
            (404, "it doesn't take A2A JSON-RPC calls there (HTTP 404)"),
            (500, "it answered HTTP 500"),
            (302, "it answered HTTP 302"),
        ],
    )
    def test_other_answers_are_inconclusive(self, status: int, detail: str) -> None:
        got = _test("http://billing:9600", _answer(status))
        assert (got["state"], got["detail"]) == ("inconclusive", detail)

    def test_an_agent_that_cant_be_reached(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        def hang(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        def bad_certificate(request: httpx.Request) -> httpx.Response:
            try:
                raise ssl.SSLCertVerificationError("certificate verify failed")
            except ssl.SSLError as exc:
                raise httpx.ConnectError("certificate verify failed", request=request) from exc

        assert _test("http://billing:9600", httpx.MockTransport(refuse))["state"] == "unreachable"
        hung = _test("http://billing:9600", httpx.MockTransport(hang))
        assert hung["detail"] == "it didn't answer within 5 seconds"
        tls = _test("https://billing:9600", httpx.MockTransport(bad_certificate))
        assert tls["state"] == "inconclusive" and "certificate" in tls["detail"]

    def test_link_local_addresses_arent_called(self) -> None:
        def never(request: httpx.Request) -> httpx.Response:
            raise AssertionError("called")

        got = _test("http://169.254.169.254/latest", httpx.MockTransport(never))
        assert (got["state"], got["detail"]) == (
            "inconclusive",
            "a link-local address isn't tested",
        )

    def test_several_agents_are_tested_at_once(self) -> None:
        got = reachability.call_all(
            {"agt_1": "http://a:1", "agt_2": "http://b:2"}, transport=_answer(401)
        )
        assert {k: v["state"] for k, v in got.items()} == {"agt_1": "refused", "agt_2": "refused"}
        assert reachability.call_all({}) == {}


# --------------------------------------------------------------- the posture scan


class TestPosture:
    def test_only_the_test_mode_tests_and_only_published_agents(self, rt, settings) -> None:
        with rt.db.session() as s:
            billing = _agent(s, settings).id
            _agent(s, settings, "kb", a2a_url=None)
            pending = agents.register(
                s, settings, {"name": "draft", "a2a_url": "http://draft:1"}, actor="test"
            )
            assert pending.status == "pending"
        with rt.db.session() as s:
            assert reachability.targets(s) is None  # watch, the default
        _mode(rt, "test")
        with rt.db.session() as s:
            assert reachability.targets(s) == {billing: "http://billing:9600"}
            features.set_mode(s, settings, "a2a-gateway", "off", actor="admin:t")
        with rt.db.session() as s:
            assert reachability.targets(s) is None

    def test_owners_that_havent_said_what_stops_calls_are_asked(self, rt, settings) -> None:
        with rt.db.session() as s:
            _agent(s, settings)
            posture.scan(s, settings)
        found = _open(rt)[reachability.UNDECLARED]
        assert found.severity == "low" and found.agent_id
        assert found.title == "billing's owners haven't said what stops calls around the gateway"
        with rt.db.session() as s:
            agents.update(s, agents.get(s, "billing"), {"a2a_protection": "network"}, actor="t")
            posture.scan(s, settings)
        assert reachability.UNDECLARED not in _open(rt)

    def test_an_agent_that_takes_calls_around_the_gateway_is_an_issue(self, rt, settings) -> None:
        with rt.db.session() as s:
            billing = _agent(s, settings).id
        accepted = {"state": "accepted", "detail": "it took a call", "url": "http://billing:9600"}
        with rt.db.session() as s:
            posture.scan(s, settings, tested={billing: accepted})
        found = _open(rt)[reachability.REACHABLE]
        assert found.severity == "medium"
        assert found.title == "billing takes calls that don't come through the gateway"
        assert found.details["test"] == accepted
        with rt.db.session() as s:
            assert agents.get(s, billing).a2a_probe == accepted
            # Its owners say the network stops them: it didn't, which is worse.
            agents.update(s, agents.get(s, billing), {"a2a_protection": "network"}, actor="t")
            posture.scan(s, settings, tested={billing: accepted})
        found = _open(rt)[reachability.REACHABLE]
        assert found.severity == "high"
        assert "Its owners say the network lets only the gateway reach it" in found.description
        # Not tested this time: it stays, unverified.
        with rt.db.session() as s:
            posture.scan(s, settings)
        assert _open(rt)[reachability.REACHABLE].verified is False
        # Tested again, and refused: resolved.
        refused = {**accepted, "state": "refused", "detail": "it refused"}
        with rt.db.session() as s:
            posture.scan(s, settings, tested={billing: refused})
        assert reachability.REACHABLE not in _open(rt)
        # The ledger has what each test found, when it changed.
        with rt.db.session() as s:
            tests = s.scalars(
                select(LedgerEntry)
                .where(LedgerEntry.type == "agent.a2a_tested")
                .order_by(LedgerEntry.seq)
            ).all()
            assert [(e.decision, e.reason, e.resource) for e in tests] == [
                ("accepted", "it took a call", "billing"),
                ("refused", "it refused", "billing"),
            ]

    def test_an_agent_that_refused_the_test_isnt_asked(self, rt, settings) -> None:
        with rt.db.session() as s:
            billing = _agent(s, settings).id
            refused = {"state": "refused", "detail": "it refused", "url": "http://billing:9600"}
            posture.scan(s, settings, tested={billing: refused})
        assert _open(rt) == {}
        # Watched, not tested, after that: the last test still says it refuses.
        with rt.db.session() as s:
            posture.scan(s, settings)
        assert _open(rt) == {}

    def test_off_nothing_is_looked_for_and_what_was_found_stays(self, rt, settings) -> None:
        with rt.db.session() as s:
            _agent(s, settings)
            posture.scan(s, settings)
        _mode(rt, "off")
        with rt.db.session() as s:
            posture.scan(s, settings)
        found = _open(rt)[reachability.UNDECLARED]
        assert found.verified is False

    def test_the_scheduled_scan_calls_the_agents(self, rt, settings) -> None:
        refused: list[str] = []

        class Agent(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                refused.append(self.headers.get("X-AgentGov-Check", ""))
                body = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"message": "No"}})
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Agent)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with rt.db.session() as s:
                _agent(s, settings, a2a_url=f"http://127.0.0.1:{server.server_address[1]}")
            _mode(rt, "test")
            rt.run_posture_scan()
        finally:
            server.shutdown()
            server.server_close()
        assert refused == ["calls-around-gateway"]
        with rt.db.session() as s:
            assert agents.get(s, "billing").a2a_probe["state"] == "refused"
        assert _open(rt) == {}


# ---------------------------------------------------------------------- telemetry


def _client_span(trace: str = "a" * 32, kind: Any = 3, **attrs: Any) -> dict[str, Any]:
    values = []
    for key, value in attrs.items():
        kind_ = "intValue" if isinstance(value, int) else "stringValue"
        values.append({"key": key.replace("__", "."), "value": {kind_: str(value)}})
    return {
        "traceId": trace,
        "spanId": "b" * 16,
        "name": "POST",
        "kind": kind,
        "attributes": values,
    }


def _batch(service: str, *spans: dict[str, Any], agent_id: str | None = None) -> dict[str, Any]:
    resource = [{"key": "service.name", "value": {"stringValue": service}}]
    if agent_id:
        resource.append({"key": "gen_ai.agent.id", "value": {"stringValue": agent_id}})
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": resource},
                "scopeSpans": [{"scope": {"name": "httpx"}, "spans": list(spans)}],
            }
        ]
    }


class TestTelemetry:
    def test_a_call_straight_to_an_agents_url_is_recorded(self, rt, settings) -> None:
        with rt.db.session() as s:
            billing = _agent(s, settings)
            frontdesk = _agent(s, settings, "frontdesk", a2a_url=None)
            billing_id, frontdesk_id = billing.id, frontdesk.id
        straight = _client_span(server__address="billing", server__port=9600)
        with rt.db.session() as s:
            # Twice in one trace (an HTTP span and its retry): one call.
            stats = telemetry.ingest(s, _batch("frontdesk", straight, straight))
        assert stats["around_the_gateway"] == 1
        with rt.db.session() as s:
            [entry] = s.scalars(
                select(LedgerEntry).where(LedgerEntry.type == "telemetry.a2a_around_gateway")
            ).all()
            assert (entry.agent_id, entry.resource) == (frontdesk_id, "billing")
            assert entry.decision == "observed" and entry.trace_id == "a" * 32
            event = ocsf.event(entry)
        assert (event["class_uid"], event["activity_name"]) == (6003, "Agent call")
        assert event["resources"] == [{"name": "billing", "type": "AI Agent"}]
        assert event["is_alert"] is True and event["severity_id"] == 3
        found = _open(rt)
        called = found[reachability.CALLED_AROUND]
        assert called.agent_id == billing_id
        assert called.title == "frontdesk called billing around the gateway"
        calls = found[reachability.CALLS_AROUND]
        assert calls.agent_id == frontdesk_id
        assert calls.remediation == "Call billing through the gateway, at /a2a/billing."

    def test_calls_by_a_service_that_isnt_an_agent(self, rt, settings) -> None:
        with rt.db.session() as s:
            _agent(s, settings)
        span = _client_span(url__full="http://billing.agents.svc.cluster.local:9600/")
        with rt.db.session() as s:
            assert telemetry.ingest(s, _batch("invoice-job", span))["around_the_gateway"] == 1
        found = _open(rt)
        assert found[reachability.CALLED_AROUND].title == (
            "invoice-job called billing around the gateway"
        )
        assert reachability.CALLS_AROUND not in found

    @pytest.mark.parametrize(
        ("service", "span"),
        [
            # The gateway calls agents at their own URLs: that's its job.
            ("agentgateway", _client_span(server__address="billing", server__port=9600)),
            # The agent's own server span names its own address.
            ("billing", _client_span(kind=2, server__address="billing", server__port=9600)),
            ("frontdesk", _client_span(server__address="billing", server__port=9700)),
            ("frontdesk", _client_span(server__address="billing.example.com", server__port=9600)),
            ("frontdesk", _client_span(server__address="agentgateway", server__port=8080)),
        ],
    )
    def test_calls_that_arent_around_the_gateway(self, rt, settings, service, span) -> None:
        with rt.db.session() as s:
            _agent(s, settings)
        with rt.db.session() as s:
            assert telemetry.ingest(s, _batch(service, span))["around_the_gateway"] == 0
        assert reachability.CALLED_AROUND not in _open(rt)

    def test_nothing_is_looked_for_while_the_feature_is_off(self, rt, settings) -> None:
        with rt.db.session() as s:
            _agent(s, settings)
        _mode(rt, "off")
        span = _client_span(server__address="billing", server__port=9600)
        with rt.db.session() as s:
            assert telemetry.ingest(s, _batch("frontdesk", span))["around_the_gateway"] == 0

    def test_hosts_match_as_kubernetes_names_them(self) -> None:
        same = reachability._same_host
        assert same("billing", "billing")
        assert same("billing", "billing.agents")
        assert same("billing.agents.svc.cluster.local", "billing")
        assert not same("billing", "billing.example.com")
        assert not same("billing.agents", "billing.agents.example.com")
        assert not same("billing", "invoicing")


# ------------------------------------------------------------------ API and CLI


class TestSurfaces:
    def test_owners_say_what_stops_calls_and_see_the_test(self, client) -> None:
        client.post(
            "/v1/agents",
            json={
                "name": "billing",
                "a2a_url": "http://billing:9600",
                "sponsors": ["bob@example.com"],
                "approve": True,
            },
            headers=ADMIN,
        ).raise_for_status()
        bad = client.patch("/v1/agents/billing", json={"a2a_protection": "hope"}, headers=ADMIN)
        assert bad.status_code == 422 and "network, delegation" in bad.json()["detail"]
        agent = client.patch(
            "/v1/agents/billing", json={"a2a_protection": "delegation"}, headers=ADMIN
        ).json()
        assert agent["a2a_protection"] == "delegation" and agent["a2a_test"] is None
        view = client.get("/v1/agents/billing/a2a", headers=ADMIN).json()
        assert view["around_gateway"] == {"mode": "watch", "protection": "delegation", "test": None}
        feature = client.get("/v1/features/calls-around-gateway", headers=ADMIN).json()
        assert (feature["modes"], feature["mode"]) == (list(reachability.MODES), "watch")
        assert features.feature(reachability.FEATURE).default == reachability.WATCH

    def test_the_cli(self, client, monkeypatch) -> None:
        monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))

        def agentgov(*args: str) -> str:
            return ok(runner.invoke(cli.app, list(args)))

        agentgov("agents", "create", "billing", "--a2a-url", "http://billing:9600",
                 "--sponsor", "bob@example.com", "--a2a-protection", "network",
                 "--approve")  # fmt: skip
        out = agentgov("agents", "a2a", "billing")
        assert "calls around the gateway: stopped by the network" in out
        assert "not tested (calls-around-gateway is watch)" in out
        agentgov("agents", "update", "billing", "--no-a2a-protection")
        out = agentgov("agents", "a2a", "billing")
        assert "its owners haven't said what stops them" in out

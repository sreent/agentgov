"""Calls around the gateway (agentgov.registry.reachability): what agents' owners say stops
them, the test that calls an agent's A2A URL itself, and calls seen in telemetry."""

from __future__ import annotations

import http.server
import json
import socket
import ssl
import threading
from typing import Any

import httpcore
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


class _Agent(httpcore.NetworkBackend):
    """Stands in for an agent's A2A endpoint on the network: records the address it is
    connected to and what it is sent, and answers ``reply``, a chunk a read, each read
    taking ``each`` seconds on ``clock``. ``error``: what connecting raises instead."""

    def __init__(
        self,
        reply: Any = (),
        *,
        error: Exception | None = None,
        clock: list[float] | None = None,
        each: float = 0.0,
        tls_error: bool = False,
    ) -> None:
        self.reply, self.error, self.clock, self.each = iter(reply), error, clock, each
        self.tls_error = tls_error
        self.connected: list[str] = []
        self.sent = bytearray()
        self.reads = self.read_bytes = 0

    def connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any) -> Any:
        self.connected.append(host)
        if self.error is not None:
            raise self.error
        return _AgentStream(self)


class _AgentStream(httpcore.NetworkStream):
    def __init__(self, agent: _Agent) -> None:
        self.agent = agent

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        agent = self.agent
        if agent.clock is not None:
            agent.clock[0] += agent.each
        chunk = next(agent.reply, b"")
        agent.reads += 1
        agent.read_bytes += len(chunk)
        return chunk

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.agent.sent += buffer

    def close(self) -> None:
        pass

    def start_tls(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
        if self.agent.tls_error:
            try:
                raise ssl.SSLCertVerificationError("certificate verify failed")
            except ssl.SSLError as exc:
                raise httpcore.ConnectError("certificate verify failed") from exc
        return self

    def get_extra_info(self, info: str) -> Any:
        return None


def _http(status: int, body: Any = None) -> list[bytes]:
    text = json.dumps(body).encode() if body is not None else b""
    head = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
    return [f"{head}Content-Length: {len(text)}\r\n\r\n".encode() + text]


def _test(url: str, agent: _Agent, **options: Any) -> dict[str, Any]:
    """The test, against ``agent``, at an address it may call."""
    options.setdefault("resolver", lambda host, port: ["10.0.0.5"])
    got = reachability.call(url, backend=agent, **options)
    if agent.sent:
        head, _, body = bytes(agent.sent).partition(b"\r\n\r\n")
        assert b"X-AgentGov-Check: calls-around-gateway" in head
        assert b"x-agentgov-delegation" not in head.lower()
        assert json.loads(body)["method"] == "GetTask"
    return got


# ------------------------------------------------------------------------ the test


class TestTheTest:
    def test_an_agent_that_refuses_calls_without_a_delegation(self) -> None:
        body = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Refused"}}
        got = _test("http://billing:9600", _Agent(_http(401, body)))
        assert (got["state"], got["status"]) == ("refused", 401)
        assert got["detail"] == "it refused a call without credentials (HTTP 401): Refused"
        assert got["url"] == "http://billing:9600" and got["checked_at"]

    def test_an_agent_that_takes_the_call(self) -> None:
        body = {"jsonrpc": "2.0", "id": "x", "error": {"code": -32001, "message": "No task"}}
        got = _test("http://billing:9600", _Agent(_http(200, body)))
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
        got = _test("http://billing:9600", _Agent(_http(status)))
        assert (got["state"], got["detail"]) == ("inconclusive", detail)

    def test_an_agent_that_cant_be_reached(self) -> None:
        refused = _Agent(error=httpcore.ConnectError("connection refused"))
        assert _test("http://billing:9600", refused)["state"] == "unreachable"

        def nowhere(host: str, port: int) -> list[str]:
            raise socket.gaierror(-2, "Name or service not known")

        unknown = _test("http://billing:9600", _Agent(), resolver=nowhere)
        assert unknown["state"] == "unreachable" and "can't be resolved" in unknown["detail"]
        hung = _test("http://billing:9600", _Agent(error=httpcore.ReadTimeout("timed out")))
        assert hung["detail"] == "it didn't answer within 5 seconds"
        tls = _test("https://billing:9600", _Agent(_http(200), tls_error=True))
        assert tls["state"] == "inconclusive" and "certificate" in tls["detail"]
        # A URL it can't call doesn't stop the others' tests.
        odd = _test("http://\u0125ost.example:9600", _Agent())
        assert odd["state"] == "inconclusive" and "can't be called" in odd["detail"]

    @pytest.mark.parametrize(
        "address",
        ["169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200",
         "::ffff:169.254.169.254", "127.0.0.1", "::1", "0.0.0.0"],  # noqa: S104
    )  # fmt: skip
    def test_addresses_an_agent_isnt_at_arent_called(self, address: str) -> None:
        agent = _Agent(_http(200))
        # However the agent's host resolves: one such address among others is enough.
        got = _test(
            "http://agent.example.com:9600", agent,
            resolver=lambda host, port: ["10.0.0.5", address],
        )  # fmt: skip
        assert got["state"] == "inconclusive" and "which isn't tested" in got["detail"]
        assert agent.connected == []

    @pytest.mark.parametrize(
        "host", ["169.254.169.254", "2852039166", "0251.0376.0251.0376", "0xa9fea9fe", "127.1"]
    )
    def test_however_an_address_is_written(self, host: str) -> None:
        agent = _Agent(_http(200))
        got = reachability.call(f"http://{host}/", backend=agent)
        assert got["state"] == "inconclusive" and "which isn't tested" in got["detail"]
        assert agent.connected == []

    def test_this_machine_only_where_people_reach_the_control_plane_on_it(self) -> None:
        agent = _Agent(_http(401))
        got = _test("http://localhost:9600", agent, resolver=lambda h, p: ["127.0.0.1"])
        assert got["state"] == "inconclusive" and "this machine" in got["detail"]
        got = _test(
            "http://localhost:9600", agent, resolver=lambda h, p: ["127.0.0.1"], loopback=True
        )
        assert got["state"] == "refused" and agent.connected == ["127.0.0.1"]

    def test_it_calls_the_address_it_checked(self) -> None:
        agent = _Agent(_http(401))
        _test("http://billing:9600", agent, resolver=lambda host, port: ["10.0.0.5"])
        # Not the name again, which a second lookup could resolve elsewhere.
        assert agent.connected == ["10.0.0.5"]
        assert b"Host: billing:9600" in agent.sent

    def test_it_reads_64_kib_of_an_answer_at_most(self) -> None:
        def endless() -> Any:
            yield b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            while True:
                yield b"x" * 4096

        agent = _Agent(endless())
        got = _test("http://billing:9600", agent)
        assert got["state"] == "accepted"
        assert agent.read_bytes <= reachability.ANSWER_BYTES + 2 * 4096

    def test_it_gives_up_after_ten_seconds_however_slowly_it_answers(self) -> None:
        """A byte every second, never a whole answer: not even its headers."""
        clock = [0.0]

        def trickle() -> Any:
            while True:
                yield b"X"

        head = (b"HTTP/1.1 200 OK\r\n", *(bytes([c]) for c in b"X-Slow: " * 100))
        for reply in (trickle(), iter(head)):
            agent = _Agent(reply, clock=clock, each=1.0)
            got = _test("http://billing:9600", agent, clock=lambda: clock[0])
            assert got["detail"] == "it didn't answer within 10 seconds"
            assert agent.reads <= 11
            clock[0] = 0.0

    def test_several_agents_are_tested_at_once(self) -> None:
        got = reachability.call_all(
            {"agt_1": "http://a:1", "agt_2": "http://b:2"},
            backend=_Agent(_http(401) * 2),
            resolver=lambda host, port: ["10.0.0.5"],
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

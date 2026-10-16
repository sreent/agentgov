"""Calls around the gateway: can an agent that serves A2A be called without its gateway?

AgentGov checks the calls between agents that come through its gateway. It doesn't own
the network the agents run on, so a call that goes straight to an agent's own A2A URL is
one it never sees: none of its controls apply to it. AgentGov can't stop such calls; the
agent's network can (a Kubernetes NetworkPolicy that lets only the gateway in), or the
agent can (refusing calls without the delegation the gateway gives with each one,
agentgov.a2a_auth). What AgentGov does is find out, and tell the agent's owners
(docs/agent-to-agent.md#calls-around-the-gateway), as the feature ``calls-around-gateway``
says:

* each agent's owners say what stops such calls (``a2a_protection``: "network" or
  "delegation"); an agent whose owners haven't said is an issue for them;
* "test": each posture scan also calls each agent's A2A URL itself, without a delegation,
  as a call around the gateway would (a read of a task that doesn't exist, which changes
  nothing), and records what happened; an agent that takes the call is an issue for its
  owners, a serious one if they said something stops it;
* telemetry that shows a call straight to an agent's A2A URL is recorded in the ledger and
  is an issue for the owners of both agents (agentgov.telemetry).

The test calls a URL an agent's owners give, so it goes only where an agent may be: not to
where cloud metadata services live, nor to this machine itself (unless people reach the
control plane on this machine only), whichever way the address is written; and to the
address it checked, not to one a second lookup gives. It reads at most 64 KiB of the
answer, and gives up after ten seconds, however slowly the agent answers.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from agentgov import __version__, db, ids, ledger
from agentgov.db.models import DELETED, Agent
from agentgov.registry import agents as agents_svc
from agentgov.registry import features

FEATURE = "calls-around-gateway"
WATCH, TEST = "watch", "test"
MODES = (features.OFF, WATCH, TEST)

# What a test found.
REFUSED, ACCEPTED, UNREACHABLE, INCONCLUSIVE = "refused", "accepted", "unreachable", "inconclusive"
# Each step of a test's call (connecting, sending, each read) waits this long at most, and
# the call this long all told; this much of the answer is read, at most.
TIMEOUT = 5.0
DEADLINE = 10.0
ANSWER_BYTES = 64 * 1024
WORKERS = 8
# Where cloud providers serve instance metadata, besides link-local addresses.
METADATA = frozenset(ipaddress.ip_address(a) for a in ("fd00:ec2::254", "100.100.100.200"))
# The test's call: a read of a task that doesn't exist, which changes nothing.
CALL = {
    "jsonrpc": "2.0",
    "id": "agentgov-calls-around-gateway",
    "method": "GetTask",
    "params": {"id": "agentgov-calls-around-gateway"},
}
# So that the agent's owners can tell it from other calls in their logs.
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": f"AgentGov/{__version__} (calls-around-gateway test)",
    "X-AgentGov-Check": "calls-around-gateway",
}

UNDECLARED = "agent.a2a_protection_undeclared"
REACHABLE = "agent.a2a_reachable_around_gateway"
# From telemetry: on the agent called, and on the agent that called it.
CALLED_AROUND = "agent.a2a_called_around_gateway"
CALLS_AROUND = "agent.a2a_calls_around_gateway"
PROTECTIONS = {
    "network": "the network lets only the gateway reach it",
    "delegation": "it refuses calls without the delegation the gateway gives with each one",
}


def on(modes: dict[str, str]) -> bool:
    """Whether calls around the gateway are looked for (``modes``: features.modes)."""
    return modes.get("a2a-gateway") != features.OFF and modes.get(FEATURE) != features.OFF


def checked(agent: Agent, modes: dict[str, str]) -> bool:
    """Whether they are looked for, for this agent: published on the gateway for other
    agents to call, with the feature on."""
    return agents_svc.a2a_published(agent) and on(modes)


# ----------------------------------------------------------------------- the test


def _result(state: str, detail: str, url: str, status: int | None = None) -> dict[str, Any]:
    return {
        "state": state,
        "status": status,
        "detail": detail,
        "url": url,
        "checked_at": ids.isoformat(ids.utcnow()),
    }


class Refused(Exception):
    """An address the test doesn't call."""


class OutOfTime(httpcore.TimeoutException):
    """The call took all the time it had."""


def resolve(host: str, port: int) -> list[str]:
    """``host``'s addresses, as the system resolves them (an address in any form too:
    2852039166 and 0251.0376.0251.0376 are 169.254.169.254)."""
    found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in found))


def refused(address: str, *, loopback: bool = False) -> str | None:
    """Why the test doesn't call ``address``, if it doesn't."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_link_local or ip in METADATA:
        return "a link-local or metadata address"
    if ip.is_unspecified or ip.is_multicast:
        return "no agent's address"
    if ip.is_loopback and not loopback:
        return "this machine's own address"
    return None


class _Guard(httpcore.NetworkBackend):
    """Connects a call to an address it may go to, the one it checked, and gives the call
    DEADLINE seconds all told: no step waits past it."""

    def __init__(
        self,
        backend: httpcore.NetworkBackend,
        resolver: Callable[[str, int], list[str]],
        *,
        loopback: bool,
        clock: Callable[[], float],
    ) -> None:
        self.backend, self.resolver, self.loopback, self.clock = backend, resolver, loopback, clock
        self.ends = clock() + DEADLINE

    def left(self, timeout: float | None) -> float:
        remaining = self.ends - self.clock()
        if remaining <= 0:
            raise OutOfTime(f"no answer within {DEADLINE:g} seconds")
        return remaining if timeout is None else min(timeout, remaining)

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        try:
            addresses = self.resolver(host, port)
        except OSError as exc:
            raise httpcore.ConnectError(f"{host} can't be resolved: {exc}") from exc
        for address in addresses:
            why = refused(address, loopback=self.loopback)
            if why:
                raise Refused(f"{host} is {why}")
        stream = self.backend.connect_tcp(
            addresses[0], port, self.left(timeout), local_address, socket_options
        )
        return _Stream(stream, self)


class _Stream(httpcore.NetworkStream):
    def __init__(self, stream: httpcore.NetworkStream, guard: _Guard) -> None:
        self.stream, self.guard = stream, guard

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self.stream.read(max_bytes, self.guard.left(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.stream.write(buffer, self.guard.left(timeout))

    def close(self) -> None:
        self.stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        tls = self.stream.start_tls(ssl_context, server_hostname, self.guard.left(timeout))
        return _Stream(tls, self.guard)

    def get_extra_info(self, info: str) -> Any:
        return self.stream.get_extra_info(info)


def _tls_failed(exc: BaseException) -> bool:
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return True
        cause = cause.__cause__ or cause.__context__
    return False


def _rpc_error(answer: bytes) -> str:
    """The message of a JSON-RPC error, if the answer is one (and nothing else of it)."""
    try:
        body = json.loads(answer)
    except ValueError:
        return ""
    error = body.get("error") if isinstance(body, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    return message[:200] if isinstance(message, str) else ""


def call(
    url: str,
    *,
    loopback: bool = False,
    backend: httpcore.NetworkBackend | None = None,
    resolver: Callable[[str, int], list[str]] = resolve,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Call an agent's A2A URL as a call around the gateway would, and say what happened.
    ``loopback``: whether this machine's own addresses may be called."""
    try:
        target = httpcore.URL(url)
    except (TypeError, ValueError) as exc:
        # One agent's URL never stops the others' tests.
        return _result(INCONCLUSIVE, f"its URL can't be called ({exc})", url)
    guard = _Guard(backend or httpcore.SyncBackend(), resolver, loopback=loopback, clock=clock)
    timeouts = {"connect": TIMEOUT, "read": TIMEOUT, "write": TIMEOUT, "pool": TIMEOUT}
    answer = bytearray()
    try:
        with (
            httpcore.ConnectionPool(
                ssl_context=httpx.create_ssl_context(), network_backend=guard
            ) as pool,
            pool.stream(
                "POST",
                target,
                headers=HEADERS,
                content=json.dumps(CALL).encode(),
                extensions={"timeout": timeouts},
            ) as resp,
        ):
            status = resp.status
            for chunk in resp.iter_stream():
                answer += chunk
                if len(answer) >= ANSWER_BYTES:
                    break  # enough to say what it answered
    except Refused as exc:
        return _result(INCONCLUSIVE, f"{exc}, which isn't tested", url)
    except OutOfTime:
        return _result(UNREACHABLE, f"it didn't answer within {DEADLINE:g} seconds", url)
    except httpcore.TimeoutException:
        return _result(UNREACHABLE, f"it didn't answer within {TIMEOUT:g} seconds", url)
    except (httpcore.NetworkError, httpcore.ProtocolError, httpcore.UnsupportedProtocol) as exc:
        if _tls_failed(exc):
            return _result(INCONCLUSIVE, f"its certificate couldn't be verified ({exc})", url)
        return _result(UNREACHABLE, f"it couldn't be reached ({exc})", url)
    said = _rpc_error(bytes(answer))
    if status in (401, 403):
        why = f": {said}" if said else ""
        return _result(
            REFUSED, f"it refused a call without credentials (HTTP {status}){why}", url, status
        )
    if 200 <= status < 300:
        why = f", answering {said!r}" if said else ""
        return _result(
            ACCEPTED,
            f"it took a call that didn't come through the gateway (HTTP {status}{why})",
            url,
            status,
        )
    if status in (404, 405, 415):
        return _result(
            INCONCLUSIVE, f"it doesn't take A2A JSON-RPC calls there (HTTP {status})", url, status
        )
    return _result(INCONCLUSIVE, f"it answered HTTP {status}", url, status)


def targets(tx: db.Transaction) -> dict[str, str] | None:
    """The agents to test, by ID: their A2A URLs (None unless the feature says "test")."""
    modes = features.modes(tx)
    if modes.get(FEATURE) != TEST or not on(modes):
        return None
    found = Agent.objects.exclude(status=DELETED)
    return {a.id: a.a2a_url for a in found if a.a2a_url and checked(a, modes)}


def call_all(urls: dict[str, str], **options: Any) -> dict[str, Any]:
    """Call each agent's A2A URL (a few at a time), outside any transaction; ``options``
    as :func:`call` takes them."""
    if not urls:
        return {}
    with ThreadPoolExecutor(max_workers=min(WORKERS, len(urls))) as pool:
        found = pool.map(lambda item: (item[0], call(item[1], **options)), urls.items())
        return dict(found)


# ------------------------------------------------------------------- the posture scan


Flag = Callable[..., None]


def scan(tx: db.Transaction, agent: Agent, flag: Flag, *, tested: dict[str, Any] | None) -> None:
    """Record the agent's test, if this scan tested it, and raise what it shows (and what
    its owners haven't said) for posture.scan."""
    if tested is not None:
        before = (agent.a2a_probe or {}).get("state")
        agent.a2a_probe = tested
        agent.save()
        if tested["state"] != before:
            # What it found, in the ledger when it changes: evidence of what was tested.
            ledger.append(
                tx,
                type="agent.a2a_tested",
                actor="system:posture-scan",
                agent=agent,
                severity="warning" if tested["state"] == ACCEPTED else "info",
                action="a2a.test",
                resource=agent.name,
                decision=tested["state"],
                reason=tested["detail"],
                details={"url": tested["url"], "status": tested.get("status")},
            )
    result = tested
    last = agent.a2a_probe
    if result is not None and result["state"] == ACCEPTED:
        declared = agent.a2a_protection
        flag(
            REACHABLE,
            agent.id,
            "high" if declared else "medium",
            f"{agent.name} takes calls that don't come through the gateway",
            agent_id=agent.id,
            description=(
                f"AgentGov called {result['url']} without a delegation and {result['detail']}. "
                + (
                    f"Its owners say {PROTECTIONS[declared]}, but that didn't stop it. "
                    if declared
                    else ""
                )
                + "Calls that go around the gateway skip every control AgentGov applies."
            ),
            remediation="Let only the gateway reach it (a NetworkPolicy, for example), or have "
            "it refuse calls without the delegation the gateway gives with each one "
            "(agentgov.a2a_auth); then say which with its a2a_protection.",
            details={"test": result},
        )
    elif not agent.a2a_protection and not (last and last["state"] == REFUSED):
        flag(
            UNDECLARED,
            agent.id,
            "low",
            f"{agent.name}'s owners haven't said what stops calls around the gateway",
            agent_id=agent.id,
            description="AgentGov checks the calls that come through its gateway. Calls "
            f"straight to {agent.name}'s A2A URL skip its controls, unless its network or "
            "the agent itself stops them.",
            remediation="Say what stops them (a2a_protection: network or delegation) once one "
            "of them does: docs/agent-to-agent.md#calls-around-the-gateway.",
        )


# ------------------------------------------------------------------------ telemetry

# Client spans: a call the service that reports the span made (OTLP's JSON has the number,
# protobuf decoded to JSON the name).
CLIENT_KINDS = {3, "SPAN_KIND_CLIENT"}
DEFAULT_PORTS = {"http": 80, "https": 443}


def _host(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".").strip("[]")


def _endpoint_of(url: str) -> tuple[str, int | None] | None:
    try:
        parts = urlsplit(url)
        port = parts.port or DEFAULT_PORTS.get(parts.scheme)
    except ValueError:
        return None
    return (_host(parts.hostname), port) if parts.hostname else None


def _same_host(a: str, b: str) -> bool:
    if a == b:
        return True
    short, full = sorted((a, b), key=len)
    if "." in short or not full.startswith(short + "."):
        return False
    # A Kubernetes service by its short name and a longer one: billing-agent and
    # billing-agent.agents, or billing-agent.agents.svc.cluster.local.
    rest = full[len(short) + 1 :]
    return "." not in rest or ".svc" in f".{rest}"


def endpoints(tx: db.Transaction, modes: dict[str, str]) -> list[tuple[str, int | None, Agent]]:
    """Where the agents whose calls around the gateway are looked for serve A2A."""
    if not on(modes):
        return []
    found = Agent.objects.exclude(status=DELETED)
    out = []
    for agent in found:
        where = _endpoint_of(agent.a2a_url) if agent.a2a_url else None
        if where is not None and checked(agent, modes):
            out.append((*where, agent))
    return out


def called(
    attrs: dict[str, Any], span: dict[str, Any], served: list[tuple[str, int | None, Agent]]
) -> Agent | None:
    """The agent a client span called at its own A2A URL, if it called one."""
    op = attrs.get("gen_ai.operation.name")
    if span.get("kind") not in CLIENT_KINDS and op != "invoke_agent":
        return None
    host = _host(attrs.get("server.address") or attrs.get("net.peer.name"))
    port = attrs.get("server.port") or attrs.get("net.peer.port")
    url = attrs.get("url.full") or attrs.get("http.url")
    if isinstance(url, str) and url:
        where = _endpoint_of(url)
        if where is not None:
            host, port = host or where[0], port or where[1]
    if not host:
        return None
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        port = None
    for agent_host, agent_port, agent in served:
        if not _same_host(host, agent_host):
            continue
        # A span without a port called the scheme's default one.
        if port == agent_port or (port is None and agent_port in DEFAULT_PORTS.values()):
            return agent
    return None


def caller_key(service: str | None, agent: Agent | None) -> str:
    if agent is not None:
        return agent.id
    return f"service:{service}" if service else "unknown"


_NAME = re.compile(r"[^\w.-]+")


def caller_name(service: str | None, agent: Agent | None) -> str:
    if agent is not None:
        return agent.name
    return _NAME.sub("-", service)[:100] if service else "An unknown service"

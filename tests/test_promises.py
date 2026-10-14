"""AgentGov's promises about trust, each checked as a whole (docs/threat-model.md).

Each test takes what an attacker would try and follows it as far as a test can reach: the
real gateway, given forged headers and tokens with forged claims; the kill switch, from a
block to OPA's decision; usage, which only the gateway may report; and the ledger's history,
changed by whoever can write to its database. Who may call each API route is checked route
by route in tests/test_authz_matrix.py.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import delete, select, update

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.gateway import render, to_yaml
from agentgov.models import (
    Agent,
    IdentityIssuer,
    LedgerCheckpoint,
    LedgerEntry,
    LedgerHead,
    ModelProvider,
)
from agentgov.registry import agents
from tests.conftest import requires_opa
from tests.test_gateway import IMAGE, _docker_ready
from tests.test_opa import _decide, _seed

ROOT = Path(__file__).resolve().parent.parent

# What a caller sends, posing as AgentGov: the headers AgentGov tells its processor (and the
# agent called) who is calling, and for whom.
FORGED = {
    "x-agentgov-agent-id": "agt_victim",
    "x-agentgov-client-id": "victim-client",
    "x-agentgov-subject": "forged",
    "x-agentgov-issuer": "https://evil.example.com",
    "x-agentgov-username": "ceo",
    "x-agentgov-email": "ceo@example.com",
    "x-agentgov-groups": '["admins"]',
    "x-agentgov-roles": '["admin"]',
    "x-agentgov-act": '{"sub": "ceo"}',
    "x-agentgov-sign-in": "true",
    "x-agentgov-path": "/a2a/elsewhere",
    "x-agentgov-caller": "forged-caller",
    "x-agentgov-on-behalf-of": "ceo",
    "x-agentgov-chain": "ceo > forged-caller",
}
# What the processor's answer to a call between agents tells the agent called.
PASSED_ON = {
    "x-agentgov-delegation": "",
    "x-agentgov-caller": "real-caller",
    "x-agentgov-on-behalf-of": "",
    "x-agentgov-chain": "real-caller",
}
SEND = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "SendMessage",
    "params": {"message": {"role": "ROLE_USER", "messageId": "m-1", "parts": [{"text": "hi"}]}},
}


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Issuer:
    """An identity provider's signing key, and its keys as a JSON Web Key Set."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = uuid.uuid4().hex
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwk = {**public, "kid": self.kid, "use": "sig", "alg": "RS256"}

    def token(self, **claims: Any) -> str:
        now = int(time.time())
        body = {"iss": self.url, "iat": now, "exp": now + 300, "jti": uuid.uuid4().hex, **claims}
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": self.kid})


class StandIns:
    """One server for everything the gateway calls: Keycloak's keys, the processor's
    webhook (model calls, and calls between agents), the model, and the agent called. It
    records the headers each call carries, and lets everything through."""

    def __init__(self, keycloak: Issuer) -> None:
        self.seen: list[tuple[str, dict[str, str]]] = []
        stand_ins = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                headers = {k.lower(): v for k, v in self.headers.items()}
                stand_ins.seen.append((self.path, headers))
                extra: dict[str, str] = {}
                if self.path.endswith("/jwks"):
                    body: Any = {"keys": [keycloak.jwk]}
                elif self.path.startswith("/a2a/check/"):
                    body, extra = {}, PASSED_ON
                elif self.path.startswith("/v1/chat/completions"):
                    body = {
                        "id": "c-1",
                        "object": "chat.completion",
                        "created": 0,
                        "model": "mock",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "hello"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    }
                elif self.path.startswith("/agent"):
                    body = {"jsonrpc": "2.0", "id": 1, "result": {}}
                else:  # the model webhook: go ahead
                    body = {"action": {}}
                data = json.dumps(body).encode()
                self.send_response(200)
                for name, value in extra.items():
                    self.send_header(name, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _answer
            do_POST = _answer

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def where(self, prefix: str) -> list[dict[str, str]]:
        return [headers for path, headers in self.seen if path.startswith(prefix)]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _agentgovs(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.startswith("x-agentgov-")}


@pytest.fixture
def gateway(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """The real agentgateway, configured as AgentGov configures it: Keycloak, and an
    identity issuer it trusts; a model provider; an agent other agents call."""
    keycloak = Issuer("")
    stand_ins = StandIns(keycloak)
    here = f"127.0.0.1:{stand_ins.port}"
    keycloak.url = f"http://{here}/realms/agentgov"
    corp = Issuer("https://login.corp.example.com")
    port, admin, stats, ready = (_port() for _ in range(4))
    settings = Settings(
        keycloak_issuer=keycloak.url,
        keycloak_jwks_url=f"http://{here}/jwks",
        processor_webhook_address=here,
        processor_address=f"127.0.0.1:{_port()}",  # nothing there: answers aren't checked
        gateway_port=port,
        gateway_public_url=f"http://127.0.0.1:{port}",
    )
    issuer = IdentityIssuer(
        name="corp",
        kind="oidc",
        issuer=corp.url,
        gateway=True,
        gateway_keys=[corp.jwk],
        status="approved",
    )
    provider = ModelProvider(
        name="demo", kind="openai-compatible", base_url=f"http://{here}/v1", status="approved"
    )
    target = Agent(name="target", a2a_url=f"http://{here}/agent", status="active")
    modes = {"a2a-gateway": "enforce", "data-protection": "off", "prompt-injection": "off"}
    config = render([], settings, modes, providers=[provider], agents=[target], issuers=[issuer])
    config["config"].update(
        {
            "adminAddr": f"127.0.0.1:{admin}",
            "statsAddr": f"127.0.0.1:{stats}",
            "readinessAddr": f"127.0.0.1:{ready}",
        }
    )
    (tmp_path / "gateway").mkdir()
    (tmp_path / "gateway" / "config.yaml").write_text(to_yaml(config))
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "demo").write_text("sk-test")
    name = f"agentgov-promises-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "--network", "host",
         "-v", f"{tmp_path / 'gateway'}:/gateway:ro", "-v", f"{tmp_path / 'keys'}:/model-keys:ro",
         IMAGE, "-f", "/gateway/config.yaml"],
        check=True, capture_output=True,
    )  # fmt: skip
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{ready}/healthz/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            pytest.fail(f"agentgateway didn't start: {logs.stdout}{logs.stderr}")
        yield {
            "url": f"http://127.0.0.1:{port}",
            "stand_ins": stand_ins,
            "keycloak": keycloak,
            "corp": corp,
            "audience": settings.gateway_public_url,
        }
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        stand_ins.close()


@pytest.mark.skipif(not _docker_ready(), reason=f"docker or {IMAGE} not available")
def test_callers_cannot_say_who_they_are(gateway: dict[str, Any]) -> None:
    """Who calls, and for whom, comes from the token the gateway checked, and only from
    AgentGov's own (Keycloak's) for which agent and which person: neither headers named as
    AgentGov's nor claims in another issuer's token reach the processor or the agent
    called."""
    stand_ins: StandIns = gateway["stand_ins"]
    # Another issuer's token, with an AgentGov token's claims in it.
    corp = gateway["corp"].token(
        sub="sp-helper",
        aud=gateway["audience"],
        agent_id="agt_victim",
        azp="victim-client",
        preferred_username="ceo",
        email="ceo@example.com",
        act={"sub": "ceo"},
    )
    # AgentGov's own token for a client that is no agent's.
    own = gateway["keycloak"].token(sub="svc-1", aud="agentgov-gateway", azp="svc-client")
    chat = {"model": "mock", "messages": [{"role": "user", "content": "hi"}]}
    for token in (corp, own):
        headers = {"authorization": f"Bearer {token}", **FORGED}
        model = httpx.post(
            f"{gateway['url']}/llm/demo/v1/chat/completions", json=chat, headers=headers
        )
        assert model.status_code == 200, model.text
        httpx.post(f"{gateway['url']}/a2a/target", json=SEND, headers=headers)

    asked = stand_ins.where("/request") + stand_ins.where("/a2a/check/")
    assert len(asked) == 4
    from_corp = [_agentgovs(h) for h in asked if h.get("x-agentgov-subject") == "sp-helper"]
    from_own = [_agentgovs(h) for h in asked if h.get("x-agentgov-subject") == "svc-1"]
    assert len(from_corp) == len(from_own) == 2
    for told in from_corp:
        # The issuer and subject name the agent; nothing else of the token is believed.
        assert told["x-agentgov-issuer"] == "https://login.corp.example.com"
        for believed_from_keycloak_alone in (
            "x-agentgov-agent-id",
            "x-agentgov-client-id",
            "x-agentgov-username",
            "x-agentgov-email",
            "x-agentgov-act",
        ):
            assert believed_from_keycloak_alone not in told
    for told in from_own:
        assert told["x-agentgov-client-id"] == "svc-client"
        assert told["x-agentgov-issuer"] == gateway["keycloak"].url
        assert "x-agentgov-agent-id" not in told  # its token names no agent
    for told in from_corp + from_own:
        forged = {k: v for k, v in told.items() if FORGED.get(k) == v}
        assert forged == {}, forged
    # The agent called hears who called it from AgentGov alone.
    called = [_agentgovs(h) for h in stand_ins.where("/agent")]
    assert called == [PASSED_ON, PASSED_ON]


@requires_opa
def test_a_blocked_agent_is_refused_within_seconds(rt, settings, tmp_path: Path) -> None:
    """The kill switch: a block reaches OPA, which every check asks, as OPA's long poll
    returns (within seconds), and OPA refuses the agent's calls from then on."""
    _seed(rt, settings)
    call = {
        "agent": {"client_id": "agent-bot"},
        "resource": {"server": "crm", "tool": "get_customer"},
        "detections": {},
    }
    assert _decide(rt, tmp_path, call)["effect"] == "allow"

    async def block_while_opa_waits() -> float:
        rt.bundles.bind_loop(asyncio.get_running_loop())
        etag = rt.bundles.current().etag
        loop = asyncio.get_running_loop()
        waiting = asyncio.create_task(rt.bundles.wait_for_change(etag, timeout=30))
        await asyncio.sleep(0.2)
        started = loop.time()

        def block() -> None:
            with rt.db.session() as s:
                agents.transition(s, settings, agents.get(s, "bot"), "block", actor="secops")

        await asyncio.to_thread(block)
        assert await waiting is not None
        return loop.time() - started

    assert asyncio.run(block_while_opa_waits()) < 2
    decision = _decide(rt, tmp_path, call)
    assert decision["effect"] == "deny"
    assert any("blocked" in reason for reason in decision["reasons"]), decision


def test_usage_comes_from_the_gateway_alone() -> None:
    """What usage says is billed to agents and counts against their budgets: the collector
    takes the gateway's access logs on a receiver of their own, which asks for a
    certificate from AgentGov's authority, not on the one agents send traces to."""
    collector = yaml.safe_load((ROOT / "deploy/compose/otel/collector.yaml").read_text())
    logs = collector["service"]["pipelines"]["logs"]
    assert logs["receivers"] == ["otlp/gateway"]
    receiver = collector["receivers"]["otlp/gateway"]["protocols"]
    assert list(receiver) == ["grpc"] and receiver["grpc"]["tls"]["client_ca_file"]
    assert "otlp/gateway" not in collector["service"]["pipelines"]["traces"]["receivers"]
    compose = yaml.safe_load((ROOT / "deploy/compose/docker-compose.yml").read_text())
    env = compose["services"]["control-plane"]["environment"]
    assert env["AGENTGOV_GATEWAY_USAGE_ENDPOINT"] == "otel-collector:4319"
    # Not published on the host, as the traces' receiver is.
    assert not any("4319" in str(p) for p in compose["services"]["otel-collector"]["ports"])


def _edited(s: Any) -> None:
    s.execute(update(LedgerEntry).where(LedgerEntry.seq == 3).values(reason="edited later"))


def _removed(s: Any) -> None:
    s.execute(delete(LedgerEntry).where(LedgerEntry.seq == 3))


def _removed_behind_a_made_up_archive(s: Any) -> None:
    # As archiving leaves the chain's start, without archiving.
    s.get(LedgerCheckpoint, 5).pruned_at = ids.utcnow()
    s.execute(delete(LedgerEntry).where(LedgerEntry.seq <= 5))


def _cut_back_past_a_checkpoint(s: Any) -> None:
    kept = s.get(LedgerEntry, 7)
    s.execute(delete(LedgerEntry).where(LedgerEntry.seq > 7))
    s.execute(update(LedgerHead).where(LedgerHead.id == 1).values(last_seq=7, last_hash=kept.hash))


def _rewritten_with_its_hashes_worked_out_again(s: Any) -> None:
    from tests.test_ledger import _rewrite

    _rewrite(s, 2, "a denial, now an allow")


@pytest.mark.parametrize(
    "change",
    [
        _edited,
        _removed,
        _removed_behind_a_made_up_archive,
        _cut_back_past_a_checkpoint,
        _rewritten_with_its_hashes_worked_out_again,
    ],
)
def test_a_change_to_the_ledgers_history_is_found(rt, change: Any) -> None:
    """Whoever can write to the database can't change what the ledger says happened without
    its verification saying so: an entry edited or removed, the oldest removed as if
    archived, the newest cut back with the head, or the chain rewritten with its hashes
    worked out again (the checkpoints don't match it; time-stamped by an authority, which
    tests/test_evidence.py checks, they can't be made to). A database restored from an older
    copy shows at the witness (tests/test_witness.py)."""
    from tests.test_ledger import _append

    _append(rt, 5)
    with rt.db.session() as s:
        ledger.checkpoint(s)
    _append(rt, 5)
    with rt.db.session() as s:
        ledger.checkpoint(s)
    _append(rt, 2)
    with rt.db.session() as s:
        assert ledger.verify(s)["valid"] is True
        change(s)
    with rt.db.session() as s:
        assert ledger.verify(s)["valid"] is False


def test_a_row_slipped_in_past_the_ledgers_head_is_found(rt) -> None:
    """A row stored past the chain's head, around it, makes verification fail, and nothing
    serves or counts it as the ledger's."""
    from tests.test_ledger import _append, past_the_head

    _append(rt, 3)
    seq = past_the_head(rt)
    with rt.db.session() as s:
        assert ledger.verify(s)["valid"] is False
        listed = s.scalars(select(LedgerEntry.seq).where(ledger.in_chain())).all()
    assert seq not in listed

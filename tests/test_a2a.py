"""Agent to agent: delegation chains (agentgov.identity.chains), the processor's checks on
calls between agents (agentgov.processor.a2a_guard), chains on tool and model calls, the
gateway's A2A routes, and the registry, ledger and OCSF events that go with them."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import http.server
import json
import threading
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from agentgov import a2a_auth, cli
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.gateway import render
from agentgov.identity import chains
from agentgov.models import ACTIVE, BLOCKED, PENDING, Agent, LedgerEntry
from agentgov.opa.bundle import registry_snapshot
from agentgov.processor import a2a_guard
from agentgov.processor.control_plane import DecisionRecorder
from agentgov.processor.model_guard import ModelGuard
from agentgov.processor.proto import ext_mcp_pb2 as pb
from agentgov.processor.server import GovernanceProcessor
from agentgov.registry import decisions, manifests
from agentgov.secops import ocsf
from tests.conftest import ADMIN, seed
from tests.test_cli import _Shared, ok, runner
from tests.test_model_guard import HEADERS as MODEL_HEADERS
from tests.test_model_guard import prompt, user
from tests.test_processor import (
    AGENT,
    FakeControlPlane,
    FakeOpa,
    FakePresidio,
    call_request,
    run,
)

SECRET = "test-service-token"
KEYS = chains.keys(SECRET)
SETTINGS = Settings(service_token=SECRET)
BILLING = {"id": "agt_2", "name": "billing-agent", "status": "active"}
CALLER = {"x-agentgov-agent-id": "agt_1", "x-agentgov-client-id": "agent-bot"}
SAM = {"id": "u-1", "username": "sam", "groups": ["/support"], "via": "exchange"}
SEND = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "SendMessage",
    "params": {
        "message": {
            "role": "ROLE_USER",
            "messageId": "m-1",
            "contextId": "ctx-1",
            "parts": [{"text": "What does customer c-001 owe?"}],
        }
    },
}


def allow(inp: dict[str, Any]) -> dict[str, Any]:
    return {"effect": "allow", "reasons": [], "monitored": [], "agent": AGENT, "target": BILLING}


def refuse(reasons: list[str]):
    return lambda inp: {
        "effect": "deny",
        "reasons": reasons,
        "monitored": [],
        "agent": AGENT,
        "target": BILLING,
    }


def ask(
    opa: FakeOpa,
    *,
    body: Any = SEND,
    headers: dict[str, str] | None = None,
    method: str = "POST",
    path: str = "/a2a/billing-agent",
    cp: FakeControlPlane | None = None,
    settings: Settings = SETTINGS,
    presidio: Any = None,
) -> tuple[httpx.Response, FakeControlPlane]:
    """One check, as agentgateway asks the processor about a request to /a2a/billing-agent."""
    cp = cp or FakeControlPlane()

    async def go() -> httpx.Response:
        recorder = DecisionRecorder(cp)
        processor = GovernanceProcessor(
            settings, opa=opa, control_plane=cp, recorder=recorder, presidio=presidio
        )
        app = ModelGuard(processor).app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://processor"
        ) as client:
            resp = await client.request(
                method,
                "/a2a/check/billing-agent",
                content=json.dumps(body).encode() if body is not None else b"",
                headers={**CALLER, "x-agentgov-path": path, **(headers or {})},
            )
        await asyncio.gather(*processor._background)
        await recorder.flush()
        return resp

    return asyncio.run(go()), cp


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hand_signed(claims: dict[str, Any], alg: str, secret: bytes | None) -> str:
    """A JWT signed by hand, as a forger would: with an HMAC of ``secret``, or nothing."""
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    unsigned = f"{header}.{b64(json.dumps(claims).encode())}"
    signature = hmac.new(secret, unsigned.encode(), hashlib.sha256).digest() if secret else b""
    return f"{unsigned}.{b64(signature)}"


def delegation(audience: str = "agt_1", **kw: Any) -> tuple[str, chains.Chain]:
    links = kw.pop(
        "links",
        [chains.person_link(SAM), chains.link("agent", "agt_0", "frontdesk")],
    )
    return chains.issue(KEYS, links=links, audience=audience, person=kw.pop("person", SAM), **kw)


# ----------------------------------------------------------------------- chains


class TestChains:
    def test_a_delegation_is_for_the_agent_it_was_given_to(self) -> None:
        token, chain = delegation()
        got = chains.verify(KEYS, token, holder="agt_1")
        assert got.uid == chain.uid and got.uid.startswith("dlg_")
        assert [x["name"] for x in got.links] == ["sam", "frontdesk"]
        assert got.person == {
            "id": "u-1",
            "username": "sam",
            "groups": ["/support"],
            "via": "exchange",
        }
        assert got.describe(chains.link("agent", "agt_1", "bot")) == "sam > frontdesk > bot"
        with pytest.raises(chains.ChainError, match="given to another agent"):
            chains.verify(KEYS, token, holder="agt_9")

    def test_forged_expired_and_unkeyed_delegations_are_refused(self) -> None:
        token, _ = delegation()
        forged = jwt.encode(
            jwt.decode(token, options={"verify_signature": False}),
            b"a-key-that-is-not-agentgovs-but-long-enough",
            algorithm="HS256",
        )
        with pytest.raises(chains.ChainError, match="isn't one AgentGov gave"):
            chains.verify(KEYS, forged, holder="agt_1")
        old, _ = delegation(now=1)
        with pytest.raises(chains.ChainError, match="expired"):
            chains.verify(KEYS, old, holder="agt_1")
        with pytest.raises(chains.ChainError, match="AGENTGOV_SERVICE_TOKEN"):
            chains.verify(None, token, holder="agt_1")
        with pytest.raises(chains.ChainError, match="not a registered agent"):
            chains.verify(KEYS, token, holder=None)
        with pytest.raises(chains.ChainError, match="isn't one AgentGov gave"):
            chains.verify(KEYS, "garbage", holder="agt_1")
        assert chains.keys(None) is None and chains.keys("") is None

    def test_delegations_signed_with_another_key_or_none_are_refused(self) -> None:
        token, _ = delegation()
        claims = jwt.decode(token, options={"verify_signature": False})
        another = ec.generate_private_key(ec.SECP256R1())
        public = KEYS.public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        for bad in (
            jwt.encode(claims, another, algorithm="ES256", headers={"kid": KEYS.kid}),
            # AgentGov's public key as an HMAC secret, the old confusion of algorithms.
            hand_signed(claims, "HS256", public),
            hand_signed(claims, "none", None),
            hand_signed(claims, "ES384", None),
        ):
            with pytest.raises(chains.ChainError, match="isn't one AgentGov gave"):
                chains.verify(KEYS, bad, holder="agt_1")

    def test_delegations_are_signed_with_a_key_agents_can_check(self) -> None:
        token, _ = delegation()
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "ES256" and header["kid"] == KEYS.kid
        # Every processor with the service token signs with the same key; another, another.
        assert chains.keys(SECRET).kid == KEYS.kid != chains.keys("another-token").kid
        published = chains.jwks(KEYS)
        [jwk] = published["keys"]
        assert set(jwk) == {"crv", "kty", "x", "y", "kid", "alg", "use"}
        assert (jwk["kty"], jwk["crv"], jwk["alg"], jwk["use"]) == ("EC", "P-256", "ES256", "sig")
        # Its ID is its thumbprint (RFC 7638): the required members, in order, no spaces.
        members = f'{{"crv":"P-256","kty":"EC","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'
        assert jwk["kid"] == b64(hashlib.sha256(members.encode()).digest())
        # Any JWT library checks it with the published key; no secret is published.
        key = jwt.PyJWKSet.from_dict(published)[jwk["kid"]].key
        assert jwt.decode(token, key, algorithms=["ES256"], audience="agt_1")["iss"] == "agentgov"
        assert "d" not in jwk
        assert chains.jwks(None) == {"keys": []}

    def test_delegations_signed_before_are_checked_until_they_expire(self) -> None:
        now = int(time.time())
        claims = {
            "iss": "agentgov",
            "aud": "agt_1",
            "jti": "dlg_before",
            "iat": now,
            "exp": now + 60,
            "chain": [chains.person_link(SAM)],
        }
        before = jwt.encode(claims, KEYS.legacy, algorithm="HS256")
        assert chains.verify(KEYS, before, holder="agt_1").uid == "dlg_before"
        expired = jwt.encode({**claims, "iat": 1, "exp": 2}, KEYS.legacy, algorithm="HS256")
        with pytest.raises(chains.ChainError, match="expired"):
            chains.verify(KEYS, expired, holder="agt_1")
        assert KEYS.legacy == chains.signing_key(SECRET)

    def test_re_delegation_names_its_parent(self) -> None:
        first, chain = delegation()
        _, second = chains.issue(KEYS, links=chain.links, audience="agt_3", parent=chain.uid)
        assert second.parent == chain.uid
        claims = jwt.decode(first, KEYS.public, algorithms=["ES256"], audience="agt_1")
        assert claims["iss"] == "agentgov" and claims["exp"] - claims["iat"] == chains.TTL_SECONDS


# ---------------------------------------------------------------- calls between


class TestA2AGuard:
    def test_an_allowed_call_goes_ahead_with_a_delegation_for_the_called_agent(self) -> None:
        opa = FakeOpa(allow)
        resp, cp = ask(
            opa, headers={"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
        )
        assert resp.status_code == 200
        path, inp = opa.inputs[0]
        assert path == "agentgov/a2a/decision"
        assert inp == {
            "kind": "a2a",
            "method": "SendMessage",
            "agent": {"agent_id": "agt_1", "client_id": "agent-bot"},
            "target": "billing-agent",
            "chain": [],
            "detections": inp["detections"],
        }
        given = chains.verify(KEYS, resp.headers[chains.HEADER], holder="agt_2")
        assert [x["name"] for x in given.links] == ["bot"] and given.parent is None
        assert resp.headers[chains.CALLER_HEADER] == "bot"
        assert resp.headers[chains.PERSON_HEADER] == ""
        assert resp.headers[chains.CHAIN_HEADER] == "bot"
        [record] = cp.records
        assert (record["kind"], record["method"], record["resource"]) == (
            "a2a",
            "SendMessage",
            "billing-agent",
        )
        assert record["a2a"] == {
            "target": "billing-agent",
            "target_id": "agt_2",
            "context_id": "ctx-1",
            "task_id": None,
        }
        assert record["delegation"] == {"chain": [], "uid": given.uid, "parent_uid": None}
        assert record["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_the_person_heads_the_chain(self) -> None:
        opa = FakeOpa(allow)
        person = {
            "x-agentgov-subject": "u-1",
            "x-agentgov-username": "sam",
            "x-agentgov-groups": '["/support"]',
        }
        resp, _ = ask(opa, headers=person)
        inp = opa.inputs[0][1]
        assert inp["user"]["username"] == "sam"
        assert inp["chain"] == [{"type": "person", "id": "u-1", "name": "sam"}]
        assert resp.headers[chains.PERSON_HEADER] == "sam"
        assert resp.headers[chains.CHAIN_HEADER] == "sam > bot"
        given = chains.verify(KEYS, resp.headers[chains.HEADER], holder="agt_2")
        assert given.person and given.person["username"] == "sam"

    def test_a_call_handed_down_carries_its_chain_on(self) -> None:
        opa = FakeOpa(allow)
        token, incoming = delegation()
        resp, cp = ask(opa, headers={chains.HEADER: token})
        inp = opa.inputs[0][1]
        assert [x["name"] for x in inp["chain"]] == ["sam", "frontdesk"]
        assert inp["user"]["username"] == "sam"  # the chain's person
        given = chains.verify(KEYS, resp.headers[chains.HEADER], holder="agt_2")
        assert given.parent == incoming.uid
        assert resp.headers[chains.CHAIN_HEADER] == "sam > frontdesk > bot"
        assert cp.records[0]["delegation"]["parent_uid"] == incoming.uid

    @pytest.mark.parametrize(
        ("token", "reason"),
        [
            ("forged", "isn't one AgentGov gave"),
            ("someone-elses", "given to another agent"),
        ],
    )
    def test_unusable_delegations_are_refused(self, token: str, reason: str) -> None:
        if token == "someone-elses":
            token, _ = delegation(audience="agt_9")
        opa = FakeOpa(allow)
        resp, cp = ask(opa, headers={chains.HEADER: token})
        assert resp.status_code == 403
        error = resp.json()["error"]
        assert reason in error["message"] and error["code"] == a2a_guard.REFUSED
        assert opa.inputs == []
        # The agent that presented it did it: the ledger and its risk count it.
        assert cp.records[0]["effect"] == "deny" and cp.records[0]["agent"] == {"id": "agt_1"}

    def test_a_delegation_for_another_person_is_refused(self) -> None:
        token, _ = delegation()
        other = {"x-agentgov-subject": "u-2", "x-agentgov-username": "olga"}
        resp, _ = ask(FakeOpa(allow), headers={chains.HEADER: token, **other})
        assert resp.status_code == 403
        assert "acts for one person" in resp.json()["error"]["message"]

    def test_refusals_are_json_rpc_errors(self) -> None:
        resp, cp = ask(FakeOpa(refuse(["Agent bot may not call agent billing-agent"])))
        assert resp.status_code == 403
        body = resp.json()
        assert body["id"] == 7 and body["jsonrpc"] == "2.0"
        assert body["error"]["message"] == "AgentGov: Agent bot may not call agent billing-agent"
        assert body["error"]["data"][0]["effect"] == "deny"
        assert chains.HEADER not in resp.headers
        assert cp.records[0]["reasons"] == ["Agent bot may not call agent billing-agent"]

    def test_reading_the_card_is_checked_too(self) -> None:
        opa = FakeOpa(allow)
        resp, _ = ask(
            opa, method="GET", body=None, path="/a2a/billing-agent/.well-known/agent-card.json"
        )
        assert resp.status_code == 200
        assert opa.inputs[0][1]["method"] == "GetAgentCard"

    def test_credentials_in_the_message_are_found(self) -> None:
        opa = FakeOpa(allow)
        message = json.loads(json.dumps(SEND))
        message["params"]["message"]["parts"] = [{"text": "key AKIAIOSFODNN7EXAMPLE"}]
        ask(opa, body=message)
        assert "secret" in opa.inputs[0][1]["detections"]["categories"]

    def test_what_the_gateway_masks_in_the_message_is_recorded(self) -> None:
        def masks(inp: dict[str, Any]) -> dict[str, Any]:
            return {**allow(inp), "redact": ["pii"]}  # a2a-masking enforced

        message = json.loads(json.dumps(SEND))
        message["params"]["message"]["parts"] = [{"text": "Write to ada@example.com"}]
        resp, cp = ask(FakeOpa(masks), body=message, presidio=FakePresidio())
        assert resp.status_code == 200
        assert cp.records[0]["redacted"] == ["pii"]
        # Nothing in the message to mask: nothing masked.
        _, cp = ask(FakeOpa(masks), presidio=FakePresidio())
        assert cp.records[0]["redacted"] == []

    def test_organisation_policies_can_ask_for_approval(self) -> None:
        def wait(inp: dict[str, Any]) -> dict[str, Any]:
            return {
                **allow(inp),
                "effect": "require_approval",
                "reasons": ["billing needs a person"],
            }

        resp, cp = ask(FakeOpa(wait))
        assert resp.status_code == 403
        assert "Approval request apr_0123456789abcdef is pending" in resp.json()["error"]["message"]
        kind, payload = cp.calls[0]
        assert kind == "approval"
        assert (payload["action"], payload["resource"]) == ("SendMessage", "a2a/billing-agent")
        assert payload["arguments"] == {"parts": [{"text": "What does customer c-001 owe?"}]}
        approved, _ = ask(FakeOpa(wait), cp=FakeControlPlane(approval_outcome="approved"))
        assert approved.status_code == 200

    def test_policy_engine_outage_fails_closed(self) -> None:
        resp, _ = ask(FakeOpa(fail=True))
        assert resp.status_code == 403

    def test_without_a_service_token_no_delegation_is_given(self) -> None:
        resp, _ = ask(FakeOpa(allow), settings=Settings())
        assert resp.status_code == 200
        assert resp.headers[chains.HEADER] == ""
        assert resp.headers[chains.CALLER_HEADER] == "bot"


class TestAgentsTakeOnlyCallsThroughTheGateway:
    """What an agent runs to refuse calls around the gateway (agentgov.a2a_auth), with the
    delegation the gateway gives it and the keys the control plane publishes."""

    def given(self) -> str:
        resp, _ = ask(FakeOpa(allow))
        return resp.headers[chains.HEADER]

    def test_the_agent_called_knows_its_delegation_by_its_name_or_its_id(self) -> None:
        token = self.given()
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["aud"] == ["agt_2", "billing-agent"]
        for name in ("billing-agent", "agt_2"):
            got = a2a_auth.DelegationCheck(name, jwks=chains.jwks(KEYS))(token)
            assert [x["name"] for x in got["chain"]] == ["bot"]
        with pytest.raises(a2a_auth.DelegationRefused, match="isn't valid"):
            a2a_auth.DelegationCheck("crm-agent", jwks=chains.jwks(KEYS))(token)

    def test_calls_without_a_valid_delegation_are_refused(self) -> None:
        check = a2a_auth.DelegationCheck("billing-agent", jwks=chains.jwks(KEYS))
        now = int(time.time())
        claims = {
            "iss": "agentgov",
            "aud": ["agt_2", "billing-agent"],
            "jti": "dlg_1",
            "iat": now,
            "exp": now + 3600,
            "chain": [],
        }
        another = chains.keys("another-token")
        assert another is not None
        refused = {
            "carries no delegation": None,
            "doesn't publish": jwt.encode(
                claims, another.private, algorithm="ES256", headers={"kid": another.kid}
            ),
            # Signed as delegations were before: AgentGov checks those, agents needn't.
            "isn't valid": jwt.encode(claims, KEYS.legacy, algorithm="HS256"),
            "expired": jwt.encode(
                {**claims, "iat": now - 7200, "exp": now - 3600},
                KEYS.private,
                algorithm="ES256",
                headers={"kid": KEYS.kid},
            ),
        }
        for reason, token in refused.items():
            with pytest.raises(a2a_auth.DelegationRefused, match=reason):
                check(token)
        # The gateway gives one with each call: one given ten minutes ago came another way.
        earlier = jwt.encode(
            {**claims, "iat": now - 600}, KEYS.private, algorithm="ES256", headers={"kid": KEYS.kid}
        )
        with pytest.raises(a2a_auth.DelegationRefused, match="given for an earlier call"):
            check(earlier)
        lenient = a2a_auth.DelegationCheck("billing-agent", jwks=chains.jwks(KEYS), max_age=None)
        assert lenient(earlier)["jti"] == "dlg_1"

    def test_agentgovs_keys_are_read_once_and_kept(self) -> None:
        reads: list[str] = []
        published = {"body": json.dumps(chains.jwks(KEYS)).encode()}

        class Keys(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                reads.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(published["body"])

            def log_message(self, *args: Any) -> None:
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Keys)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/delegations/jwks"
        try:
            check = a2a_auth.DelegationCheck("billing-agent", jwks_url=url)
            token = self.given()
            assert check(token)["iss"] == "agentgov" and check(token)
            assert reads == ["/v1/delegations/jwks"]
            # A key AgentGov doesn't publish: read again, but not for every such call.
            another = chains.keys("another-token")
            assert another is not None
            forged = jwt.encode(
                jwt.decode(token, options={"verify_signature": False}),
                another.private,
                algorithm="ES256",
                headers={"kid": another.kid},
            )
            for _ in range(3):
                with pytest.raises(a2a_auth.DelegationRefused, match="doesn't publish"):
                    check(forged)
            assert len(reads) == 1  # read moments ago: not again within the retry interval
        finally:
            server.shutdown()
            server.server_close()
        # AgentGov can't be reached: the keys read last still check its delegations.
        assert check(token)["jti"]
        unreachable = a2a_auth.DelegationCheck("billing-agent", jwks_url=url)
        with pytest.raises(a2a_auth.DelegationRefused, match="keys can't be read"):
            unreachable(token)

    def test_the_middleware_refuses_calls_without_one_and_serves_the_card(self) -> None:
        seen: list[Any] = []

        async def agent_app(scope: Any, receive: Any, send: Any) -> None:
            seen.append(scope.get("state", {}).get("agentgov_delegation"))
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        check = a2a_auth.DelegationCheck("billing-agent", jwks=chains.jwks(KEYS))
        app = a2a_auth.RequireDelegation(agent_app, check=check, open_paths=("/healthz",))
        token = self.given()

        async def go() -> list[httpx.Response]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://billing"
            ) as client:
                return [
                    await client.post("/", json=SEND),
                    await client.post("/", json=SEND, headers={chains.HEADER: "forged"}),
                    await client.post("/", json=SEND, headers={chains.HEADER: token}),
                    await client.get("/.well-known/agent-card.json"),
                    await client.get("/healthz"),
                ]

        bare, forged, through, card, health = asyncio.run(go())
        assert bare.status_code == forged.status_code == 401
        assert bare.json()["error"]["code"] == a2a_auth.REFUSED == -32600
        assert "didn't come through the gateway" in bare.json()["error"]["message"]
        assert "isn't valid" in forged.json()["error"]["message"]
        assert through.status_code == card.status_code == health.status_code == 200
        assert seen[0]["aud"] == ["agt_2", "billing-agent"] and seen[1:] == [None, None]

        sent: list[dict[str, Any]] = []

        async def collect(message: dict[str, Any]) -> None:
            sent.append(message)

        socket = {"type": "websocket", "path": "/ws", "headers": []}
        asyncio.run(app(socket, None, collect))  # type: ignore[arg-type]
        assert sent == [{"type": "websocket.close", "code": 1008}]
        with pytest.raises(ValueError, match="name the agent"):
            a2a_auth.RequireDelegation(agent_app)
        with pytest.raises(ValueError, match="jwks_url or as jwks"):
            a2a_auth.DelegationCheck("billing-agent")

    def test_the_control_plane_publishes_the_keys_to_anyone(self, client, settings) -> None:
        resp = client.get("/v1/delegations/jwks")
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "public, max-age=300"
        found = chains.keys(settings.service_token)
        assert found is not None and resp.json() == chains.jwks(found)
        assert client.get("/v1/info").json()["delegation_jwks"] == "/v1/delegations/jwks"
        unsigned = create_app(dataclasses.replace(settings, service_token=None), background=False)
        with TestClient(unsigned) as other:
            assert other.get("/v1/delegations/jwks").json() == {"keys": []}
            assert other.get("/v1/info").json()["delegation_jwks"] is None


class TestChainsOnToolsAndModels:
    def test_a_tool_call_handed_down_has_its_chain_in_policy_and_the_record(self) -> None:
        opa = FakeOpa()
        token, incoming = delegation()
        request = call_request("get_customer", {"id": "c-1"})
        request.headers.append(pb.McpHeader(key=chains.HEADER, value=token.encode()))
        reply, cp = run(opa, settings=SETTINGS, request=request)
        assert reply.WhichOneof("result") != "error"
        inp = opa.inputs[0][1]
        assert [x["name"] for x in inp["chain"]] == ["sam", "frontdesk"]
        assert inp["user"]["username"] == "sam"
        assert cp.records[0]["delegation"]["uid"] == incoming.uid

    def test_a_forged_delegation_stops_a_tool_call(self) -> None:
        request = call_request("get_customer", {"id": "c-1"})
        request.headers.append(pb.McpHeader(key=chains.HEADER, value=b"forged"))
        reply, cp = run(FakeOpa(), settings=SETTINGS, request=request)
        assert reply.WhichOneof("result") == "error"
        assert "isn't one AgentGov gave" in reply.error.reason
        assert cp.records[0]["effect"] == "deny" and cp.records[0]["agent"] == {"id": AGENT["id"]}

    def test_a_model_call_handed_down_has_its_chain(self) -> None:
        from tests.test_model_guard import allow as model_allow

        opa = FakeOpa(model_allow())
        token, incoming = delegation()

        async def go() -> FakeControlPlane:
            cp = FakeControlPlane()
            recorder = DecisionRecorder(cp)
            processor = GovernanceProcessor(SETTINGS, opa=opa, control_plane=cp, recorder=recorder)
            app = ModelGuard(processor).app()
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://processor"
            ) as client:
                resp = await client.post(
                    "/request",
                    json=prompt(user("Summarise c-001")),
                    headers={**MODEL_HEADERS, chains.HEADER: token},
                )
                assert resp.json() == {"action": {}}
                bad = await client.post(
                    "/request",
                    json=prompt(user("Summarise c-001")),
                    headers={**MODEL_HEADERS, chains.HEADER: "forged"},
                )
                assert bad.json()["action"]["status_code"] == 403
            await recorder.flush()
            return cp

        cp = asyncio.run(go())
        inp = opa.inputs[0][1]
        assert inp["chain"][0]["name"] == "sam" and inp["user"]["username"] == "sam"
        assert cp.records[0]["delegation"]["uid"] == incoming.uid
        assert cp.records[1]["effect"] == "deny"
        assert cp.records[1]["agent"] == {"id": MODEL_HEADERS["x-agentgov-agent-id"]}


# ---------------------------------------------------------------------- gateway


def _agent(name: str, status: str = ACTIVE, url: str | None = "http://billing:9600") -> Agent:
    return Agent(id=f"agt_{name}", name=name, status=status, a2a_url=url, source="registered")


class TestGatewayRoutes:
    settings = Settings(
        keycloak_issuer="http://kc/realms/agentgov",
        keycloak_jwks_url="http://kc/certs",
        processor_webhook_address="processor:8091",
    )

    def routes(self, agents: list[Agent], **modes: str) -> dict[str, Any]:
        config = render([], self.settings, modes, [], agents)
        return {r["name"]: r for r in config["binds"][0]["listeners"][0]["routes"]}

    def test_agents_that_serve_a2a_are_published(self) -> None:
        routes = self.routes(
            [
                _agent("billing-agent"),
                _agent("kb", url="https://kb.internal:8443/a2a/"),
                _agent("held", status=BLOCKED),
                _agent("new", status=PENDING),
                _agent("plain", url=None),
                _agent("v6", url="http://[fd00::7]:9600"),
            ]
        )
        assert set(routes) == {
            "a2a-billing-agent",
            "a2a-kb",
            "a2a-held",
            "a2a-v6",
            "agentgov-health",
        }
        assert routes["a2a-v6"]["backends"] == [{"host": "[fd00::7]:9600"}]
        billing = routes["a2a-billing-agent"]
        assert billing["matches"] == [{"path": {"pathPrefix": "/a2a/billing-agent"}}]
        assert billing["backends"] == [{"host": "billing:9600"}]
        policies = billing["policies"]
        assert policies["a2a"] == {} and policies["urlRewrite"] == {"path": {"prefix": "/"}}
        assert policies["jwtAuth"]["audiences"] == ["agentgov-gateway"]
        check = policies["extAuthz"]
        assert check["host"] == "processor:8091" and check["failureMode"] == "deny"
        http = check["protocol"]["http"]
        assert http["path"] == '"/a2a/check/billing-agent"'
        assert http["includeResponseHeaders"] == [
            chains.HEADER,
            chains.CALLER_HEADER,
            chains.PERSON_HEADER,
            chains.CHAIN_HEADER,
        ]
        assert http["addRequestHeaders"][chains.HEADER] == f'request.headers["{chains.HEADER}"]'
        assert http["addRequestHeaders"]["x-agentgov-agent-id"] == "jwt.agent_id"
        # Answers come back through the processor, asked for plain so that it can read them.
        assert policies["extProc"]["failureMode"] == "failClosed"
        assert policies["requestHeaderModifier"] == {"set": {"accept-encoding": "identity"}}
        kb = routes["a2a-kb"]["policies"]
        assert kb["urlRewrite"] == {"path": {"prefix": "/a2a"}} and kb["backendTLS"] == {}
        assert routes["a2a-kb"]["backends"] == [{"host": "kb.internal:8443"}]

    def test_messages_go_through_the_processor_while_masking_is_enforced(self) -> None:
        def options(**modes: str) -> dict[str, Any]:
            route = self.routes([_agent("billing-agent")], **modes)["a2a-billing-agent"]
            return route["policies"]["extProc"]["processingOptions"]

        assert options()["requestBodyMode"] == "none"  # monitored, by default
        enforced = options(**{"a2a-masking": "enforce"})
        assert (enforced["requestHeaderMode"], enforced["requestBodyMode"]) == (
            "send",
            "fullDuplexStreamed",
        )
        # Data protection off finds nothing to mask.
        off = options(**{"a2a-masking": "enforce", "data-protection": "off"})
        assert off["requestBodyMode"] == "none"

    def test_answers_go_unchecked_with_both_controls_off(self) -> None:
        modes = {"data-protection": "off", "prompt-injection": "off"}
        policies = self.routes([_agent("billing-agent")], **modes)["a2a-billing-agent"]["policies"]
        assert "extProc" not in policies and "requestHeaderModifier" not in policies

    def test_off_publishes_none(self) -> None:
        assert set(self.routes([_agent("billing-agent")], **{"a2a-gateway": "off"})) == {
            "agentgov-health"
        }

    def test_model_calls_pass_the_delegation_to_the_processor(self) -> None:
        from agentgov.models import ModelProvider

        provider = ModelProvider(name="openai", kind="openai", status="approved")
        config = render([], self.settings, {}, [provider], [])
        route = config["binds"][0]["listeners"][0]["routes"][0]
        hook = route["policies"]["ai"]["promptGuard"]["request"][0]["webhook"]
        assert hook["headers"][chains.HEADER] == f'request.headers["{chains.HEADER}"]'


# --------------------------------------------------------- registry and ledger


class TestRegistry:
    def test_agents_and_blueprints_say_whom_they_may_call(self, client) -> None:
        seed(client)
        bp = client.patch(
            "/v1/blueprints/support", json={"agent_access": ["kb", "billing-*"]}, headers=ADMIN
        ).json()
        assert bp["agent_access"] == ["kb", "billing-*"]
        agent = client.patch(
            "/v1/agents/support-bot",
            json={"a2a_url": "http://support-bot:9600/", "agent_access": ["payroll", "kb"]},
            headers=ADMIN,
        ).json()
        assert agent["a2a_url"] == "http://support-bot:9600"
        assert agent["a2a_route"] == "/a2a/support-bot"
        assert agent["agent_access"] == ["payroll", "kb"]
        assert agent["effective_agent_access"] == ["kb", "billing-*", "payroll"]
        for bad in (
            {"a2a_url": "ftp://x"},
            {"a2a_url": "http://u:p@x"},
            {"a2a_url": "http://billing:port"},
            {"a2a_url": "http://billing:99999"},
            {"agent_access": ["Billing Agent"]},
            {"agent_access": "kb"},
        ):
            assert (
                client.patch("/v1/agents/support-bot", json=bad, headers=ADMIN).status_code == 422
            ), bad
        cleared = client.patch("/v1/agents/support-bot", json={"a2a_url": None}, headers=ADMIN)
        assert cleared.json()["a2a_route"] is None

    def test_the_bundle_has_what_policy_needs(self, client, rt) -> None:
        seed(client)
        client.patch(
            "/v1/agents/support-bot",
            json={"a2a_url": "http://support-bot:9600", "agent_access": ["kb"]},
            headers=ADMIN,
        ).raise_for_status()
        with rt.db.session() as s:
            data = registry_snapshot(s)
        agent_id = data["agent_names"]["support-bot"]
        assert data["agents"][agent_id]["a2a"] is True
        assert data["agents"][agent_id]["agent_access"] == ["kb"]

    def test_manifests_round_trip(self, client, rt) -> None:
        seed(client)
        docs = manifests.parse(
            """
apiVersion: agentgov/v1alpha1
kind: Agent
metadata: {name: support-bot}
spec:
  blueprint: support
  owner: cx
  sponsors: [alice@example.com]
  a2a_url: http://support-bot:9600
  agent_access: [kb]
"""
        )
        with rt.db.session() as s:
            [result] = manifests.apply(s, rt.settings, docs, actor="admin:ada")
            assert result["action"] == "configured"
            exported = next(
                d for d in manifests.export(s) if d["metadata"]["name"] == "support-bot"
            )
        assert exported["spec"]["a2a_url"] == "http://support-bot:9600"
        assert exported["spec"]["agent_access"] == ["kb"]

    def test_decisions_between_agents_are_in_the_ledger_with_their_chain(self, client, rt) -> None:
        agent = seed(client)
        record = {
            "kind": "a2a",
            "phase": "request",
            "method": "SendMessage",
            "server": "billing-agent",
            "target": "billing-agent",
            "resource": "billing-agent",
            "agent": {"id": agent["id"], "name": "support-bot"},
            "identity": {"agent_id": agent["id"]},
            "user": SAM,
            "effect": "allow",
            "reasons": [],
            "detections": {},
            "a2a": {"target": "billing-agent", "target_id": "agt_2", "context_id": "ctx-1"},
            "delegation": {"chain": [chains.person_link(SAM)], "uid": "dlg_1", "parent_uid": None},
        }
        with rt.db.session() as s:
            decisions.record_mcp_decisions(s, rt.settings, [record])
        entry = client.get("/v1/ledger", params={"type": "decision.a2a.request"}, headers=ADMIN)
        [got] = entry.json()
        assert (got["action"], got["resource"], got["on_behalf_of"]) == (
            "SendMessage",
            "billing-agent",
            "sam",
        )
        assert [x["name"] for x in got["details"]["chain"]] == [
            "sam",
            "support-bot",
            "billing-agent",
        ]
        assert got["details"]["delegation"] == {"uid": "dlg_1"}
        with rt.db.session() as s:
            row = s.scalar(select(LedgerEntry).where(LedgerEntry.id == got["id"]))
            event = ocsf.event(row)
        assert event["activity_name"] == "Agent call"
        assert event["api"]["service"]["name"] == "billing-agent"
        assert event["resources"] == [{"name": "billing-agent", "type": "AI Agent", "uid": "agt_2"}]
        assert event["delegation"] == {"uid": "dlg_1", "issuer_uid": "agentgov"}
        assert event["message_context"]["uid"] == "ctx-1"


def _billing(client, *, a2a_url: str = "http://billing-agent:9600") -> dict[str, Any]:
    resp = client.post(
        "/v1/agents",
        json={
            "name": "billing-agent",
            "owner": "finance",
            "sponsors": ["bob@example.com"],
            "a2a_url": a2a_url,
            "approve": True,
        },
        headers=ADMIN,
    )
    resp.raise_for_status()
    return resp.json()


def _a2a_record(agent: dict[str, Any], target: str, effect: str) -> dict[str, Any]:
    return {
        "kind": "a2a",
        "phase": "request",
        "method": "SendMessage",
        "server": target,
        "target": target,
        "resource": target,
        "agent": {"id": agent["id"], "name": agent["name"]},
        "identity": {"agent_id": agent["id"]},
        "effect": effect,
        "reasons": [] if effect == "allow" else [f"Agent {agent['name']} may not call {target}"],
        "detections": {},
        "a2a": {"target": target},
        "delegation": {"chain": []},
    }


class TestApiAndCli:
    def test_whom_an_agent_may_call_and_who_calls_it(self, client) -> None:
        seed(client)
        client.patch(
            "/v1/blueprints/support", json={"agent_access": ["billing-*"]}, headers=ADMIN
        ).raise_for_status()
        _billing(client)
        view = client.get("/v1/agents/billing-agent/a2a", headers=ADMIN).json()
        assert view["serves"] is True and view["published"] is True
        assert view["url"].endswith("/a2a/billing-agent")
        assert view["card_url"] == view["url"] + "/.well-known/agent-card.json"
        assert (view["may_call"], view["called_by"]) == ([], ["support-bot"])
        view = client.get("/v1/agents/support-bot/a2a", headers=ADMIN).json()
        assert view["serves"] is False and view["url"] is None
        assert (view["may_call"], view["agent_access"]) == (["billing-agent"], ["billing-*"])
        # Agents the gateway doesn't publish say why.
        client.post(
            "/v1/agents",
            json={"name": "kb", "a2a_url": "http://kb:9600", "sponsors": ["bob@example.com"]},
            headers=ADMIN,
        ).raise_for_status()
        view = client.get("/v1/agents/kb/a2a", headers=ADMIN).json()
        assert (view["published"], view["unpublished"]) == (False, "it is pending")
        client.put("/v1/features/a2a-gateway", json={"mode": "off"}, headers=ADMIN)
        view = client.get("/v1/agents/billing-agent/a2a", headers=ADMIN).json()
        assert view["unpublished"] == "the a2a-gateway feature is off"

    def test_the_map_shows_agents_calling_agents(self, client, rt) -> None:
        bot = seed(client)
        client.patch(
            "/v1/blueprints/support", json={"agent_access": ["billing-*"]}, headers=ADMIN
        ).raise_for_status()
        billing = _billing(client)
        kb = client.post(
            "/v1/agents",
            json={"name": "kb", "owner": "it", "sponsors": ["bob@example.com"],
                  "a2a_url": "http://kb:9600", "approve": True},
            headers=ADMIN,
        ).json()  # fmt: skip
        records = [_a2a_record(bot, "billing-agent", "allow")] * 2
        records.append(_a2a_record(bot, "kb", "deny"))
        with rt.db.session() as s:
            decisions.record_mcp_decisions(s, rt.settings, records)
        graph = client.get("/v1/graph", headers=ADMIN).json()
        calls = {
            (e["to"], e["kind"]): (e["calls"], e["denied"])
            for e in graph["edges"]
            if e["from"] == f"agent:{bot['id']}" and e["kind"].startswith("calls")
        }
        assert calls == {
            (f"agent:{billing['id']}", "calls"): (2, 0),
            (f"agent:{kb['id']}", "calls-ungranted"): (1, 1),
        }

    def test_cli(self, client, monkeypatch) -> None:
        def agentgov(*args: str):
            monkeypatch.setattr(cli, "_client", lambda: _Shared(client, "test-admin"))
            return runner.invoke(cli.app, list(args))

        seed(client)
        ok(agentgov("blueprints", "update", "support", "--agent-access", "billing-*,kb"))
        assert client.get("/v1/blueprints/support", headers=ADMIN).json()["agent_access"] == [
            "billing-*",
            "kb",
        ]
        ok(agentgov("agents", "create", "billing-agent", "--owner", "finance",
                    "--sponsor", "bob@example.com", "--a2a-url", "http://billing-agent:9600/",
                    "--approve"))  # fmt: skip
        billing = client.get("/v1/agents/billing-agent", headers=ADMIN).json()
        assert (billing["a2a_url"], billing["a2a_route"]) == (
            "http://billing-agent:9600",
            "/a2a/billing-agent",
        )
        out = ok(agentgov("agents", "a2a", "billing-agent"))
        assert "serves A2A at http://billing-agent:9600; other agents call it at" in out
        assert "/a2a/billing-agent/.well-known/agent-card.json" in out
        assert "called by: support-bot" in out
        out = ok(agentgov("agents", "a2a", "support-bot"))
        assert "doesn't serve A2A" in out
        assert "may call: billing-agent" in out and "(grants: billing-*, kb)" in out
        ok(agentgov("agents", "update", "support-bot", "--agent-access", "payroll"))
        bot = client.get("/v1/agents/support-bot", headers=ADMIN).json()
        assert bot["agent_access"] == ["payroll"]
        assert bot["effective_agent_access"] == ["billing-*", "kb", "payroll"]
        ok(agentgov("agents", "update", "support-bot", "--no-agent-access"))
        ok(agentgov("agents", "update", "billing-agent", "--no-a2a"))
        assert client.get("/v1/agents/support-bot", headers=ADMIN).json()["agent_access"] == []
        assert client.get("/v1/agents/billing-agent", headers=ADMIN).json()["a2a_url"] is None
        bad = agentgov("agents", "update", "billing-agent", "--a2a-url", "ftp://billing")
        assert bad.exit_code == 1 and "error 422" in bad.output
        ok(agentgov("blueprints", "update", "support", "--no-agent-access"))
        assert client.get("/v1/blueprints/support", headers=ADMIN).json()["agent_access"] == []

    def test_what_if_for_a_call_between_agents(self, monkeypatch) -> None:
        sent = []

        def fake_call(method: str, path: str, **kwargs: Any) -> Any:
            if path == "/v1/agents/bot":
                return {"id": "agt_1", "identity": {"client_id": "agent-bot"}}
            sent.append(kwargs["json"])
            return {
                "result": {
                    "effect": "deny",
                    "reasons": ["Agent bot may not call agent payroll"],
                    "monitored": [],
                }
            }

        monkeypatch.setattr(cli, "_call", fake_call)
        args = ["policies", "evaluate", "--call-agent", "payroll", "--agent", "bot"]
        out = ok(runner.invoke(cli.app, args))
        assert out.splitlines()[0] == "deny"
        assert "Agent bot may not call agent payroll" in out
        body = sent[0]
        assert body["path"] == "agentgov/a2a/decision"
        assert body["input"]["kind"] == "a2a" and body["input"]["target"] == "payroll"
        assert body["input"]["chain"] == []
        assert body["input"]["agent"] == {"agent_id": "agt_1", "client_id": "agent-bot"}
        # For a person: the person heads the chain.
        ok(runner.invoke(cli.app, [*args, "--user", "sam"]))
        assert sent[-1]["input"]["chain"] == [{"type": "person", "id": "sam", "name": "sam"}]
        assert sent[-1]["input"]["user"]["username"] == "sam"
        # One kind of call at a time.
        both = [*args, "--server", "crm", "--tool", "get_customer"]
        assert runner.invoke(cli.app, both).exit_code == 2

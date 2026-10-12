"""A billing agent for the AgentGov demo: other agents hand it billing questions over A2A
(1.0, the JSON-RPC binding), through the gateway at /a2a/billing-agent.

To answer, it looks the customer up in the CRM, through the gateway too, as itself. It
has no secret: it authenticates with the service account token its cluster gives it
(the stand-in in examples/identity/workload-issuer), as a pod reads its projected token.
The work was handed to it, so the calls it makes for a request carry the delegation
AgentGov gave it with that request (the X-AgentGov-Delegation header): policy and the
ledger then see who handed the work down, up to the person at the head of the chain.

    GET  /.well-known/agent-card.json   its agent card
    POST /                              A2A JSON-RPC: SendMessage, GetTask

It takes only calls that came through the gateway: each one AgentGov lets through carries
the delegation, which it checks with AgentGov's public keys (DELEGATION_JWKS_URL), and a
call around the gateway has none (docs/agent-to-agent.md#calls-around-the-gateway).

Not for real use: it keeps tasks in memory.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx2
import jwt
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

NAME = os.environ.get("AGENT_NAME", "billing-agent")
# Where it serves A2A, as the gateway reaches it. The gateway tells callers its own URL.
URL = os.environ.get("PUBLIC_URL", "http://billing-agent:9600")
GATEWAY = os.environ.get("GATEWAY_URL", "http://agentgateway:8080").rstrip("/")
# Its Keycloak client (AgentGov creates it), and the token its cluster gives it.
TOKEN_URL = os.environ.get(
    "TOKEN_URL", "http://keycloak:8080/realms/agentgov/protocol/openid-connect/token"
)
AUDIENCE = os.environ.get("ASSERTION_AUDIENCE", "http://localhost:8180/realms/agentgov")
CLIENT_ID = os.environ.get("CLIENT_ID", f"agent-{NAME}")
WORKLOAD_ISSUER = os.environ.get("WORKLOAD_ISSUER", "http://workload-issuer:9200").rstrip("/")
SUBJECT = os.environ.get("SUBJECT", f"system:serviceaccount:agents:{NAME}")
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# What the gateway tells it with each request: who handed it the work. AgentGov sets
# these on every call it lets through, so no caller can set them itself.
DELEGATION = "x-agentgov-delegation"
CALLER = "x-agentgov-caller"
ON_BEHALF_OF = "x-agentgov-on-behalf-of"
CHAIN = "x-agentgov-chain"
# AgentGov's public keys, to check the delegation each call carries. Unset, it takes any
# call, as an agent that doesn't check does.
JWKS_URL = os.environ.get("DELEGATION_JWKS_URL", "")
_KEYS = jwt.PyJWKClient(JWKS_URL, cache_jwk_set=True, lifespan=300) if JWKS_URL else None

CARD = {
    "name": NAME,
    "description": "Answers billing questions about customers: what they owe, and when.",
    "version": "1.0.0",
    "supportedInterfaces": [{"url": URL, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
    "capabilities": {"streaming": False, "pushNotifications": False},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain", "application/json"],
    "skills": [
        {
            "id": "balance",
            "name": "Customer balance",
            "description": "What a customer owes and when it is due, by customer ID (c-001).",
            "tags": ["billing", "crm"],
            "examples": ["What does customer c-001 owe?"],
        }
    ],
}
# The invoices it knows about; the CRM knows the customers.
INVOICES = {
    "c-001": ("INV-2041", "1,250.00", "1 November"),
    "c-002": ("INV-2057", "310.40", "15 November"),
    "c-003": ("INV-2066", "0.00", "nothing due"),
}
CUSTOMER_ID = re.compile(r"\bc-\d{3}\b")
TASKS: dict[str, dict[str, Any]] = {}
_token: dict[str, Any] = {}
log = logging.getLogger("billing-agent")


async def access_token() -> str:
    """Its own access token: client credentials, with its service account token in place
    of a secret (RFC 7523), as AgentGov's workload identity sets its client up."""
    if _token.get("expires", 0) > time.time() + 30:
        return str(_token["value"])
    async with httpx2.AsyncClient(timeout=30.0) as http:
        issued = await http.post(
            f"{WORKLOAD_ISSUER}/token", json={"subject": SUBJECT, "audience": AUDIENCE}
        )
        issued.raise_for_status()
        resp = await http.post(
            TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_assertion_type": JWT_BEARER,
                "client_assertion": issued.json()["token"],
            },
        )
        resp.raise_for_status()
    body = resp.json()
    _token.update(value=body["access_token"], expires=time.time() + int(body.get("expires_in", 60)))
    return str(_token["value"])


async def get_customer(customer_id: str, delegation: str | None) -> tuple[bool, Any]:
    """The customer, from the CRM through the gateway: ``(allowed, record_or_reason)``."""
    headers = {"Authorization": f"Bearer {await access_token()}"}
    if delegation:
        headers["X-AgentGov-Delegation"] = delegation
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=60.0)) as http,
        Client(
            streamable_http_client(f"{GATEWAY}/mcp/crm", http_client=http),
            client_info=Implementation(name=NAME, version="1.0.0"),
        ) as client,
    ):
        try:
            result = await client.call_tool("get_customer", {"customer_id": customer_id})
        except MCPError as exc:
            return False, exc.message
    text = " ".join(b.text for b in result.content if isinstance(b, TextContent))
    if result.is_error:
        return False, text
    return True, result.structured_content or {"text": text}


def message(text: str, context_id: str, task_id: str) -> dict[str, Any]:
    return {
        "messageId": str(uuid.uuid4()),
        "role": "ROLE_AGENT",
        "parts": [{"text": text}],
        "contextId": context_id,
        "taskId": task_id,
    }


async def send_message(params: dict[str, Any], request: Request) -> dict[str, Any]:
    asked = params.get("message") if isinstance(params.get("message"), dict) else {}
    text = " ".join(
        str(p.get("text") or "") for p in asked.get("parts") or [] if isinstance(p, dict)
    )
    task_id = str(uuid.uuid4())
    context_id = str(asked.get("contextId") or uuid.uuid4())
    task: dict[str, Any] = {"id": task_id, "contextId": context_id, "history": [asked]}
    # Who handed it the work, as AgentGov tells it.
    caller = request.headers.get(CALLER) or "an agent"
    person = request.headers.get(ON_BEHALF_OF)
    chain = request.headers.get(CHAIN)
    asked_by = f"Asked by {caller}" + (f" for {person}" if person else "")
    asked_by += f" ({chain} > {NAME})" if chain else ""
    found = CUSTOMER_ID.search(text)
    if found is None:
        state, reply = "TASK_STATE_INPUT_REQUIRED", "Which customer? Give their ID, such as c-001."
    else:
        allowed: bool | None
        try:
            allowed, record = await get_customer(found.group(), request.headers.get(DELEGATION))
        except Exception as exc:
            log.exception("looking up %s failed", found.group())
            allowed, record = None, f"The CRM could not be reached ({type(exc).__name__})"
        invoice = INVOICES.get(found.group())
        if allowed is None:
            state, reply = "TASK_STATE_FAILED", str(record)
        elif not allowed:
            state, reply = "TASK_STATE_FAILED", f"The CRM refused: {record}"
        elif invoice is None:
            state, reply = "TASK_STATE_COMPLETED", f"{found.group()} has no invoices."
        else:
            number, amount, due = invoice
            tier = record.get("tier", "?") if isinstance(record, dict) else "?"
            state = "TASK_STATE_COMPLETED"
            reply = f"{found.group()} ({tier} tier) owes ${amount} on {number}, due {due}."
            task["artifacts"] = [
                {
                    "artifactId": str(uuid.uuid4()),
                    "name": "customer",
                    "parts": [{"data": record, "mediaType": "application/json"}],
                }
            ]
    answer = message(f"{reply} {asked_by}.", context_id, task_id)
    task["status"] = {
        "state": state,
        "message": answer,
        "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    task["history"].append(answer)
    TASKS[task_id] = task
    while len(TASKS) > 1000:
        TASKS.pop(next(iter(TASKS)))
    return {"task": task}


def rpc_error(rpc_id: Any, code: int, text: str, status: int = 200) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": text}},
        status_code=status,
    )


def around_the_gateway(delegation: str | None) -> str | None:
    """Why a call can't be taken, if it didn't come through AgentGov's gateway: the
    delegation it carries, signed by AgentGov for this agent, says it did."""
    if _KEYS is None:
        return None
    if not delegation:
        return "it didn't come through AgentGov's gateway"
    try:
        key = _KEYS.get_signing_key_from_jwt(delegation).key
        claims = jwt.decode(
            delegation,
            key,
            algorithms=["ES256"],
            audience=NAME,
            issuer="agentgov",
            leeway=30,
            options={"require": ["exp", "iat"]},
        )
    except jwt.PyJWTError as exc:
        return f"the delegation it carries isn't valid ({exc})"
    # The gateway gives one with each call, moments before: an old one came another way.
    if time.time() - claims["iat"] > 150:
        return "the delegation it carries was given for an earlier call"
    return None


async def rpc(request: Request) -> JSONResponse:
    refused = await asyncio.to_thread(around_the_gateway, request.headers.get(DELEGATION))
    if refused:
        return rpc_error(None, -32600, f"Refused: {refused}", status=401)
    try:
        body = await request.json()
    except ValueError:
        return rpc_error(None, -32700, "Parse error")
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        return rpc_error(None, -32600, "Invalid request")
    rpc_id, method = body.get("id"), body.get("method")
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    if method == "SendMessage":
        result = await send_message(params, request)
    elif method == "GetTask":
        task = TASKS.get(str(params.get("id")))
        if task is None:
            return rpc_error(rpc_id, -32001, "Task not found")
        result = task
    else:
        return rpc_error(rpc_id, -32601, f"Method not found: {method}")
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": result})


async def card(_: Request) -> JSONResponse:
    return JSONResponse(CARD)


async def healthz(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app = Starlette(
    routes=[
        Route("/", rpc, methods=["POST"]),
        Route("/.well-known/agent-card.json", card, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]
)

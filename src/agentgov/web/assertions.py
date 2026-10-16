"""AgentGov as the issuer of identity assertions (ID-JAG) for MCP servers outside the
gateway (docs/acting-for-people.md#mcp-servers-outside-the-gateway), while the
identity-assertions feature is on: its metadata (RFC 8414), its keys, and its token
endpoint, where an agent exchanges the token it has for the gateway for an assertion
(RFC 8693). OPA decides, through ``data.agentgov.idjag.decision``; the ledger records
each assertion given, or refused (``decision.assertion``)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

import httpx
from django.http import HttpRequest, HttpResponse

from agentgov import db, ids, ledger
from agentgov.db.models import Agent, ToolServer
from agentgov.identity import assertions, people
from agentgov.registry import features
from agentgov.web.api import HTTPException, Router, json_response
from agentgov.web.auth import runtime

router = Router(tags=["identity assertions"])
FEATURE = "identity-assertions"
POLICY = "agentgov/idjag/decision"
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_tokens_lock = threading.Lock()


def _on(request: HttpRequest) -> None:
    with runtime(request).db.session() as s:
        if not features.is_on(s, FEATURE):
            raise HTTPException(404, "AgentGov doesn't give identity assertions here")


@router.get(assertions.METADATA_PATH)
def metadata(request: HttpRequest) -> dict[str, Any]:
    """AgentGov's metadata as the issuer of identity assertions."""
    _on(request)
    return assertions.metadata(runtime(request).settings.public_url)


@router.get(assertions.JWKS_PATH)
def jwks(request: HttpRequest) -> HttpResponse:
    """The public key authorization servers check AgentGov's assertions with. Served with
    the feature off too, while assertions given before may still be traded."""
    key = assertions.signing_key(runtime(request).settings.key_secret)
    return json_response(assertions.jwks(key), headers={"Cache-Control": "public, max-age=300"})


@router.post(assertions.TOKEN_PATH)
def token(request: HttpRequest) -> HttpResponse:
    """An identity assertion for an MCP server outside the gateway, for the agent whose
    token this is, or the person it got the token for (OAuth 2.0 Token Exchange)."""
    _on(request)
    kind = request.headers.get("content-type") or ""
    try:
        answer = _exchange(runtime(request), request.body, kind)
    except assertions.Refused as refused:
        return json_response(refused.body(), refused.status, headers=NO_STORE)
    return json_response(answer, headers=NO_STORE)


def _subject_tokens(rt: Any) -> assertions.SubjectTokens:
    """The checker of the tokens agents bring, made once."""
    with _tokens_lock:
        found = getattr(rt, "subject_tokens", None)
        if found is None:
            settings = rt.settings
            found = assertions.SubjectTokens(
                settings.keycloak_issuer, settings.keycloak_jwks_url, settings.gateway_audience
            )
            rt.subject_tokens = found
        return found


def _server(s: db.Where, request: assertions.Request) -> ToolServer:
    """The tool server the assertion is for: the one registered with that authorization
    server, or, of several, the one at the resource asked for."""
    listed = list(ToolServer.objects.filter(authorization_server=request.audience))
    if request.resource:
        listed = [ts for ts in listed if ts.url == request.resource]
    if len(listed) == 1:
        return listed[0]
    if not listed:
        where = f" at {request.resource}" if request.resource else ""
        raise assertions.Refused(
            "invalid_target",
            f"no MCP server{where} is registered with authorization server {request.audience}",
        )
    raise assertions.Refused(
        "invalid_target",
        f"several MCP servers take tokens from {request.audience}: name one with resource",
    )


def _decide(rt: Any, opa_input: dict[str, Any]) -> dict[str, Any]:
    url = rt.settings.opa_url
    if not url:
        raise assertions.Refused("temporarily_unavailable", "OPA isn't configured", 503)
    try:
        resp = httpx.post(
            f"{url.rstrip('/')}/v1/data/{POLICY}",
            json={"input": opa_input},
            timeout=5,
            verify=rt.tls.client_context() if rt.tls else True,
        )
    except httpx.HTTPError:
        raise assertions.Refused(
            "temporarily_unavailable", "AgentGov's policies can't be asked", 503
        ) from None
    result = resp.json().get("result") if resp.status_code == 200 else None
    if not isinstance(result, dict) or result.get("effect") not in ("allow", "deny"):
        raise assertions.Refused(
            "temporarily_unavailable", "AgentGov's policies didn't decide", 503
        )
    return result


def _agent(s: db.Where, identity: dict[str, Any]) -> Agent | None:
    found = (
        Agent.objects.filter(pk=identity["agent_id"]).first() if identity.get("agent_id") else None
    )
    if found is None and identity.get("client_id"):
        found = Agent.objects.filter(client_id=identity["client_id"]).first()
    return found


def _exchange(rt: Any, body: bytes, kind: str) -> dict[str, Any]:
    settings = rt.settings
    if not kind.startswith("application/x-www-form-urlencoded"):
        raise assertions.Refused(
            "invalid_request", "send the request as a form (application/x-www-form-urlencoded)"
        )
    request = assertions.parse(assertions.form(body))
    key = assertions.signing_key(settings.key_secret)
    if key is None or not (settings.keycloak_issuer and settings.keycloak_jwks_url):
        raise assertions.Refused(
            "temporarily_unavailable", "AgentGov isn't set up to give identity assertions", 503
        )
    claims = _subject_tokens(rt).check(request.subject_token, request.subject_token_type)
    identity, person = assertions.caller(claims, request.subject_token_type)
    # What the registry says, then the policies (no transaction held while they decide),
    # then the record.
    with rt.db.session() as s:
        server = _server(s, request)
        target = {"name": server.name, "url": server.url, "client_id": server.oauth_client_id}
        agent = _agent(s, identity)
        agent_id, agent_client = (agent.id, agent.client_id) if agent else (None, None)
    decision = _decide(
        rt,
        {
            "agent": identity,
            "user": person,
            "resource": {"server": target["name"]},
            "scope": request.scope,
        },
    )
    reasons = [str(r) for r in decision.get("reasons") or []]
    monitored = [str(m) for m in decision.get("monitored") or []]
    effect = str(decision["effect"])
    # The client the agent is at the server's authorization server: the one the server
    # names, or the agent's own.
    client_id = target["client_id"] or agent_client or identity.get("client_id") or ""
    resource = request.resource or target["url"]
    details: dict[str, Any] = {
        "audience": request.audience,
        "resource": resource,
        "client_id": client_id,
        "scope": request.scope,
        "monitored": monitored,
        "identity": identity,
        **({"user": person} if person else {}),
    }
    answer: dict[str, Any] = {}
    refused: assertions.Refused | None = None
    if effect == "allow":
        assertion, issued = assertions.issue(
            key,
            issuer=settings.public_url,
            subject=str(person["id"] if person else claims["sub"]),
            audience=request.audience,
            client_id=client_id,
            resource=resource,
            actor=(agent_client or identity.get("client_id")) if person else None,
            scope=request.scope,
            email=(person or {}).get("email"),
            lifetime=settings.assertion_lifetime_seconds,
        )
        details["jti"] = issued["jti"]
        details["expires_at"] = ids.isoformat(datetime.fromtimestamp(issued["exp"], UTC))
        answer = assertions.response(assertion, issued)
    else:
        said = "; ".join(reasons) or "AgentGov's policies refused it"
        refused = assertions.Refused("invalid_target", said)
    if not reasons and monitored:
        reason = "monitored: " + "; ".join(monitored)
    else:
        reason = "; ".join(reasons) or None
    with rt.db.session() as s:
        agent = Agent.objects.filter(pk=agent_id).first() if agent_id else None
        client = identity.get("client_id") or "unknown"
        ledger.append(
            s,
            type="decision.assertion",
            actor=f"agent:{agent.name}" if agent else f"client:{client}",
            agent=agent,
            agent_name=None if agent else identity.get("client_id"),
            severity="warning" if effect == "deny" or monitored else "info",
            action="token-exchange",
            resource=target["name"],
            decision=effect,
            reason=reason,
            details=details,
            on_behalf_of=people.name_of(person),
        )
    if refused is not None:
        raise refused
    return answer

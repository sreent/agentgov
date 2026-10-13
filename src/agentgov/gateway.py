"""Generates agentgateway's configuration from the registry.

Every registered MCP server becomes a route ``/mcp/<server>`` (while the
mcp-gateway feature is on) with three policies, all enforced by agentgateway:

* ``jwtAuth``       - the caller must present a Keycloak-issued agent token
                      for the gateway audience. With the developer-sign-in feature,
                      ``mcpAuthentication`` instead, which checks the token the same way
                      and tells MCP clients where to sign in: the route also serves its
                      OAuth protected resource metadata (RFC 9728) at
                      ``/.well-known/oauth-protected-resource/mcp/<server>``, which names
                      Keycloak, and a call without a token is answered 401 with a pointer
                      to it, so that developers' MCP clients sign in to a public client.
* ``mcpGuardrails`` - every tool call, tool result and tools/list response is
                      sent to the governance processor (agentgateway's ExtMcp
                      gRPC protocol), which consults OPA and Presidio. Failure
                      mode is fail-closed.
* ``cors``          - permissive, since credentials are bearer tokens.

Every approved model provider becomes a route
``/llm/<provider>/v1/chat/completions`` (while the model-gateway feature is on),
where agents call models in OpenAI's format with their agent token:

* ``jwtAuth``       - as for tool servers, but always strict: the gateway spends the
                      provider's key, so a call without a valid token is refused even
                      while unknown callers are monitored (and without a token issuer to
                      check against, the route answers 503).
* ``backendAuth``   - the provider's API key, which the gateway reads from a file
                      mounted into it (it never enters AgentGov).
* ``promptGuard``   - every prompt and answer goes to the governance processor's
                      guardrail webhook (``agentgov.processor.model_guard``) with
                      the caller's identity from the validated token.

agentgateway translates the request for Anthropic and Gemini. Its access logs,
sent to the OpenTelemetry Collector, carry each call's tokens and the agent's
identity; the control plane meters them (``agentgov.registry.model_usage``).

Every agent that serves A2A (an ``a2a_url`` in the registry, while the a2a-gateway feature
is on) becomes a route ``/a2a/<agent>``, where other agents call it with their agent
token:

* ``jwtAuth``       - as for tool servers.
* ``a2a``           - agentgateway handles the traffic as A2A: the agent's card, at
                      ``/a2a/<agent>/.well-known/agent-card.json``, names the gateway as
                      where to call it.
* ``extAuthz``      - every request goes to the governance processor first
                      (``agentgov.processor.a2a_guard``), with the caller's identity and
                      the delegation it carries; the processor's answer hands the called
                      agent a delegation of its own and who called it, in headers that
                      replace any the caller set (``agentgov.identity.chains``).
* ``extProc``       - every answer goes to the processor as it streams back
                      (``agentgov.processor.a2a_answers``), which masks credentials and
                      personal data in it or withholds it, as it does tool results; while
                      data protection or prompt-injection defence is on. While
                      a2a-masking is enforced, every message goes there too, after
                      ``extAuthz``, to mask the personal data in it. The agent is
                      asked for answers that aren't compressed (``requestHeaderModifier``),
                      which the processor couldn't read.

Agents carry their delegation (``X-AgentGov-Delegation``) on the calls they make for the
work they were handed, to tools and models too: the processor reads it there as well. The
listener drops every other header named as AgentGov's that a caller sends (``DROPPED``),
before any route's policies: only AgentGov sets those.

agentgateway watches the file and reloads it, so it only has to be rewritten
atomically when tool servers or model providers change. The control plane serves
it (``GET /v1/gateway/config``), and ``agentgov gateway-config``, beside the
gateway, keeps the gateway's copy current (``sync_from_control_plane``), as the
Compose stack and the Helm chart do. Where the control plane shares a volume
with the gateway, it can write the file itself instead (``GatewayConfigWriter``).

agentgateway refuses a whole configuration that names a key file it can't read,
so whoever writes the file checks the key files first: a provider whose key is
missing answers 503 until it is there (``with_available_keys``).

Tokens: Keycloak's, AgentGov's own, and those of the identity issuers the gateway trusts
(docs/agent-identity.md#straight-to-the-gateway), each a ``jwtAuth`` provider, with the
keys AgentGov fetched from them written in. The claims only AgentGov's tokens are believed
for (which agent and client, and the person an agent acts for) are passed on from those
alone; the issuer and subject of every token are, which name an agent with a workload
identity.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml
from sqlalchemy import select

from agentgov.config import Settings
from agentgov.db import Database
from agentgov.identity import chains
from agentgov.models import PENDING, Agent, IdentityIssuer, ModelProvider, ToolServer
from agentgov.registry import features, identity_issuers, model_providers
from agentgov.registry.agents import a2a_published

log = logging.getLogger(__name__)

# What the processor inspects, per MCP method. agentgateway takes the exact name first,
# then a prefix ("notifications/*"), then "*".
GUARDED_METHODS = {
    "tools/call": "full",  # arguments and results
    "tools/list": "response",  # filter the list per agent, learn the catalog
    "resources/read": "full",
    "prompts/get": "request",
    # Everything else is checked before it reaches the server: listing its prompts or
    # resources, completing an argument, a method MCP adds later. Only setting up and
    # keeping up the session isn't.
    "*": "request",
    "initialize": "off",
    "ping": "off",
    "notifications/*": "off",
}

# Context forwarded to the processor, evaluated by agentgateway after it has
# validated the token. Missing values are simply omitted. "request" carries the
# metadata the processor returned for the request (agentgateway exposes it to
# CEL as mcpGuardrails), which tells the response side which tool was called.
# When the agent acts for a person, the token's subject is the person: their name,
# email address, groups and realm roles come with it, and "act" names the agent if
# the person delegated to it (agentgov.identity.people).
# Where a protected resource's OAuth metadata is (RFC 9728), before the resource's path.
RESOURCE_METADATA = "/.well-known/oauth-protected-resource"

IDENTITY_METADATA = {
    "client_id": "jwt.azp",
    "agent_id": "jwt.agent_id",
    "subject": "jwt.sub",
    "token_id": "jwt.jti",
    "username": "jwt.preferred_username",
    "email": "jwt.email",
    "groups": "jwt.groups",
    "roles": "jwt.realm_access.roles",
    "act": "jwt.act",
    "sign_in": "jwt.agentgov_sign_in",
    "request": "mcpGuardrails",
}

# The same for model calls, whose guardrail webhook takes them as headers: lists and
# objects as JSON.
PERSON_HEADERS = {
    "x-agentgov-subject": "jwt.sub",
    "x-agentgov-username": "jwt.preferred_username",
    "x-agentgov-email": "jwt.email",
    "x-agentgov-groups": "toJson(jwt.groups)",
    "x-agentgov-roles": "toJson(jwt.realm_access.roles)",
    "x-agentgov-act": "toJson(jwt.act)",
    "x-agentgov-sign-in": "toJson(jwt.agentgov_sign_in)",
}


# What only AgentGov's own tokens (Keycloak's) are believed for: which agent and client, and
# the person an agent acts for (IDENTITY_METADATA's keys, PERSON_HEADERS' and the like).
OWN_CLAIMS = frozenset(
    {"client_id", "agent_id", "username", "email", "groups", "roles", "act", "sign_in"}
)
OWN_HEADERS = frozenset(
    {
        "x-agentgov-agent-id",
        "x-agentgov-client-id",
        "x-agentgov-username",
        "x-agentgov-email",
        "x-agentgov-groups",
        "x-agentgov-roles",
        "x-agentgov-act",
        "x-agentgov-sign-in",
    }
)


# The headers named as AgentGov's that only AgentGov sets. Those a caller sends never reach
# the processor (agentgateway passes it only those it computes from the token), and the
# gateway drops them as a request arrives, before any route's checks: so no agent, tool
# server or model provider called takes a caller's for AgentGov's, even for a call let
# through unchecked (the processor's answer sets who called an agent, after the drop). The
# delegation a caller carries goes on, for the processor to check: it is signed.
DROPPED = (
    *sorted(PERSON_HEADERS.keys() | OWN_HEADERS),
    "x-agentgov-issuer",
    "x-agentgov-provider",
    "x-agentgov-model",
    "x-agentgov-path",
    chains.CALLER_HEADER,
    chains.PERSON_HEADER,
    chains.CHAIN_HEADER,
)


def _own(expression: str, settings: Settings, issuers: Any, *, empty: str = "null") -> str | None:
    """``expression``, a claim only AgentGov's own tokens are believed for: as it is while
    the gateway takes no one else's; else only for Keycloak's tokens (``empty`` for the
    others), or nothing at all without Keycloak."""
    if not issuers:
        return expression
    if not settings.keycloak_issuer:
        return None
    issued = f"has(jwt.iss) && jwt.iss == {json.dumps(settings.keycloak_issuer)}"
    return f"{issued} ? {expression} : {empty}"


def _believed(
    values: dict[str, str], own: frozenset[str], settings: Settings, issuers: Any
) -> dict[str, str]:
    """``values`` (CEL by name), those named in ``own`` only from AgentGov's own tokens."""
    out: dict[str, str] = {}
    for name, expression in values.items():
        value = _own(expression, settings, issuers) if name in own else expression
        if value is not None:
            out[name] = value
    return out


def identity_metadata(settings: Settings, issuers: Any = ()) -> dict[str, str]:
    """IDENTITY_METADATA, with the issuer of the token too while the gateway trusts other
    issuers than Keycloak."""
    out = _believed(IDENTITY_METADATA, OWN_CLAIMS, settings, issuers)
    if issuers:
        out["issuer"] = "jwt.iss"
    return out


def identity_headers(settings: Settings, issuers: Any = ()) -> dict[str, str]:
    """The agent, its client and the person it acts for, as headers (model calls, and calls
    to other agents), with the token's issuer while the gateway trusts other issuers."""
    values = {"x-agentgov-agent-id": "jwt.agent_id", "x-agentgov-client-id": "jwt.azp"}
    out = _believed({**values, **PERSON_HEADERS}, OWN_HEADERS, settings, issuers)
    if issuers:
        out["x-agentgov-issuer"] = "jwt.iss"
    return out


def processor_tls(settings: Settings, address: str, *, grpc: bool = False) -> dict[str, Any]:
    """agentgateway's TLS to the processor (with AGENTGOV_TLS_DIR): it checks the
    processor's certificate against AgentGov's authority, and shows its own."""
    folder = settings.gateway_tls_dir.rstrip("/")
    tls: dict[str, Any] = {
        "cert": f"{folder}/tls.crt",
        "key": f"{folder}/tls.key",
        "root": f"{folder}/ca.crt",
        "hostname": address.rsplit(":", 1)[0],
    }
    if grpc:
        tls["alpn"] = ["h2"]
    return tls


def _to_processor(settings: Settings, address: str, *, grpc: bool = False) -> dict[str, Any]:
    """A target's backend policies for the processor at ``address``: mutual TLS, when the
    components have certificates."""
    if not settings.tls_dir:
        return {}
    return {"policies": {"backendTLS": processor_tls(settings, address, grpc=grpc)}}


def _fails_open(settings: Settings, modes: dict[str, str]) -> bool:
    """Whether agentgateway lets a call through when the processor can't be reached or
    fails, as it does itself when it can't check one (AGENTGOV_GATEWAY_FAILURE_MODE)."""
    return features.fails_open(settings.gateway_failure_mode, modes)


def _failure_mode(settings: Settings, modes: dict[str, str]) -> str:
    return "failOpen" if _fails_open(settings, modes) else "failClosed"


def route_for(
    ts: ToolServer, settings: Settings, modes: dict[str, str], issuers: Any = ()
) -> dict[str, Any]:
    policies: dict[str, Any] = {
        "cors": {
            "allowOrigins": ["*"],
            "allowHeaders": ["*"],
            "exposeHeaders": ["Mcp-Session-Id"],
        },
        "mcpGuardrails": {
            "processors": [
                {
                    "kind": "remote",
                    "host": settings.processor_address,
                    "failureMode": _failure_mode(settings, modes),
                    "methods": dict(GUARDED_METHODS),
                    "metadata": {
                        **identity_metadata(settings, issuers),
                        "server": f'"{ts.name}"',
                    },
                    "requestHeaders": {"disallowed": ["authorization", "cookie"]},
                    **_to_processor(settings, settings.processor_address, grpc=True),
                }
            ]
        },
    }
    matches = [{"path": {"exact": f"/mcp/{ts.name}"}}]
    keycloak = _jwt_auth(settings, modes)
    auth = _jwt_auth(settings, modes, issuers=issuers)
    if keycloak and modes["developer-sign-in"] == features.ON:
        # The same check, and where to sign in for MCP clients that have no token: the
        # metadata, at the route's well-known path (served only where the route matches
        # it), names Keycloak; its resource is the server's address on the gateway. It
        # names one issuer: Keycloak's tokens alone are taken here then.
        metadata: dict[str, Any] = {"bearerMethodsSupported": ["header"]}
        if settings.gateway_public_url:
            metadata["resource"] = f"{settings.gateway_public_url.rstrip('/')}/mcp/{ts.name}"
        policies["mcpAuthentication"] = {**keycloak, "resourceMetadata": metadata}
        policies["cors"]["exposeHeaders"].append("WWW-Authenticate")
        matches.append({"path": {"exact": f"{RESOURCE_METADATA}/mcp/{ts.name}"}})
    elif auth:
        policies["jwtAuth"] = auth
    return {
        "name": f"mcp-{ts.name}",
        "matches": matches,
        "policies": policies,
        "backends": [{"mcp": {"targets": [{"name": ts.name, "mcp": {"host": ts.url}}]}}],
    }


# agentgateway's provider types, by AgentGov's provider kind.
AI_PROVIDERS = {
    "openai": "openAI",
    "openai-compatible": "openAI",
    "anthropic": "anthropic",
    "gemini": "gemini",
}
CHAT_PATH = "/v1/chat/completions"


def _providers(settings: Settings, issuers: Any) -> list[dict[str, Any]]:
    """Whose tokens the gateway takes: Keycloak's, then those of each identity issuer it
    trusts, for the audience the issuer's tokens carry, with its keys written in (the
    gateway never fetches them, and agentgateway won't load keys it can't use)."""
    providers = []
    if settings.keycloak_issuer and settings.keycloak_jwks_url:
        providers.append(
            {
                "issuer": settings.keycloak_issuer,
                "audiences": [settings.gateway_audience],
                "jwks": {"url": settings.keycloak_jwks_url},
            }
        )
    for issuer in issuers:
        providers.append(
            {
                "issuer": issuer.issuer,
                "audiences": [issuer.audience or settings.gateway_audience],
                "jwks": json.dumps({"keys": issuer.gateway_keys}, sort_keys=True),
            }
        )
    return providers


def _jwt_auth(
    settings: Settings, modes: dict[str, str], *, strict: bool = False, issuers: Any = ()
) -> dict[str, Any] | None:
    providers = _providers(settings, issuers)
    if not providers:
        return None
    optional = modes["unknown-callers"] == features.MONITOR and not strict
    # "optional" lets unauthenticated callers reach the processor, which lets them through
    # and records them while unknown callers are monitored.
    mode = "optional" if optional else "strict"
    if not issuers:
        return {"mode": mode, **providers[0]}  # Keycloak's alone
    return {"mode": mode, "providers": providers}


def model_route_for(
    provider: ModelProvider, settings: Settings, modes: dict[str, str], issuers: Any = ()
) -> dict[str, Any]:
    name = provider.name
    matches = [{"path": {"exact": f"/llm/{name}{CHAT_PATH}"}}]
    why = model_providers.refused(provider, settings)
    if why:
        # Set before the rules were, or the deployment's list changed since: no key goes.
        message = f"The gateway doesn't send {name}'s key: {why}"
        return {
            "name": f"llm-{name}",
            "matches": matches,
            "policies": {
                "directResponse": {
                    "body": json.dumps({"error": {"message": message}}),
                    "status": 503,
                }
            },
        }
    backend: dict[str, Any] = {"name": name, "provider": {AI_PROVIDERS[provider.kind]: {}}}
    policies: dict[str, Any] = {}
    if provider.kind == "openai-compatible" and provider.base_url:
        url = urlsplit(provider.base_url)
        port = url.port or (443 if url.scheme == "https" else 80)
        backend["hostOverride"] = f"{url.hostname}:{port}"
        # base_url is the server's OpenAI API base, as an OpenAI SDK takes it (".../v1").
        if url.path.rstrip("/"):
            backend["pathPrefix"] = url.path.rstrip("/")
        if url.scheme == "https":
            policies["backendTLS"] = {}
    guard_headers = {
        **identity_headers(settings, issuers),
        "x-agentgov-provider": f'"{name}"',
        "x-agentgov-model": "llmRequest.model",
        # The delegation the agent carries, when another agent handed it the work.
        chains.HEADER: f'request.headers["{chains.HEADER}"]',
    }
    webhook = {
        "host": settings.processor_webhook_address,
        **_to_processor(settings, settings.processor_webhook_address),
    }
    policies.update(
        {
            "urlRewrite": {"path": {"full": CHAT_PATH}},
            "backendAuth": {"key": {"file": model_providers.key_file(provider)}},
            "ai": {
                "routes": {CHAT_PATH: "completions"},
                "promptGuard": {
                    # Answers that arrive as a stream are checked too, before they reach
                    # the agent.
                    "streaming": "Enabled",
                    "request": [
                        {
                            "webhook": {
                                "target": webhook,
                                "headers": guard_headers,
                                "failureMode": _failure_mode(settings, modes),
                            }
                        }
                    ],
                    "response": [
                        {
                            "webhook": {
                                "target": webhook,
                                "headers": guard_headers,
                                "failureMode": _failure_mode(settings, modes),
                            }
                        }
                    ],
                },
            },
        }
    )
    # The gateway spends the provider's key on the caller's behalf: only for callers whose
    # token it has checked, whatever the mode of unknown callers, and not at all when it
    # can't check tokens.
    auth = _jwt_auth(settings, modes, strict=True, issuers=issuers)
    if not auth:
        message = (
            f"The gateway uses {name}'s key only for agents whose tokens it can check: "
            "set AGENTGOV_KEYCLOAK_ISSUER and AGENTGOV_KEYCLOAK_JWKS_URL, or trust an "
            "identity issuer at the gateway"
        )
        return {
            "name": f"llm-{name}",
            "matches": matches,
            "policies": {
                "directResponse": {
                    "body": json.dumps({"error": {"message": message}}),
                    "status": 503,
                }
            },
        }
    policies["jwtAuth"] = auth
    return {
        "name": f"llm-{name}",
        "matches": matches,
        "policies": policies,
        "backends": [{"ai": backend}],
    }


# What agentgateway passes on from the processor's answer to the called agent.
A2A_PASSED_ON = [
    chains.HEADER,
    chains.CALLER_HEADER,
    chains.PERSON_HEADER,
    chains.CHAIN_HEADER,
]
# A2A requests are checked with their body (a message, with its parts), up to this size.
A2A_MAX_BODY = 256 * 1024
# Agents called while they are blocked are refused by policy, with the reason, rather
# than not found.


def _answer_checks(
    agent: Agent, settings: Settings, modes: dict[str, str], issuers: Any = ()
) -> dict[str, Any]:
    """agentgateway's external processing of the agent's answers, by the processor
    (agentgov.processor.a2a_answers): each answer as it streams, with whom it answers in
    metadata; and while a2a-masking is enforced, each message sent to it, to mask it.
    Guarded expressions give "" where a claim or a header is missing."""
    masking = modes["a2a-masking"] == features.ENFORCE and modes["data-protection"] != features.OFF

    def claim(path: str, *, as_json: bool = False) -> str:
        parts = path.split(".")
        present = " && ".join(f"has(jwt.{'.'.join(parts[: i + 1])})" for i in range(len(parts)))
        value = f"toJson(jwt.{path})" if as_json else f"jwt.{path}"
        return f'{present} ? {value} : ""'

    claims = {
        "agent_id": claim("agent_id"),
        "client_id": claim("azp"),
        "subject": claim("sub"),
        "username": claim("preferred_username"),
        "email": claim("email"),
        "groups": claim("groups", as_json=True),
        "roles": claim("realm_access.roles", as_json=True),
        "act": claim("act", as_json=True),
        "sign_in": claim("agentgov_sign_in", as_json=True),
    }
    believed = {
        name: value
        for name, expression in claims.items()
        if (
            value := _own(f"({expression})", settings, issuers, empty='""')
            if name in OWN_CLAIMS
            else expression
        )
        is not None
    }
    if issuers:
        believed["issuer"] = claim("iss")
    return {
        "host": settings.processor_address,
        "failureMode": _failure_mode(settings, modes),
        "metadataContext": {
            "agentgov": {
                "agent": json.dumps(agent.name),
                "path": "request.path",
                **believed,
                "traceparent": (
                    '"traceparent" in request.headers ? request.headers["traceparent"] : ""'
                ),
            }
        },
        # The answers; and the messages only to mask them, as the call itself went to the
        # processor already (extAuthz, which sees the message as it was sent). Streamed, so
        # that a streamed answer reaches the caller as it comes. With a streamed body
        # agentgateway sends trailers whatever these say (and warns when they say skip);
        # the processor passes them on.
        "processingOptions": {
            "requestHeaderMode": "send" if masking else "skip",
            "requestBodyMode": "fullDuplexStreamed" if masking else "none",
            "requestTrailerMode": "send",
            "responseHeaderMode": "send",
            "responseBodyMode": "fullDuplexStreamed",
            "responseTrailerMode": "send",
        },
        **_to_processor(settings, settings.processor_address, grpc=True),
    }


def a2a_route_for(
    agent: Agent, settings: Settings, modes: dict[str, str], issuers: Any = ()
) -> dict[str, Any]:
    url = urlsplit(agent.a2a_url or "")
    port = url.port or (443 if url.scheme == "https" else 80)
    host = f"[{url.hostname}]" if ":" in (url.hostname or "") else url.hostname
    route = f"/a2a/{agent.name}"
    check_headers = {
        **identity_headers(settings, issuers),
        chains.HEADER: f'request.headers["{chains.HEADER}"]',
        "traceparent": 'request.headers["traceparent"]',
        "x-agentgov-path": "request.path",
    }
    policies: dict[str, Any] = {
        "cors": {"allowOrigins": ["*"], "allowHeaders": ["*"]},
        "a2a": {},
        # /a2a/<agent>/... reaches the agent at its own path.
        "urlRewrite": {"path": {"prefix": url.path.rstrip("/") or "/"}},
        "extAuthz": {
            "host": settings.processor_webhook_address,
            "protocol": {
                "http": {
                    "path": f'"/a2a/check/{agent.name}"',
                    "includeResponseHeaders": list(A2A_PASSED_ON),
                    "addRequestHeaders": check_headers,
                }
            },
            "includeRequestBody": {"maxRequestBytes": A2A_MAX_BODY},
            # Let through, a call goes on without a delegation from AgentGov: agents that
            # check for one refuse it (docs/agent-to-agent.md).
            "failureMode": "allow" if _fails_open(settings, modes) else "deny",
            **_to_processor(settings, settings.processor_webhook_address),
        },
    }
    if modes["data-protection"] != features.OFF or modes["prompt-injection"] != features.OFF:
        policies["extProc"] = _answer_checks(agent, settings, modes, issuers)
        # Answers the processor can read: not compressed, whatever the caller accepts.
        policies["requestHeaderModifier"] = {"set": {"accept-encoding": "identity"}}
    if url.scheme == "https":
        policies["backendTLS"] = {}
    auth = _jwt_auth(settings, modes, issuers=issuers)
    if auth:
        policies["jwtAuth"] = auth
    return {
        "name": f"a2a-{agent.name}",
        "matches": [{"path": {"pathPrefix": route}}],
        "policies": policies,
        "backends": [{"host": f"{host}:{port}"}],
    }


def render(
    servers: list[ToolServer],
    settings: Settings,
    modes: dict[str, str] | None = None,
    providers: list[ModelProvider] | None = None,
    agents: list[Agent] | None = None,
    issuers: list[IdentityIssuer] | None = None,
) -> dict[str, Any]:
    """The gateway's configuration. ``issuers``: the identity issuers whose tokens it takes
    besides Keycloak's (identity_issuers.at_the_gateway)."""
    modes = {**{f.key: f.default for f in features.CATALOG}, **(modes or {})}
    trusted = list(issuers or [])
    routes = []
    if modes["mcp-gateway"] != features.OFF:
        # Servers only for developers aren't published: they run elsewhere.
        routes = [
            route_for(ts, settings, modes, trusted)
            for ts in servers
            if ts.status != PENDING and ts.gateway is not False
        ]
    if modes["model-gateway"] != features.OFF:
        routes += [model_route_for(p, settings, modes, trusted) for p in providers or []]
    if modes["a2a-gateway"] != features.OFF:
        routes += [
            a2a_route_for(a, settings, modes, trusted) for a in agents or [] if a2a_published(a)
        ]
    # A static health route keeps the listener valid when no servers exist yet.
    routes.append(
        {
            "name": "agentgov-health",
            "matches": [{"path": {"exact": "/healthz"}}],
            "policies": {"directResponse": {"body": "ok", "status": 200}},
        }
    )
    config: dict[str, Any] = {"config": {"enableIpv6": settings.gateway_ipv6}}
    if settings.gateway_otlp_endpoint:
        endpoint = urlsplit(settings.gateway_otlp_endpoint)
        host = endpoint.netloc or endpoint.path
        config["frontendPolicies"] = {
            "tracing": {"host": host, "protocol": "grpc", "randomSampling": "true"},
            # Access logs carry each model call's tokens; the agent comes from its token.
            "accessLog": {
                "add": _access_log_fields(settings, trusted),
                "otlp": {"host": host, "protocol": "grpc"},
            },
        }
    listener = {
        "policies": {"transformations": {"request": {"remove": list(DROPPED)}}},
        "routes": routes,
    }
    config["binds"] = [{"port": settings.gateway_port, "listeners": [listener]}]
    return config


def _access_log_fields(settings: Settings, issuers: Any) -> dict[str, str]:
    """Whom each access log entry is about: the agent or client AgentGov's tokens name, and
    the issuer and subject of others' (agentgov.registry.model_usage)."""
    fields = _believed(
        {"agentgov.agent_id": "jwt.agent_id", "agentgov.client_id": "jwt.azp"},
        frozenset({"agentgov.agent_id", "agentgov.client_id"}),
        settings,
        issuers,
    )
    if issuers:
        fields.update({"agentgov.issuer": "jwt.iss", "agentgov.subject": "jwt.sub"})
    return fields


def with_available_keys(
    config: dict[str, Any], exists: Callable[[str], bool] = os.path.exists
) -> dict[str, Any]:
    """``config`` with each route whose key file is missing answering 503 instead:
    agentgateway would refuse the whole configuration, and with it every later change."""
    out = copy.deepcopy(config)
    for bind in out.get("binds") or []:
        for listener in bind.get("listeners") or []:
            for i, route in enumerate(listener.get("routes") or []):
                key = ((route.get("policies") or {}).get("backendAuth") or {}).get("key")
                path = key.get("file") if isinstance(key, dict) else None
                if path and not exists(path):
                    message = (
                        f"The gateway has no API key for {route['name'].removeprefix('llm-')}: "
                        f"put it in {path}"
                    )
                    listener["routes"][i] = {
                        "name": route["name"],
                        "matches": route["matches"],
                        "policies": {
                            "directResponse": {
                                "body": json.dumps({"error": {"message": message}}),
                                "status": 503,
                            }
                        },
                    }
    return out


def to_yaml(config: dict[str, Any]) -> str:
    header = (
        "# Generated by the AgentGov control plane. Do not edit: changes are overwritten.\n"
        "# yaml-language-server: $schema=https://agentgateway.dev/schema/config\n"
    )
    return header + yaml.safe_dump(config, sort_keys=False, default_flow_style=False)


def write_if_changed(path: str, content: str) -> bool:
    """Atomically replace ``path`` (agentgateway reloads on rename)."""
    target = Path(path)
    if target.exists() and target.read_text() == content:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".agentgateway-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


class GatewayConfigWriter:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self._lock = threading.Lock()

    def render_config(self) -> dict[str, Any]:
        with self.db.session() as session:
            servers = list(session.scalars(select(ToolServer).order_by(ToolServer.name)))
            agents = list(
                session.scalars(
                    select(Agent).where(Agent.a2a_url.is_not(None)).order_by(Agent.name)
                ).unique()
            )
            # Ready for the strictest mode any agent has: the gateway can't tell agents
            # apart, the processor and OPA do (docs/features.md#exceptions).
            return render(
                servers,
                self.settings,
                features.strictest_modes(session),
                model_providers.list_all(session),
                agents,
                identity_issuers.at_the_gateway(session),
            )

    def render_current(self) -> str:
        """The configuration as the registry has it (served to gateway sidecars)."""
        return to_yaml(self.render_config())

    def sync(self) -> bool:
        """Write the configuration where the gateway reads it, with the key check."""
        if not self.settings.gateway_config_path:
            return False
        with self._lock:
            content = to_yaml(with_available_keys(self.render_config()))
            changed = write_if_changed(self.settings.gateway_config_path, content)
        if changed:
            log.info("wrote agentgateway config to %s", self.settings.gateway_config_path)
        return changed


def etag_of(content: str) -> str:
    return '"' + hashlib.sha256(content.encode()).hexdigest()[:32] + '"'


class Fetched:
    """The configuration last fetched from the control plane, and its ETag."""

    def __init__(self) -> None:
        self.etag: str | None = None
        self.config: dict[str, Any] | None = None


def sync_from_control_plane(
    client: httpx.Client, path: str, fetched: Fetched, *, certificates: Any = None
) -> bool:
    """Fetch the configuration from the control plane and write it to ``path``, with the
    key check, if that changes the file; returns whether the file was rewritten. The key
    check runs on every call: a key file can appear without the configuration changing.

    With ``certificates`` (the gateway's agentgov.tls.Identity), the file also says which
    certificate the gateway holds: agentgateway reads the files it calls the processor
    with only as it loads its configuration, so a renewed certificate rewrites the file,
    and agentgateway loads it, and them, again."""
    headers = {"If-None-Match": fetched.etag} if fetched.etag else {}
    resp = client.get("/v1/gateway/config", headers=headers)
    if resp.status_code != 304:
        resp.raise_for_status()
        fetched.etag, fetched.config = resp.headers.get("ETag"), yaml.safe_load(resp.text)
    if fetched.config is None:
        return False
    text = to_yaml(with_available_keys(fetched.config))
    if certificates is not None:
        text += f"# The gateway's certificate: {certificates.fingerprint()[:16]}\n"
    return write_if_changed(path, text)


def keep_current(
    client: httpx.Client,
    path: str,
    *,
    interval: float,
    once: bool,
    heartbeat: str | None = None,
    certificates: Any = None,
) -> None:
    """Keep ``path`` current until stopped; with ``once``, return after the first write.
    Errors (the control plane starting, a network blip) are retried. Every round touches
    ``heartbeat``, so that a liveness probe can tell the loop is still going."""
    fetched = Fetched()
    while True:
        if heartbeat:
            with open(heartbeat, "a"):
                os.utime(heartbeat)
        try:
            changed = sync_from_control_plane(client, path, fetched, certificates=certificates)
        except httpx.HTTPError as exc:
            log.warning("could not fetch the gateway configuration: %s", exc)
        else:
            if changed:
                log.info("wrote agentgateway config to %s", path)
            if once:
                return
        time.sleep(interval)

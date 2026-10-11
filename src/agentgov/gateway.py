"""Generates agentgateway's configuration from the registry.

Every registered MCP server becomes a route ``/mcp/<server>`` (while the
mcp-gateway feature is on) with three policies, all enforced by agentgateway:

* ``jwtAuth``       - the caller must present a Keycloak-issued agent token
                      for the gateway audience.
* ``mcpGuardrails`` - every tool call, tool result and tools/list response is
                      sent to the governance processor (agentgateway's ExtMcp
                      gRPC protocol), which consults OPA and Presidio. Failure
                      mode is fail-closed.
* ``cors``          - permissive, since credentials are bearer tokens.

Every approved model provider becomes a route
``/llm/<provider>/v1/chat/completions`` (while the model-gateway feature is on),
where agents call models in OpenAI's format with their agent token:

* ``jwtAuth``       - as for tool servers.
* ``backendAuth``   - the provider's API key, which the gateway reads from a file
                      mounted into it (it never enters AgentGov).
* ``promptGuard``   - every prompt and answer goes to the governance processor's
                      guardrail webhook (``agentgov.processor.model_guard``) with
                      the caller's identity from the validated token.

agentgateway translates the request for Anthropic and Gemini. Its access logs,
sent to the OpenTelemetry Collector, carry each call's tokens and the agent's
identity; the control plane meters them (``agentgov.registry.model_usage``).

agentgateway watches the file and reloads it, so it only has to be rewritten
atomically when tool servers or model providers change. The control plane serves
it (``GET /v1/gateway/config``), and ``agentgov gateway-config``, beside the
gateway, keeps the gateway's copy current (``sync_from_control_plane``), as the
Compose stack and the Helm chart do. Where the control plane shares a volume
with the gateway, it can write the file itself instead (``GatewayConfigWriter``).

agentgateway refuses a whole configuration that names a key file it can't read,
so whoever writes the file checks the key files first: a provider whose key is
missing answers 503 until it is there (``with_available_keys``).
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
from agentgov.models import PENDING, ModelProvider, ToolServer
from agentgov.registry import features, model_providers

log = logging.getLogger(__name__)

# What the processor inspects, per MCP method.
GUARDED_METHODS = {
    "tools/call": "full",  # arguments and results
    "tools/list": "response",  # filter the list per agent, learn the catalog
    "resources/read": "full",
    "prompts/get": "request",
}

# Context forwarded to the processor, evaluated by agentgateway after it has
# validated the token. Missing values are simply omitted. "request" carries the
# metadata the processor returned for the request (agentgateway exposes it to
# CEL as mcpGuardrails), which tells the response side which tool was called.
IDENTITY_METADATA = {
    "client_id": "jwt.azp",
    "agent_id": "jwt.agent_id",
    "subject": "jwt.sub",
    "token_id": "jwt.jti",
    "request": "mcpGuardrails",
}


def route_for(ts: ToolServer, settings: Settings, modes: dict[str, str]) -> dict[str, Any]:
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
                    "failureMode": "failClosed",
                    "methods": dict(GUARDED_METHODS),
                    "metadata": {**IDENTITY_METADATA, "server": f'"{ts.name}"'},
                    "requestHeaders": {"disallowed": ["authorization", "cookie"]},
                }
            ]
        },
    }
    auth = _jwt_auth(settings, modes)
    if auth:
        policies["jwtAuth"] = auth
    return {
        "name": f"mcp-{ts.name}",
        "matches": [{"path": {"exact": f"/mcp/{ts.name}"}}],
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


def _jwt_auth(settings: Settings, modes: dict[str, str]) -> dict[str, Any] | None:
    if not (settings.keycloak_issuer and settings.keycloak_jwks_url):
        return None
    return {
        # "optional" lets unauthenticated callers reach the processor, which lets
        # them through and records them while unknown callers are monitored.
        "mode": "optional" if modes["unknown-callers"] == features.MONITOR else "strict",
        "issuer": settings.keycloak_issuer,
        "audiences": [settings.gateway_audience],
        "jwks": {"url": settings.keycloak_jwks_url},
    }


def model_route_for(
    provider: ModelProvider, settings: Settings, modes: dict[str, str]
) -> dict[str, Any]:
    name = provider.name
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
        "x-agentgov-agent-id": "jwt.agent_id",
        "x-agentgov-client-id": "jwt.azp",
        "x-agentgov-provider": f'"{name}"',
        "x-agentgov-model": "llmRequest.model",
    }
    webhook = {"host": settings.processor_webhook_address}
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
                                "failureMode": "failClosed",
                            }
                        }
                    ],
                    "response": [
                        {
                            "webhook": {
                                "target": webhook,
                                "headers": guard_headers,
                                "failureMode": "failClosed",
                            }
                        }
                    ],
                },
            },
        }
    )
    auth = _jwt_auth(settings, modes)
    if auth:
        policies["jwtAuth"] = auth
    return {
        "name": f"llm-{name}",
        "matches": [{"path": {"exact": f"/llm/{name}{CHAT_PATH}"}}],
        "policies": policies,
        "backends": [{"ai": backend}],
    }


def render(
    servers: list[ToolServer],
    settings: Settings,
    modes: dict[str, str] | None = None,
    providers: list[ModelProvider] | None = None,
) -> dict[str, Any]:
    modes = {**{f.key: f.default for f in features.CATALOG}, **(modes or {})}
    routes = []
    if modes["mcp-gateway"] != features.OFF:
        # Servers only for developers aren't published: they run elsewhere.
        routes = [
            route_for(ts, settings, modes)
            for ts in servers
            if ts.status != PENDING and ts.gateway is not False
        ]
    if modes["model-gateway"] != features.OFF:
        routes += [model_route_for(p, settings, modes) for p in providers or []]
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
                "add": {"agentgov.agent_id": "jwt.agent_id", "agentgov.client_id": "jwt.azp"},
                "otlp": {"host": host, "protocol": "grpc"},
            },
        }
    config["binds"] = [{"port": settings.gateway_port, "listeners": [{"routes": routes}]}]
    return config


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
            return render(
                servers,
                self.settings,
                features.modes(session),
                model_providers.list_all(session),
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


def sync_from_control_plane(client: httpx.Client, path: str, fetched: Fetched) -> bool:
    """Fetch the configuration from the control plane and write it to ``path``, with the
    key check, if that changes the file; returns whether the file was rewritten. The key
    check runs on every call: a key file can appear without the configuration changing."""
    headers = {"If-None-Match": fetched.etag} if fetched.etag else {}
    resp = client.get("/v1/gateway/config", headers=headers)
    if resp.status_code != 304:
        resp.raise_for_status()
        fetched.etag, fetched.config = resp.headers.get("ETag"), yaml.safe_load(resp.text)
    if fetched.config is None:
        return False
    return write_if_changed(path, to_yaml(with_available_keys(fetched.config)))


def keep_current(client: httpx.Client, path: str, *, interval: float, once: bool) -> None:
    """Keep ``path`` current until stopped; with ``once``, return after the first write.
    Errors (the control plane starting, a network blip) are retried."""
    fetched = Fetched()
    while True:
        try:
            changed = sync_from_control_plane(client, path, fetched)
        except httpx.HTTPError as exc:
            log.warning("could not fetch the gateway configuration: %s", exc)
        else:
            if changed:
                log.info("wrote agentgateway config to %s", path)
            if once:
                return
        time.sleep(interval)

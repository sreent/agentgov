"""Input validation shared by the API and declarative manifests."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from agentgov.models import (
    ACTS_FOR,
    APPROVALS_BY,
    DATA_CLASSIFICATIONS,
    RISK_TIERS,
    TRUST_LEVELS,
)
from agentgov.registry.errors import ValidationError

# Names become Keycloak client ids, URL path segments (/mcp/<server>) and OPA
# data keys, so they are restricted to DNS-label style slugs.
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def slug(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SLUG.match(value):
        raise ValidationError(
            f"{field} must be 1-63 lowercase letters, digits or '-', "
            f"starting and ending with a letter or digit (got {value!r})"
        )
    return value


def one_of(value: Any, allowed: tuple[str, ...], field: str) -> str:
    if value not in allowed:
        raise ValidationError(f"{field} must be one of {', '.join(allowed)} (got {value!r})")
    return value


def risk_tier(value: Any) -> str:
    return one_of(value, RISK_TIERS, "risk_tier")


def trust_level(value: Any) -> str:
    return one_of(value, TRUST_LEVELS, "trust_level")


def data_classification(value: Any) -> str:
    return one_of(value, DATA_CLASSIFICATIONS, "data_classification")


def acts_for(value: Any) -> str:
    return one_of(value, ACTS_FOR, "acts_for")


def approvals_by(value: Any) -> str:
    return one_of(value, APPROVALS_BY, "approvals_by")


def people_groups(value: Any) -> list[str]:
    """Group names or paths (``support``, ``/emea/support``); the leading "/" is optional."""
    groups = string_list(value, "people_groups")
    for group in groups:
        if not group.strip("/") or group != group.strip():
            raise ValidationError(
                f"people_groups: {group!r} is not a group, such as support or /emea/support"
            )
    return groups


def string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ValidationError(f"{field} must be a list of non-empty strings")
    return list(dict.fromkeys(value))  # de-duplicate, keep order


def labels(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise ValidationError("labels must be a mapping of strings to strings")
    return dict(value)


def permissions(value: Any) -> list[dict[str, Any]]:
    """Validate grants: ``[{"server": "<glob>", "tools": ["<glob>", ...]}]``."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("permissions must be a list of {server, tools} grants")
    grants = []
    for i, grant in enumerate(value):
        if not isinstance(grant, dict) or set(grant) - {"server", "tools"}:
            raise ValidationError(f"permissions[{i}] must have only 'server' and 'tools' keys")
        server = grant.get("server")
        if not isinstance(server, str) or not server:
            raise ValidationError(f"permissions[{i}].server must be a non-empty string")
        tools = string_list(grant.get("tools", ["*"]), f"permissions[{i}].tools")
        if not tools:
            raise ValidationError(f"permissions[{i}].tools must not be empty")
        grants.append({"server": server, "tools": tools})
    return grants


def model_access(value: Any) -> list[dict[str, Any]]:
    """Validate model grants: ``[{"provider": "<name>", "models": ["<glob>", ...]}]``."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("model_access must be a list of {provider, models} grants")
    grants = []
    for i, grant in enumerate(value):
        if not isinstance(grant, dict) or set(grant) - {"provider", "models"}:
            raise ValidationError(f"model_access[{i}] must have only 'provider' and 'models' keys")
        provider = slug(grant.get("provider"), f"model_access[{i}].provider")
        models = string_list(grant.get("models", ["*"]), f"model_access[{i}].models")
        if not models:
            raise ValidationError(f"model_access[{i}].models must not be empty")
        grants.append({"provider": provider, "models": models})
    return grants


def merge_model_access(*grant_lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, list[str]] = {}
    for grants in grant_lists:
        for grant in grants or []:
            models = merged.setdefault(grant["provider"], [])
            models.extend(m for m in grant["models"] if m not in models)
    return [{"provider": provider, "models": models} for provider, models in merged.items()]


# Agent names, or glob patterns over them.
_AGENT_PATTERN = re.compile(r"^[a-z0-9*?\[\]!-]{1,63}$")


def agent_access(value: Any) -> list[str]:
    """The agents an agent may call over A2A: names or glob patterns (``billing-*``)."""
    patterns = string_list(value, "agent_access")
    for pattern in patterns:
        if not _AGENT_PATTERN.match(pattern):
            raise ValidationError(
                f"agent_access: {pattern!r} is not an agent's name or a pattern of names "
                "(lowercase letters, digits, '-', and * or ? to match any)"
            )
    return patterns


def merge_agent_access(*lists: list[str]) -> list[str]:
    return list(dict.fromkeys(p for patterns in lists for p in patterns or []))


def a2a_url(value: Any) -> str | None:
    """An agent's A2A endpoint: http(s), no credentials, query or fragment."""
    if value is None or value == "":
        return None
    parts = urlsplit(str(value))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationError(f"a2a_url must be an http(s) URL (got {value!r})")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValidationError("a2a_url must not hold credentials, a query or a fragment")
    try:
        parts.port  # noqa: B018 (raises on a port that isn't one)
    except ValueError:
        raise ValidationError(f"a2a_url has an invalid port (got {value!r})") from None
    return str(value).rstrip("/")


def issuer_url(value: Any, field: str) -> str | None:
    """An OAuth issuer identifier: an http(s) URL without a query or fragment."""
    if value is None or value == "":
        return None
    parts = urlsplit(str(value))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationError(f"{field} must be an http(s) URL, its issuer (got {value!r})")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValidationError(f"{field} must not hold credentials, a query or a fragment")
    # Exactly as the issuer names itself (some end with "/"): assertions name it so.
    return str(value)


# What stops calls to an agent that don't come through the gateway, as its owners say
# (registry/reachability): the network lets only the gateway reach it, or the agent refuses
# calls without the delegation the gateway gives with each one.
A2A_PROTECTIONS = ("network", "delegation")


def a2a_protection(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if value not in A2A_PROTECTIONS:
        raise ValidationError(
            f"a2a_protection is one of {', '.join(A2A_PROTECTIONS)}, or null (got {value!r})"
        )
    return str(value)


# An agent's client in the identity provider (identity/keycloak): "service", confidential,
# with tokens for itself; or "public", one people sign in to on their own machines, such as
# a developer's MCP client, which acts for them only.
SERVICE, PUBLIC = "service", "public"
CLIENT_TYPES = (SERVICE, PUBLIC)
# Where a public client's sign-in may return when it names none: the machine itself, at any
# port (Keycloak lets loopback addresses take any port), as MCP clients such as VS Code and
# Claude Code listen for it.
LOOPBACK_REDIRECTS = ["http://127.0.0.1/*", "http://localhost/*"]
_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def client_type(value: Any) -> str:
    if value is None or value == "":
        return SERVICE
    if value not in CLIENT_TYPES:
        raise ValidationError(f"client_type is one of {', '.join(CLIENT_TYPES)} (got {value!r})")
    return str(value)


def redirect_uris(value: Any) -> list[str]:
    """A public client's redirect URIs, as Keycloak takes them: "*" only at the end, and
    plain http only to the machine itself (OAuth for native apps, RFC 8252)."""
    uris = string_list(value, "redirect_uris")
    for uri in uris:
        parts = urlsplit(uri)
        if "*" in uri[:-1] or not parts.scheme or parts.fragment:
            raise ValidationError(
                f"redirect_uris: {uri!r} isn't one: a URL, without a fragment, with * only "
                "at its end"
            )
        if parts.scheme in ("http", "https") and not parts.hostname:
            raise ValidationError(f"redirect_uris: {uri!r} names no host")
        if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
            raise ValidationError(
                f"redirect_uris: {uri!r} is plain http to another machine: use https, or "
                "127.0.0.1 or localhost"
            )
    return uris


def token_budget(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError("daily_token_budget must be a whole number of tokens, or null")
    return value


def merge_grants(*grant_lists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, list[str]] = {}
    for grants in grant_lists:
        for grant in grants or []:
            tools = merged.setdefault(grant["server"], [])
            tools.extend(t for t in grant["tools"] if t not in tools)
    return [{"server": server, "tools": tools} for server, tools in merged.items()]


def is_broad(grants: list[dict[str, Any]]) -> bool:
    """True when a grant covers every tool on every server."""
    return any(g["server"] == "*" and "*" in g["tools"] for g in grants)


def known_fields(data: dict[str, Any], allowed: Any, what: str) -> None:
    """Refuse fields an API body doesn't take, rather than ignore them: a field sent and
    silently dropped (an API key's "scope", say) looks like a setting that took."""
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}; {what} takes {', '.join(sorted(allowed))}"
        )

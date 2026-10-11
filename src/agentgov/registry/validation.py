"""Input validation shared by the API and declarative manifests."""

from __future__ import annotations

import re
from typing import Any

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

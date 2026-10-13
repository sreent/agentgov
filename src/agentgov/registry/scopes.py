"""Which agents something applies to: a management rule (docs/management-rules.md) or a
control's exceptions (docs/features.md#exceptions).

A scope narrows by the agent's blueprint, team (its own, or its blueprint's), environment,
the platform it runs on ("gateway" for agents AgentGov's gateway serves) and labels (its
own); every key it has must match, and an empty scope matches every agent.
"""

from __future__ import annotations

from typing import Any

from agentgov.models import Agent
from agentgov.registry import validation
from agentgov.registry.errors import ValidationError

KEYS = ("blueprints", "teams", "environments", "platforms", "labels")


def parse(value: Any, what: str = "scope") -> dict[str, Any]:
    """A scope as the API takes it, checked: lists of names, and labels to match."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{what} is a mapping of {', '.join(KEYS)}")
    unknown = sorted(set(value) - set(KEYS))
    if unknown:
        raise ValidationError(
            f"unknown {what} key(s) {', '.join(unknown)}; a {what} is {', '.join(KEYS)}"
        )
    out: dict[str, Any] = {}
    for key, raw in value.items():
        if key == "labels":
            labels = validation.labels(raw)
            if labels:
                out[key] = labels
        else:
            items = validation.string_list(raw, f"{what}.{key}")
            if items:
                out[key] = items
    return out


def platform(agent: Agent) -> str:
    """Where the agent runs: "gateway", or the platform that runs it."""
    return (agent.source or "")[len("platform:") :] if agent.on_platform else "gateway"


def team(agent: Agent) -> str | None:
    return agent.team or (agent.blueprint.team if agent.blueprint else None)


def matches(scope: dict[str, Any], agent: Agent) -> bool:
    """Whether ``agent`` is in ``scope``."""
    blueprint = agent.blueprint.name if agent.blueprint else None
    if scope.get("blueprints") and blueprint not in scope["blueprints"]:
        return False
    if scope.get("teams") and team(agent) not in scope["teams"]:
        return False
    if scope.get("environments") and agent.environment not in scope["environments"]:
        return False
    if scope.get("platforms") and platform(agent) not in scope["platforms"]:
        return False
    labels = agent.labels or {}
    return all(labels.get(k) == v for k, v in (scope.get("labels") or {}).items())


def describe(scope: dict[str, Any]) -> str:
    """A scope in words, for messages: "team payments, environment dev"."""
    parts = []
    for key, word in (
        ("blueprints", "blueprint"),
        ("teams", "team"),
        ("environments", "environment"),
        ("platforms", "platform"),
    ):
        if scope.get(key):
            parts.append(f"{word} {' or '.join(scope[key])}")
    parts += [f"label {k}={v}" for k, v in sorted((scope.get("labels") or {}).items())]
    return ", ".join(parts) or "every agent"

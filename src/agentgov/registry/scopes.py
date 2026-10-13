"""Which agents something applies to: a management rule (docs/management-rules.md) or a
control's exceptions (docs/features.md#exceptions).

A scope narrows by the agent's blueprint, team (its own, or its blueprint's), environment,
the platform it runs on ("gateway" for agents AgentGov's gateway serves) and labels (its
own); every key it has must match, and an empty scope matches every agent.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov.models import Agent, Blueprint, FeatureSetting, ManagementRule, Team
from agentgov.registry import validation
from agentgov.registry.errors import ValidationError

KEYS = ("blueprints", "teams", "environments", "platforms", "labels")
# The keys whose names must exist, and what each names.
WORDS = {"teams": "team", "blueprints": "blueprint", "platforms": "platform"}
# Where agents run: AgentGov's gateway, or a platform it reads (registry.platforms.SOURCES).
PLATFORMS = (
    "gateway",
    "microsoft-365",
    "copilot-studio",
    "entra-agent-id",
    "aws",
    "google-cloud",
    "salesforce",
    "databricks",
    "microsoft-foundry",
)


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


def known(session: Session) -> dict[str, set[str]]:
    """The names a scope may use: the teams and blueprints there are, and the platforms."""
    return {
        "teams": set(session.scalars(select(Team.name))),
        "blueprints": set(session.scalars(select(Blueprint.name))),
        "platforms": set(PLATFORMS),
    }


def missing(scope: dict[str, Any], names: dict[str, set[str]]) -> list[str]:
    """What ``scope`` names that there isn't ("team cx-platfrom"): it matches no agent there."""
    return [
        f"{word} {name}"
        for key, word in WORDS.items()
        for name in scope.get(key) or []
        if name not in names[key]
    ]


def check_names(
    session: Session,
    scope: dict[str, Any],
    what: str = "scope",
    *,
    had: list[dict[str, Any]] | None = None,
) -> None:
    """Refuse names there aren't: a misspelt team, blueprint or platform would leave the
    scope matching no agent, and nobody would know. What the scopes it ``had`` named stays,
    so editing them isn't stopped by a name from before."""
    before: set[str] = set()
    for old in had or []:
        before |= {f"{w} {n}" for k, w in WORDS.items() for n in old.get(k) or []}
    gone = [m for m in missing(scope, known(session)) if m not in before]
    if gone:
        where = (
            f"; the platforms are {', '.join(PLATFORMS)}"
            if any(m.startswith("platform ") for m in gone)
            else ""
        )
        raise ValidationError(
            f"{what}: there is no {', '.join(gone)} (add it first, or check the spelling{where})"
        )


def naming(session: Session, key: str, name: str) -> list[str]:
    """The controls' exceptions and management rules that name ``name``, a team or a
    blueprint (``key``): without it, their scopes would match no agent, and a rule that
    gives agents an owner couldn't give them that team."""
    found = [
        f"the exceptions to {row.key}"
        for row in session.scalars(select(FeatureSetting).order_by(FeatureSetting.key))
        if any(name in ((e.get("scope") or {}).get(key) or []) for e in row.scopes or [])
    ]
    found += [
        f"management rule {rule.name}"
        for rule in session.scalars(select(ManagementRule).order_by(ManagementRule.name))
        if name in ((rule.scope or {}).get(key) or [])
        or (key == "teams" and (rule.params or {}).get("owner") == name)
    ]
    return found


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

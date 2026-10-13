"""Model providers agents call through the gateway, and which models agents may call.

Each approved provider is a gateway route, ``/llm/<name>``, where agents call it
with their own AgentGov token instead of the provider's API key. The gateway
holds the key: it reads it from a file mounted into it (``key_file``), so the key
never enters AgentGov's database, its API or its ledger.

Agents may call the models their blueprint and their own ``model_access`` grant
(provider plus model globs), within a daily token budget if one is set.
"""

from __future__ import annotations

import fnmatch
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import lock, mark_changed
from agentgov.models import BLOCKED, MODEL_PROVIDER_KINDS, Agent, ModelProvider
from agentgov.registry import validation
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

APPROVED = "approved"
KEY_DIR = "/model-keys"
FIELDS = ("kind", "description", "base_url", "key_file", "trust_level", "prices", "labels")


def get(session: Session, ref: str) -> ModelProvider:
    provider = session.get(ModelProvider, ref) or session.scalar(
        select(ModelProvider).where(ModelProvider.name == ref)
    )
    if provider is None:
        raise NotFound(f"model provider {ref!r} not found")
    return provider


def list_all(session: Session) -> list[ModelProvider]:
    return list(session.scalars(select(ModelProvider).order_by(ModelProvider.name)))


def key_file(provider: ModelProvider) -> str:
    """Where the gateway reads the provider's API key."""
    return provider.key_file or f"{KEY_DIR}/{provider.name}"


def _prices(value: Any) -> dict[str, dict[str, float]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError('prices must map model globs to {"input": USD, "output": USD}')
    prices = {}
    for model, price in value.items():
        if not isinstance(model, str) or not model or not isinstance(price, dict):
            raise ValidationError(f"prices[{model!r}] must be {{input, output}} in USD")
        if set(price) - {"input", "output"}:
            raise ValidationError(f"prices[{model!r}] takes only 'input' and 'output'")
        clean = {}
        for side in ("input", "output"):
            amount = price.get(side, 0)
            if isinstance(amount, bool) or not isinstance(amount, int | float) or amount < 0:
                raise ValidationError(
                    f"prices[{model!r}].{side} must be USD per million tokens (got {amount!r})"
                )
            clean[side] = float(amount)
        prices[model] = clean
    return prices


def _apply(provider: ModelProvider, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "kind":
            value = validation.one_of(value, MODEL_PROVIDER_KINDS, "kind")
        elif key == "base_url":
            value = value or None
            if value is not None:
                parts = urlsplit(str(value))
                if parts.scheme not in ("http", "https") or not parts.hostname:
                    raise ValidationError(
                        "base_url must be an http(s) URL, such as http://vllm:8000"
                    )
        elif key == "key_file":
            value = value or None
            if value is not None and not str(value).startswith("/"):
                raise ValidationError("key_file must be an absolute path inside the gateway")
        elif key == "trust_level":
            value = validation.trust_level(value)
        elif key == "prices":
            value = _prices(value)
        elif key == "labels":
            value = validation.labels(value)
        elif key == "description":
            value = str(value or "")
        if getattr(provider, key) != value:
            setattr(provider, key, value)
            changed.append(key)
    if provider.kind == "openai-compatible" and not provider.base_url:
        raise ValidationError("an openai-compatible provider needs base_url")
    if provider.kind != "openai-compatible" and provider.base_url:
        raise ValidationError(
            f"base_url is only for openai-compatible providers, not {provider.kind}"
        )
    return changed


def create(session: Session, data: dict[str, Any], *, actor: str) -> ModelProvider:
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(ModelProvider).where(ModelProvider.name == name)):
        raise Conflict(f"model provider {name!r} already exists")
    if "kind" not in data:
        raise ValidationError(f"kind is required: one of {', '.join(MODEL_PROVIDER_KINDS)}")
    provider = ModelProvider(
        id=ids.new_id(ids.MODEL_PROVIDER),
        name=name,
        status=APPROVED,
        trust_level="unverified",
        prices={},
        labels={},
        created_by=actor,
    )
    _apply(provider, data)
    session.add(provider)
    session.flush()
    ledger.append(
        session,
        type="model_provider.registered",
        actor=actor,
        resource=f"model-provider/{name}",
        details={"kind": provider.kind, "trust_level": provider.trust_level},
    )
    mark_changed(session, "toolservers")  # the gateway's routes and OPA's data
    return provider


def update(
    session: Session,
    provider: ModelProvider,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(session, provider, version, f"model provider {provider.name}")
    changed = _apply(provider, data)
    if changed:
        edited(provider)
        ledger.append(
            session,
            type="model_provider.updated",
            actor=actor,
            resource=f"model-provider/{provider.name}",
            details={**{k: getattr(provider, k) for k in changed}, "changes": changes(provider)},
        )
        mark_changed(session, "toolservers")
    return changed


def set_status(
    session: Session, provider: ModelProvider, action: str, *, actor: str
) -> ModelProvider:
    if action not in ("block", "unblock"):
        raise ValidationError(f"unknown action {action!r}")
    lock(session, provider)
    if action == "unblock" and provider.status != BLOCKED:
        raise InvalidTransition("model provider is not blocked")
    if action == "block" and provider.status == BLOCKED:
        raise InvalidTransition("model provider is already blocked")
    previous = provider.status
    provider.status = BLOCKED if action == "block" else APPROVED
    ledger.append(
        session,
        type=f"model_provider.{action}",
        actor=actor,
        resource=f"model-provider/{provider.name}",
        severity="warning" if action == "block" else "info",
        details={"from": previous, "to": provider.status},
    )
    mark_changed(session, "toolservers")
    return provider


def delete(session: Session, provider: ModelProvider, *, actor: str) -> None:
    ledger.append(
        session,
        type="model_provider.deleted",
        actor=actor,
        resource=f"model-provider/{provider.name}",
    )
    session.delete(provider)
    mark_changed(session, "toolservers")


def to_dict(provider: ModelProvider) -> dict[str, Any]:
    return {
        "id": provider.id,
        "name": provider.name,
        "version": provider.version,
        "kind": provider.kind,
        "description": provider.description or "",
        "base_url": provider.base_url,
        "key_file": key_file(provider),
        "status": provider.status,
        "trust_level": provider.trust_level,
        "prices": provider.prices or {},
        "labels": provider.labels or {},
        "route": f"/llm/{provider.name}",
        "created_by": provider.created_by,
        "created_at": ids.isoformat(provider.created_at),
        "updated_at": ids.isoformat(provider.updated_at),
    }


def price_of(provider: ModelProvider | None, model: str) -> dict[str, float] | None:
    """USD per million input and output tokens for ``model``, from the most specific glob."""
    if provider is None:
        return None
    matches = [g for g in (provider.prices or {}) if fnmatch.fnmatchcase(model, g)]
    if not matches:
        return None
    return provider.prices[max(matches, key=len)]


def effective_model_access(agent: Agent) -> list[dict[str, Any]]:
    blueprint = agent.blueprint.model_access if agent.blueprint else []
    return validation.merge_model_access(blueprint or [], agent.model_access or [])


def effective_budget(agent: Agent) -> int | None:
    """The agent's daily token budget: its own, else its blueprint's."""
    if agent.daily_token_budget is not None:
        return agent.daily_token_budget
    return agent.blueprint.daily_token_budget if agent.blueprint else None


def may_call(agent: Agent, provider: str, model: str) -> bool:
    return any(
        g["provider"] == provider and any(fnmatch.fnmatchcase(model, m) for m in g["models"])
        for g in effective_model_access(agent)
    )

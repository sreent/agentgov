"""Model providers agents call through the gateway, and what agents spend there."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from ninja import Body

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES
from agentgov.api.versions import if_match
from agentgov.db.models import Agent
from agentgov.registry import model_providers, model_usage
from agentgov.registry.errors import NotFound
from agentgov.registry.validation import known_fields
from agentgov.secops import handoff
from agentgov.web.api import Router
from agentgov.web.auth import guard, require, runtime

router = Router(tags=["models"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("/v1/models/providers", auth=read)
def list_providers(request: HttpRequest) -> list[dict[str, Any]]:
    with runtime(request).db.transaction() as tx:
        return [model_providers.to_dict(p) for p in model_providers.list_all(tx)]


@router.post("/v1/models/providers", status_code=201, auth=admin)
def create_provider(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Approve a model provider; agents call it at ``/llm/<name>`` once the gateway can
    read its API key (``key_file``)."""
    known_fields(body, {"name", *model_providers.FIELDS}, "a model provider")
    rt = runtime(request)
    with rt.db.transaction() as tx:
        provider = model_providers.create(tx, body, actor=request.auth.actor, settings=rt.settings)
        return model_providers.to_dict(provider)


@router.get("/v1/models/providers/{ref}", auth=read)
def get_provider(request: HttpRequest, ref: str) -> dict[str, Any]:
    with runtime(request).db.transaction() as tx:
        return model_providers.to_dict(model_providers.get(tx, ref))


@router.patch("/v1/models/providers/{ref}", auth=admin)
def update_provider(
    request: HttpRequest, ref: str, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    known_fields(body, model_providers.FIELDS, "a model provider's edit")
    rt = runtime(request)
    with rt.db.transaction() as tx:
        provider = model_providers.get(tx, ref)
        model_providers.update(
            tx,
            provider,
            body,
            actor=request.auth.actor,
            version=if_match(request),
            settings=rt.settings,
        )
        return model_providers.to_dict(provider)


@router.post("/v1/models/providers/{ref}/{action}", auth=require("secops"))
def provider_action(request: HttpRequest, ref: str, action: str) -> dict[str, Any]:
    """``block`` stops every call to the provider at once; ``unblock`` allows them again."""
    if action not in ("block", "unblock"):
        raise NotFound(f"no action {action!r}: block or unblock")
    principal = request.auth
    with runtime(request).db.transaction() as tx:
        handoff.check_kill_switch(tx, principal, action)
        provider = model_providers.get(tx, ref)
        model_providers.set_status(tx, provider, action, actor=principal.actor)
        return model_providers.to_dict(provider)


@router.delete("/v1/models/providers/{ref}", status_code=204, auth=admin)
def delete_provider(request: HttpRequest, ref: str) -> None:
    with runtime(request).db.transaction() as tx:
        model_providers.delete(tx, model_providers.get(tx, ref), actor=request.auth.actor)


@router.get("/v1/models/usage", auth=guard(reach.read))
def get_usage(
    request: HttpRequest,
    days: int = 7,
    agent: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    """Calls, tokens and cost per agent, day, provider and model for the last ``days`` days;
    the same added up per owner and per sponsor of the agents; and each agent's tokens
    today against its budget. For someone with roles for some teams only, their agents'."""
    principal = request.auth
    with runtime(request).db.transaction() as tx:
        agent_id = reach.agent(tx, principal, agent).id if agent else None
        rows = model_usage.usage(
            tx, days=min(max(days, 1), 90), agent_id=agent_id, provider=provider
        )
        used = model_usage.tokens_used(tx)
        reached = reach.agent_ids(tx, principal, *READ_ROLES)
        if reached is not None:
            rows = [r for r in rows if r.agent_id in reached]
            used = {k: v for k, v in used.items() if k in reached}
        ids = {r.agent_id for r in rows}
        names = dict(Agent.objects.filter(id__in=ids).values_list("id", "name"))
        budgets = []
        wanted = set(used) | ({agent_id} if agent_id else set())
        for a in Agent.objects.filter(id__in=wanted):
            budget = model_providers.effective_budget(a)
            budgets.append(
                {
                    "agent_id": a.id,
                    "agent_name": a.name,
                    "used_today": used.get(a.id, 0),
                    "daily_token_budget": budget,
                    "over_budget": model_usage.over_budget(budget, used.get(a.id, 0)),
                }
            )
        spend = model_usage.spend(tx, rows)
        return {
            "day": model_usage.today(),
            "rows": [{**model_usage.to_dict(r), "agent_name": names.get(r.agent_id)} for r in rows],
            "by_owner": spend["owner"],
            "by_sponsor": spend["sponsor"],
            "today": sorted(budgets, key=lambda b: -b["used_today"]),
            "totals": {
                "calls": sum(r.calls for r in rows),
                "refused": sum(r.refused for r in rows),
                "input_tokens": sum(r.input_tokens for r in rows),
                "output_tokens": sum(r.output_tokens for r in rows),
                "cost_usd": round(sum(r.cost_usd for r in rows), 6),
            },
        }

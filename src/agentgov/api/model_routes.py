"""Model providers agents call through the gateway, and what agents spend there."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import select

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.models import Agent
from agentgov.registry import agents, model_providers, model_usage
from agentgov.registry.errors import NotFound
from agentgov.secops import handoff

router = APIRouter(prefix="/v1/models", tags=["models"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("/providers")
def list_providers(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    with request.app.state.rt.db.session() as s:
        return [model_providers.to_dict(p) for p in model_providers.list_all(s)]


@router.post("/providers", status_code=201)
def create_provider(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Approve a model provider; agents call it at ``/llm/<name>`` once the gateway can
    read its API key (``key_file``)."""
    with request.app.state.rt.db.session() as s:
        return model_providers.to_dict(model_providers.create(s, body, actor=principal.actor))


@router.get("/providers/{ref}")
def get_provider(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    with request.app.state.rt.db.session() as s:
        return model_providers.to_dict(model_providers.get(s, ref))


@router.patch("/providers/{ref}")
def update_provider(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with request.app.state.rt.db.session() as s:
        provider = model_providers.get(s, ref)
        model_providers.update(s, provider, body, actor=principal.actor)
        return model_providers.to_dict(provider)


@router.post("/providers/{ref}/{action}")
def provider_action(
    request: Request, ref: str, action: str, principal: Principal = Depends(require("secops"))
) -> dict[str, Any]:
    """``block`` stops every call to the provider at once; ``unblock`` allows them again."""
    if action not in ("block", "unblock"):
        raise NotFound(f"no action {action!r}: block or unblock")
    with request.app.state.rt.db.session() as s:
        handoff.check_kill_switch(s, principal, action)
        provider = model_providers.get(s, ref)
        model_providers.set_status(s, provider, action, actor=principal.actor)
        return model_providers.to_dict(provider)


@router.delete("/providers/{ref}", status_code=204)
def delete_provider(request: Request, ref: str, principal: Principal = Depends(admin)) -> None:
    with request.app.state.rt.db.session() as s:
        model_providers.delete(s, model_providers.get(s, ref), actor=principal.actor)


@router.get("/usage")
def get_usage(
    request: Request,
    days: int = 7,
    agent: str | None = None,
    provider: str | None = None,
    _: Principal = Depends(read),
) -> dict[str, Any]:
    """Calls, tokens and cost per agent, day, provider and model for the last ``days`` days;
    the same added up per owner and per sponsor of the agents; and each agent's tokens
    today against its budget."""
    with request.app.state.rt.db.session() as s:
        agent_id = agents.get(s, agent).id if agent else None
        rows = model_usage.usage(
            s, days=min(max(days, 1), 90), agent_id=agent_id, provider=provider
        )
        ids = {r.agent_id for r in rows}
        names = {a.id: a.name for a in s.scalars(select(Agent).where(Agent.id.in_(ids))).unique()}
        used = model_usage.tokens_used(s)
        budgets = []
        wanted = set(used) | ({agent_id} if agent_id else set())
        for a in s.scalars(select(Agent).where(Agent.id.in_(wanted))).unique():
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
        spend = model_usage.spend(s, rows)
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

"""Management rules: what to do about agents that meet some conditions for long enough
(docs/management-rules.md)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from agentgov.api.auth import READ_ROLES, Principal, require, signed_in
from agentgov.registry import access_packages, agents, rules

router = APIRouter(prefix="/v1", tags=["management rules"])
read = require(*READ_ROLES)
admin = require("admin")


def _rt(request: Request) -> Any:
    return request.app.state.rt


@router.get("/rules")
def list_rules(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    with _rt(request).db.session() as s:
        return [rules.to_dict(s, r) for r in rules.list_all(s)]


@router.post("/rules", status_code=201)
def create_rule(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return rules.to_dict(s, rules.create(s, body, actor=principal.actor))


@router.post("/rules/preview")
def preview_draft(
    request: Request, body: dict[str, Any] = Body(...), _: Principal = Depends(read)
) -> dict[str, Any]:
    """What a rule that isn't saved would match, and do: to check one before creating it.
    Changes nothing."""
    with _rt(request).db.session() as s:
        return rules.preview(s, rules.draft(s, body))


@router.post("/rules/evaluate")
def evaluate(request: Request, _: Principal = Depends(admin)) -> dict[str, Any]:
    """Run the rules now, instead of after the next posture scan."""
    result = _rt(request).run_rules()
    if "skipped" in result:
        raise HTTPException(409, result["skipped"])
    return result


@router.get("/rules/{ref}")
def get_rule(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return rules.to_dict(s, rules.get(s, ref))


@router.get("/rules/{ref}/preview")
def preview_rule(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    """The agents the rule matches now, since when, and what it will do to each."""
    with _rt(request).db.session() as s:
        return rules.preview(s, rules.get(s, ref))


@router.patch("/rules/{ref}")
def update_rule(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        rule = rules.get(s, ref)
        rules.update(s, rule, body, actor=principal.actor)
        return rules.to_dict(s, rule)


@router.delete("/rules/{ref}")
def delete_rule(
    request: Request, ref: str, principal: Principal = Depends(admin)
) -> dict[str, str]:
    """Delete a rule: its issues are resolved, and what it did stays done."""
    with _rt(request).db.session() as s:
        rules.delete(s, rules.get(s, ref), actor=principal.actor)
        return {"deleted": ref}


@router.get("/agents/{ref}/rules", tags=["agents"])
def agent_rules(
    request: Request, ref: str, principal: Principal = Depends(signed_in)
) -> list[dict[str, Any]]:
    """The rules that match the agent, and what each will do or did: for readers, and the
    agent's owner and sponsors."""
    with _rt(request).db.session() as s:
        agent = agents.get(s, ref)
        responsible = principal.name.lower() in access_packages.responsible(s, agent)
        if not principal.roles & set(READ_ROLES) and not responsible:
            raise HTTPException(403, f"role {principal.role!r} may not do this")
        return rules.for_agent(s, agent)

"""Management rules: what to do about agents that meet some conditions for long enough
(docs/management-rules.md)."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest
from ninja import Body

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES
from agentgov.api.versions import if_match
from agentgov.registry import access_packages, agents, rules
from agentgov.registry.errors import NotFound
from agentgov.runtime import JOB_WAIT_SECONDS
from agentgov.web.api import HTTPException, Router
from agentgov.web.auth import require, runtime, signed_in

router = Router(tags=["management rules"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("/v1/rules", auth=read)
def list_rules(request: HttpRequest) -> list[dict[str, Any]]:
    with runtime(request).db.transaction() as tx:
        return [rules.to_dict(tx, r) for r in rules.list_all(tx)]


@router.post("/v1/rules", status_code=201, auth=admin)
def create_rule(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    with runtime(request).db.transaction() as tx:
        return rules.to_dict(tx, rules.create(tx, body, actor=request.auth.actor))


@router.post("/v1/rules/preview", auth=read)
def preview_draft(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """What a rule that isn't saved would match, and do: to check one before creating it.
    Changes nothing."""
    with runtime(request).db.transaction() as tx:
        return rules.preview(tx, rules.draft(tx, body))


@router.post("/v1/rules/evaluate", auth=admin)
def evaluate(request: HttpRequest) -> dict[str, Any]:
    """Run the rules now, instead of after the next posture scan."""
    result = runtime(request).run_rules(wait=JOB_WAIT_SECONDS)
    if "skipped" in result:
        raise HTTPException(409, result["skipped"])
    return result


@router.get("/v1/rules/{ref}", auth=read)
def get_rule(request: HttpRequest, ref: str) -> dict[str, Any]:
    with runtime(request).db.transaction() as tx:
        return rules.to_dict(tx, rules.get(tx, ref))


@router.get("/v1/rules/{ref}/preview", auth=read)
def preview_rule(request: HttpRequest, ref: str) -> dict[str, Any]:
    """The agents the rule matches now, since when, and what it will do to each."""
    with runtime(request).db.transaction() as tx:
        return rules.preview(tx, rules.get(tx, ref))


@router.patch("/v1/rules/{ref}", auth=admin)
def update_rule(request: HttpRequest, ref: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    with runtime(request).db.transaction() as tx:
        rule = rules.get(tx, ref)
        rules.update(tx, rule, body, actor=request.auth.actor, version=if_match(request))
        return rules.to_dict(tx, rule)


@router.delete("/v1/rules/{ref}", auth=admin)
def delete_rule(request: HttpRequest, ref: str) -> dict[str, str]:
    """Delete a rule: its issues are resolved, and what it did stays done."""
    with runtime(request).db.transaction() as tx:
        rules.delete(tx, rules.get(tx, ref), actor=request.auth.actor)
        return {"deleted": ref}


@router.get("/v1/agents/{ref}/rules", tags=["agents"], auth=signed_in)
def agent_rules(request: HttpRequest, ref: str) -> list[dict[str, Any]]:
    """The rules that match the agent, and what each will do or did: for readers, and the
    agent's owner and sponsors."""
    principal = request.auth
    with runtime(request).db.transaction() as tx:
        agent = agents.get(tx, ref)
        person = principal.person
        responsible = person is not None and person.lower() in access_packages.responsible(
            tx, agent
        )
        if not reach.roles_at(tx, principal, agent) & set(READ_ROLES) and not responsible:
            raise NotFound(f"agent {ref!r} not found")  # out of their reach
        return rules.for_agent(tx, agent)

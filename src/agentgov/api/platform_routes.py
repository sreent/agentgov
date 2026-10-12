"""Agents on other platforms (Microsoft 365, Copilot Studio) and the connector allowlist."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.identity.delegation import GRAPH, POWER_PLATFORM, DelegationError
from agentgov.platforms import connections, threat_detection
from agentgov.platforms.microsoft import PlatformError
from agentgov.registry import agents, connector_policy, entra_access, features, platforms
from agentgov.runtime import JOB_WAIT_SECONDS

router = APIRouter(prefix="/v1/platforms", tags=["platforms"])
agent_router = APIRouter(prefix="/v1/agents", tags=["platforms"])
read = require(*READ_ROLES)
admin = require("admin")


def _as_signed_in_admin(rt: Any, principal: Principal, api: str) -> str:
    """An access token to act as this administrator in Microsoft, or a 409 saying why not."""
    if rt.delegations is None:
        raise HTTPException(
            409,
            "AgentGov is not set up to act in Microsoft 365 as a signed-in administrator "
            "(AGENTGOV_MICROSOFT_ADMIN_ACTIONS; see docs/platforms.md)",
        )
    if principal.session_id is None:
        raise HTTPException(
            409,
            "Microsoft accepts this only from a signed-in administrator: sign in to AgentGov "
            "with Microsoft Entra ID (in the CLI, `agentgov login`)",
        )
    try:
        return rt.delegations.access_token(principal.session_id, api)
    except DelegationError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("")
def overview(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Each source of platform agents, how many it reported and how its last sync went."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        view = platforms.overview(
            s, m365_configured=rt.m365 is not None, connected=set(rt.platforms)
        )
        detection = threat_detection.summary(s, features.mode(s, threat_detection.FEATURE))
        links = connections.state(s, rt.settings, threat_detection=detection)
    return {
        **view,
        # Whether signed-in administrators can act in Microsoft through AgentGov.
        "admin_actions": rt.delegations is not None,
        "threat_detection": detection,
        "connections": links,
    }


NOT_CONFIGURED = (
    "AgentGov's Microsoft app registration is not configured: set AGENTGOV_M365_TENANT_ID, "
    "AGENTGOV_M365_CLIENT_ID and AGENTGOV_M365_CLIENT_SECRET"
)


def _app_sync(rt: Any, key: str, actor: str) -> dict[str, Any]:
    if rt.m365 is None:
        raise HTTPException(409, NOT_CONFIGURED)
    try:
        outcome = rt.sync_microsoft([key], actor=actor, wait=JOB_WAIT_SECONDS)[key]
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    if outcome.get("off"):
        raise HTTPException(409, f"{key} is turned off: turn it on in Features first")
    if "lacks_permission" in outcome:
        raise HTTPException(
            409,
            "AgentGov's app registration lacks the application permission "
            f"{outcome['lacks_permission']}: grant it, with admin consent, then sync again",
        )
    if "error" in outcome:
        raise HTTPException(502, outcome["error"])
    return outcome


@router.post("/sync")
def sync_all(request: Request, principal: Principal = Depends(admin)) -> dict[str, Any]:
    """Run every connection AgentGov's app registration may use (they also run on a
    schedule); returns each one's counts, its error, or the permission it lacks."""
    rt = request.app.state.rt
    if rt.m365 is None:
        raise HTTPException(409, NOT_CONFIGURED)
    try:
        return rt.sync_microsoft(actor=principal.actor, wait=JOB_WAIT_SECONDS)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post("/microsoft-365/sync")
def sync_microsoft_365(request: Request, principal: Principal = Depends(admin)) -> dict[str, Any]:
    """Read the Microsoft 365 agent catalog now (it is also read on a schedule)."""
    return _app_sync(request.app.state.rt, "microsoft-365", principal.actor)


@router.post("/copilot-studio/import")
def import_copilot_studio(
    request: Request, payload: Any = Body(...), principal: Principal = Depends(admin)
) -> dict[str, int]:
    """Import Copilot Studio agents from a Power Platform inventory export (JSON)."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        counts = platforms.import_copilot_studio(s, payload, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
        return counts


@router.post("/copilot-studio/sync")
def sync_copilot_studio(request: Request, principal: Principal = Depends(admin)) -> dict[str, int]:
    """Read the Copilot Studio inventory now, as the signed-in administrator."""
    rt = request.app.state.rt
    token = _as_signed_in_admin(rt, principal, POWER_PLATFORM)
    try:
        rows = rt.microsoft_admin.copilot_studio_agents(token)
    except PlatformError as exc:
        with rt.db.session() as s:
            platforms.set_sync(
                s, "copilot-studio", ok=False, counts={}, message=str(exc), actor=principal.actor
            )
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s:
        counts = platforms.import_copilot_studio(s, rows, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
        return counts


@router.post("/{source}/sync")
def sync_source(
    request: Request, source: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Run one of the app's connections now (entra-agent-id, purview-audit or defender), or
    read another platform's agents (aws, google-cloud, salesforce or databricks)."""
    rt = request.app.state.rt
    if source in platforms.INVENTORY_SOURCES:
        if source not in rt.platforms:
            raise HTTPException(
                409, f"{platforms.SOURCES[source]} is not configured (docs/other-platforms.md)"
            )
        with rt.db.session() as s:
            if not features.is_on(s, source):
                raise HTTPException(409, f"{source} is turned off: turn it on in Features first")
        try:
            return rt.sync_platform(source, actor=principal.actor, wait=JOB_WAIT_SECONDS)
        except PlatformError as exc:
            raise HTTPException(502, str(exc)) from exc
    if source not in connections.APP_CONNECTIONS:
        raise HTTPException(404, f"no connection {source!r} to sync")
    return _app_sync(rt, source, principal.actor)


@router.get("/connectors")
def connectors(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """Every connector Copilot Studio agents use, and whether it is on the allowlist."""
    with request.app.state.rt.db.session() as s:
        return platforms.connector_usage(s)


@router.put("/connectors/{connector_id}/approval")
def approve_connector(
    request: Request,
    connector_id: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    """Put a connector on the allowlist. Agents using others get a finding."""
    note = body.get("note") or ""
    if not isinstance(note, str):
        raise HTTPException(422, "note must be a string")
    rt = request.app.state.rt
    with rt.db.session() as s:
        platforms.approve_connector(s, connector_id, note=note, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
    return {"connector_id": platforms.connector_key(connector_id), "approved": True}


@router.delete("/connectors/{connector_id}/approval")
def remove_approval(
    request: Request, connector_id: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Take a connector off the allowlist."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        platforms.remove_approval(s, connector_id, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
    return {"connector_id": platforms.connector_key(connector_id), "approved": False}


# ------------------------------------------------- the allowlist in Power Platform


class PolicyTarget(BaseModel):
    scope: Literal["group", "environment"]
    id: str = Field(min_length=1, max_length=100)


class PolicyPush(BaseModel):
    targets: list[PolicyTarget] = Field(min_length=1)


def _policy_targets(rt: Any, token: str) -> list[dict[str, Any]]:
    """Environment groups, and environments with Copilot Studio agents, with the
    policies applied to each."""
    admin_api = rt.microsoft_admin
    targets = []
    for group in admin_api.environment_groups(token):
        assigned = admin_api.policy_assignments(token, "group", str(group.get("id")))
        targets.append(
            {
                "scope": "group",
                "id": str(group.get("id")),
                "name": group.get("displayName") or str(group.get("id")),
                "assigned": [a.get("policyId") for a in assigned],
            }
        )
    with rt.db.session() as s:
        environments = connector_policy.studio_environments(s)
    for environment, count in sorted(environments.items()):
        assigned = admin_api.policy_assignments(token, "environment", environment)
        targets.append(
            {
                "scope": "environment",
                "id": environment,
                "name": environment,
                "agents": count,
                "assigned": [a.get("policyId") for a in assigned],
            }
        )
    return targets


@router.get("/connector-policy")
def connector_policy_preview(request: Request, principal: Principal = Depends(admin)) -> dict:
    """What pushing the connector allowlist into Power Platform would do, read as the
    signed-in administrator."""
    rt = request.app.state.rt
    token = _as_signed_in_admin(rt, principal, POWER_PLATFORM)
    try:
        policies = rt.microsoft_admin.connector_policies(token)
        targets = _policy_targets(rt, token)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s:
        view = connector_policy.preview(s, policies, targets)
        return {**view, "last_push": connector_policy.pushed(s) or None}


@router.post("/connector-policy")
def push_connector_policy(
    request: Request, body: PolicyPush, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Make Power Platform's connector policy "AgentGov connector allowlist" allow
    exactly the approved connectors, and apply it to ``targets``. Every other
    connector is blocked there, for apps and flows as well as agents."""
    rt = request.app.state.rt
    with rt.db.session() as s:
        allowlist = connector_policy.approved(s)
    if not allowlist:
        raise HTTPException(
            409,
            "the connector allowlist is empty: approve at least one connector first "
            "(Power Platform would block every connector)",
        )
    token = _as_signed_in_admin(rt, principal, POWER_PLATFORM)
    admin_api = rt.microsoft_admin
    try:
        policies = admin_api.connector_policies(token)
        mine = connector_policy.ours(policies)
        mine_id = str(mine["id"]) if mine is not None else None
        names = {str(p.get("id")): p.get("name") for p in policies}
        others = {str(p.get("id")) for p in policies if connector_policy.is_connector_policy(p)} - {
            mine_id
        }
        to_apply = []
        for target in body.targets:
            assigned = {
                str(a.get("policyId"))
                for a in admin_api.policy_assignments(token, target.scope, target.id)
            }
            if assigned & others:
                taken = ", ".join(sorted(str(names.get(a) or a) for a in assigned & others))
                raise HTTPException(
                    409,
                    f"{target.scope} {target.id} already has the connector policy {taken}, and "
                    "an environment takes one: remove it in the Power Platform admin center, "
                    "or add AgentGov's connectors to it there",
                )
            if mine_id not in assigned:
                to_apply.append(target)
        saved = admin_api.save_connector_policy(
            token, mine_id, connector_policy.policy_body(allowlist, mine)
        )
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    policy_id = str(saved.get("id") or mine_id or "")
    if not policy_id:
        raise HTTPException(502, "Power Platform saved the policy but gave it no ID")
    applied: list[dict[str, Any]] = [t.model_dump() for t in body.targets if t not in to_apply]
    failure = None
    for target in to_apply:
        try:
            admin_api.assign_policy(token, policy_id, target.scope, target.id)
        except PlatformError as exc:
            failure = str(exc)
            break
        applied.append(target.model_dump())
    # The policy changed in Power Platform either way: record what was done.
    with rt.db.session() as s:
        connector_policy.record_push(
            s, policy_id=policy_id, connectors=allowlist, targets=applied, actor=principal.actor
        )
    if failure:
        raise HTTPException(502, failure)
    return {"policy_id": policy_id, "connectors": allowlist, "targets": applied}


def _platform_block(request: Request, ref: str, principal: Principal, *, blocked: bool) -> dict:
    rt = request.app.state.rt
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        where = platforms.target(s, agent)
    api = POWER_PLATFORM if where["source"] == "copilot-studio" else GRAPH
    token = _as_signed_in_admin(rt, principal, api)
    try:
        if where["source"] == "copilot-studio":
            rt.microsoft_admin.quarantine(
                token, where["environment"], where["id"], quarantined=blocked
            )
        else:
            rt.microsoft_admin.block_package(token, where["id"], blocked=blocked)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        platforms.record_platform_block(s, agent, where, blocked=blocked, actor=principal.actor)
    return {"agent": agent.name, "platform": platforms.SOURCES[where["source"]], "blocked": blocked}


@agent_router.post("/{ref}/platform/block")
def platform_block(request: Request, ref: str, principal: Principal = Depends(admin)) -> dict:
    """Block the agent in its own platform, as the signed-in administrator: quarantine a
    Copilot Studio agent, or block a Microsoft 365 agent for the whole organisation."""
    return _platform_block(request, ref, principal, blocked=True)


@agent_router.post("/{ref}/platform/unblock")
def platform_unblock(request: Request, ref: str, principal: Principal = Depends(admin)) -> dict:
    """Undo a block in the agent's own platform, as the signed-in administrator."""
    return _platform_block(request, ref, principal, blocked=False)


# ------------------------------------------------------ Entra access packages


@router.get("/entra-access-packages")
def entra_access_packages(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """The Microsoft Entra access packages agents can hold, and what each agent's Entra
    identity holds, as last read."""
    with request.app.state.rt.db.session() as s:
        return entra_access.view(s)


@agent_router.get("/{ref}/entra-access-packages")
def agent_entra_access(request: Request, ref: str, _: Principal = Depends(read)) -> dict:
    """The Entra access packages the agent's Entra identity holds, and those it could."""
    with request.app.state.rt.db.session() as s:
        return entra_access.for_agent(s, agents.get(s, ref))


@agent_router.post("/{ref}/entra-access-packages/assign")
def assign_entra_package(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    """Ask Entra to assign an access package to the agent's identity (manage mode). Entra
    delivers it, or refuses; the next sync shows which."""
    rt = request.app.state.rt
    if rt.m365 is None:
        raise HTTPException(409, NOT_CONFIGURED)
    package = body.get("package")
    if not isinstance(package, str) or not package:
        raise HTTPException(422, "package is required: an Entra access package's ID or name")
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        name = agent.name
        identity, package_id, policy_id = entra_access.target(s, agent, package)
    try:
        made = rt.m365.assign_package(
            target_id=identity, policy_id=policy_id, package_id=package_id
        )
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    out = {"request_id": made.get("id"), "state": made.get("state"), "status": made.get("status")}
    with rt.db.session() as s:
        entra_access.requested(
            s, agents.get(s, ref), change="requested", package=package_id, actor=principal.actor,
            policy_id=policy_id, **out,
        )  # fmt: skip
    return {"agent": name, "package_id": package_id, **out}


@agent_router.delete("/{ref}/entra-access-packages/{assignment_id}")
def remove_entra_package(
    request: Request, ref: str, assignment_id: str, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Ask Entra to remove one of the agent identity's assignments (manage mode)."""
    rt = request.app.state.rt
    if rt.m365 is None:
        raise HTTPException(409, NOT_CONFIGURED)
    with rt.db.session() as s:
        agent = agents.get(s, ref)
        name = agent.name
        held = entra_access.holding(s, agent, assignment_id)
    try:
        made = rt.m365.remove_assignment(assignment_id)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    out = {"request_id": made.get("id"), "state": made.get("state"), "status": made.get("status")}
    with rt.db.session() as s:
        entra_access.requested(
            s, agents.get(s, ref), change="removal_requested", package=held["package_id"],
            actor=principal.actor, assignment_id=assignment_id, **out,
        )  # fmt: skip
    return {"agent": name, "assignment_id": assignment_id, **out}

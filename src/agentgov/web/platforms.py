"""Agents on other platforms (Microsoft 365, Copilot Studio) and the connector allowlist."""

from __future__ import annotations

import json
from typing import Any, Literal

from django.http import HttpRequest
from ninja import Body
from pydantic import BaseModel, Field

from agentgov.api import reach
from agentgov.api.auth import READ_ROLES, Principal
from agentgov.coordination import JobBusy
from agentgov.identity.delegation import GRAPH, POWER_PLATFORM, DelegationError
from agentgov.platforms import connections, threat_detection
from agentgov.platforms.microsoft import PlatformError
from agentgov.registry import (
    agents,
    connector_policy,
    entra_access,
    features,
    people,
    platforms,
)
from agentgov.runtime import JOB_WAIT_SECONDS
from agentgov.web.api import (
    HTTPException,
    Router,
)
from agentgov.web.auth import guard, require, runtime

router = Router(tags=["platforms"])
agent_router = Router(tags=["platforms"])
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


@router.get("/v1/platforms", auth=read)
def overview(request: HttpRequest) -> dict[str, Any]:
    """Each source of platform agents, how many it reported and how its last sync went."""
    rt = runtime(request)
    with rt.db.session() as s:
        view = platforms.overview(
            s, m365_configured=rt.m365 is not None, connected=set(rt.platforms)
        )
        detection = threat_detection.summary(s, features.mode(s, threat_detection.FEATURE))
        links = connections.state(s, rt.settings, threat_detection=detection)
        known = people.summary(s)
    return {
        **view,
        # The people platforms name as agents' makers and owners: how many AgentGov knows.
        "people": known,
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


@router.post("/v1/platforms/sync", auth=admin)
def sync_all(request: HttpRequest) -> dict[str, Any]:
    """Run every connection AgentGov's app registration may use (they also run on a
    schedule); returns each one's counts, its error, or the permission it lacks."""
    principal = request.auth
    rt = runtime(request)
    if rt.m365 is None:
        raise HTTPException(409, NOT_CONFIGURED)
    try:
        return rt.sync_microsoft(actor=principal.actor, wait=JOB_WAIT_SECONDS)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc


@router.post("/v1/platforms/microsoft-365/sync", auth=admin)
def sync_microsoft_365(request: HttpRequest) -> dict[str, Any]:
    """Read the Microsoft 365 agent catalog now (it is also read on a schedule)."""
    principal = request.auth
    return _app_sync(runtime(request), "microsoft-365", principal.actor)


# People looked up with a Copilot Studio import or sync, at most: the scheduled lookup
# takes the rest.
PEOPLE_NOW = 200


def _people(rt: Any, principal: Principal) -> dict[str, Any] | None:
    """Look up the people a Copilot Studio import or sync named (docs/platforms.md#who-made-
    each-agent): with AgentGov's app when it may read users, else as the signed-in
    administrator. None when neither can; what went wrong, when it did."""
    with rt.db.session() as s:
        nobody = not people.wanted(s, limit=1) and not people.wanted_emails(s, limit=1)
        if not features.is_on(s, "entra-users") or nobody:
            return None  # off, or nobody to look up
        roles = connections.granted(s)
    ways = []
    if rt.m365 is not None and connections.runnable(connections.BY_KEY["entra-users"], roles):
        ways.append("app")
    if rt.delegations is not None and rt.delegations.has(principal.session_id):
        ways.append("admin")
    error = None
    for way in ways:  # the app first; if it may not, the administrator
        try:
            if way == "app":
                return rt.sync_people(actor=principal.actor, limit=PEOPLE_NOW)
            token = rt.delegations.access_token(principal.session_id, GRAPH)
            return rt.sync_people(actor=principal.actor, token=token, limit=PEOPLE_NOW)
        except (PlatformError, DelegationError, JobBusy) as exc:
            error = str(exc)
    return {"error": error} if error else None


def _with_people(counts: dict[str, Any], looked_up: dict[str, Any] | None) -> dict[str, Any]:
    return {**counts, "people": looked_up} if looked_up is not None else counts


@router.post("/v1/platforms/copilot-studio/import", auth=admin)
def import_copilot_studio(
    request: HttpRequest, payload: Any = Body(...), complete: bool = False
) -> dict[str, Any]:
    """Import Copilot Studio agents from a Power Platform inventory export (JSON). With
    ``complete``, the export is the whole inventory: agents missing from it are marked gone,
    and their findings close."""
    principal = request.auth
    rt = runtime(request)
    with rt.db.session() as s, platforms.first_sync(s, "copilot-studio"):
        counts = platforms.import_copilot_studio(
            s, payload, actor=principal.actor, complete=complete
        )
        platforms.refresh_risk(s, rt.settings)
    return _with_people(counts, _people(rt, principal))


@router.post("/v1/platforms/copilot-studio/sync", auth=admin)
def sync_copilot_studio(request: HttpRequest) -> dict[str, Any]:
    """Read the Copilot Studio inventory now, as the signed-in administrator."""
    principal = request.auth
    rt = runtime(request)
    token = _as_signed_in_admin(rt, principal, POWER_PLATFORM)
    try:
        rows = rt.microsoft_admin.copilot_studio_agents(token)
    except PlatformError as exc:
        with rt.db.session() as s:
            platforms.set_sync(
                s, "copilot-studio", ok=False, counts={}, message=str(exc), actor=principal.actor
            )
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s, platforms.first_sync(s, "copilot-studio"):
        # Every page of the inventory, as the administrator's role sees the tenant.
        counts = platforms.import_copilot_studio(s, rows, actor=principal.actor, complete=True)
        platforms.refresh_risk(s, rt.settings)
    return _with_people(counts, _people(rt, principal))


@router.post("/v1/platforms/entra-users/import", auth=admin)
def import_people(request: HttpRequest) -> dict[str, Any]:
    """Keep the people in a list of users from Microsoft Entra ID: CSV (the Entra admin
    center's Download users) or JSON. Then the makers of Copilot Studio agents are known
    by name without Microsoft Graph."""
    principal = request.auth
    raw = request.body.decode("utf-8-sig", errors="replace")
    payload: Any = raw
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            payload = json.loads(raw or "null")
        except ValueError as exc:
            raise HTTPException(422, f"invalid JSON: {exc}") from exc
    with runtime(request).db.session() as s:
        counts = people.import_list(s, payload, actor=principal.actor)
        return {**counts, "makers": people.summary(s)}


@router.post("/v1/platforms/{source}/sync", auth=admin)
def sync_source(request: HttpRequest, source: str) -> dict[str, Any]:
    """Run one of the app's connections now (entra-agent-id, purview-audit or defender), or
    read another platform's agents (aws, google-cloud, salesforce, databricks or
    microsoft-foundry)."""
    principal = request.auth
    rt = runtime(request)
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


@router.get("/v1/platforms/connectors", auth=read)
def connectors(request: HttpRequest) -> dict[str, Any]:
    """Every connector Copilot Studio agents use, and whether it is on the allowlist."""
    with runtime(request).db.session() as s:
        return platforms.connector_usage(s)


@router.put("/v1/platforms/connectors/{connector_id}/approval", auth=admin)
def approve_connector(
    request: HttpRequest, connector_id: str, body: dict[str, Any] = Body(default={})
) -> dict[str, Any]:
    """Put a connector on the allowlist. Agents using others get a finding."""
    principal = request.auth
    note = body.get("note") or ""
    if not isinstance(note, str):
        raise HTTPException(422, "note must be a string")
    rt = runtime(request)
    with rt.db.session() as s:
        platforms.approve_connector(s, connector_id, note=note, actor=principal.actor)
        platforms.refresh_risk(s, rt.settings)
    return {"connector_id": platforms.connector_key(connector_id), "approved": True}


@router.delete("/v1/platforms/connectors/{connector_id}/approval", auth=admin)
def remove_approval(request: HttpRequest, connector_id: str) -> dict[str, Any]:
    """Take a connector off the allowlist."""
    principal = request.auth
    rt = runtime(request)
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


@router.get("/v1/platforms/connector-policy", auth=admin)
def connector_policy_preview(request: HttpRequest) -> dict:
    """What pushing the connector allowlist into Power Platform would do, read as the
    signed-in administrator."""
    principal = request.auth
    rt = runtime(request)
    token = _as_signed_in_admin(rt, principal, POWER_PLATFORM)
    try:
        policies = rt.microsoft_admin.connector_policies(token)
        targets = _policy_targets(rt, token)
    except PlatformError as exc:
        raise HTTPException(502, str(exc)) from exc
    with rt.db.session() as s:
        view = connector_policy.preview(s, policies, targets)
        return {**view, "last_push": connector_policy.pushed(s) or None}


@router.post("/v1/platforms/connector-policy", auth=admin)
def push_connector_policy(request: HttpRequest, body: PolicyPush) -> dict[str, Any]:
    """Make Power Platform's connector policy "AgentGov connector allowlist" allow
    exactly the approved connectors, and apply it to ``targets``. Every other
    connector is blocked there, for apps and flows as well as agents."""
    principal = request.auth
    rt = runtime(request)
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


def _platform_block(request: HttpRequest, ref: str, principal: Principal, *, blocked: bool) -> dict:
    rt = runtime(request)
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
        platforms.record_platform_block(
            s, rt.settings, agent, where, blocked=blocked, actor=principal.actor
        )
    return {"agent": agent.name, "platform": platforms.SOURCES[where["source"]], "blocked": blocked}


@agent_router.post("/v1/agents/{ref}/platform/block", auth=admin)
def platform_block(request: HttpRequest, ref: str) -> dict:
    """Block the agent in its own platform, as the signed-in administrator: quarantine a
    Copilot Studio agent, or block a Microsoft 365 agent for the whole organisation."""
    principal = request.auth
    return _platform_block(request, ref, principal, blocked=True)


@agent_router.post("/v1/agents/{ref}/platform/unblock", auth=admin)
def platform_unblock(request: HttpRequest, ref: str) -> dict:
    """Undo a block in the agent's own platform, as the signed-in administrator."""
    principal = request.auth
    return _platform_block(request, ref, principal, blocked=False)


# ------------------------------------------------------ Entra access packages


@router.get("/v1/platforms/entra-access-packages", auth=read)
def entra_access_packages(request: HttpRequest) -> dict[str, Any]:
    """The Microsoft Entra access packages agents can hold, and what each agent's Entra
    identity holds, as last read."""
    with runtime(request).db.session() as s:
        return entra_access.view(s)


@agent_router.get("/v1/agents/{ref}/entra-access-packages", auth=guard(reach.read))
def agent_entra_access(request: HttpRequest, ref: str) -> dict:
    """The Entra access packages the agent's Entra identity holds, and those it could."""
    principal = request.auth
    with runtime(request).db.session() as s:
        return entra_access.for_agent(s, reach.agent(s, principal, ref))


@agent_router.post("/v1/agents/{ref}/entra-access-packages/assign", auth=admin)
def assign_entra_package(
    request: HttpRequest, ref: str, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    """Ask Entra to assign an access package to the agent's identity (manage mode). Entra
    delivers it, or refuses; the next sync shows which."""
    principal = request.auth
    rt = runtime(request)
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


@agent_router.delete("/v1/agents/{ref}/entra-access-packages/{assignment_id}", auth=admin)
def remove_entra_package(request: HttpRequest, ref: str, assignment_id: str) -> dict[str, Any]:
    """Ask Entra to remove one of the agent identity's assignments (manage mode)."""
    principal = request.auth
    rt = runtime(request)
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

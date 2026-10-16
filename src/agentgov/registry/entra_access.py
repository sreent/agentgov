"""Microsoft Entra access packages for agents' Entra identities
(docs/microsoft-connections.md#entra-access-packages).

Microsoft Entra ID Governance assigns access packages (security groups, API permissions,
Entra roles) to agent identities, for a while. AgentGov reads which packages agents can
hold, which each agent's Entra identity holds and until when, and raises an issue before
one expires (or when Entra couldn't deliver one), so that the agent's people can extend it.
That is the inform mode, which writes nothing into Entra. In manage mode, administrators
also assign packages to agents and remove them from AgentGov: Entra's own adminAdd and
adminRemove requests, made by AgentGov's app, which Entra may refuse. Nothing is done
when the feature is off.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from agentgov import db, ids, ledger
from agentgov.db.models import Agent
from agentgov.models import DELETED
from agentgov.platforms import connections
from agentgov.registry import features, findings
from agentgov.registry.errors import InvalidTransition, NotFound, ValidationError

FEATURE = connections.ENTRA_ACCESS
# Policies whose holders may be agents' identities: Entra has "all agents", and agent
# identities are service principals.
AGENT_SCOPES = (
    "allDirectoryAgentIdentities",
    "allDirectoryServicePrincipals",
    "specificDirectoryServicePrincipals",
)
# What an identity holds: delivered, or on its way.
HELD = ("delivering", "partiallyDelivered", "delivered")
EXPIRING, FAILED = "entra.access_expiring", "entra.access_failed"
FINDING_TYPES = {EXPIRING, FAILED}
REMIND = timedelta(days=14)
SYSTEM = "system:microsoft"
# Packages whose assignments are read per sync, at most.
MAX_PACKAGES = 200


def _end(assignment: dict[str, Any]) -> datetime | None:
    expiration = (assignment.get("schedule") or {}).get("expiration") or {}
    when = expiration.get("endDateTime") or assignment.get("expiredDateTime")
    if not when:
        return None
    try:
        return datetime.fromisoformat(str(when).replace("Z", "+00:00"))
    except ValueError:
        return None


def agent_policies(package: dict[str, Any]) -> list[dict[str, Any]]:
    """A package's assignment policies that agents' identities may hold it through, the
    ones for all agents first."""
    policies = [
        p
        for p in package.get("assignmentPolicies") or []
        if isinstance(p, dict) and p.get("allowedTargetScope") in AGENT_SCOPES
    ]
    return sorted(policies, key=lambda p: AGENT_SCOPES.index(p["allowedTargetScope"]))


def _identities(tx: db.Where) -> dict[str, Agent]:
    """Agents by their Entra identity's object ID (lower case)."""
    out = {}
    for agent in Agent.objects.exclude(status=DELETED):
        entra = (agent.external_ids or {}).get("entra_agent_id")
        if entra:
            out[str(entra).lower()] = agent
    return out


def record(
    tx: db.Where,
    packages: list[dict[str, Any]],
    assignments: dict[str, list[dict[str, Any]]],
    now: datetime | None = None,
) -> dict[str, int]:
    """Remember the packages agents can hold and what each agent's identity holds, and
    raise or resolve their issues; returns the counts."""
    now = now or ids.utcnow()
    agents = _identities(tx)
    kept = [
        {
            "id": p.get("id"),
            "name": p.get("displayName") or p.get("id"),
            "description": p.get("description") or "",
            "hidden": bool(p.get("isHidden")),
            "policies": [
                {"id": x.get("id"), "name": x.get("displayName"), "scope": x["allowedTargetScope"]}
                for x in agent_policies(p)
            ],
        }
        for p in packages
    ]
    names = {p["id"]: p["name"] for p in kept}
    held: dict[str, list[dict[str, Any]]] = {}
    present: set[str] = set()
    counts = {"packages": len(kept), "assignments": 0, "unlinked": 0, "expiring": 0}
    for package_id, rows in assignments.items():
        for row in rows:
            target = row.get("target") or {}
            agent = agents.get(str(target.get("objectId") or "").lower())
            if agent is None:
                counts["unlinked"] += 1
                continue
            state, end = row.get("state"), _end(row)
            if state not in (*HELD, "deliveryFailed"):
                continue  # expired: gone from the identity
            counts["assignments"] += 1
            name = names.get(package_id, package_id)
            held.setdefault(agent.id, []).append(
                {
                    "id": row.get("id"),
                    "package_id": package_id,
                    "package": name,
                    "state": state,
                    "status": row.get("status"),
                    "expires_at": ids.isoformat(end),
                }
            )
            if state == "deliveryFailed":
                finding, _ = findings.raise_finding(
                    tx,
                    type=FAILED,
                    severity="medium",
                    subject=str(row.get("id")),
                    agent_id=agent.id,
                    title=f"Entra couldn't give {agent.name} its access package {name}",
                    description="Microsoft Entra ID Governance reports the assignment as "
                    f"deliveryFailed ({row.get('status') or 'no status'}).",
                    remediation="Look at the assignment in Microsoft Entra ID Governance; "
                    "remove it, or ask for it again.",
                )
                present.add(finding.key)
            elif end is not None and end - now <= REMIND:
                left = end - now
                days = max(1, int(left.total_seconds() // 86400))
                finding, _ = findings.raise_finding(
                    tx,
                    type=EXPIRING,
                    severity="high"
                    if left <= timedelta(days=1)
                    else "medium"
                    if days <= 7
                    else "low",
                    subject=str(row.get("id")),
                    agent_id=agent.id,
                    title=f"{agent.name}'s Entra access package {name} expires "
                    + ("within a day" if left <= timedelta(days=1) else f"in {days} days"),
                    description=f"Microsoft Entra ID Governance removes it on "
                    f"{end:%Y-%m-%d %H:%M} UTC, with what it grants the agent's identity.",
                    remediation="Its sponsors or owners ask for an extension in My Access, or "
                    "an administrator extends it in Entra; or let it expire if the agent no "
                    "longer needs it.",
                )
                present.add(finding.key)
                counts["expiring"] += 1
    # Gone from two syncs in a row: extended, removed or delivered after all.
    findings.resolve_absent(tx, types=FINDING_TYPES, present_keys=present, actor=SYSTEM, clean=2)
    connections.save_state(
        tx, FEATURE, {"packages": kept, "held": held, "synced_at": ids.isoformat(now)}
    )
    return counts


# ------------------------------------------------------------------------- views


def view(tx: db.Where) -> dict[str, Any]:
    """The packages agents can hold, and what each agent's identity holds."""
    state = connections.load_state(tx, FEATURE)
    held = state.get("held", {})
    names = {}
    for agent_id in held:
        agent = Agent.objects.filter(pk=agent_id).first()
        names[agent_id] = agent.name if agent else agent_id
    return {
        "mode": features.mode(tx, FEATURE),
        "packages": state.get("packages", []),
        "held": held,
        "agents": names,
        "synced_at": state.get("synced_at"),
    }


def for_agent(tx: db.Where, agent: Agent) -> dict[str, Any]:
    state = view(tx)
    entra = (agent.external_ids or {}).get("entra_agent_id")
    return {
        "mode": state["mode"],
        "entra_agent_id": entra,
        "held": state["held"].get(agent.id, []),
        # What it could hold: the packages with a policy for agents.
        "packages": [p for p in state["packages"] if p["policies"]],
        "synced_at": state["synced_at"],
    }


# ------------------------------------------------------------------------ manage


def target(tx: db.Where, agent: Agent, package_id: str) -> tuple[str, str, str]:
    """What an adminAdd for this agent needs: its Entra identity, the package and its
    policy for agents. Refused unless the feature manages packages."""
    if features.mode(tx, FEATURE) != features.MANAGE:
        raise InvalidTransition(
            "Entra access packages are read, not managed: an administrator sets the "
            f"{FEATURE} feature to manage first"
        )
    entra = (agent.external_ids or {}).get("entra_agent_id")
    if not entra:
        raise ValidationError(f"{agent.name} has no Microsoft Entra agent identity")
    package = next(
        (p for p in view(tx)["packages"] if p["id"] == package_id or p["name"] == package_id),
        None,
    )
    if package is None:
        raise NotFound(f"Entra access package {package_id!r} not found: sync it first")
    if not package["policies"]:
        raise ValidationError(
            f"Entra access package {package['name']!r} has no assignment policy for agents"
        )
    return str(entra), package["id"], package["policies"][0]["id"]


def holding(tx: db.Where, agent: Agent, assignment_id: str) -> dict[str, Any]:
    """One of the agent's Entra assignments, for an adminRemove."""
    if features.mode(tx, FEATURE) != features.MANAGE:
        raise InvalidTransition(
            "Entra access packages are read, not managed: an administrator sets the "
            f"{FEATURE} feature to manage first"
        )
    for row in view(tx)["held"].get(agent.id, []):
        if row["id"] == assignment_id:
            return row
    raise NotFound(f"{agent.name} holds no Entra assignment {assignment_id!r}")


def requested(
    tx: db.Where, agent: Agent, *, change: str, package: str, actor: str, **details: Any
) -> None:
    """An Entra request AgentGov's app made, in the ledger."""
    ledger.append(
        tx,
        type=f"entra.access_{change}",
        actor=actor,
        severity="warning" if change == "removal_requested" else "info",
        agent=agent,
        resource=f"entra-access-package/{package}",
        details=details,
    )

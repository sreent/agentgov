"""Posture management: periodic checks that turn registry state into findings.

These mirror the Agent 365 registry tiles ("agents without owners",
"unmanaged agents", "agents at risk") and Entra ID Governance practices
(sponsors, periodic attestation).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.config import Settings
from agentgov.models import ACTIVE, BLOCKED, DELETED, PENDING, Agent, ToolServer
from agentgov.registry import agents as agents_svc
from agentgov.registry import (
    destinations,
    features,
    findings,
    identity_issuers,
    platforms,
    reachability,
    validation,
)

# Failed deliveries in a row before a destination is a finding.
FAILING = 3
POSTURE_TYPES = {
    "agent.no_owner",
    "agent.no_sponsor",
    "agent.attestation_expired",
    "agent.stale",
    "agent.broad_permissions",
    "agent.no_blueprint",
    "agent.identity_error",
    "agent.no_workload_identity",
    "identity_issuer.sync_error",
    "destination.failing",
    "toolserver.unverified",
    "toolserver.pending_review",
}


def scan(
    session: Session, settings: Settings, *, tested: dict[str, Any] | None = None
) -> dict[str, Any]:
    """``tested``: what calling each agent's A2A URL around the gateway found, by agent ID,
    when the scan's test ran (registry/reachability); None when it didn't."""
    now = ids.utcnow()
    present: set[str] = set()
    modes = features.modes(session)

    def flag(type_: str, subject: str, severity: str, title: str, **kw: Any) -> None:
        findings.raise_finding(
            session, type=type_, severity=severity, subject=subject, title=title, **kw
        )
        present.add(f"{type_}:{subject}")

    # Copilot Studio checks (connector allowlist, sharing) first: they count towards risk.
    platform_findings = platforms.evaluate(session)
    # In one order, as the other jobs that update many agents at once take them: none of
    # them waits for a row another holds while holding one the other wants.
    agents = (
        session.scalars(select(Agent).where(Agent.status != DELETED).order_by(Agent.id))
        .unique()
        .all()
    )
    for agent in agents:
        managed = agent.status in (ACTIVE, PENDING, BLOCKED)
        # Agents run by another platform (Microsoft 365, Copilot Studio) never call
        # tools through the gateway: grants, blueprints and activity don't apply.
        on_gateway = not agent.on_platform
        if managed and not agent.owner:
            flag(
                "agent.no_owner",
                agent.id,
                "medium",
                f"Agent {agent.name} has no owner",
                agent_id=agent.id,
                remediation="Assign an owning team or person.",
            )
        if agent.status == ACTIVE and not agent.sponsors:
            flag(
                "agent.no_sponsor",
                agent.id,
                "medium",
                f"Agent {agent.name} has no sponsor",
                agent_id=agent.id,
                remediation="Add an accountable human sponsor.",
            )
        if (
            agent.status == ACTIVE
            and agent.attestation_expires_at is not None
            and agent.attestation_expires_at < now
        ):
            flag(
                "agent.attestation_expired",
                agent.id,
                "medium",
                f"Attestation for {agent.name} expired",
                agent_id=agent.id,
                remediation="A sponsor should confirm the agent is still needed "
                "(POST /v1/agents/{id}/attest) or delete it.",
            )
        stale_cutoff = now - timedelta(days=settings.stale_agent_days)
        last = agent.last_seen_at or agent.created_at
        if on_gateway and agent.status == ACTIVE and last < stale_cutoff:
            flag(
                "agent.stale",
                agent.id,
                "low",
                f"Agent {agent.name} has been inactive for {settings.stale_agent_days}+ days",
                agent_id=agent.id,
                remediation="Delete agents that are no longer used.",
            )
        if on_gateway and managed and validation.is_broad(agents_svc.effective_grants(agent)):
            flag(
                "agent.broad_permissions",
                agent.id,
                "medium",
                f"Agent {agent.name} may call every tool on every server",
                agent_id=agent.id,
                remediation="Replace the */* grant with the tools the agent needs.",
            )
        if on_gateway and managed and agent.blueprint_id is None:
            flag(
                "agent.no_blueprint",
                agent.id,
                "low",
                f"Agent {agent.name} has no blueprint",
                agent_id=agent.id,
                remediation="Assign an IT-approved blueprint.",
            )
        if managed and agent.identity_error:
            flag(
                "agent.identity_error",
                agent.id,
                "medium",
                f"Identity for {agent.name} is out of sync",
                agent_id=agent.id,
                description=agent.identity_error,
            )
        # Its blueprint came to require a workload identity after it was activated.
        if (
            agent.status == ACTIVE
            and agent.blueprint is not None
            and agent.blueprint.require_workload_identity
            and not agent.workload_issuer
        ):
            flag(
                "agent.no_workload_identity",
                agent.id,
                "medium",
                f"Agent {agent.name} authenticates with a client secret",
                agent_id=agent.id,
                description=f"Blueprint {agent.blueprint.name} requires a workload identity.",
                remediation="Give it a workload identity: an identity issuer and its subject "
                "there.",
            )
        if reachability.checked(agent, modes):
            # Calls around the gateway: what its owners say stops them, and the test.
            reachability.scan(
                session, agent, flag, tested=tested.get(agent.id) if tested is not None else None
            )
        agents_svc.refresh_risk(session, settings, agent)

    for issuer in identity_issuers.list_all(session):
        if issuer.sync_error:
            # A block that hasn't reached Keycloak leaves the issuer's agents signing in.
            flag(
                "identity_issuer.sync_error",
                issuer.id,
                "high" if issuer.status == BLOCKED else "medium",
                f"Identity issuer {issuer.name} is out of sync with Keycloak",
                description=issuer.sync_error,
                remediation="Fix what the error names: until then Keycloak trusts the issuer "
                "as it last did, blocked or not.",
            )

    for destination in destinations.list_all(session):
        if destination.status == destinations.ACTIVE and destination.failures >= FAILING:
            # The security team isn't getting the evidence or the alerts it expects.
            flag(
                "destination.failing",
                destination.id,
                "high",
                f"Destination {destination.name} is failing: the security team isn't getting "
                "what it should",
                description=destination.last_error or "",
                remediation="Fix what the error names (the destination's URL, its secret file, "
                "or the SIEM or chat itself). It keeps its place in the ledger and catches up "
                "once it works again.",
            )

    for ts in session.scalars(select(ToolServer)):
        if ts.status == "approved" and ts.trust_level != "verified":
            flag(
                "toolserver.unverified",
                ts.id,
                "medium",
                f"Tool server {ts.name} is approved but unverified",
                remediation="Review the server's publisher and code, then mark it verified.",
            )
        if ts.status == PENDING:
            flag(
                "toolserver.pending_review",
                ts.id,
                "low",
                f"Tool server {ts.name} is waiting for review",
            )

    # What this scan looked for resolves when it's gone; what it didn't look for (the
    # feature off, or no test this time) stays open, unverified, until it looks again.
    checked = set(POSTURE_TYPES)
    unchecked = set()
    for type_, looked in (
        (reachability.UNDECLARED, reachability.on(modes)),
        (reachability.REACHABLE, tested is not None),
    ):
        (checked if looked else unchecked).add(type_)
    resolved = findings.resolve_absent(session, types=checked, present_keys=present)
    findings.mark_unverified(session, types=unchecked)
    return {
        "checked_agents": len(agents),
        "open_posture_findings": len(present),
        "resolved": resolved,
        "open_platform_findings": platform_findings,
    }

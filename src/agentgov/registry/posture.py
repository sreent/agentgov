"""Posture management: periodic checks that turn registry state into findings.

These mirror the Agent 365 registry tiles ("agents without owners",
"unmanaged agents", "agents at risk") and Entra ID Governance practices
(sponsors, periodic attestation).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from agentgov import db, ids
from agentgov.config import Settings
from agentgov.db.models import (
    ACTIVE,
    BLOCKED,
    DELETED,
    PENDING,
    Agent,
    IntegrationState,
    ToolServer,
)
from agentgov.registry import agents as agents_svc
from agentgov.registry import (
    apikeys,
    destinations,
    features,
    findings,
    identity_issuers,
    people,
    platforms,
    reachability,
    validation,
)

# Failed deliveries in a row before a destination is a finding.
FAILING = 3
# Where the last scan's time is kept (an IntegrationState).
SCANNED = "posture-scan"
POSTURE_TYPES = {
    "agent.no_owner",
    "agent.no_sponsor",
    "agent.owner_left",
    "agent.sponsor_left",
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
    apikeys.EXPIRING,
}


def _people_who_left(agent: Agent, gone: list[dict[str, Any]], flag: Any) -> None:
    """An agent whose owner, or some of its sponsors, have left: its issues no longer reach
    them, and someone names others."""

    def words(g: dict[str, Any]) -> str:
        return (
            f"{g['name']} has left" if g["how"] == "left" else f"{g['name']}'s account is disabled"
        )

    owner = [g for g in gone if g["role"] == "owner"]
    if owner:
        flag(
            "agent.owner_left",
            agent.id,
            "medium",
            f"The owner of {agent.name} "
            + ("has left" if owner[0]["how"] == "left" else "has a disabled account"),
            agent_id=agent.id,
            description=f"{words(owner[0])}: its issues go to its sponsors and team instead.",
            remediation="Give it a new owner on its page (Edit), or delete it if nobody needs it.",
            details={"person": owner[0]["name"], "how": owner[0]["how"]},
        )
    sponsors = [g for g in gone if g["role"] == "sponsor"]
    if sponsors:
        none_left = len(sponsors) >= len(agent.sponsors or [])
        flag(
            "agent.sponsor_left",
            agent.id,
            "medium" if none_left else "low",
            f"{'Every' if none_left else 'A'} sponsor of {agent.name} has left",
            agent_id=agent.id,
            description="; ".join(words(g) for g in sponsors) + ".",
            remediation="Name another sponsor: someone who vouches that it is still needed.",
            details={"people": [g["name"] for g in sponsors]},
        )


def scan(
    tx: db.Transaction, settings: Settings, *, tested: dict[str, Any] | None = None
) -> dict[str, Any]:
    """``tested``: what calling each agent's A2A URL around the gateway found, by agent ID,
    when the scan's test ran (registry/reachability); None when it didn't."""
    now = ids.utcnow()
    present: set[str] = set()
    modes = features.modes(tx)

    def flag(type_: str, subject: str, severity: str, title: str, **kw: Any) -> None:
        findings.raise_finding(
            tx, type=type_, severity=severity, subject=subject, title=title, **kw
        )
        present.add(f"{type_}:{subject}")

    # Copilot Studio checks (connector allowlist, sharing) first: they count towards risk.
    platform_findings = platforms.evaluate(tx)
    # In one order, as the other jobs that update many agents at once take them: none of
    # them waits for a row another holds while holding one the other wants.
    agents = list(Agent.objects.exclude(status=DELETED).order_by("id"))
    # The people who left (docs/issues.md#people-who-leave), read once.
    left = people.gone(tx)
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
                remediation="One of its sponsors confirms it is still needed: Attest, on its "
                "issue or its page in AgentGov, or `agentgov agents attest NAME`. If it isn't "
                "needed, an administrator deletes it.",
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
        if managed and left:
            _people_who_left(agent, people.who_left(tx, agent, left), flag)
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
                tx, agent, flag, tested=tested.get(agent.id) if tested is not None else None
            )
        agents_svc.refresh_risk(tx, settings, agent)
    platforms.review_summary(tx)

    for issuer in identity_issuers.list_all(tx):
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

    for destination in destinations.list_all(tx):
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

    for ts in ToolServer.objects.order_by("name"):
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

    for key in apikeys.list_all(tx):
        # A key in use that stops working soon, or did: what uses it needs a new one.
        when = apikeys.expiring(key, settings.api_key_max_days, now)
        if when is not None:
            past = when <= now
            flag(
                apikeys.EXPIRING,
                key.id,
                "medium",
                f"API key {key.name} {'expired' if past else 'expires'} on {when:%Y-%m-%d}",
                description=(
                    "Requests made with it are refused"
                    + (" since then" if past else " from then on")
                    + f". It was last used {key.last_used_at:%Y-%m-%d}, as {key.role}:{key.name}."
                ),
                remediation="Create a new key for what uses it (Access > Create API key, or "
                "agentgov apikeys create), switch it over, then revoke this one, which closes "
                "this issue.",
                details={"key": key.id, "name": key.name, "expires_at": ids.isoformat(when)},
            )

    # What this scan looked for resolves when it's gone; what it didn't look for (the
    # feature off, or no test this time) stays open, unverified, until it looks again.
    checked = set(POSTURE_TYPES)
    for type_, looked, why in (
        (reachability.UNDECLARED, reachability.on(modes), "the check for it is off"),
        (reachability.REACHABLE, tested is not None, "the last posture scan didn't test it"),
    ):
        if looked:
            checked.add(type_)
        else:
            findings.mark_unverified(tx, types={type_}, reason=why)
    resolved = findings.resolve_absent(tx, types=checked, present_keys=present)
    # When it last ran, for the compliance reports: a check set up but never run shows
    # nothing working (agentgov.compliance).
    row = IntegrationState.objects.filter(pk=SCANNED).first()
    row = row or IntegrationState(key=SCANNED, data={})
    row.data, row.updated_at = {"at": ids.isoformat(now), "agents": len(agents)}, now
    row.save(force_insert=row._state.adding)
    return {
        "checked_agents": len(agents),
        "open_posture_findings": len(present),
        "resolved": resolved,
        "open_platform_findings": platform_findings,
    }

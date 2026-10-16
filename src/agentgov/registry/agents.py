"""Agent inventory and lifecycle (the Agent 365 registry, open-source edition)."""

from __future__ import annotations

import fnmatch
from datetime import timedelta
from typing import Any

from django.db.models import Q

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db import lock, mark_changed
from agentgov.db.models import (
    ACTIVE,
    AGENT_STATUSES,
    BLOCKED,
    DELETED,
    DISCOVERED,
    PENDING,
    AccessAssignment,
    Agent,
    AgentInstructions,
)
from agentgov.registry import (
    approvals,
    blueprints,
    features,
    findings,
    identity_issuers,
    model_providers,
    risk,
    teams,
    validation,
)
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

# action -> (allowed source states, target state). Unblocking gives back what blocking found
# (Agent.blocked_from): active, as here, for an agent blocked before that was kept.
TRANSITIONS: dict[str, tuple[frozenset[str], str]] = {
    "approve": (frozenset({PENDING}), ACTIVE),
    "block": (frozenset({PENDING, ACTIVE, DISCOVERED}), BLOCKED),
    "unblock": (frozenset({BLOCKED}), ACTIVE),
    "delete": (frozenset({PENDING, ACTIVE, BLOCKED, DISCOVERED}), DELETED),
    "restore": (frozenset({DELETED}), PENDING),
    "adopt": (frozenset({DISCOVERED}), PENDING),
}
ACTIVATING = {"approve", "unblock"}
# Where an agent registered through the API or a manifest comes from (connectors' agents come
# from platform:<platform>, those seen in traffic from discovered:<how>).
REGISTERED = "registered"
# What an agent's risk counts that an edit can change.
RISKY_FIELDS = {"owner", "sponsors", "risk_tier", "blueprint", "permissions"}

EDITABLE = (
    "description",
    "owner",
    "sponsors",
    "team",
    "labels",
    "framework",
    "platform",
    "models",
    "environment",
    "risk_tier",
    "permissions",
    "model_access",
    "daily_token_budget",
    "agent_card",
    "a2a_url",
    "a2a_protection",
    "agent_access",
    "client_type",
    "redirect_uris",
    "external_ids",
    "blueprint",
)


def client_id_for(name: str) -> str:
    return f"agent-{name}"


def get(tx: db.Transaction, ref: str) -> Agent:
    agent = (
        Agent.objects.filter(pk=ref).first()
        or Agent.objects.filter(Q(name=ref) | Q(client_id=ref)).first()
    )
    if agent is None:
        raise NotFound(f"agent {ref!r} not found")
    return agent


def list_agents(
    tx: db.Transaction,
    *,
    status: str | None = None,
    blueprint: str | None = None,
    risk_level: str | None = None,
    q: str | None = None,
    source: str | None = None,
    include_deleted: bool = False,
) -> list[Agent]:
    found = Agent.objects.order_by("name")
    if source:
        found = found.filter(source=source)
    if status:
        found = found.filter(status=status)
    elif not include_deleted:
        found = found.exclude(status=DELETED)
    if blueprint:
        found = found.filter(blueprint_id=blueprints.get(tx, blueprint).id)
    if risk_level:
        found = found.filter(risk_level=risk_level)
    if q:
        found = found.filter(Q(name__contains=q.lower()) | Q(description__icontains=q))
    return list(found)


def effective_grants(agent: Agent) -> list[dict[str, Any]]:
    bp_grants = agent.blueprint.permissions if agent.blueprint else []
    return validation.merge_grants(bp_grants or [], agent.permissions or [])


def effective_agent_access(agent: Agent) -> list[str]:
    """The agents it may call over A2A: its blueprint's, and its own."""
    blueprint = agent.blueprint.agent_access if agent.blueprint else []
    return validation.merge_agent_access(blueprint or [], agent.agent_access or [])


A2A_PATH = "/a2a/"
# The agents the gateway publishes for A2A: calls to a blocked one are refused, with why.
A2A_PUBLISHED = (ACTIVE, BLOCKED)


def a2a_route(agent: Agent) -> str | None:
    """Where other agents call it through the gateway, when it serves A2A."""
    return f"{A2A_PATH}{agent.name}" if agent.a2a_url else None


def a2a_published(agent: Agent) -> bool:
    """Whether the gateway publishes it for other agents to call (with a2a-gateway on)."""
    return bool(agent.a2a_url) and agent.status in A2A_PUBLISHED and not agent.on_platform


def _unpublished(tx: db.Transaction, agent: Agent) -> str | None:
    """Why the gateway doesn't publish an agent that serves A2A, if it doesn't."""
    if not agent.a2a_url:
        return None
    if features.mode(tx, "a2a-gateway") == features.OFF:
        return "the a2a-gateway feature is off"
    if agent.on_platform:
        return "it runs on a platform AgentGov inventories"
    if agent.status not in A2A_PUBLISHED:
        return f"it is {agent.status}"
    return None


def may_call(caller: Agent, target: Agent) -> bool:
    """Whether ``caller``'s grants let it call ``target`` over A2A (as policy decides)."""
    return (
        caller.id != target.id
        and bool(target.a2a_url)
        and any(fnmatch.fnmatchcase(target.name, p) for p in effective_agent_access(caller))
    )


def a2a_view(
    tx: db.Transaction, settings: Settings, agent: Agent, *, reached: set[str] | None = None
) -> dict[str, Any]:
    """Agent to agent: where it is called through the gateway, whom it may call, and who
    may call it (of the agents ``reached``, by ID, for a role for some teams only)."""
    others = [
        a for a in list_agents(tx) if a.id != agent.id and (reached is None or a.id in reached)
    ]
    route = a2a_route(agent)
    gateway = settings.gateway_public_url.rstrip("/")
    unpublished = _unpublished(tx, agent)
    return {
        "serves": bool(agent.a2a_url),
        "published": bool(agent.a2a_url) and unpublished is None,
        "unpublished": unpublished,
        "a2a_url": agent.a2a_url,
        "url": f"{gateway}{route}" if route else None,
        "card_url": f"{gateway}{route}/.well-known/agent-card.json" if route else None,
        "agent_access": effective_agent_access(agent),
        "may_call": [a.name for a in others if may_call(agent, a)],
        "called_by": [a.name for a in others if may_call(a, agent)],
        # Calls around the gateway (registry/reachability): whether they're looked for,
        # what its owners say stops them, and what AgentGov found when it last called the
        # agent's A2A URL itself.
        "around_gateway": {
            "mode": features.mode(tx, "calls-around-gateway"),
            "protection": agent.a2a_protection,
            "test": agent.a2a_probe,
        },
    }


def _apply(tx: db.Transaction, agent: Agent, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in EDITABLE:
        if key not in data:
            continue
        value = data[key]
        if key == "blueprint":
            bp = blueprints.get(tx, value) if value else None
            if agent.blueprint_id != (bp.id if bp else None):
                agent.blueprint = bp
                if bp and "risk_tier" not in data:
                    agent.risk_tier = bp.risk_tier
                changed.append(key)
            continue
        if key in ("sponsors", "models"):
            value = validation.string_list(value, key)
        elif key == "team":
            value = teams.reference(tx, value)
        elif key == "labels":
            value = validation.labels(value)
        elif key == "permissions":
            value = validation.permissions(value)
        elif key == "model_access":
            value = validation.model_access(value)
        elif key == "agent_access":
            value = validation.agent_access(value)
        elif key == "a2a_url":
            value = validation.a2a_url(value)
        elif key == "a2a_protection":
            value = validation.a2a_protection(value)
        elif key == "client_type":
            value = validation.client_type(value)
        elif key == "redirect_uris":
            value = validation.redirect_uris(value)
        elif key == "daily_token_budget":
            value = validation.token_budget(value)
        elif key == "risk_tier":
            value = validation.risk_tier(value)
        elif key in ("agent_card", "external_ids"):
            if value is not None and not isinstance(value, dict):
                raise ValidationError(f"{key} must be an object")
            if key == "external_ids":
                value = value or {}
        elif key == "description":
            value = str(value or "")
        elif value is not None and not isinstance(value, str):
            raise ValidationError(f"{key} must be a string")
        if getattr(agent, key) != value:
            setattr(agent, key, value)
            changed.append(key)
    if "workload_identity" in data:
        # Its own identity, from an identity issuer, instead of a client secret.
        identity = identity_issuers.workload_identity(tx, agent, data["workload_identity"])
        issuer, subject = identity or (None, None)
        if (agent.workload_issuer, agent.workload_subject) != (issuer, subject):
            agent.workload_issuer, agent.workload_subject = issuer, subject
            changed.append("workload_identity")
    if {"client_type", "redirect_uris", "workload_identity", "blueprint"} & set(changed):
        _check_client(agent)
    if (
        {"workload_identity", "blueprint"} & set(changed)
        and agent.status == ACTIVE
        and _requires_workload_identity(agent)
        and not agent.workload_issuer
        and agent.client_type != validation.PUBLIC
    ):
        raise Conflict(
            f"blueprint {agent.blueprint.name if agent.blueprint else ''} requires a workload "
            "identity: its agents have no client secret"
        )
    return changed


def _check_client(agent: Agent) -> None:
    """A public client is one people sign in to: no secret, nor any identity of its own."""
    if agent.client_type != validation.PUBLIC:
        if agent.redirect_uris:
            raise ValidationError(
                "redirect_uris are for public clients, which people sign in to (client_type public)"
            )
        return
    if agent.workload_issuer:
        raise ValidationError(
            "a public client has no identity of its own, and so no workload identity: people "
            "sign in to it"
        )
    bp = agent.blueprint
    if bp and bp.require_workload_identity:
        raise ValidationError(
            f"blueprint {bp.name} requires a workload identity, which a public client can't "
            "have: people sign in to it"
        )
    if bp and bp.acts_for == "itself":
        raise ValidationError(
            f"a public client acts for the people who sign in to it, and blueprint {bp.name}'s "
            "agents act only for themselves"
        )


def _requires_workload_identity(agent: Agent) -> bool:
    return bool(agent.blueprint and agent.blueprint.require_workload_identity)


def workload_identity(agent: Agent) -> dict[str, str] | None:
    if not agent.workload_issuer:
        return None
    return {"issuer": agent.workload_issuer, "subject": agent.workload_subject or ""}


# Labels under this prefix change what AgentGov does to an agent (agentgov/exempt-rules,
# agentgov/exempt-controls): only administrators set them.
RESERVED_LABELS = "agentgov/"
# Labels the built-in policies read as an allowance (agentgov/policies): pii-access lets the
# agent have personal data unmasked. Only administrators set them too.
ENTITLEMENTS = ("pii-access",)
RESERVED_WORDS = f"labels under {RESERVED_LABELS} and {', '.join(ENTITLEMENTS)}"


def reserved(key: Any) -> bool:
    """Whether only administrators set, change or remove the label ``key``."""
    return str(key).startswith(RESERVED_LABELS) or str(key) in ENTITLEMENTS


def reserved_changes(old: Any, new: Any) -> list[str]:
    """The reserved labels that ``new`` adds, removes or changes from ``old``."""
    old, new = dict(old or {}), dict(new or {})
    return sorted(k for k in set(old) | set(new) if reserved(k) and old.get(k) != new.get(k))


def register(
    tx: db.Transaction,
    settings: Settings,
    data: dict[str, Any],
    *,
    actor: str,
    approve: bool = False,
    admin: bool = True,
) -> Agent:
    """Register an agent. It starts ``pending`` unless ``approve`` is set. Only an
    administrator (``admin``) sets the reserved labels: those that exempt it from rules or
    controls, and those the policies read as an allowance. Where it comes from, the server
    says: registered (connectors and discovery make the others)."""
    name = validation.slug(data.get("name"), "name")
    labels = data.get("labels")
    held = sorted(k for k in labels if reserved(k)) if isinstance(labels, dict) else []
    if held and not admin:
        raise ValidationError(
            f"label(s) {', '.join(held)}: {RESERVED_WORDS} are set by administrators"
        )
    if Agent.objects.filter(name=name).exists():
        raise Conflict(f"agent {name!r} already exists")
    agent = Agent(
        id=ids.new_id(ids.AGENT),
        name=name,
        status=PENDING,
        source=REGISTERED,
        client_id=client_id_for(name),
        created_by=actor,
        sponsors=[],
        labels={},
        models=[],
        permissions=[],
        model_access=[],
        agent_access=[],
        external_ids={},
        client_type=validation.SERVICE,
        redirect_uris=[],
    )
    _apply(tx, agent, data)
    agent.save(force_insert=True)
    ledger.append(
        tx,
        type="agent.registered",
        actor=actor,
        agent=agent,
        details={
            "blueprint": agent.blueprint.name if agent.blueprint else None,
            "owner": agent.owner,
            "sponsors": agent.sponsors,
            "source": agent.source,
        },
    )
    mark_changed(tx, "agents")
    if approve:
        transition(tx, settings, agent, "approve", actor=actor)
    return agent


def update(
    tx: db.Transaction,
    agent: Agent,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
    reason: str | None = None,
) -> list[str]:
    start_edit(tx, agent, version, f"agent {agent.name}")
    if agent.status == DELETED:
        raise Conflict("restore the agent before editing it")
    changed = _apply(tx, agent, data)
    if changed:
        edited(agent)
        agent.save()
        ledger.append(
            tx,
            type="agent.updated",
            actor=actor,
            agent=agent,
            reason=reason,
            details={"changed": changed, "changes": changes(agent)},
        )
        mark_changed(tx, "agents")
    return changed


def _check_activation(agent: Agent) -> None:
    require_sponsor = agent.blueprint.require_sponsor if agent.blueprint else True
    if require_sponsor and not agent.sponsors:
        raise Conflict(
            "an agent needs at least one sponsor before it can be activated "
            "(sponsors are accountable humans, as in Entra Agent ID)"
        )
    if agent.client_type == validation.PUBLIC:
        _check_client(agent)
    elif _requires_workload_identity(agent) and not agent.workload_issuer:
        raise Conflict(
            f"blueprint {agent.blueprint.name if agent.blueprint else ''} requires a workload "
            "identity: give the agent one (an identity issuer and its subject there) first"
        )


def transition(
    tx: db.Transaction,
    settings: Settings,
    agent: Agent,
    action: str,
    *,
    actor: str,
    reason: str | None = None,
) -> Agent:
    if action not in TRANSITIONS:
        raise ValidationError(f"unknown lifecycle action {action!r}")
    lock(tx, agent)
    allowed, target = TRANSITIONS[action]
    if agent.status not in allowed:
        raise InvalidTransition(f"cannot {action} an agent that is {agent.status}")
    if action == "unblock":
        # As it was when it was blocked: blocking then unblocking approves nothing.
        target = agent.blocked_from or target
    if action in ACTIVATING and target == ACTIVE:
        _check_activation(agent)
    if action == "delete" and agent.status == DELETED:
        raise InvalidTransition("agent is already deleted")
    previous = agent.status
    agent.status = target
    agent.blocked_from = previous if target == BLOCKED else None
    agent.status_reason = reason
    now = ids.utcnow()
    if target == ACTIVE and agent.attestation_expires_at is None:
        days = agent.blueprint.attestation_days if agent.blueprint else 90
        if days:
            agent.attestation_expires_at = now + timedelta(days=days)
    if action == "delete":
        agent.deleted_at = now
    elif action == "restore":
        agent.deleted_at = None
    agent.save()
    ledger.append(
        tx,
        type=f"agent.{action}",
        actor=actor,
        agent=agent,
        severity="warning" if action in ("block", "delete") else "info",
        reason=reason,
        details={"from": previous, "to": target},
    )
    if action in ("block", "delete"):
        approvals.cancel_for_agent(tx, agent, actor=actor, reason=f"agent {target}")
    if action == "adopt":
        # Adopting a discovered agent is the answer to its "unmanaged agent" finding.
        findings.resolve_key(tx, f"agent.unmanaged:{agent.id}", actor=actor)
    from agentgov.registry import platforms  # it imports this module

    # Blocked here, an agent on another platform still runs there until someone stops it.
    platforms.check_stop(tx, settings, agent, actor=actor)
    mark_changed(tx, "agents")
    return agent


def attest(tx: db.Transaction, agent: Agent, *, actor: str, note: str | None = None) -> Agent:
    """Record a sponsor's periodic confirmation that the agent is still needed."""
    lock(tx, agent)
    if agent.status not in (ACTIVE, BLOCKED, PENDING):
        raise InvalidTransition(f"cannot attest an agent that is {agent.status}")
    days = (agent.blueprint.attestation_days if agent.blueprint else None) or 90
    now = ids.utcnow()
    agent.attested_at = now
    agent.attested_by = actor
    agent.attestation_expires_at = now + timedelta(days=days)
    agent.save()
    ledger.append(
        tx,
        type="agent.attested",
        actor=actor,
        agent=agent,
        reason=note,
        details={"expires_at": ids.isoformat(agent.attestation_expires_at)},
    )
    mark_changed(tx, "agents")
    return agent


def purge(tx: db.Transaction, agent: Agent, *, actor: str) -> None:
    lock(tx, agent)
    if agent.status != DELETED:
        raise InvalidTransition("only deleted agents can be purged")
    ledger.append(tx, type="agent.purged", actor=actor, agent=agent, severity="warning")
    # Its instructions and access packages go too: the ledger keeps their history (and the
    # instructions' hashes, not their text).
    AgentInstructions.objects.filter(agent_id=agent.id).delete()
    AccessAssignment.objects.filter(agent_id=agent.id).delete()
    Agent.objects.filter(pk=agent.id).delete()
    mark_changed(tx, "agents")


def purge_expired(tx: db.Transaction, settings: Settings) -> list[str]:
    """Purge the agents deleted longer ago than the retention period (0 keeps them):
    until then they can be restored."""
    days = settings.soft_delete_retention_days
    if days <= 0:
        return []
    cutoff = ids.utcnow() - timedelta(days=days)
    expired = Agent.objects.filter(status=DELETED, deleted_at__lt=cutoff).order_by(
        "id"  # in the posture scan's order (registry/posture)
    )
    names = []
    for agent in list(expired):
        names.append(agent.name)
        purge(tx, agent, actor="system:retention")
    return names


def _high_risk(
    tx: db.Transaction, agent: Agent, result: risk.RiskResult, *, raise_it: bool
) -> None:
    """The finding that an agent at the gateway is high or critical risk: a threat when what
    it did adds to its risk, otherwise about how it is set up. It resolves once the risk is
    down. An agent on another platform has none: its risk is the sum of its own findings,
    each already raised."""
    key = f"agent.high_risk:{agent.id}"
    if agent.on_platform or result.level not in ("high", "critical"):
        findings.resolve_key(tx, key, actor="system:risk")
        return
    if not raise_it:
        return
    acted = any(f["factor"] in risk.SIGNAL_LABELS.values() for f in result.factors)
    findings.raise_finding(
        tx,
        type="agent.high_risk",
        severity="critical" if result.level == "critical" else "high",
        subject=agent.id,
        agent_id=agent.id,
        category=findings.THREAT if acted else findings.POSTURE,
        title=f"Agent {agent.name} is {result.level} risk (score {result.score})",
        description="; ".join(f["factor"] for f in result.factors),
        remediation="Investigate recent decisions in the ledger; block the agent if the "
        "activity is not expected."
        if acted
        else "Fix what adds to its risk: its open findings, its owner and sponsors, its grants.",
    )


def refresh_risk(tx: db.Transaction, settings: Settings, agent: Agent) -> risk.RiskResult:
    """Recompute the agent's risk; publish level changes and apply auto-block."""
    result = risk.evaluate(tx, agent, settings.risk_window_hours)
    level_changed = result.level != agent.risk_level
    agent.risk_score = result.score
    agent.risk_level = result.level
    agent.risk_factors = result.factors
    agent.save()
    if level_changed:
        mark_changed(tx, "agents")
    _high_risk(tx, agent, result, raise_it=level_changed)
    # Auto-block is a gateway kill switch: it can't stop an agent on another platform.
    threshold = settings.auto_block_risk_score
    if threshold and result.score >= threshold and agent.status == ACTIVE and not agent.on_platform:
        mode = features.mode_for(tx, agent, "risk-based-access")
        if mode == features.ENFORCE:
            transition(
                tx,
                settings,
                agent,
                "block",
                actor="system:risk",
                reason=f"auto-blocked: risk score {result.score} >= {threshold}",
            )
            findings.raise_finding(
                tx,
                type="agent.auto_blocked",
                severity="critical",
                subject=agent.id,
                agent_id=agent.id,
                category=findings.THREAT,
                title=f"Agent {agent.name} was blocked automatically (risk {result.score})",
                remediation="Review the agent's activity, then unblock it or delete it.",
            )
        elif mode == features.MONITOR:
            findings.raise_finding(
                tx,
                type="agent.would_auto_block",
                severity="high",
                subject=agent.id,
                agent_id=agent.id,
                category=findings.THREAT,
                title=f"Agent {agent.name} would have been blocked automatically "
                f"(risk {result.score})",
                description="Risk-based access is in monitor mode, so the agent was not blocked.",
                remediation="Review the agent's activity, and block it if it isn't expected.",
            )
    return result


def identity_method(agent: Agent) -> str:
    if agent.client_type == validation.PUBLIC:
        return "sign-in"
    return "workload-identity" if agent.workload_issuer else "client-secret"


def to_dict(agent: Agent) -> dict[str, Any]:
    return {
        "id": agent.id,
        "name": agent.name,
        "version": agent.version,
        "description": agent.description,
        "status": agent.status,
        "status_reason": agent.status_reason,
        # Blocked, what unblocking gives back.
        "blocked_from": agent.blocked_from,
        "blueprint": agent.blueprint.name if agent.blueprint else None,
        "owner": agent.owner,
        "sponsors": agent.sponsors or [],
        "team": agent.team,
        "labels": agent.labels or {},
        "framework": agent.framework,
        "platform": agent.platform,
        "models": agent.models or [],
        "environment": agent.environment,
        "risk_tier": agent.risk_tier,
        "classification": agent.classification,
        "risk": {
            "score": agent.risk_score,
            "level": agent.risk_level,
            "factors": agent.risk_factors or [],
        },
        "permissions": agent.permissions or [],
        "effective_permissions": effective_grants(agent),
        "model_access": agent.model_access or [],
        "effective_model_access": model_providers.effective_model_access(agent),
        "daily_token_budget": agent.daily_token_budget,
        "effective_daily_token_budget": model_providers.effective_budget(agent),
        # Who it acts for, and who decides approvals made for a person: its blueprint's.
        "acts_for": agent.blueprint.acts_for if agent.blueprint else "either",
        "people_groups": (agent.blueprint.people_groups or []) if agent.blueprint else [],
        "approvals_by": agent.blueprint.approvals_by if agent.blueprint else "approvers",
        "agent_card": agent.agent_card,
        # Agent to agent: where it serves A2A, its route on the gateway, and whom it calls.
        "a2a_url": agent.a2a_url,
        "a2a_route": a2a_route(agent),
        "a2a_protection": agent.a2a_protection,
        "a2a_test": agent.a2a_probe,
        "agent_access": agent.agent_access or [],
        "effective_agent_access": effective_agent_access(agent),
        "external_ids": agent.external_ids or {},
        "source": agent.source,
        "workload_identity": workload_identity(agent),
        "client_type": agent.client_type or validation.SERVICE,
        "redirect_uris": agent.redirect_uris or [],
        "identity": {
            "provider": "keycloak",
            "client_id": agent.client_id,
            # How it gets its tokens: people sign in to it (a public client), or it
            # authenticates to Keycloak with its workload identity or a client secret.
            "method": identity_method(agent),
            "synced_at": ids.isoformat(agent.identity_synced_at),
            "error": agent.identity_error,
        },
        "attestation": {
            "attested_at": ids.isoformat(agent.attested_at),
            "attested_by": agent.attested_by,
            "expires_at": ids.isoformat(agent.attestation_expires_at),
        },
        "created_by": agent.created_by,
        "created_at": ids.isoformat(agent.created_at),
        "updated_at": ids.isoformat(agent.updated_at),
        "last_seen_at": ids.isoformat(agent.last_seen_at),
        "deleted_at": ids.isoformat(agent.deleted_at),
    }


assert set(AGENT_STATUSES) >= {t for _, t in TRANSITIONS.values()}

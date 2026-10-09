"""Agent inventory and lifecycle (the Agent 365 registry, open-source edition)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import mark_changed
from agentgov.models import (
    ACTIVE,
    AGENT_STATUSES,
    BLOCKED,
    DELETED,
    DISCOVERED,
    PENDING,
    Agent,
)
from agentgov.registry import blueprints, findings, risk, validation
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError

# action -> (allowed source states, target state)
TRANSITIONS: dict[str, tuple[frozenset[str], str]] = {
    "approve": (frozenset({PENDING}), ACTIVE),
    "block": (frozenset({PENDING, ACTIVE, DISCOVERED}), BLOCKED),
    "unblock": (frozenset({BLOCKED}), ACTIVE),
    "delete": (frozenset({PENDING, ACTIVE, BLOCKED, DISCOVERED}), DELETED),
    "restore": (frozenset({DELETED}), PENDING),
    "adopt": (frozenset({DISCOVERED}), PENDING),
}
ACTIVATING = {"approve", "unblock"}

EDITABLE = (
    "description",
    "owner",
    "sponsors",
    "labels",
    "framework",
    "platform",
    "models",
    "environment",
    "risk_tier",
    "permissions",
    "agent_card",
    "external_ids",
    "blueprint",
)


def client_id_for(name: str) -> str:
    return f"agent-{name}"


def get(session: Session, ref: str) -> Agent:
    agent = session.get(Agent, ref) or session.scalar(
        select(Agent).where(or_(Agent.name == ref, Agent.client_id == ref))
    )
    if agent is None:
        raise NotFound(f"agent {ref!r} not found")
    return agent


def list_agents(
    session: Session,
    *,
    status: str | None = None,
    blueprint: str | None = None,
    risk_level: str | None = None,
    q: str | None = None,
    include_deleted: bool = False,
) -> list[Agent]:
    stmt = select(Agent).order_by(Agent.name)
    if status:
        stmt = stmt.where(Agent.status == status)
    elif not include_deleted:
        stmt = stmt.where(Agent.status != DELETED)
    if blueprint:
        stmt = stmt.where(Agent.blueprint_id == blueprints.get(session, blueprint).id)
    if risk_level:
        stmt = stmt.where(Agent.risk_level == risk_level)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(Agent.name.like(like), Agent.description.ilike(like)))
    return list(session.scalars(stmt).unique())


def effective_grants(agent: Agent) -> list[dict[str, Any]]:
    bp_grants = agent.blueprint.permissions if agent.blueprint else []
    return validation.merge_grants(bp_grants or [], agent.permissions or [])


def _apply(session: Session, agent: Agent, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in EDITABLE:
        if key not in data:
            continue
        value = data[key]
        if key == "blueprint":
            bp = blueprints.get(session, value) if value else None
            if agent.blueprint_id != (bp.id if bp else None):
                agent.blueprint = bp
                agent.blueprint_id = bp.id if bp else None
                if bp and "risk_tier" not in data:
                    agent.risk_tier = bp.risk_tier
                changed.append(key)
            continue
        if key in ("sponsors", "models"):
            value = validation.string_list(value, key)
        elif key == "labels":
            value = validation.labels(value)
        elif key == "permissions":
            value = validation.permissions(value)
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
    return changed


def register(
    session: Session,
    settings: Settings,
    data: dict[str, Any],
    *,
    actor: str,
    approve: bool = False,
) -> Agent:
    """Register an agent. It starts ``pending`` unless ``approve`` is set."""
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(Agent).where(Agent.name == name)):
        raise Conflict(f"agent {name!r} already exists")
    agent = Agent(
        id=ids.new_id(ids.AGENT),
        name=name,
        status=PENDING,
        source=str(data.get("source") or "registered"),
        client_id=client_id_for(name),
        created_by=actor,
        sponsors=[],
        labels={},
        models=[],
        permissions=[],
        external_ids={},
    )
    _apply(session, agent, data)
    session.add(agent)
    session.flush()
    ledger.append(
        session,
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
    mark_changed(session, "agents")
    if approve:
        transition(session, settings, agent, "approve", actor=actor)
    return agent


def update(session: Session, agent: Agent, data: dict[str, Any], *, actor: str) -> list[str]:
    if agent.status == DELETED:
        raise Conflict("restore the agent before editing it")
    changed = _apply(session, agent, data)
    if changed:
        ledger.append(
            session,
            type="agent.updated",
            actor=actor,
            agent=agent,
            details={"changed": changed},
        )
        mark_changed(session, "agents")
    return changed


def _check_activation(agent: Agent) -> None:
    require_sponsor = agent.blueprint.require_sponsor if agent.blueprint else True
    if require_sponsor and not agent.sponsors:
        raise Conflict(
            "an agent needs at least one sponsor before it can be activated "
            "(sponsors are accountable humans, as in Entra Agent ID)"
        )


def transition(
    session: Session,
    settings: Settings,
    agent: Agent,
    action: str,
    *,
    actor: str,
    reason: str | None = None,
) -> Agent:
    if action not in TRANSITIONS:
        raise ValidationError(f"unknown lifecycle action {action!r}")
    allowed, target = TRANSITIONS[action]
    if agent.status not in allowed:
        raise InvalidTransition(f"cannot {action} an agent that is {agent.status}")
    if action in ACTIVATING:
        _check_activation(agent)
    if action == "delete" and agent.status == DELETED:
        raise InvalidTransition("agent is already deleted")
    previous = agent.status
    agent.status = target
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
    ledger.append(
        session,
        type=f"agent.{action}",
        actor=actor,
        agent=agent,
        severity="warning" if action in ("block", "delete") else "info",
        reason=reason,
        details={"from": previous, "to": target},
    )
    mark_changed(session, "agents")
    return agent


def attest(session: Session, agent: Agent, *, actor: str, note: str | None = None) -> Agent:
    """Record a sponsor's periodic confirmation that the agent is still needed."""
    if agent.status not in (ACTIVE, BLOCKED, PENDING):
        raise InvalidTransition(f"cannot attest an agent that is {agent.status}")
    days = (agent.blueprint.attestation_days if agent.blueprint else None) or 90
    now = ids.utcnow()
    agent.attested_at = now
    agent.attested_by = actor
    agent.attestation_expires_at = now + timedelta(days=days)
    ledger.append(
        session,
        type="agent.attested",
        actor=actor,
        agent=agent,
        reason=note,
        details={"expires_at": ids.isoformat(agent.attestation_expires_at)},
    )
    mark_changed(session, "agents")
    return agent


def purge(session: Session, agent: Agent, *, actor: str) -> None:
    if agent.status != DELETED:
        raise InvalidTransition("only deleted agents can be purged")
    ledger.append(session, type="agent.purged", actor=actor, agent=agent, severity="warning")
    session.delete(agent)
    mark_changed(session, "agents")


def refresh_risk(session: Session, settings: Settings, agent: Agent) -> risk.RiskResult:
    """Recompute the agent's risk; publish level changes and apply auto-block."""
    result = risk.evaluate(session, agent, settings.risk_window_hours)
    level_changed = result.level != agent.risk_level
    agent.risk_score = result.score
    agent.risk_level = result.level
    agent.risk_factors = result.factors
    if level_changed:
        mark_changed(session, "agents")
        if result.level in ("high", "critical"):
            findings.raise_finding(
                session,
                type="agent.high_risk",
                severity="critical" if result.level == "critical" else "high",
                subject=agent.id,
                agent_id=agent.id,
                category=findings.THREAT,
                title=f"Agent {agent.name} is {result.level} risk (score {result.score})",
                description="; ".join(f["factor"] for f in result.factors),
                remediation="Investigate recent decisions in the ledger; block the agent if "
                "the activity is not expected.",
            )
    threshold = settings.auto_block_risk_score
    if threshold and result.score >= threshold and agent.status == ACTIVE:
        transition(
            session,
            settings,
            agent,
            "block",
            actor="system:risk",
            reason=f"auto-blocked: risk score {result.score} >= {threshold}",
        )
        findings.raise_finding(
            session,
            type="agent.auto_blocked",
            severity="critical",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"Agent {agent.name} was blocked automatically (risk {result.score})",
            remediation="Review the agent's activity, then unblock it or delete it.",
        )
    return result


def to_dict(agent: Agent) -> dict[str, Any]:
    return {
        "id": agent.id,
        "name": agent.name,
        "description": agent.description,
        "status": agent.status,
        "status_reason": agent.status_reason,
        "blueprint": agent.blueprint.name if agent.blueprint else None,
        "owner": agent.owner,
        "sponsors": agent.sponsors or [],
        "labels": agent.labels or {},
        "framework": agent.framework,
        "platform": agent.platform,
        "models": agent.models or [],
        "environment": agent.environment,
        "risk_tier": agent.risk_tier,
        "risk": {
            "score": agent.risk_score,
            "level": agent.risk_level,
            "factors": agent.risk_factors or [],
        },
        "permissions": agent.permissions or [],
        "effective_permissions": effective_grants(agent),
        "agent_card": agent.agent_card,
        "external_ids": agent.external_ids or {},
        "source": agent.source,
        "identity": {
            "provider": "keycloak",
            "client_id": agent.client_id,
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

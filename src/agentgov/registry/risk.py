"""Agent risk scoring (the open equivalent of Entra ID Protection's risky agents).

The score combines static posture factors with runtime signals from the
governance processor. Signals decay after ``risk_window_hours``. The resulting
risk level is published to OPA, where the baseline policy blocks agents whose
risk is critical (risk-based conditional access).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.models import DISCOVERED, Agent, Finding, RiskSignal
from agentgov.registry import validation

TIER_POINTS = {"minimal": 0, "low": 5, "medium": 10, "high": 25, "critical": 40}

# kind -> (points per occurrence, cap)
SIGNAL_WEIGHTS: dict[str, tuple[int, int]] = {
    "policy_denied": (3, 15),
    "secret_detected": (15, 30),
    "prompt_injection": (10, 30),
    "approval_denied": (5, 15),
    "tool_poisoning_exposure": (10, 20),
    "unregistered_activity": (10, 20),
}

# An open "unsafe instructions" finding, by its severity.
INSTRUCTION_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}

# Open findings about how an agent on another platform (Copilot Studio) is set up.
FINDING_WEIGHTS: dict[str, tuple[str, int]] = {
    "platform.no_authentication": ("Published without user authentication", 25),
    "platform.unapproved_connector": ("Uses connectors that are not approved", 20),
    "platform.maker_credentials": ("Tools run with the maker's connections", 10),
    "platform.shared_with_everyone": ("Shared with the whole organisation", 10),
}

SIGNAL_LABELS = {
    "policy_denied": "Recent policy denials",
    "secret_detected": "Credentials found in tool arguments",
    "prompt_injection": "Prompt-injection payloads in tool results",
    "approval_denied": "Approvals denied by reviewers",
    "tool_poisoning_exposure": "Exposure to poisoned tool definitions",
    "unregistered_activity": "Activity while unregistered",
}


def level_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


@dataclass
class RiskResult:
    score: int
    level: str
    factors: list[dict[str, Any]] = field(default_factory=list)


def add_signal(session: Session, agent_id: str, kind: str, detail: str | None = None) -> None:
    session.add(RiskSignal(id=ids.new_id(ids.SIGNAL), agent_id=agent_id, kind=kind, detail=detail))


def evaluate(session: Session, agent: Agent, window_hours: int) -> RiskResult:
    factors: list[dict[str, Any]] = []

    def factor(name: str, points: int, detail: str = "") -> None:
        if points:
            factors.append({"factor": name, "points": points, "detail": detail})

    factor("Declared risk tier", TIER_POINTS.get(agent.risk_tier, 10), agent.risk_tier)
    if agent.status == DISCOVERED and agent.on_platform:
        # Inventoried by its platform, not seen acting outside governance.
        factor("Not reviewed in AgentGov yet", 15)
    elif agent.status == DISCOVERED:
        factor("Unmanaged (discovered, not registered)", 30)
    if not agent.owner:
        factor("No owner", 10)
    if not agent.sponsors:
        factor("No sponsor", 10)
    expires = agent.attestation_expires_at
    if expires is not None and expires < ids.utcnow():
        factor("Attestation expired", 10, ids.isoformat(expires) or "")
    blueprint_grants = agent.blueprint.permissions if agent.blueprint else []
    if validation.is_broad(validation.merge_grants(blueprint_grants, agent.permissions)):
        factor("Unrestricted tool permissions (*/*)", 15)

    since = ids.utcnow() - timedelta(hours=window_hours)
    rows = session.execute(
        select(RiskSignal.kind, func.count())
        .where(RiskSignal.agent_id == agent.id, RiskSignal.ts >= since)
        .group_by(RiskSignal.kind)
    ).all()
    for kind, count in rows:
        per, cap = SIGNAL_WEIGHTS.get(kind, (2, 10))
        factor(SIGNAL_LABELS.get(kind, kind), min(cap, per * count), f"{count} in {window_hours}h")

    unsafe = session.scalar(
        select(Finding.severity).where(
            Finding.key == f"agent.unsafe_instructions:{agent.id}", Finding.status == "open"
        )
    )
    if unsafe:
        factor("Unsafe instructions", INSTRUCTION_POINTS.get(unsafe, 10), unsafe)
    if agent.on_platform:
        open_types = session.scalars(
            select(Finding.type).where(
                Finding.agent_id == agent.id,
                Finding.status == "open",
                Finding.type.in_(FINDING_WEIGHTS),
            )
        )
        for type_ in sorted(set(open_types)):
            factor(*FINDING_WEIGHTS[type_])

    score = min(100, sum(f["points"] for f in factors))
    return RiskResult(score=score, level=level_for(score), factors=factors)

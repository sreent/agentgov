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

from django.db.models import Count

from agentgov import db, ids
from agentgov.db.models import Finding, RiskSignal
from agentgov.models import DISCOVERED, Agent
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
    "jailbreak_attempt": (5, 20),
}

# An open "unsafe instructions" finding, by its severity.
INSTRUCTION_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}

# Open findings about how an agent on another platform is set up.
FINDING_WEIGHTS: dict[str, tuple[str, int]] = {
    "platform.no_authentication": ("Published without user authentication", 25),
    "platform.unapproved_connector": ("Uses connectors that are not approved", 20),
    "platform.plain_secret": ("Secrets in its settings, in plain text", 20),
    "platform.weak_authentication": ("Callers aren't narrowed down", 15),
    "platform.broad_identity": ("Runs with broad or default access", 15),
    "platform.risky_tool": ("Can run code or work a computer", 15),
    "platform.maker_credentials": ("Tools run with the maker's connections", 10),
    "platform.shared_with_everyone": ("Shared with the whole organisation", 10),
    "platform.no_guardrail": ("No guardrails on what it says", 10),
    "defender.alert": ("Open Microsoft Defender alerts", 20),
    "entra.disabled_by_microsoft": ("Entra agent identity disabled by Microsoft", 25),
}

SIGNAL_LABELS = {
    "policy_denied": "Recent policy denials",
    "secret_detected": "Credentials found in tool arguments",
    "prompt_injection": "Prompt-injection payloads in tool results",
    "approval_denied": "Approvals denied by reviewers",
    "tool_poisoning_exposure": "Exposure to poisoned tool definitions",
    "unregistered_activity": "Activity while unregistered",
    "jailbreak_attempt": "Jailbreak attempts in conversations",
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


def add_signal(tx: db.Where, agent_id: str, kind: str, detail: str | None = None) -> None:
    RiskSignal.objects.create(
        id=ids.new_id(ids.SIGNAL), agent_id=agent_id, kind=kind, detail=detail
    )


def evaluate(tx: db.Where, agent: Agent, window_hours: int) -> RiskResult:
    factors: list[dict[str, Any]] = []

    def factor(name: str, points: int, detail: str = "") -> None:
        if points:
            factors.append({"factor": name, "points": points, "detail": detail})

    # An agent found on a platform and not reviewed yet: that is its status, not a risk, and
    # nobody has declared its tier. Its risk is what its platform's settings expose, which
    # its findings say, and its missing owner and sponsor.
    unreviewed = agent.status == DISCOVERED and agent.on_platform
    if not unreviewed:
        factor("Declared risk tier", TIER_POINTS.get(agent.risk_tier, 10), agent.risk_tier)
    if agent.status == DISCOVERED and not agent.on_platform:
        # Seen acting outside governance.
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
    rows = (
        RiskSignal.objects.filter(agent_id=agent.id, ts__gte=since)
        .values("kind")
        .annotate(n=Count("id"))
        .order_by("kind")
        .values_list("kind", "n")
    )
    for kind, count in rows:
        per, cap = SIGNAL_WEIGHTS.get(kind, (2, 10))
        factor(SIGNAL_LABELS.get(kind, kind), min(cap, per * count), f"{count} in {window_hours}h")

    unsafe = (
        Finding.objects.filter(key=f"agent.unsafe_instructions:{agent.id}", status="open")
        .values_list("severity", flat=True)
        .first()
    )
    if unsafe:
        factor("Unsafe instructions", INSTRUCTION_POINTS.get(unsafe, 10), unsafe)
    if agent.on_platform:
        open_types = Finding.objects.filter(
            agent_id=agent.id, status="open", type__in=list(FINDING_WEIGHTS)
        ).values_list("type", flat=True)
        for type_ in sorted(set(open_types)):
            factor(*FINDING_WEIGHTS[type_])

    score = min(100, sum(f["points"] for f in factors))
    level = level_for(score)
    # An open issue of high severity or worse about how the agent is exposed: whatever the
    # score adds up to, the agent is at high risk at least (not critical, which would block
    # it where risk-based access is enforced).
    if level in ("low", "medium"):
        worst = (
            Finding.objects.filter(
                agent_id=agent.id,
                status="open",
                severity__in=("high", "critical"),
                type__in=(*FINDING_WEIGHTS, "agent.unsafe_instructions"),
            )
            .values_list("title", flat=True)
            .first()
        )
        if worst:
            level = "high"
            factors.append(
                {
                    "factor": "Open issue of high severity: at least high risk",
                    "points": 0,
                    "detail": worst,
                }
            )
    return RiskResult(score=score, level=level, factors=factors)

"""Each agent's classification under the EU AI Act, and the register of them
(docs/evidence.md#a-classification-register): whether it is an AI system and at which level
of risk, the organisation's role for it, why, and what it is for. Which obligations apply
to an agent follows from these; deciding them is the organisation's, and AgentGov keeps
what it decided, who decided and when.
"""

from __future__ import annotations

from typing import Any

from agentgov import db, ids, ledger
from agentgov.db.models import Agent
from agentgov.registry.errors import ValidationError

CATEGORIES = {
    "prohibited": "A prohibited practice (Art. 5)",
    "high-risk": "High-risk (Art. 6: Annex I or Annex III)",
    "transparency": "Transparency obligations (Art. 50)",
    "minimal": "Minimal risk",
    "not-ai-system": "Not an AI system (Art. 3(1))",
}
ROLES = {
    "provider": "Provider",
    "deployer": "Deployer",
    "provider-and-deployer": "Provider and deployer",
}
FIELDS = ("category", "role", "basis", "purpose")
# Those that need a reason: the Annex III area, say, or the practice.
EXPLAINED = ("prohibited", "high-risk")
MAX_TEXT = 2000


def normalize(value: Any) -> dict[str, str] | None:
    """A classification as given, checked: None clears it."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError("classification is an object: category, role, basis and purpose")
    unknown = sorted(set(value) - {*FIELDS, "by", "at"})
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}: send category, role, basis and purpose"
        )
    category, role = value.get("category"), value.get("role")
    if category not in CATEGORIES:
        raise ValidationError(f"category is one of {', '.join(CATEGORIES)}")
    if role not in ROLES:
        raise ValidationError(f"role is one of {', '.join(ROLES)}")
    out = {"category": category, "role": role}
    for key in ("basis", "purpose"):
        text = value.get(key)
        if text is not None and not isinstance(text, str):
            raise ValidationError(f"{key} is text")
        out[key] = (text or "").strip()
        if len(out[key]) > MAX_TEXT:
            raise ValidationError(f"{key} is {MAX_TEXT} characters at most")
    if category in EXPLAINED and not out["basis"]:
        raise ValidationError(
            f"say why it is {category} (basis): the Annex III area, say, or the Article 5 practice"
        )
    return out


def _plain(value: dict[str, Any] | None) -> dict[str, str] | None:
    return {k: value.get(k, "") for k in FIELDS} if value else None


def classify(tx: db.Transaction, agent: Agent, value: Any, *, actor: str) -> bool:
    """Classify ``agent`` (None: no longer classified); returns whether that changed it.
    The ledger keeps what it was and what it is (agent.classified)."""
    new = normalize(value)
    old = _plain(agent.classification)
    if old == new:
        return False
    agent.classification = (
        {**new, "by": actor, "at": ids.isoformat(ids.utcnow())} if new is not None else None
    )
    agent.save()
    ledger.append(
        tx,
        type="agent.classified",
        actor=actor,
        agent=agent,
        details={"from": old, "to": new},
    )
    return True


# The register's columns.
COLUMNS = (
    "agent",
    "id",
    "status",
    "owner",
    "source",
    "category",
    "role",
    "basis",
    "purpose",
    "classified_by",
    "classified_at",
)


def row(agent: Agent) -> dict[str, Any]:
    """The agent's line in the register."""
    c = agent.classification or {}
    return {
        "agent": agent.name,
        "id": agent.id,
        "status": agent.status,
        "owner": agent.owner,
        "source": agent.source,
        "category": c.get("category"),
        "role": c.get("role"),
        "basis": c.get("basis"),
        "purpose": c.get("purpose"),
        "classified_by": c.get("by"),
        "classified_at": c.get("at"),
    }

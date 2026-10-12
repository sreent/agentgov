"""Agent instructions: what each agent is told to do, and what scanning finds in it.

An agent's instructions (its system prompt) come from three sources:

* ``registered``: given at registration, in a manifest, or set by an admin;
* ``telemetry``: reported by the agent in OpenTelemetry spans
  (``gen_ai.system_instructions``, when the agent captures content);
* ``microsoft-365``: a declarative agent's instructions, from its package in the
  Microsoft 365 agent catalog.

The latest text from each source is kept, with credentials redacted. AgentGov's
rules (``agentgov.scanners.instructions``) check it as soon as it arrives; the
optional classifier (``agentgov.scanners.guardian``) checks it in the
background. Problems become one finding per agent, ``agent.unsafe_instructions``,
which counts towards the agent's risk.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import mark_changed
from agentgov.models import Agent, AgentInstructions, Finding
from agentgov.processor import detectors
from agentgov.registry import features, findings
from agentgov.registry.errors import Conflict, NotFound, ValidationError
from agentgov.scanners import guardian
from agentgov.scanners import instructions as rules

SOURCES = {
    "registered": "Registered",
    "telemetry": "Telemetry",
    "microsoft-365": "Microsoft 365",
    "aws": "AWS",
    "google-cloud": "Google Cloud",
    "salesforce": "Salesforce",
    "databricks": "Databricks",
}
FINDING = "agent.unsafe_instructions"
SYSTEM_ACTOR = "system:instructions"
MAX_STORED_CHARS = 32_000
MAX_TEXT_CHARS = 200_000
# How often a source that keeps reporting the same text refreshes "last reported".
REPORT_EVERY = timedelta(minutes=10)
# The classifier state of instructions that arrived while instruction checks were
# off: neither the rules nor the classifier looked at them yet.
UNCHECKED = "unchecked"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _redact(text: str) -> str:
    spans = detectors.find_secrets((), text)
    return detectors.redact(text, spans, {detectors.SECRET}) if spans else text


def issues_of(row: AgentInstructions) -> list[dict[str, Any]]:
    """The rules' issues plus the criteria the classifier says were met."""
    found = list(row.issues or [])
    if row.classifier_state == "done":
        found += guardian.issues((row.classifier or {}).get("verdicts") or {})
    return found


def report(
    session: Session,
    agent: Agent,
    *,
    source: str,
    text: str,
    actor: str,
    classify: bool,
) -> AgentInstructions:
    """Record ``agent``'s instructions from ``source``; scan them when they change."""
    if source not in SOURCES:
        raise ValidationError(f"source must be one of {', '.join(SOURCES)}")
    if not isinstance(text, str) or not text.strip():
        raise ValidationError("instructions must be non-empty text")
    if len(text) > MAX_TEXT_CHARS:
        raise ValidationError(f"instructions are limited to {MAX_TEXT_CHARS} characters")
    text = text.strip()
    digest = _digest(text)
    row = session.get(AgentInstructions, f"{agent.id}:{source}")
    now = ids.utcnow()
    if row is not None and row.sha256 == digest:
        if now - row.reported_at > REPORT_EVERY:
            row.reported_at = now
        return row
    before = {i["rule"] for i in issues_of(row)} if row is not None else set()
    if row is None:
        row = AgentInstructions(id=f"{agent.id}:{source}", agent_id=agent.id, source=source)
        session.add(row)
    stored = _redact(text)
    row.text, row.truncated = stored[:MAX_STORED_CHARS], len(stored) > MAX_STORED_CHARS
    row.sha256, row.reported_by, row.updated_at, row.reported_at = digest, actor, now, now
    checking = features.is_on(session, "instruction-checks")
    if checking:
        _scan(row, classify)
    else:
        row.issues, row.classifier_state, row.classifier = [], UNCHECKED, {}
    session.flush()
    found = sorted({i["rule"] for i in row.issues})
    # Agents may report changing text all day: the ledger records what changes the outcome.
    if source != "telemetry" or set(found) != before:
        ledger.append(
            session,
            type="agent.instructions_changed",
            actor=actor,
            agent=agent,
            severity="warning" if found else "info",
            details={"source": source, "sha256": digest, "issues": found, "checked": checking},
        )
    if checking:
        evaluate(session, agent)
    mark_changed(session, "instructions")
    return row


def _scan(row: AgentInstructions, classify: bool) -> None:
    row.issues = [i.to_dict() for i in rules.scan(row.text)]
    row.classifier_state, row.classifier = ("pending" if classify else "off"), {}


def clear(session: Session, agent: Agent, *, source: str, actor: str) -> None:
    row = session.get(AgentInstructions, f"{agent.id}:{source}")
    if row is None:
        raise NotFound(f"agent {agent.name} has no {source} instructions")
    session.delete(row)
    session.flush()
    ledger.append(
        session,
        type="agent.instructions_cleared",
        actor=actor,
        agent=agent,
        details={"source": source},
    )
    evaluate(session, agent)


def rescan(session: Session, agent: Agent, *, actor: str, classify: bool) -> int:
    """Check the stored instructions again (after a rules update, or for the classifier)."""
    if not features.is_on(session, "instruction-checks"):
        raise Conflict("instruction checks are off: turn them on in Features first")
    rows = list(
        session.scalars(select(AgentInstructions).where(AgentInstructions.agent_id == agent.id))
    )
    for row in rows:
        _scan(row, classify)
    if rows:
        ledger.append(
            session,
            type="agent.instructions_rescanned",
            actor=actor,
            agent=agent,
            details={"sources": [r.source for r in rows], "classifier": classify},
        )
        evaluate(session, agent)
        mark_changed(session, "instructions")
    return len(rows)


def check_unchecked(session: Session, *, classify: bool) -> list[Agent]:
    """Check the instructions that arrived while instruction checks were off; returns
    the agents they belong to."""
    rows = list(
        session.scalars(
            select(AgentInstructions).where(AgentInstructions.classifier_state == UNCHECKED)
        )
    )
    for row in rows:
        _scan(row, classify)
    checked = []
    for agent_id in sorted({row.agent_id for row in rows}):
        agent = session.get(Agent, agent_id)
        if agent is not None:
            evaluate(session, agent)
            checked.append(agent)
    if rows:
        mark_changed(session, "instructions")
    return checked


# ---------------------------------------------------------------- classifier


def queue_unclassified(session: Session) -> int:
    """Queue instructions stored before the classifier was configured."""
    rows = list(
        session.scalars(
            select(AgentInstructions).where(AgentInstructions.classifier_state == "off")
        )
    )
    for row in rows:
        row.classifier_state = "pending"
    return len(rows)


def pending(session: Session, limit: int = 5) -> list[tuple[str, str, str]]:
    """``(id, text, sha256)`` of instructions waiting for the classifier."""
    rows = session.scalars(
        select(AgentInstructions)
        .where(AgentInstructions.classifier_state == "pending")
        .order_by(AgentInstructions.updated_at)
        .limit(limit)
    )
    return [(r.id, r.text, r.sha256) for r in rows]


def record_classification(
    session: Session,
    row_id: str,
    digest: str,
    result: dict[str, Any],
    *,
    error: str | None = None,
) -> Agent | None:
    """Store the classifier's verdicts; returns the agent when they were stored."""
    row = session.get(AgentInstructions, row_id)
    if row is None or row.sha256 != digest:
        return None  # changed while being classified: the new text is queued already
    row.classifier_state = "error" if error else "done"
    row.classifier = {**result, "error": error, "scanned_at": ids.isoformat(ids.utcnow())}
    agent = session.get(Agent, row.agent_id)
    if agent is None:
        return None
    flagged = [i["rule"] for i in guardian.issues(result.get("verdicts") or {})]
    if flagged:
        ledger.append(
            session,
            type="agent.instructions_flagged",
            actor="system:classifier",
            agent=agent,
            severity="warning",
            details={"source": row.source, "model": result.get("model"), "criteria": flagged},
        )
    evaluate(session, agent)
    return agent


# ------------------------------------------------------------------- finding


def evaluate(session: Session, agent: Agent) -> Finding | None:
    """Raise, update or resolve the agent's ``agent.unsafe_instructions`` finding."""
    found = [
        {**issue, "source": row.source}
        for row in session.scalars(
            select(AgentInstructions)
            .where(AgentInstructions.agent_id == agent.id)
            .order_by(AgentInstructions.source)
        )
        for issue in issues_of(row)
    ]
    key = f"{FINDING}:{agent.id}"
    if not found:
        findings.resolve_key(session, key, actor=SYSTEM_ACTOR)
        return None
    found.sort(key=lambda i: rules.SEVERITIES.index(i["severity"]))
    fingerprint = sorted({f"{i['source']}:{i['rule']}" for i in found})
    existing = session.scalar(select(Finding).where(Finding.key == key))
    if (
        existing is not None
        and existing.status == "dismissed"
        and (existing.details or {}).get("fingerprint") != fingerprint
    ):
        # Dismissing accepted the problems found then; new ones are asked about again.
        findings.set_status(session, existing.id, "open", SYSTEM_ACTOR)
    finding, _ = findings.raise_finding(
        session,
        type=FINDING,
        severity=found[0]["severity"],
        subject=agent.id,
        agent_id=agent.id,
        title=f"Unsafe instructions for {agent.name}: {found[0]['title']}",
        description="; ".join(
            dict.fromkeys(f"{i['title']} ({SOURCES.get(i['source'], i['source'])})" for i in found)
        ),
        remediation="Review the instructions on the agent's page and remove what isn't "
        "intended where the agent is configured. If this is a false positive, dismiss the "
        "finding: it opens again only if new problems appear.",
        details={"issues": found[:20], "fingerprint": fingerprint},
    )
    return finding


# --------------------------------------------------------------------- views


def to_dict(row: AgentInstructions) -> dict[str, Any]:
    return {
        "source": row.source,
        "source_name": SOURCES.get(row.source, row.source),
        "text": row.text,
        "truncated": row.truncated,
        "sha256": row.sha256,
        "reported_by": row.reported_by,
        "updated_at": ids.isoformat(row.updated_at),
        "reported_at": ids.isoformat(row.reported_at),
        "issues": issues_of(row),
        "classifier": {"state": row.classifier_state, **(row.classifier or {})},
    }


def for_agent(session: Session, agent_id: str) -> list[dict[str, Any]]:
    return [
        to_dict(row)
        for row in session.scalars(
            select(AgentInstructions)
            .where(AgentInstructions.agent_id == agent_id)
            .order_by(AgentInstructions.source)
        )
    ]


def check(text: str, classifier: guardian.Guardian | None, *, classify: bool) -> dict[str, Any]:
    """Check text without storing it: for CI pipelines and drafts."""
    if not isinstance(text, str) or not text.strip():
        raise ValidationError("text must be non-empty")
    if len(text) > MAX_TEXT_CHARS:
        raise ValidationError(f"text is limited to {MAX_TEXT_CHARS} characters")
    found = [i.to_dict() for i in rules.scan(text)]
    verdict: dict[str, Any] = {"state": "off"}
    if classify and classifier is not None:
        try:
            verdict = {"state": "done", **classifier.classify(text)}
            found += guardian.issues(verdict["verdicts"])
        except guardian.GuardianError as exc:
            verdict = {"state": "error", "model": classifier.model, "error": str(exc)}
    found.sort(key=lambda i: rules.SEVERITIES.index(i["severity"]))
    return {
        "severity": rules.worst([i["severity"] for i in found]),
        "issues": found,
        "classifier": verdict,
    }

"""Posture and threat findings (the Agent 365 'agents at risk' / Defender view)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import SEVERITIES, Agent, Finding
from agentgov.registry.errors import NotFound, ValidationError

POSTURE = "posture"
THREAT = "threat"


def raise_finding(
    session: Session,
    *,
    type: str,
    severity: str,
    subject: str,
    title: str,
    description: str = "",
    remediation: str = "",
    agent_id: str | None = None,
    category: str = POSTURE,
    details: dict[str, Any] | None = None,
) -> tuple[Finding, bool]:
    """Create or refresh the finding keyed by ``type:subject``.

    Returns ``(finding, is_new)``. Dismissed findings stay dismissed; resolved
    ones are reopened because the condition has come back.
    """
    if severity not in SEVERITIES:
        raise ValidationError(f"unknown severity {severity!r}")
    key = f"{type}:{subject}"
    finding = session.scalar(select(Finding).where(Finding.key == key))
    now = ids.utcnow()
    if finding is None:
        finding = Finding(
            id=ids.new_id(ids.FINDING),
            key=key,
            type=type,
            category=category,
            severity=severity,
            subject=subject,
            agent_id=agent_id,
            title=title,
            description=description,
            remediation=remediation,
            details=details or {},
            first_seen=now,
            last_seen=now,
        )
        session.add(finding)
        session.flush()
        return finding, True
    finding.last_seen = now
    finding.severity = severity
    finding.title = title
    finding.description = description or finding.description
    finding.remediation = remediation or finding.remediation
    if details:
        finding.details = {**(finding.details or {}), **details}
    if category == THREAT:
        finding.occurrences += 1
    reopened = finding.status == "resolved"
    if reopened:
        finding.status = "open"
        finding.resolved_at = None
        finding.resolved_by = None
    return finding, reopened


def resolve_absent(
    session: Session,
    *,
    types: set[str],
    present_keys: set[str],
    actor: str = "system:posture-scan",
) -> int:
    """Auto-resolve open posture findings whose condition no longer holds."""
    count = 0
    open_findings = session.scalars(
        select(Finding).where(Finding.status == "open", Finding.type.in_(types))
    ).all()
    for finding in open_findings:
        if finding.key not in present_keys:
            finding.status = "resolved"
            finding.resolved_at = ids.utcnow()
            finding.resolved_by = actor
            count += 1
    return count


def resolve_key(session: Session, key: str, *, actor: str) -> None:
    """Resolve the open finding ``key`` (``type:subject``), if there is one."""
    finding = session.scalar(select(Finding).where(Finding.key == key))
    if finding is not None and finding.status == "open":
        set_status(session, finding.id, "resolved", actor)


def set_status(session: Session, finding_id: str, status: str, actor: str) -> Finding:
    if status not in ("open", "resolved", "dismissed"):
        raise ValidationError("status must be open, resolved or dismissed")
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NotFound(f"finding {finding_id} not found")
    if finding.status == status:
        return finding
    finding.status = status
    if status == "open":
        finding.resolved_at = None
        finding.resolved_by = None
    else:
        finding.resolved_at = ids.utcnow()
        finding.resolved_by = actor
    ledger.append(
        session,
        type=f"finding.{'reopened' if status == 'open' else status}",
        actor=actor,
        agent=session.get(Agent, finding.agent_id) if finding.agent_id else None,
        agent_id=finding.agent_id,
        resource=finding.subject,
        reason=finding.title,
        details={"finding_id": finding.id, "type": finding.type, "severity": finding.severity},
    )
    return finding


def to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "type": f.type,
        "category": f.category,
        "severity": f.severity,
        "status": f.status,
        "agent_id": f.agent_id,
        "subject": f.subject,
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        "details": f.details or {},
        "occurrences": f.occurrences,
        "first_seen": ids.isoformat(f.first_seen),
        "last_seen": ids.isoformat(f.last_seen),
        "resolved_at": ids.isoformat(f.resolved_at),
        "resolved_by": f.resolved_by,
    }

"""Posture and threat findings (the Agent 365 'agents at risk' / Defender view).

Findings are also issues for the people responsible for them (agentgov.registry.issues,
docs/issues.md): who it is with, whether they acknowledged it, and a risk accepted until a
date. Raised again after being resolved or accepted, a finding starts its chain over.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.db import lock
from agentgov.models import SEVERITIES, Agent, Finding
from agentgov.registry.errors import NotFound, ValidationError

POSTURE = "posture"
THREAT = "threat"
SYSTEM = "system:agentgov"
STATUSES = ("open", "resolved", "dismissed", "accepted")
# In an unverified finding's details: why its check couldn't run.
UNVERIFIED = "unverified"
# In a finding's details: found by a platform's first sync, there before AgentGov looked
# (agentgov.registry.platforms.first_sync; agentgov.registry.issues sends it to no inbox).
BASELINE = "baseline"


def checked(finding: Finding) -> None:
    """Its check ran: it holds, or it is gone, as far as anyone can tell."""
    finding.verified = True
    if UNVERIFIED in (finding.details or {}):
        finding.details = {k: v for k, v in finding.details.items() if k != UNVERIFIED}


def restart_chain(finding: Finding) -> None:
    """Raised again: its chain starts over, from its first step."""
    finding.round = (finding.round or 0) + 1
    finding.level = None
    finding.assignees = []
    finding.escalate_at = None
    finding.acknowledged_at = None
    finding.acknowledged_by = None


def record(
    session: Session,
    finding: Finding,
    change: str,
    actor: str,
    *,
    severity: str | None = None,
    **extra: Any,
) -> None:
    """A finding raised, reopened, resolved or dismissed, or what happened to it as an issue
    (assigned, escalated, acknowledged, accepted, notified), in the ledger (and so on its
    way to the security team's tools)."""
    ledger.append(
        session,
        type=f"finding.{change}",
        actor=actor,
        severity=severity
        or (
            "warning"
            if change != "resolved" and finding.severity in ("high", "critical")
            else "info"
        ),
        agent=session.get(Agent, finding.agent_id) if finding.agent_id else None,
        agent_id=finding.agent_id,
        resource=finding.subject,
        reason=finding.title,
        details={
            "finding_id": finding.id,
            "type": finding.type,
            "category": finding.category,
            "severity": finding.severity,
            **({"description": finding.description[:2000]} if finding.description else {}),
            **({"remediation": finding.remediation[:1000]} if finding.remediation else {}),
            **extra,
        },
    )


_record = record


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

    Returns ``(finding, is_new)``. Dismissed findings stay dismissed, and accepted ones
    accepted until their date; resolved ones are reopened because the condition has come
    back. Its type's settings apply (agentgov.registry.finding_types): its severity, and,
    while the type is off, it is kept dismissed instead; found again once its type is on,
    it is reopened.
    """
    from agentgov.registry import finding_types

    if severity not in SEVERITIES:
        raise ValidationError(f"unknown severity {severity!r}")
    severity, off = finding_types.effective(session, type, severity)
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
        if off:
            finding_types.suppress(finding, now)
            session.add(finding)
            session.flush()
            return finding, False
        session.add(finding)
        session.flush()
        _record(session, finding, "raised", SYSTEM)
        return finding, True
    finding.last_seen = now
    # The check ran and found it: it holds, as far as anyone can tell.
    finding.clean_checks = 0
    checked(finding)
    finding.severity = severity
    finding.title = title
    finding.description = description or finding.description
    finding.remediation = remediation or finding.remediation
    if details:
        finding.details = {**(finding.details or {}), **details}
    if category == THREAT:
        finding.occurrences += 1
    if off and finding.status in ("open", "resolved"):
        # Found again, but its type is off.
        if finding.status == "open":
            _record(session, finding, "dismissed", finding_types.ACTOR, reason="its type is off")
        finding_types.suppress(finding, now)
    suppressed = finding.status == "dismissed" and finding_types.SUPPRESSED in (
        finding.details or {}
    )
    reopened = finding.status == "resolved" or (suppressed and not off)
    if reopened:
        finding.status = "open"
        finding.resolved_at = None
        finding.resolved_by = None
        # Back after it was gone: news, whatever it was before.
        finding.details = {
            k: v
            for k, v in (finding.details or {}).items()
            if k not in (finding_types.SUPPRESSED, BASELINE)
        }
        restart_chain(finding)
        _record(session, finding, "reopened", SYSTEM)
    return finding, reopened


def _open(types: set[str], subjects: set[str] | None) -> Any:
    query = select(Finding).where(Finding.status == "open", Finding.type.in_(types))
    return query if subjects is None else query.where(Finding.subject.in_(subjects))


def resolve_absent(
    session: Session,
    *,
    types: set[str],
    present_keys: set[str],
    actor: str = "system:posture-scan",
    clean: int = 1,
    subjects: set[str] | None = None,
) -> int:
    """Auto-resolve open findings whose condition no longer holds, once ``clean`` checks in
    a row found it gone: findings from other systems' data take two, so that one odd sync
    doesn't close and reopen them. ``subjects`` limits it to the findings about those (a
    platform's agents, where other platforms raise findings of the same types)."""
    count = 0
    open_findings = session.scalars(_open(types, subjects)).all()
    for finding in open_findings:
        if finding.key in present_keys:
            continue
        checked(finding)
        finding.clean_checks = (finding.clean_checks or 0) + 1
        if finding.clean_checks >= clean:
            finding.status = "resolved"
            finding.resolved_at = ids.utcnow()
            finding.resolved_by = actor
            finding.escalate_at = None
            _record(session, finding, "resolved", actor)
            count += 1
    return count


def close_stale_threats(session: Session, days: int, now: datetime | None = None) -> int:
    """Resolve the threats that haven't happened again for ``days`` days (0: none are): they
    were events, and one that happens again opens again."""
    if days <= 0:
        return 0
    now = now or ids.utcnow()
    count = 0
    for finding in session.scalars(
        select(Finding).where(
            Finding.status == "open",
            Finding.category == THREAT,
            Finding.last_seen < now - timedelta(days=days),
        )
    ):
        finding.status = "resolved"
        finding.resolved_at = now
        finding.resolved_by = SYSTEM
        finding.escalate_at = None
        record(session, finding, "resolved", SYSTEM, why=f"it hasn't happened for {days} days")
        count += 1
    return count


def mark_unverified(
    session: Session,
    *,
    types: set[str],
    verified: bool = False,
    subjects: set[str] | None = None,
    present_keys: set[str] | None = None,
    reason: str = "",
) -> int:
    """The check behind these findings couldn't run (a sync failed): their open findings
    may or may not still hold, so they stay open, marked unverified with ``reason``, until
    it runs again (``verified=True``, when it does). ``subjects`` as for
    :func:`resolve_absent`; findings in ``present_keys`` were found again by a check that
    ran in part, so they still hold."""
    count = 0
    for finding in session.scalars(_open(types, subjects)):
        if present_keys and finding.key in present_keys:
            continue
        if verified:
            if finding.verified is False:
                count += 1
            checked(finding)
            continue
        if finding.verified is not False:
            count += 1
        finding.verified = False
        if reason and (finding.details or {}).get(UNVERIFIED) != reason:
            finding.details = {**(finding.details or {}), UNVERIFIED: reason[:500]}
    return count


def resolve_key(session: Session, key: str, *, actor: str) -> None:
    """Resolve the open finding ``key`` (``type:subject``), if there is one."""
    finding = session.scalar(select(Finding).where(Finding.key == key))
    if finding is not None and finding.status == "open":
        set_status(session, finding.id, "resolved", actor)


def get(session: Session, finding_id: str) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise NotFound(f"finding {finding_id} not found")
    return finding


def set_status(session: Session, finding_id: str, status: str, actor: str) -> Finding:
    if status not in ("open", "resolved", "dismissed"):
        raise ValidationError("status must be open, resolved or dismissed")
    finding = get(session, finding_id)
    lock(session, finding)
    if finding.status == status:
        return finding
    previous, finding.status = finding.status, status
    if status == "open":
        finding.resolved_at = None
        finding.resolved_by = None
        finding.accepted_until = None
        if previous != "open":
            restart_chain(finding)
    else:
        finding.resolved_at = ids.utcnow()
        finding.resolved_by = actor
        finding.escalate_at = None
    _record(session, finding, "reopened" if status == "open" else status, actor)
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
        # As an issue for the people responsible (docs/issues.md).
        "level": f.level,
        "assignees": list(f.assignees or []),
        "escalate_at": ids.isoformat(f.escalate_at),
        "acknowledged_at": ids.isoformat(f.acknowledged_at),
        "acknowledged_by": f.acknowledged_by,
        "accepted_until": ids.isoformat(f.accepted_until),
        "accepted_reason": f.accepted_reason,
        "verified": bool(f.verified) if f.verified is not None else True,
        # Why its check couldn't run, while it is unverified.
        "unverified_reason": (f.details or {}).get(UNVERIFIED) if f.verified is False else None,
    }

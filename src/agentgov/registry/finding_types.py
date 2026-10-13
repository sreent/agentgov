"""Finding types: which kinds of findings an organisation wants raised, and how severe each
is for it (docs/issues.md#kinds-of-findings).

Every check raises findings of its own types (``agent.no_owner``, ``platform.no_guardrail``,
...) at the severity it judges. A type turned off here is still checked, but what it finds
is kept dismissed: it reaches nobody's list and no one's inbox. Turned on again, what its
checks find again comes back, the next time they run. A type's severity can be set too, for
what it finds from then on and what it found that is still open.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import SEVERITIES, Finding, FindingType
from agentgov.registry.errors import ValidationError

ON, OFF = "on", "off"
MODES = (ON, OFF)
# In a finding's details: dismissed because its type is off (and so back when it is on).
SUPPRESSED = "suppressed_by_type"
ACTOR = "system:finding-types"
TYPE = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$")


def effective(session: Session, type_: str, severity: str) -> tuple[str, bool]:
    """The severity a finding of ``type_`` takes here, and whether its type is off."""
    row = session.get(FindingType, type_)
    if row is None:
        return severity, False
    return row.severity or severity, row.mode == OFF


def off_types(session: Session) -> set[str]:
    """The types turned off here."""
    return set(session.scalars(select(FindingType.type).where(FindingType.mode == OFF)))


def suppress(finding: Finding, now: Any = None) -> None:
    """Keep a finding dismissed, because its type is off."""
    finding.status = "dismissed"
    finding.resolved_at = now or ids.utcnow()
    finding.resolved_by = ACTOR
    finding.escalate_at = None
    finding.details = {**(finding.details or {}), SUPPRESSED: True}


def configure(session: Session, type_: Any, data: Any, *, actor: str) -> dict[str, Any]:
    """Turn a type on or off (``mode``), or set its severity (``severity``; null for the one
    its check gives). Turned off, its open findings are dismissed; on again, those its
    checks find again come back (:func:`agentgov.registry.findings.raise_finding`)."""
    from agentgov.registry import findings

    if not isinstance(type_, str) or not TYPE.match(type_) or len(type_) > 128:
        raise ValidationError(f"{type_!r} isn't a finding type, such as agent.no_owner")
    if not isinstance(data, dict) or not data or set(data) - {"mode", "severity"}:
        raise ValidationError("give the type's mode (on or off), its severity, or both")
    mode = data.get("mode")
    if "mode" in data and mode not in MODES:
        raise ValidationError(f"mode is on or off (got {mode!r})")
    severity = data.get("severity")
    if "severity" in data and severity is not None and severity not in SEVERITIES:
        raise ValidationError(f"severity is one of {', '.join(SEVERITIES)}, or null")
    row = session.get(FindingType, type_) or FindingType(type=type_, mode=ON)
    before = (row.mode, row.severity)
    if "mode" in data:
        row.mode = mode
    if "severity" in data:
        row.severity = severity
    if (row.mode, row.severity) == before and session.get(FindingType, type_) is not None:
        return to_dict(session, row)
    row.changed_by, row.changed_at = actor, ids.utcnow()
    session.add(row)
    session.flush()
    dismissed = 0
    if before[0] != OFF and row.mode == OFF:
        for finding in session.scalars(
            select(Finding).where(Finding.type == type_, Finding.status == "open")
        ):
            suppress(finding)
            findings.record(session, finding, "dismissed", actor, reason="its type is off")
            dismissed += 1
    if row.severity is not None and row.severity != before[1]:
        for finding in session.scalars(
            select(Finding).where(Finding.type == type_, Finding.status == "open")
        ):
            finding.severity = row.severity
    weaker = row.mode == OFF and before[0] != OFF
    if row.severity and before[1] and SEVERITIES.index(row.severity) < SEVERITIES.index(before[1]):
        weaker = True
    ledger.append(
        session,
        type="finding_type.changed",
        actor=actor,
        resource=f"finding-type/{type_}",
        severity="warning" if weaker else "info",
        reason=f"{type_}: {row.mode}"
        + (f", severity {row.severity}" if row.severity else ", its checks' severity"),
        details={
            "from": {"mode": before[0], "severity": before[1]},
            "to": {"mode": row.mode, "severity": row.severity},
            "dismissed": dismissed,
        },
    )
    return to_dict(session, row)


def to_dict(session: Session, row: FindingType | None, type_: str | None = None) -> dict[str, Any]:
    type_ = row.type if row is not None else str(type_)
    counts = dict(
        session.execute(
            select(Finding.status, func.count())
            .where(Finding.type == type_)
            .group_by(Finding.status)
        ).all()
    )
    return {
        "type": type_,
        "mode": row.mode if row is not None else ON,
        # Instead of its checks' severity, if set.
        "severity": row.severity if row is not None else None,
        "open": counts.get("open", 0),
        "total": sum(counts.values()),
        "changed_by": row.changed_by if row is not None else None,
        "changed_at": ids.isoformat(row.changed_at) if row is not None else None,
    }


def listing(session: Session) -> list[dict[str, Any]]:
    """Every type AgentGov has raised findings of, and every type configured, with how many
    of its findings are open."""
    rows = {r.type: r for r in session.scalars(select(FindingType))}
    seen = set(session.scalars(select(Finding.type).distinct()))
    return [to_dict(session, rows.get(t), t) for t in sorted(seen | set(rows))]


def chosen(session: Session) -> list[FindingType]:
    """The types configured here (for export)."""
    return list(session.scalars(select(FindingType).order_by(FindingType.type)))

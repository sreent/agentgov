"""Finding types: which kinds of findings an organisation wants raised, and how severe each
is for it (docs/issues.md#kinds-of-issues).

Every check raises findings of its own types (``agent.no_owner``, ``platform.no_guardrail``,
...) at the severity it judges. A type turned off here is still checked, but what it finds
is kept dismissed: it reaches nobody's list and no one's inbox. Turned on again, what its
checks find again comes back, the next time they run. A type's severity can be set too, for
what it finds from then on and what it found that is still open.
"""

from __future__ import annotations

import re
from typing import Any

from django.db.models import Count

from agentgov import db, ids, ledger
from agentgov.db.models import SEVERITIES, Finding, FindingType
from agentgov.registry.errors import ValidationError

ON, OFF = "on", "off"
MODES = (ON, OFF)
# In a finding's details: dismissed because its type is off (and so back when it is on).
SUPPRESSED = "suppressed_by_type"
# What says the evidence ledger lost entries (agentgov.witness) or can't be archived
# (agentgov.retention): never off, so that nobody quiets them while covering what happened.
ALWAYS_ON = ("ledger.rewound", "ledger.archive_failed")
ACTOR = "system:finding-types"
TYPE = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$")


def effective(tx: db.Transaction, type_: str, severity: str) -> tuple[str, bool]:
    """The severity a finding of ``type_`` takes here, and whether its type is off."""
    row = FindingType.objects.filter(pk=type_).first()
    if row is None:
        return severity, False
    return row.severity or severity, row.mode == OFF and type_ not in ALWAYS_ON


def off_types(tx: db.Transaction) -> set[str]:
    """The types turned off here."""
    off = set(FindingType.objects.filter(mode=OFF).values_list("type", flat=True))
    return off - set(ALWAYS_ON)


def suppress(finding: Finding, now: Any = None) -> None:
    """Keep a finding dismissed, because its type is off (its caller saves it)."""
    finding.status = "dismissed"
    finding.resolved_at = now or ids.utcnow()
    finding.resolved_by = ACTOR
    finding.escalate_at = None
    finding.details = {**(finding.details or {}), SUPPRESSED: True}


def configure(tx: db.Transaction, type_: Any, data: Any, *, actor: str) -> dict[str, Any]:
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
    if mode == OFF and type_ in ALWAYS_ON:
        raise ValidationError(
            f"{type_} can't be turned off: it says the evidence ledger lost entries or can't "
            "be archived"
        )
    severity = data.get("severity")
    if "severity" in data and severity is not None and severity not in SEVERITIES:
        raise ValidationError(f"severity is one of {', '.join(SEVERITIES)}, or null")
    existing = FindingType.objects.filter(pk=type_).first()
    row = existing or FindingType(type=type_, mode=ON)
    before = (row.mode, row.severity)
    if "mode" in data:
        row.mode = mode
    if "severity" in data:
        row.severity = severity
    if (row.mode, row.severity) == before and existing is not None:
        return to_dict(tx, row)
    row.changed_by, row.changed_at = actor, ids.utcnow()
    row.save(force_insert=existing is None)
    dismissed = 0
    if before[0] != OFF and row.mode == OFF:
        for finding in list(Finding.objects.filter(type=type_, status="open")):
            suppress(finding)
            finding.save()
            findings.record(tx, finding, "dismissed", actor, reason="its type is off")
            dismissed += 1
    if row.severity is not None and row.severity != before[1]:
        for finding in list(Finding.objects.filter(type=type_, status="open")):
            finding.severity = row.severity
            finding.save()
    weaker = row.mode == OFF and before[0] != OFF
    if row.severity and before[1] and SEVERITIES.index(row.severity) < SEVERITIES.index(before[1]):
        weaker = True
    ledger.append(
        tx,
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
    return to_dict(tx, row)


def to_dict(
    tx: db.Transaction, row: FindingType | None, type_: str | None = None
) -> dict[str, Any]:
    type_ = row.type if row is not None else str(type_)
    counts = dict(
        Finding.objects.filter(type=type_)
        .values("status")
        .annotate(n=Count("id"))
        .values_list("status", "n")
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


def listing(tx: db.Transaction) -> list[dict[str, Any]]:
    """Every type AgentGov has raised findings of, and every type configured, with how many
    of its findings are open."""
    rows = {r.type: r for r in FindingType.objects.all()}
    seen = set(Finding.objects.values_list("type", flat=True).distinct())
    return [to_dict(tx, rows.get(t), t) for t in sorted(seen | set(rows))]


def chosen(tx: db.Transaction) -> list[FindingType]:
    """The types configured here (for export)."""
    return list(FindingType.objects.order_by("type"))

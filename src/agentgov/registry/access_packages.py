"""Access packages: grants an agent holds for a while, requested and approved
(docs/access-packages.md).

An access package bundles grants as a blueprint does: tools, models, and other agents to
call. An agent's owner or sponsors, or an approver, request one for an agent, for some days
(at most the package's duration), saying why, and an approver decides, unless the package
needs no approval. Its grants count for the agent until the assignment expires. Before
then, the people responsible for the agent get an issue that it is expiring, so they can
renew it; packages with reviews ask them, every so many days, whether the agent still
needs it.

How strictly expiry applies is the access-packages feature. Enforced, an expired package
grants nothing. Monitored (the default), the agent keeps the access, each call that needs
it is recorded, and an issue says so. Off, packages grant nothing at all, and can't be
requested.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.db.models import Q

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db import lock, mark_changed
from agentgov.db.models import AccessAssignment, AccessPackage, Agent, Blueprint
from agentgov.models import DELETED
from agentgov.registry import features, findings, issues, validation
from agentgov.registry.errors import (
    Conflict,
    Forbidden,
    InvalidTransition,
    NotFound,
    ValidationError,
)
from agentgov.registry.versions import changes, edited, start_edit

FEATURE = "access-packages"
FIELDS = (
    "description",
    "permissions",
    "model_access",
    "agent_access",
    "blueprints",
    "duration_days",
    "approval",
    "review_days",
    "labels",
)
REQUESTED, ACTIVE, DENIED, EXPIRED, REVOKED, RENEWED = (
    "requested",
    "active",
    "denied",
    "expired",
    "revoked",
    "renewed",
)
# What an agent holds: its grants count (an expired one as the feature's mode says).
HELD = (ACTIVE, EXPIRED)
STATUSES = (REQUESTED, ACTIVE, DENIED, EXPIRED, REVOKED, RENEWED)
MAX_DAYS = 365
# Days before an assignment expires that its agent's people are told, at most: a third of
# its time for short ones, so that a two-week grant isn't "expiring" from its first day.
REMIND_DAYS = 14
SYSTEM = "system:access-packages"
EXPIRING, EXPIRED_TYPE, REVIEW_DUE = "access.expiring", "access.expired", "access.review_due"
FINDING_TYPES = (EXPIRING, EXPIRED_TYPE, REVIEW_DUE)
# Who may ask for any agent; an agent's owner and sponsors may ask for theirs.
REQUESTERS = frozenset({"admin", "approver", "registrar"})
DECIDERS = frozenset({"admin", "approver"})


# --------------------------------------------------------------------- packages


def get(tx: db.Where, ref: str) -> AccessPackage:
    package = AccessPackage.objects.filter(Q(name=ref) | Q(id=ref)).first()
    if package is None:
        raise NotFound(f"access package {ref!r} not found")
    return package


def list_all(tx: db.Where) -> list[AccessPackage]:
    return list(AccessPackage.objects.order_by("name"))


def _days(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_DAYS:
        raise ValidationError(f"{field} is a number of days from 1 to {MAX_DAYS}")
    return value


def _apply(tx: db.Where, package: AccessPackage, data: dict[str, Any]) -> list[str]:
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "permissions":
            value = validation.permissions(value)
        elif key == "model_access":
            value = validation.model_access(value)
        elif key == "agent_access":
            value = validation.agent_access(value)
        elif key == "blueprints":
            value = list(dict.fromkeys(validation.string_list(value, "blueprints")))
            known = set(Blueprint.objects.filter(name__in=value).values_list("name", flat=True))
            missing = [b for b in value if b not in known]
            if missing:
                raise ValidationError(f"blueprint(s) {', '.join(missing)} not found")
        elif key == "duration_days":
            value = _days(value, "duration_days")
        elif key == "review_days":
            value = None if value is None else _days(value, "review_days")
        elif key == "approval":
            if not isinstance(value, bool):
                raise ValidationError("approval is true (an approver decides) or false")
        elif key == "labels":
            value = validation.labels(value)
        elif key == "description":
            value = str(value or "")
        if getattr(package, key) != value:
            setattr(package, key, value)
            changed.append(key)
    if not (package.permissions or package.model_access or package.agent_access):
        raise ValidationError("an access package grants something: tools, models or agents")
    return changed


def _known(data: dict[str, Any]) -> None:
    unknown = sorted(set(data) - set(FIELDS) - {"name"})
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}; an access package takes name, "
            f"{', '.join(FIELDS)}"
        )


def create(tx: db.Where, data: dict[str, Any], *, actor: str) -> AccessPackage:
    _known(data)
    name = validation.slug(data.get("name"), "name")
    if AccessPackage.objects.filter(name=name).exists():
        raise Conflict(f"access package {name!r} already exists")
    package = AccessPackage(
        id=ids.new_id(ids.ACCESS_PACKAGE),
        name=name,
        description="",
        permissions=[],
        model_access=[],
        agent_access=[],
        blueprints=[],
        duration_days=90,
        approval=True,
        review_days=None,
        labels={},
    )
    _apply(tx, package, data)
    package.save(force_insert=True)
    mark_changed(tx, "access")
    ledger.append(
        tx,
        type="access_package.created",
        actor=actor,
        resource=f"access-package/{name}",
        details=_details(package),
    )
    return package


def update(
    tx: db.Where,
    package: AccessPackage,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(tx, package, version, f"access package {package.name}")
    _known(data)
    if "name" in data and data["name"] != package.name:
        raise ValidationError("an access package's name can't change: assignments name it")
    changed = _apply(tx, package, data)
    if changed:
        edited(package)
        package.save()
        mark_changed(tx, "access")
        ledger.append(
            tx,
            type="access_package.updated",
            actor=actor,
            resource=f"access-package/{package.name}",
            details={**{k: _details(package)[k] for k in changed}, "changes": changes(package)},
        )
    return changed


def delete(tx: db.Where, package: AccessPackage, *, actor: str) -> None:
    held = AccessAssignment.objects.filter(
        package_id=package.id, status__in=(REQUESTED, *HELD)
    ).exists()
    if held:
        raise Conflict(
            f"agents hold or ask for access package {package.name!r}: revoke or deny those "
            "assignments first"
        )
    ledger.append(
        tx,
        type="access_package.deleted",
        actor=actor,
        resource=f"access-package/{package.name}",
        severity="warning",
    )
    package.delete()
    mark_changed(tx, "access")


def _details(package: AccessPackage) -> dict[str, Any]:
    return {
        "description": package.description or "",
        "permissions": list(package.permissions or []),
        "model_access": list(package.model_access or []),
        "agent_access": list(package.agent_access or []),
        "blueprints": list(package.blueprints or []),
        "duration_days": package.duration_days,
        "approval": package.approval,
        "review_days": package.review_days,
        "labels": dict(package.labels or {}),
    }


def to_dict(tx: db.Where, package: AccessPackage) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for status in AccessAssignment.objects.filter(package_id=package.id).values_list(
        "status", flat=True
    ):
        counts[status] = counts.get(status, 0) + 1
    return {
        "id": package.id,
        "name": package.name,
        "version": package.version,
        **_details(package),
        "assignments": {s: counts.get(s, 0) for s in (REQUESTED, ACTIVE, EXPIRED)},
        "created_at": ids.isoformat(package.created_at),
        "updated_at": ids.isoformat(package.updated_at),
    }


# ------------------------------------------------------------------ assignments


def assignment(tx: db.Where, assignment_id: str) -> AccessAssignment:
    row = AccessAssignment.objects.filter(pk=assignment_id).first()
    if row is None:
        raise NotFound(f"access assignment {assignment_id} not found")
    return row


def assignments(
    tx: db.Where,
    *,
    status: str | None = None,
    agent_id: str | None = None,
    package_id: str | None = None,
    limit: int = 500,
) -> list[AccessAssignment]:
    rows = AccessAssignment.objects.order_by("-created_at")
    if status and status != "all":
        if status not in STATUSES:
            raise ValidationError(f"status is one of {', '.join(STATUSES)} or all")
        rows = rows.filter(status=status)
    if agent_id:
        rows = rows.filter(agent_id=agent_id)
    if package_id:
        rows = rows.filter(package_id=package_id)
    return list(rows[:limit])


def responsible(tx: db.Where, agent: Agent) -> set[str]:
    """The agent's owner and sponsors, as people sign in (lower case), with the members
    and addresses of teams named as either."""
    directory = issues.Directory(tx)
    names: set[str] = set()
    for name in [agent.owner, *(agent.sponsors or [])]:
        who = directory.recipient(str(name or ""))
        if who is None:
            continue
        if who.kind == "person":
            names.add(who.name.lower())
        names.update(e.lower() for e in (*who.emails, *who.members))
    return names


def may_request(tx: db.Where, roles: frozenset[str], name: str | None, agent: Agent) -> bool:
    return bool(roles & REQUESTERS) or (name or "").lower() in responsible(tx, agent)


def asked_by(row: AccessAssignment, actor: str) -> bool:
    """Whether ``actor`` asked for ``row``: the same person or key, whichever role each acted
    in ("registrar:ann" and "approver:ann")."""

    def who(value: str | None) -> str:
        return str(value or "").partition(":")[2].strip().lower()

    return bool(who(actor)) and who(actor) == who(row.requested_by)


def _resource(row: AccessAssignment, package: AccessPackage, agent: Agent) -> str:
    return f"access-package/{package.name}/{agent.name}"


def _record(
    tx: db.Where,
    row: AccessAssignment,
    change: str,
    actor: str,
    *,
    severity: str = "info",
    **extra: Any,
) -> None:
    package = AccessPackage.objects.filter(pk=row.package_id).first()
    agent = Agent.objects.filter(pk=row.agent_id).first()
    assert package is not None and agent is not None
    ledger.append(
        tx,
        type=f"access.{change}",
        actor=actor,
        severity=severity,
        agent=agent,
        resource=_resource(row, package, agent),
        reason=row.reason,
        details={
            "assignment_id": row.id,
            "package": package.name,
            "status": row.status,
            **({"expires_at": ids.isoformat(row.expires_at)} if row.expires_at else {}),
            **extra,
        },
    )


def _not_deleted(agent: Agent | None) -> None:
    if agent is not None and agent.status == DELETED:
        raise InvalidTransition(f"{agent.name} is deleted: restore it first")


def _held(tx: db.Where, agent_id: str, package_id: str) -> AccessAssignment | None:
    return AccessAssignment.objects.filter(
        agent_id=agent_id, package_id=package_id, status__in=HELD
    ).first()


def request(
    tx: db.Where,
    *,
    agent: Agent,
    package: AccessPackage,
    days: Any,
    reason: Any,
    actor: str,
    approve: bool = False,
) -> AccessAssignment:
    """Ask for a package for an agent (again, to renew it). Granted at once when the package
    needs no approval, or when an administrator assigns it (``approve``)."""
    if not features.is_on(tx, FEATURE):
        raise InvalidTransition("access packages are off: turn them on in Features first")
    _not_deleted(agent)
    days = _days(package.duration_days if days is None else days, "days")
    if days > package.duration_days:
        raise ValidationError(
            f"access package {package.name!r} is granted for {package.duration_days} days at most"
        )
    reason = str(reason or "").strip()
    if not reason:
        raise ValidationError("say why the agent needs it (reason)")
    if len(reason) > 2000:
        raise ValidationError("reason is 2000 characters at most")
    allowed = package.blueprints or []
    blueprint = agent.blueprint.name if agent.blueprint else None
    if allowed and blueprint not in allowed:
        raise ValidationError(
            f"access package {package.name!r} is for agents on {', '.join(allowed)}; "
            f"{agent.name} is on {blueprint or 'no blueprint'}"
        )
    # One request at a time per agent: two at once would both find none waiting.
    lock(tx, agent)
    pending = (
        AccessAssignment.objects.filter(agent_id=agent.id, package_id=package.id, status=REQUESTED)
        .values_list("id", flat=True)
        .first()
    )
    if pending:
        raise Conflict(f"{agent.name} already asked for {package.name!r}: {pending} waits")
    row = AccessAssignment(
        id=ids.new_id(ids.ACCESS_ASSIGNMENT),
        package_id=package.id,
        agent_id=agent.id,
        status=REQUESTED,
        days=days,
        reason=reason,
        requested_by=actor,
    )
    row.save(force_insert=True)
    held = _held(tx, agent.id, package.id)
    _record(tx, row, "requested", actor, days=days, renews=held.id if held else None)
    if approve or not package.approval:
        _grant(tx, row, actor=actor if approve else SYSTEM, note=None)
    return row


def _grant(tx: db.Where, row: AccessAssignment, *, actor: str, note: str | None) -> None:
    now = ids.utcnow()
    until = now + timedelta(days=row.days)
    held = _held(tx, row.agent_id, row.package_id)
    if held is not None:
        # A renewal: it carries on from the one it replaces, and never ends sooner.
        if held.expires_at and held.expires_at > until:
            until = held.expires_at
        held.status = RENEWED
        held.ended_at = now
        held.save()
        _settle(tx, held, actor=actor)
    row.status = ACTIVE
    row.decided_by, row.decided_at, row.note = actor, now, note
    row.starts_at, row.expires_at, row.reviewed_at = now, until, now
    row.save()
    mark_changed(tx, "access")
    _record(tx, row, "approved", actor, note=note, renewed=held.id if held else None)


def decide(
    tx: db.Where, row: AccessAssignment, *, approve: bool, actor: str, note: Any = None
) -> AccessAssignment:
    lock(tx, row)
    if row.status != REQUESTED:
        raise InvalidTransition(f"assignment {row.id} is {row.status}, not requested")
    if asked_by(row, actor):
        raise Forbidden("someone other than who asked for it decides a request")
    note = str(note).strip()[:2000] if note else None
    if approve:
        _not_deleted(Agent.objects.filter(pk=row.agent_id).first())
        _grant(tx, row, actor=actor, note=note)
    else:
        row.status = DENIED
        row.decided_by, row.decided_at, row.note = actor, ids.utcnow(), note
        row.save()
        _record(tx, row, "denied", actor, note=note)
    return row


def revoke(
    tx: db.Where, row: AccessAssignment, *, actor: str, reason: Any = None
) -> AccessAssignment:
    lock(tx, row)
    if row.status not in HELD:
        raise InvalidTransition(f"assignment {row.id} is {row.status}: only held ones are revoked")
    row.status = REVOKED
    row.ended_at = ids.utcnow()
    row.save()
    _settle(tx, row, actor=actor)
    mark_changed(tx, "access")
    _record(tx, row, "revoked", actor, severity="warning", why=str(reason or "")[:2000] or None)
    return row


def review(
    tx: db.Where, row: AccessAssignment, *, keep: bool, actor: str, note: Any = None
) -> AccessAssignment:
    """Someone looked at whether the agent still needs it: kept, or revoked."""
    lock(tx, row)
    if row.status not in HELD:
        raise InvalidTransition(f"assignment {row.id} is {row.status}: only held ones are reviewed")
    if not keep:
        return revoke(tx, row, actor=actor, reason=note or "removed in its review")
    row.reviewed_at = ids.utcnow()
    row.save()
    findings.resolve_key(tx, f"{REVIEW_DUE}:{row.id}", actor=actor)
    _record(tx, row, "reviewed", actor, kept=True, note=str(note or "")[:2000] or None)
    return row


def _settle(tx: db.Where, row: AccessAssignment, *, actor: str) -> None:
    """It no longer needs anyone's attention: its open issues are resolved."""
    for type_ in FINDING_TYPES:
        findings.resolve_key(tx, f"{type_}:{row.id}", actor=actor)


# ----------------------------------------------------------------------- rounds


def _raise(
    tx: db.Where,
    row: AccessAssignment,
    type_: str,
    severity: str,
    title: str,
    *,
    description: str,
    remediation: str,
) -> None:
    findings.raise_finding(
        tx,
        type=type_,
        severity=severity,
        subject=row.id,
        agent_id=row.agent_id,
        category=findings.POSTURE,
        title=title,
        description=description,
        remediation=remediation,
    )


def check(tx: db.Where, settings: Settings, now: datetime | None = None) -> dict[str, int]:
    """Expire assignments whose time is up, tell agents' people about those expiring, and
    ask for the reviews that are due. Nothing while the feature is off."""
    if not features.is_on(tx, FEATURE):
        return {}
    now = now or ids.utcnow()
    enforced = features.mode(tx, FEATURE) == features.ENFORCE
    counts = {"expired": 0, "expiring": 0, "reviews": 0}
    packages = AccessPackage.objects.in_bulk()
    for row in list(AccessAssignment.objects.filter(status=ACTIVE)):
        package, agent = packages.get(row.package_id), Agent.objects.filter(pk=row.agent_id).first()
        # A deleted agent's packages wait for it to be restored (or purged).
        if package is None or agent is None or agent.status == DELETED or row.expires_at is None:
            continue
        left = row.expires_at - now
        if left <= timedelta(0):
            row.status = EXPIRED
            row.save()
            mark_changed(tx, "access")
            _record(tx, row, "expired", SYSTEM, severity="warning")
            findings.resolve_key(tx, f"{EXPIRING}:{row.id}", actor=SYSTEM)
            _raise(
                tx,
                row,
                EXPIRED_TYPE,
                "medium",
                f"{agent.name}'s access package {package.name} expired",
                description=(
                    "The agent can no longer use what it granted."
                    if enforced
                    else "The agent still uses what it granted: expired access packages are "
                    "monitored, so each call that needs it goes through and is recorded."
                ),
                remediation="Renew it if the agent still needs it, or revoke it.",
            )
            counts["expired"] += 1
            continue
        if left <= timedelta(days=min(REMIND_DAYS, row.days / 3)):
            days = max(1, int(left.total_seconds() // 86400))
            _raise(
                tx,
                row,
                EXPIRING,
                "high" if left <= timedelta(days=1) else "medium" if days <= 7 else "low",
                f"{agent.name}'s access package {package.name} expires "
                + ("within a day" if left <= timedelta(days=1) else f"in {days} days"),
                description=f"It expires on {row.expires_at:%Y-%m-%d %H:%M} UTC.",
                remediation="Renew it if the agent still needs it; otherwise let it expire.",
            )
            counts["expiring"] += 1
        if package.review_days:
            since = row.reviewed_at or row.starts_at or row.created_at
            if since + timedelta(days=package.review_days) <= now:
                _raise(
                    tx,
                    row,
                    REVIEW_DUE,
                    "low",
                    f"Review {agent.name}'s access package {package.name}",
                    description=f"Access package {package.name} asks every "
                    f"{package.review_days} days whether its agents still need it.",
                    remediation="Keep it if the agent still needs it, or remove it.",
                )
                counts["reviews"] += 1
    return counts


# --------------------------------------------------------------------- policy


def held(tx: db.Where) -> dict[str, list[dict[str, Any]]]:
    """What each agent holds, for OPA (data.registry.agents[id].packages): each package's
    grants, and when they end."""
    out: dict[str, list[dict[str, Any]]] = {}
    for row, package in _with_packages(AccessAssignment.objects.filter(status__in=HELD)):
        out.setdefault(row.agent_id, []).append(
            {
                "name": package.name,
                "grants": list(package.permissions or []),
                "model_access": list(package.model_access or []),
                "agent_access": list(package.agent_access or []),
                "expires_at": ids.isoformat(row.expires_at),
            }
        )
    return out


def current(tx: db.Where, agent_id: str) -> dict[str, list[Any]]:
    """What an agent's packages grant it now, as OPA decides: those in force, and expired
    ones while the feature is monitored. Off, nothing."""
    out: dict[str, list[Any]] = {"permissions": [], "model_access": [], "agent_access": []}
    mode = features.mode(tx, FEATURE)
    if mode == features.OFF:
        return out
    now = ids.utcnow()
    theirs = AccessAssignment.objects.filter(agent_id=agent_id, status__in=HELD)
    for row, package in _with_packages(theirs):
        lapsed = row.status == EXPIRED or (row.expires_at is not None and row.expires_at <= now)
        if lapsed and mode == features.ENFORCE:
            continue
        out["permissions"] = validation.merge_grants(out["permissions"], package.permissions or [])
        out["model_access"] = validation.merge_model_access(
            out["model_access"], package.model_access or []
        )
        out["agent_access"] = validation.merge_agent_access(
            out["agent_access"], package.agent_access or []
        )
    return out


def _with_packages(rows: Any) -> list[tuple[AccessAssignment, AccessPackage]]:
    """The assignments with their packages, by the packages' names."""
    packages = AccessPackage.objects.in_bulk()
    found = [(row, packages[row.package_id]) for row in rows if row.package_id in packages]
    return sorted(found, key=lambda pair: pair[1].name)


def assignment_dict(tx: db.Where, row: AccessAssignment) -> dict[str, Any]:
    package = AccessPackage.objects.filter(pk=row.package_id).first()
    agent = Agent.objects.filter(pk=row.agent_id).first()
    expired = row.status == EXPIRED or (
        row.status == ACTIVE and row.expires_at is not None and row.expires_at <= ids.utcnow()
    )
    return {
        "id": row.id,
        "package": package.name if package else None,
        "agent_id": row.agent_id,
        "agent_name": agent.name if agent else None,
        "status": EXPIRED if expired and row.status == ACTIVE else row.status,
        "days": row.days,
        "reason": row.reason,
        "requested_by": row.requested_by,
        "requested_at": ids.isoformat(row.created_at),
        "decided_by": row.decided_by,
        "decided_at": ids.isoformat(row.decided_at),
        "note": row.note,
        "starts_at": ids.isoformat(row.starts_at),
        "expires_at": ids.isoformat(row.expires_at),
        "reviewed_at": ids.isoformat(row.reviewed_at),
        "ended_at": ids.isoformat(row.ended_at),
    }

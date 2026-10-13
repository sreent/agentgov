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

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import lock, mark_changed
from agentgov.models import DELETED, AccessAssignment, AccessPackage, Agent, Blueprint
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


def get(session: Session, ref: str) -> AccessPackage:
    package = session.scalar(
        select(AccessPackage).where((AccessPackage.name == ref) | (AccessPackage.id == ref))
    )
    if package is None:
        raise NotFound(f"access package {ref!r} not found")
    return package


def list_all(session: Session) -> list[AccessPackage]:
    return list(session.scalars(select(AccessPackage).order_by(AccessPackage.name)))


def _days(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_DAYS:
        raise ValidationError(f"{field} is a number of days from 1 to {MAX_DAYS}")
    return value


def _apply(session: Session, package: AccessPackage, data: dict[str, Any]) -> list[str]:
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
            missing = [
                b for b in value if not session.scalar(select(Blueprint).where(Blueprint.name == b))
            ]
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


def create(session: Session, data: dict[str, Any], *, actor: str) -> AccessPackage:
    _known(data)
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(AccessPackage).where(AccessPackage.name == name)):
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
    _apply(session, package, data)
    session.add(package)
    session.flush()
    mark_changed(session, "access")
    ledger.append(
        session,
        type="access_package.created",
        actor=actor,
        resource=f"access-package/{name}",
        details=_details(package),
    )
    return package


def update(
    session: Session,
    package: AccessPackage,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(session, package, version, f"access package {package.name}")
    _known(data)
    if "name" in data and data["name"] != package.name:
        raise ValidationError("an access package's name can't change: assignments name it")
    changed = _apply(session, package, data)
    if changed:
        edited(package)
        mark_changed(session, "access")
        ledger.append(
            session,
            type="access_package.updated",
            actor=actor,
            resource=f"access-package/{package.name}",
            details={**{k: _details(package)[k] for k in changed}, "changes": changes(package)},
        )
    return changed


def delete(session: Session, package: AccessPackage, *, actor: str) -> None:
    held = session.scalar(
        select(AccessAssignment.id).where(
            AccessAssignment.package_id == package.id,
            AccessAssignment.status.in_((REQUESTED, *HELD)),
        )
    )
    if held:
        raise Conflict(
            f"agents hold or ask for access package {package.name!r}: revoke or deny those "
            "assignments first"
        )
    ledger.append(
        session,
        type="access_package.deleted",
        actor=actor,
        resource=f"access-package/{package.name}",
        severity="warning",
    )
    session.delete(package)
    mark_changed(session, "access")


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


def to_dict(session: Session, package: AccessPackage) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for status in session.scalars(
        select(AccessAssignment.status).where(AccessAssignment.package_id == package.id)
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


def assignment(session: Session, assignment_id: str) -> AccessAssignment:
    row = session.get(AccessAssignment, assignment_id)
    if row is None:
        raise NotFound(f"access assignment {assignment_id} not found")
    return row


def assignments(
    session: Session,
    *,
    status: str | None = None,
    agent_id: str | None = None,
    package_id: str | None = None,
    limit: int = 500,
) -> list[AccessAssignment]:
    stmt = select(AccessAssignment).order_by(AccessAssignment.created_at.desc()).limit(limit)
    if status and status != "all":
        if status not in STATUSES:
            raise ValidationError(f"status is one of {', '.join(STATUSES)} or all")
        stmt = stmt.where(AccessAssignment.status == status)
    if agent_id:
        stmt = stmt.where(AccessAssignment.agent_id == agent_id)
    if package_id:
        stmt = stmt.where(AccessAssignment.package_id == package_id)
    return list(session.scalars(stmt))


def responsible(session: Session, agent: Agent) -> set[str]:
    """The agent's owner and sponsors, as people sign in (lower case), with the members
    and addresses of teams named as either."""
    directory = issues.Directory(session)
    names: set[str] = set()
    for name in [agent.owner, *(agent.sponsors or [])]:
        who = directory.recipient(str(name or ""))
        if who is None:
            continue
        if who.kind == "person":
            names.add(who.name.lower())
        names.update(e.lower() for e in (*who.emails, *who.members))
    return names


def may_request(session: Session, roles: frozenset[str], name: str | None, agent: Agent) -> bool:
    return bool(roles & REQUESTERS) or (name or "").lower() in responsible(session, agent)


def asked_by(row: AccessAssignment, actor: str) -> bool:
    """Whether ``actor`` asked for ``row``: the same person or key, whichever role each acted
    in ("registrar:ann" and "approver:ann")."""

    def who(value: str | None) -> str:
        return str(value or "").partition(":")[2].strip().lower()

    return bool(who(actor)) and who(actor) == who(row.requested_by)


def _resource(row: AccessAssignment, package: AccessPackage, agent: Agent) -> str:
    return f"access-package/{package.name}/{agent.name}"


def _record(
    session: Session,
    row: AccessAssignment,
    change: str,
    actor: str,
    *,
    severity: str = "info",
    **extra: Any,
) -> None:
    package, agent = session.get(AccessPackage, row.package_id), session.get(Agent, row.agent_id)
    assert package is not None and agent is not None
    ledger.append(
        session,
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


def _held(session: Session, agent_id: str, package_id: str) -> AccessAssignment | None:
    return session.scalar(
        select(AccessAssignment).where(
            AccessAssignment.agent_id == agent_id,
            AccessAssignment.package_id == package_id,
            AccessAssignment.status.in_(HELD),
        )
    )


def request(
    session: Session,
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
    if not features.is_on(session, FEATURE):
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
    lock(session, agent)
    pending = session.scalar(
        select(AccessAssignment.id).where(
            AccessAssignment.agent_id == agent.id,
            AccessAssignment.package_id == package.id,
            AccessAssignment.status == REQUESTED,
        )
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
    session.add(row)
    session.flush()
    held = _held(session, agent.id, package.id)
    _record(session, row, "requested", actor, days=days, renews=held.id if held else None)
    if approve or not package.approval:
        _grant(session, row, actor=actor if approve else SYSTEM, note=None)
    return row


def _grant(session: Session, row: AccessAssignment, *, actor: str, note: str | None) -> None:
    now = ids.utcnow()
    until = now + timedelta(days=row.days)
    held = _held(session, row.agent_id, row.package_id)
    if held is not None:
        # A renewal: it carries on from the one it replaces, and never ends sooner.
        if held.expires_at and held.expires_at > until:
            until = held.expires_at
        held.status = RENEWED
        held.ended_at = now
        _settle(session, held, actor=actor)
    row.status = ACTIVE
    row.decided_by, row.decided_at, row.note = actor, now, note
    row.starts_at, row.expires_at, row.reviewed_at = now, until, now
    mark_changed(session, "access")
    _record(session, row, "approved", actor, note=note, renewed=held.id if held else None)


def decide(
    session: Session, row: AccessAssignment, *, approve: bool, actor: str, note: Any = None
) -> AccessAssignment:
    lock(session, row)
    if row.status != REQUESTED:
        raise InvalidTransition(f"assignment {row.id} is {row.status}, not requested")
    if asked_by(row, actor):
        raise Forbidden("someone other than who asked for it decides a request")
    note = str(note).strip()[:2000] if note else None
    if approve:
        _not_deleted(session.get(Agent, row.agent_id))
        _grant(session, row, actor=actor, note=note)
    else:
        row.status = DENIED
        row.decided_by, row.decided_at, row.note = actor, ids.utcnow(), note
        _record(session, row, "denied", actor, note=note)
    return row


def revoke(
    session: Session, row: AccessAssignment, *, actor: str, reason: Any = None
) -> AccessAssignment:
    lock(session, row)
    if row.status not in HELD:
        raise InvalidTransition(f"assignment {row.id} is {row.status}: only held ones are revoked")
    row.status = REVOKED
    row.ended_at = ids.utcnow()
    _settle(session, row, actor=actor)
    mark_changed(session, "access")
    _record(
        session, row, "revoked", actor, severity="warning", why=str(reason or "")[:2000] or None
    )
    return row


def review(
    session: Session, row: AccessAssignment, *, keep: bool, actor: str, note: Any = None
) -> AccessAssignment:
    """Someone looked at whether the agent still needs it: kept, or revoked."""
    lock(session, row)
    if row.status not in HELD:
        raise InvalidTransition(f"assignment {row.id} is {row.status}: only held ones are reviewed")
    if not keep:
        return revoke(session, row, actor=actor, reason=note or "removed in its review")
    row.reviewed_at = ids.utcnow()
    findings.resolve_key(session, f"{REVIEW_DUE}:{row.id}", actor=actor)
    _record(session, row, "reviewed", actor, kept=True, note=str(note or "")[:2000] or None)
    return row


def _settle(session: Session, row: AccessAssignment, *, actor: str) -> None:
    """It no longer needs anyone's attention: its open issues are resolved."""
    for type_ in FINDING_TYPES:
        findings.resolve_key(session, f"{type_}:{row.id}", actor=actor)


# ----------------------------------------------------------------------- rounds


def _raise(
    session: Session,
    row: AccessAssignment,
    type_: str,
    severity: str,
    title: str,
    *,
    description: str,
    remediation: str,
) -> None:
    findings.raise_finding(
        session,
        type=type_,
        severity=severity,
        subject=row.id,
        agent_id=row.agent_id,
        category=findings.POSTURE,
        title=title,
        description=description,
        remediation=remediation,
    )


def check(session: Session, settings: Settings, now: datetime | None = None) -> dict[str, int]:
    """Expire assignments whose time is up, tell agents' people about those expiring, and
    ask for the reviews that are due. Nothing while the feature is off."""
    if not features.is_on(session, FEATURE):
        return {}
    now = now or ids.utcnow()
    enforced = features.mode(session, FEATURE) == features.ENFORCE
    counts = {"expired": 0, "expiring": 0, "reviews": 0}
    rows = session.scalars(select(AccessAssignment).where(AccessAssignment.status == ACTIVE)).all()
    for row in rows:
        package, agent = (
            session.get(AccessPackage, row.package_id),
            session.get(Agent, row.agent_id),
        )
        # A deleted agent's packages wait for it to be restored (or purged).
        if package is None or agent is None or agent.status == DELETED or row.expires_at is None:
            continue
        left = row.expires_at - now
        if left <= timedelta(0):
            row.status = EXPIRED
            mark_changed(session, "access")
            _record(session, row, "expired", SYSTEM, severity="warning")
            findings.resolve_key(session, f"{EXPIRING}:{row.id}", actor=SYSTEM)
            _raise(
                session,
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
                session,
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
                    session,
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


def held(session: Session) -> dict[str, list[dict[str, Any]]]:
    """What each agent holds, for OPA (data.registry.agents[id].packages): each package's
    grants, and when they end."""
    out: dict[str, list[dict[str, Any]]] = {}
    rows = session.execute(
        select(AccessAssignment, AccessPackage)
        .join(AccessPackage, AccessPackage.id == AccessAssignment.package_id)
        .where(AccessAssignment.status.in_(HELD))
        .order_by(AccessPackage.name)
    )
    for row, package in rows:
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


def current(session: Session, agent_id: str) -> dict[str, list[Any]]:
    """What an agent's packages grant it now, as OPA decides: those in force, and expired
    ones while the feature is monitored. Off, nothing."""
    out: dict[str, list[Any]] = {"permissions": [], "model_access": [], "agent_access": []}
    mode = features.mode(session, FEATURE)
    if mode == features.OFF:
        return out
    now = ids.utcnow()
    rows = session.execute(
        select(AccessAssignment, AccessPackage)
        .join(AccessPackage, AccessPackage.id == AccessAssignment.package_id)
        .where(AccessAssignment.agent_id == agent_id, AccessAssignment.status.in_(HELD))
    )
    for row, package in rows:
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


def assignment_dict(session: Session, row: AccessAssignment) -> dict[str, Any]:
    package, agent = session.get(AccessPackage, row.package_id), session.get(Agent, row.agent_id)
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

"""Who has access: the people who sign in through single sign-on, and their sessions.

People are derived from the evidence ledger's ``admin.login`` and
``admin.login_denied`` entries, so the list needs no state of its own and
always matches the record. Sessions are the live server-side sessions; ending
one forces a fresh sign-in, which reads the person's roles from the identity
provider again.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import AdminSession, LedgerEntry
from agentgov.registry.errors import NotFound

SIGN_IN_EVENTS = ("admin.login", "admin.login_denied")


def live_sessions(session: Session) -> list[AdminSession]:
    return list(
        session.scalars(
            select(AdminSession)
            .where(AdminSession.expires_at > ids.utcnow())
            .order_by(AdminSession.created_at.desc())
        )
    )


def session_to_dict(record: AdminSession) -> dict[str, Any]:
    return {
        "id": record.id,
        "subject": record.subject,
        "name": record.name,
        "roles": record.roles or [],
        "started_at": ids.isoformat(record.created_at),
        "expires_at": ids.isoformat(record.expires_at),
    }


def people(session: Session) -> list[dict[str, Any]]:
    """Everyone who has signed in or been refused, most recently active first."""
    by_subject: dict[str, list[AdminSession]] = defaultdict(list)
    for record in live_sessions(session):
        by_subject[record.subject].append(record)
    found: dict[str, dict[str, Any]] = {}
    entries = session.scalars(
        select(LedgerEntry).where(LedgerEntry.type.in_(SIGN_IN_EVENTS)).order_by(LedgerEntry.seq)
    )
    for entry in entries:
        subject = (entry.details or {}).get("subject")
        if not subject:
            continue
        person = found.setdefault(
            subject,
            {"subject": subject, "roles": [], "sign_ins": 0, "last_sign_in": None,
             "last_refused": None, "first_seen": entry.ts},
        )  # fmt: skip
        person["name"] = entry.actor.removeprefix("sso:")
        if entry.type == "admin.login":
            person["roles"] = list((entry.details or {}).get("roles") or [])
            person["sign_ins"] += 1
            person["last_sign_in"] = entry.ts
        else:
            person["last_refused"] = entry.ts
    result = []
    for subject, person in found.items():
        sessions = by_subject.get(subject, [])
        refused_last = person["last_refused"] is not None and (
            person["last_sign_in"] is None or person["last_refused"] > person["last_sign_in"]
        )
        status = "signed_in" if sessions else "refused" if refused_last else "signed_out"
        last_activity = max(t for t in (person["last_sign_in"], person["last_refused"]) if t)
        result.append(
            {
                **person,
                "status": status,
                "active_sessions": len(sessions),
                "session_expires_at": ids.isoformat(max(s.expires_at for s in sessions))
                if sessions
                else None,
                "first_seen": ids.isoformat(person["first_seen"]),
                "last_sign_in": ids.isoformat(person["last_sign_in"]),
                "last_refused": ids.isoformat(person["last_refused"]),
                "_sort": last_activity,
            }
        )
    result.sort(key=lambda p: p.pop("_sort"), reverse=True)
    return result


def _end(session: Session, records: list[AdminSession], *, actor: str) -> int:
    if records:
        ledger.append(
            session,
            type="admin.session_ended",
            actor=actor,
            severity="warning",
            details={
                "subject": records[0].subject,
                "name": records[0].name,
                "session_ids": [r.id for r in records],
            },
        )
    for record in records:
        session.delete(record)
    return len(records)


def end_session(session: Session, session_id: str, *, actor: str) -> int:
    """End one session (an admin's action; the person's own sign-out is admin.logout)."""
    record = session.get(AdminSession, session_id)
    if record is None:
        raise NotFound(f"session {session_id!r} not found")
    return _end(session, [record], actor=actor)


def session_ids(session: Session, subject: str) -> list[str]:
    return list(session.scalars(select(AdminSession.id).where(AdminSession.subject == subject)))


def sign_out(session: Session, subject: str, *, actor: str) -> int:
    """End every session of one person; returns how many were ended."""
    records = list(session.scalars(select(AdminSession).where(AdminSession.subject == subject)))
    return _end(session, records, actor=actor)

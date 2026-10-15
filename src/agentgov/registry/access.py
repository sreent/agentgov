"""Who has access: the people who sign in through single sign-on, their sessions, and
the roles given to people in AgentGov.

People are derived from the evidence ledger's ``admin.login`` and
``admin.login_denied`` entries, so the list needs no state of its own and
always matches the record. Sessions are the live server-side sessions; ending
one forces a fresh sign-in, which reads the person's roles from the identity
provider again.

Roles usually come from the identity provider. Some providers' tokens carry no groups
(Google's), and a new deployment needs its first administrators: an administrator can
give a person a role in AgentGov, by the email address the provider vouches for, which
applies from their next sign-in, beside the provider's.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from django.db.models.functions import Lower

from agentgov import db, ids, ledger
from agentgov.db.models import AdminSession, RoleGrant
from agentgov.identity.sso import GIVABLE, TEAM_ROLES, for_team
from agentgov.registry import teams
from agentgov.registry.errors import Conflict, NotFound, ValidationError

SIGN_IN_EVENTS = ("admin.login", "admin.login_denied")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def live_sessions(tx: db.Where) -> list[AdminSession]:
    return list(AdminSession.objects.filter(expires_at__gt=ids.utcnow()).order_by("-created_at"))


def session_to_dict(record: AdminSession) -> dict[str, Any]:
    return {
        "id": record.id,
        "subject": record.subject,
        "name": record.name,
        "roles": record.roles or [],
        "started_at": ids.isoformat(record.created_at),
        "expires_at": ids.isoformat(record.expires_at),
    }


def people(tx: db.Where) -> list[dict[str, Any]]:
    """Everyone who has signed in or been refused, most recently active first."""
    by_subject: dict[str, list[AdminSession]] = defaultdict(list)
    for record in live_sessions(tx):
        by_subject[record.subject].append(record)
    found: dict[str, dict[str, Any]] = {}
    entries = ledger.chain().filter(type__in=SIGN_IN_EVENTS).order_by("seq")
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


def _end(tx: db.Where, records: list[AdminSession], *, actor: str) -> int:
    if records:
        ledger.append(
            tx,
            type="admin.session_ended",
            actor=actor,
            severity="warning",
            details={
                "subject": records[0].subject,
                "name": records[0].name,
                "session_ids": [r.id for r in records],
            },
        )
    AdminSession.objects.filter(id__in=[r.id for r in records]).delete()
    return len(records)


def end_session(tx: db.Where, session_id: str, *, actor: str) -> int:
    """End one session (an admin's action; the person's own sign-out is admin.logout)."""
    record = AdminSession.objects.filter(pk=session_id).first()
    if record is None:
        raise NotFound(f"session {session_id!r} not found")
    return _end(tx, [record], actor=actor)


def session_ids(tx: db.Where, subject: str) -> list[str]:
    return list(AdminSession.objects.filter(subject=subject).values_list("id", flat=True))


def sign_out(tx: db.Where, subject: str, *, actor: str) -> int:
    """End every session of one person; returns how many were ended."""
    return _end(tx, list(AdminSession.objects.filter(subject=subject)), actor=actor)


# ------------------------------------------------------------- roles given here


def _email(value: str) -> str:
    email = (value or "").strip().lower()
    if not EMAIL.match(email):
        raise ValidationError(f"{value!r} is not an email address")
    return email


def grant_to_dict(grant: RoleGrant) -> dict[str, Any]:
    return {
        "id": grant.id,
        "email": grant.email,
        "role": grant.role,
        "granted_by": grant.granted_by,
        "reason": grant.reason,
        "granted_at": ids.isoformat(grant.created_at),
    }


def grants(tx: db.Where) -> list[RoleGrant]:
    return list(RoleGrant.objects.order_by("email", "role"))


def team_role(tx: db.Where, role: Any, team: Any, allowed: tuple[str, ...]) -> str:
    """``role``, held for team ``team`` when one is given (``approver@sales``): one of
    ``allowed``, and for a team, one of the roles that can be held for a team, and a team
    there is."""
    if not isinstance(role, str) or role not in allowed:
        raise ValidationError(f"role must be one of {', '.join(allowed)}")
    if team in (None, ""):
        return role
    if role not in TEAM_ROLES:
        raise ValidationError(
            f"the {role} role is for every team: one team takes {', '.join(TEAM_ROLES)}"
        )
    name = teams.reference(db.orm(tx), team)
    return for_team(role, str(name))


def grant(
    tx: db.Where,
    email: str,
    role: str,
    *,
    actor: str,
    reason: str | None = None,
    team: str | None = None,
) -> RoleGrant:
    """Give a person an AgentGov role, from their next sign-in: for every team, or for
    ``team``'s agents only."""
    email = _email(email)
    role = team_role(tx, role, team, GIVABLE)
    if RoleGrant.objects.filter(email=email, role=role).exists():
        raise Conflict(f"{email} already has the {role} role in AgentGov")
    record = RoleGrant.objects.create(
        id=ids.new_id(ids.ROLE_GRANT),
        email=email,
        role=role,
        granted_by=actor,
        reason=(reason or "").strip() or None,
    )
    ledger.append(
        tx,
        type="access.role_granted",
        actor=actor,
        resource=email,
        reason=record.reason,
        details={"email": email, "role": role},
    )
    return record


def revoke(tx: db.Where, email: str, role: str, *, actor: str) -> list[str]:
    """Take a role given in AgentGov away, and end the person's sessions, so that it no
    longer applies; returns the IDs of the sessions ended."""
    email = _email(email)
    record = RoleGrant.objects.filter(email=email, role=role).first()
    if record is None:
        raise NotFound(f"{email} has no {role} role given in AgentGov")
    record.delete()
    ledger.append(
        tx,
        type="access.role_revoked",
        actor=actor,
        resource=email,
        severity="warning",
        details={"email": email, "role": role},
    )
    theirs = list(AdminSession.objects.alias(lowered=Lower("name")).filter(lowered=email))
    _end(tx, theirs, actor=actor)
    return [r.id for r in theirs]

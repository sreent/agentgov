"""Scoped API keys for people and automation. Only a SHA-256 hash is stored.

A key works until it expires: the days its creator chose (AGENTGOV_API_KEY_DAYS by
default), never for one made not to, and in any case no longer than
AGENTGOV_API_KEY_MAX_DAYS when that is set, keys made before included. A key in use warns
its users before then, as an issue (``apikey.expiring``), which stays open until the key is
revoked.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import ApiKey
from agentgov.registry import findings
from agentgov.registry.errors import NotFound, ValidationError

# admin     - everything
# approver  - read, decide approvals, attest agents they sponsor
# secops    - the security team's tools (SIEM, SOAR): read, and what the hand-off to
#             security operations allows (agentgov.secops.handoff)
# auditor   - read-only, including the ledger
# registrar - register agents and tool servers for review (CI pipelines, developers)
# service   - internal components (OPA, governance processor, OTel collector)
ROLES = ("admin", "approver", "secops", "auditor", "registrar", "service")


# How long before a key in use expires AgentGov warns, and how recent a use makes it in use.
WARN = timedelta(days=14)
IN_USE = timedelta(days=30)
EXPIRING = "apikey.expiring"
# The longest a key can be made for, in days: a hundred years.
LONGEST = 36500


class Expired(Exception):
    """A request with a key that has expired."""

    def __init__(self, key: ApiKey, at: datetime) -> None:
        super().__init__(f"API key {key.name} expired on {at:%Y-%m-%d}")
        self.key, self.at = key, at


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def expiry(key: ApiKey, max_days: int = 0) -> datetime | None:
    """When the key stops working: as it was made, or sooner where AGENTGOV_API_KEY_MAX_DAYS
    ends it; None: never."""
    capped = key.created_at + timedelta(days=max_days) if max_days else None
    when = [t for t in (key.expires_at, capped) if t is not None]
    return min(when) if when else None


def status(key: ApiKey, max_days: int = 0, now: datetime | None = None) -> str:
    if key.revoked_at is not None:
        return "revoked"
    when = expiry(key, max_days)
    return "expired" if when is not None and when <= (now or ids.utcnow()) else "active"


def lifetime(value: Any, *, max_days: int = 0) -> int | None:
    """The days a new key works, as asked: a number of days, or None for never."""
    if value is None:
        if max_days:
            raise ValidationError(
                f"keys expire within {max_days} days here (AGENTGOV_API_KEY_MAX_DAYS): give "
                "expires_in_days"
            )
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= LONGEST:
        raise ValidationError(f"expires_in_days is a number of days, 1 to {LONGEST}, or null")
    if max_days and value > max_days:
        raise ValidationError(
            f"keys expire within {max_days} days here (AGENTGOV_API_KEY_MAX_DAYS)"
        )
    return value


def create(
    session: Session,
    *,
    name: str,
    role: str,
    actor: str,
    days: int | None = None,
    team: str | None = None,
) -> tuple[ApiKey, str]:
    """A new key, working for ``days`` (None: until it is revoked); with ``team``, its role is
    for that team's agents only (auditor@sales)."""
    from agentgov.registry import access

    role = access.team_role(session, role, team, ROLES)
    if not name or not isinstance(name, str):
        raise ValidationError("name is required")
    token = "agk_" + secrets.token_urlsafe(32)
    now = ids.utcnow()
    key = ApiKey(
        id=ids.new_id(ids.API_KEY),
        name=name,
        role=role,
        key_hash=_hash(token),
        prefix=token[:10],
        created_at=now,
        expires_at=now + timedelta(days=days) if days else None,
    )
    session.add(key)
    session.flush()
    ledger.append(
        session,
        type="apikey.created",
        actor=actor,
        resource=f"apikey/{key.id}",
        details={"name": name, "role": role, "expires_at": ids.isoformat(key.expires_at)},
    )
    return key, token


def revoke(session: Session, key_id: str, *, actor: str) -> ApiKey:
    key = session.get(ApiKey, key_id)
    if key is None:
        raise NotFound(f"api key {key_id} not found")
    if key.revoked_at is None:
        key.revoked_at = ids.utcnow()
        ledger.append(
            session,
            type="apikey.revoked",
            actor=actor,
            resource=f"apikey/{key.id}",
            details={"name": key.name, "role": key.role},
        )
        # Revoked, it no longer needs replacing: what said it expires is over.
        findings.resolve_key(session, f"{EXPIRING}:{key.id}", actor=actor)
    return key


def authenticate(session: Session, token: str, *, max_days: int = 0) -> ApiKey | None:
    """The key ``token`` is, if it works; raises Expired for one that has expired."""
    if not token.startswith("agk_"):
        return None
    key = session.scalar(select(ApiKey).where(ApiKey.key_hash == _hash(token)))
    if key is None or key.revoked_at is not None:
        return None
    now = ids.utcnow()
    when = expiry(key, max_days)
    if when is not None and when <= now:
        raise Expired(key, when)
    key.last_used_at = now
    return key


def expiring(key: ApiKey, max_days: int = 0, now: datetime | None = None) -> datetime | None:
    """When a key in use stops working, if that is soon or past: what its issue says. In use:
    used in the month before then (or now), so a key nobody uses expires quietly."""
    now = now or ids.utcnow()
    when = expiry(key, max_days)
    if key.revoked_at is not None or when is None or when > now + WARN:
        return None
    if key.last_used_at is None or key.last_used_at < min(now, when) - IN_USE:
        return None
    return when


def list_all(session: Session) -> list[ApiKey]:
    return list(session.scalars(select(ApiKey).order_by(ApiKey.created_at.desc())))


def to_dict(key: ApiKey, max_days: int = 0) -> dict[str, Any]:
    return {
        "id": key.id,
        "name": key.name,
        "role": key.role,
        "prefix": key.prefix,
        "created_at": ids.isoformat(key.created_at),
        "last_used_at": ids.isoformat(key.last_used_at),
        "expires_at": ids.isoformat(expiry(key, max_days)),
        "status": status(key, max_days),
        "revoked_at": ids.isoformat(key.revoked_at),
    }

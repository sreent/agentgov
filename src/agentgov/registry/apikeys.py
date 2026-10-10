"""Scoped API keys for people and automation. Only a SHA-256 hash is stored."""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import ApiKey
from agentgov.registry.errors import NotFound, ValidationError

# admin     - everything
# approver  - read, decide approvals, attest agents they sponsor
# auditor   - read-only, including the ledger
# registrar - register agents and tool servers for review (CI pipelines, developers)
# service   - internal components (OPA, governance processor, OTel collector)
ROLES = ("admin", "approver", "auditor", "registrar", "service")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(session: Session, *, name: str, role: str, actor: str) -> tuple[ApiKey, str]:
    if role not in ROLES:
        raise ValidationError(f"role must be one of {', '.join(ROLES)}")
    if not name or not isinstance(name, str):
        raise ValidationError("name is required")
    token = "agk_" + secrets.token_urlsafe(32)
    key = ApiKey(
        id=ids.new_id(ids.API_KEY), name=name, role=role, key_hash=_hash(token), prefix=token[:10]
    )
    session.add(key)
    session.flush()
    ledger.append(
        session,
        type="apikey.created",
        actor=actor,
        resource=f"apikey/{key.id}",
        details={"name": name, "role": role},
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
    return key


def authenticate(session: Session, token: str) -> ApiKey | None:
    if not token.startswith("agk_"):
        return None
    key = session.scalar(select(ApiKey).where(ApiKey.key_hash == _hash(token)))
    if key is None or key.revoked_at is not None:
        return None
    key.last_used_at = ids.utcnow()
    return key


def list_all(session: Session) -> list[ApiKey]:
    return list(session.scalars(select(ApiKey).order_by(ApiKey.created_at.desc())))


def to_dict(key: ApiKey) -> dict[str, Any]:
    return {
        "id": key.id,
        "name": key.name,
        "role": key.role,
        "prefix": key.prefix,
        "created_at": ids.isoformat(key.created_at),
        "last_used_at": ids.isoformat(key.last_used_at),
        "revoked_at": ids.isoformat(key.revoked_at),
    }

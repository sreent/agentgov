"""Edits made from an older copy.

Each object people edit (agents, blueprints, tool servers, model providers, identity
issuers, destinations, policies, teams, access packages, management rules) has a version,
which its edits raise; what the scheduled work changes about it (when it was last seen,
its risk) doesn't. An edit that names the version it was made from (HTTP ``If-Match``,
which the admin UI sends from its forms) is refused with 412 when the object has moved on,
rather than silently undoing what someone else changed meanwhile. An edit that names none
changes the fields it gives, whatever the version.

The ledger entry of each edit says what it changed, from what to what (``changes``): what
the object was when the edit started is kept until then.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime
from typing import Any

from django.db.models import Model
from sqlalchemy import inspect

from agentgov import db
from agentgov.registry.errors import RegistryError


class EditConflict(RegistryError):
    """The object changed since the copy the edit was made from."""

    status_code = 412


# What the scheduled work keeps up to date about an object, not what people edit.
UNTRACKED = frozenset(
    {
        "version",
        "created_at",
        "created_by",
        "updated_at",
        "last_seen_at",
        "deleted_at",
        "risk_score",
        "risk_level",
        "risk_factors",
        "identity_synced_at",
        "identity_error",
        "identity_digest",
        "idp_client_uuid",
        "a2a_probe",
        "cursor",
        "delivered",
        "delivered_at",
        "failures",
        "last_error",
        "retry_at",
    }
)
# Text longer than this is told by its length and SHA-256: the ledger says it changed, and
# which text it became, without holding all of it.
LONGEST = 1000
_BEFORE = "_agentgov_before"


def start_edit(tx: db.Where, obj: Any, version: int | None, what: str) -> None:
    """Lock the object for the edit (edits take turns), and refuse it if it was made from
    an older version than the one stored. What it is now is kept, for :func:`changes`."""
    db.lock(tx, obj)
    if version is not None and obj.version != version:
        raise EditConflict(
            f"{what} changed since you loaded it (version {version}; it is at version "
            f"{obj.version} now): load it again and make your change on top"
        )
    setattr(obj, _BEFORE, _snapshot(obj))


def _snapshot(obj: Any) -> dict[str, Any]:
    return {
        key: copy.deepcopy(getattr(obj, key))
        for key in _fields(obj)
        if key not in UNTRACKED and "secret" not in key
    }


def _fields(obj: Any) -> list[str]:
    """The object's columns, by attribute: one of Django's models, or, from the modules
    still on SQLAlchemy, one of its."""
    if isinstance(obj, Model):
        return [f.attname for f in obj._meta.concrete_fields]
    return [attr.key for attr in inspect(obj).mapper.column_attrs]


def _shown(value: Any) -> Any:
    """A value as the ledger keeps it."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        text = value
    elif isinstance(value, (list, dict)):
        text = json.dumps(value, sort_keys=True, default=str)
    else:
        return value
    if len(text) <= LONGEST:
        return value
    return {"length": len(text), "sha256": hashlib.sha256(text.encode()).hexdigest()}


def changes(obj: Any) -> dict[str, dict[str, Any]]:
    """What the edit changed since :func:`start_edit`: each field it changed, from what to
    what."""
    before = getattr(obj, _BEFORE, None)
    if before is None:
        return {}
    out = {}
    for key, old in before.items():
        new = getattr(obj, key)
        if new != old:
            out[key] = {"from": _shown(old), "to": _shown(new)}
    return out


def edited(obj: Any) -> None:
    obj.version = (obj.version or 0) + 1

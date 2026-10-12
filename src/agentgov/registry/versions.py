"""Edits made from an older copy.

Each object people edit (agents, blueprints, tool servers, model providers, identity
issuers, destinations, policies, teams, access packages, management rules) has a version,
which its edits raise; what the scheduled work changes about it (when it was last seen,
its risk) doesn't. An edit that names the version it was made from (HTTP ``If-Match``,
which the admin UI sends from its forms) is refused with 412 when the object has moved on,
rather than silently undoing what someone else changed meanwhile. An edit that names none
changes the fields it gives, whatever the version.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from agentgov.db import lock
from agentgov.registry.errors import RegistryError


class EditConflict(RegistryError):
    """The object changed since the copy the edit was made from."""

    status_code = 412


def start_edit(session: Session, obj: Any, version: int | None, what: str) -> None:
    """Lock the object for the edit (edits take turns), and refuse it if it was made from
    an older version than the one stored."""
    lock(session, obj)
    if version is not None and obj.version != version:
        raise EditConflict(
            f"{what} changed since you loaded it (version {version}; it is at version "
            f"{obj.version} now): load it again and make your change on top"
        )


def edited(obj: Any) -> None:
    obj.version = (obj.version or 0) + 1

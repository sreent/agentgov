"""Identifier and timestamp helpers."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

# Prefixes make identifiers self-describing in logs and audit trails.
AGENT = "agt"
BLUEPRINT = "bp"
TOOL_SERVER = "ts"
MODEL_PROVIDER = "mp"
ISSUER = "iss"
DESTINATION = "dst"
POLICY = "pol"
CREDENTIAL = "cred"
API_KEY = "key"
APPROVAL = "apr"
FINDING = "fnd"
NOTIFICATION = "ntf"
TEAM = "team"
ACCESS_PACKAGE = "apk"
ACCESS_ASSIGNMENT = "asg"
MANAGEMENT_RULE = "rul"
RULE_MATCH = "rmt"
EVENT = "evt"
SESSION = "ses"
SIGNAL = "sig"
SIGHTING = "mcs"


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def utcnow() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

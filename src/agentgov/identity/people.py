"""Who an agent acts for, from the claims of the token it called the gateway with.

An agent acting on its own calls with its own client's token (client credentials),
whose subject is the client's service account. An agent acting for a person calls
with a token it got for that person by exchanging the person's token (OAuth 2.0
Token Exchange, RFC 8693), whose subject is the person:

* with **delegation**, the person consented to the agent acting for them, and the
  token names the agent in its ``act`` claim;
* with a plain **exchange**, the person's token was issued for the agent (the agent's
  client is in its audience), so an app the person signed in to handed it to the agent.

Keycloak names a client's service account ``service-account-<client id>``, which is
how a token the agent got for itself is told from one it got for a person without
``act``.

agentgateway passes the claims on (``agentgov.gateway``): for tool calls as ExtMcp
metadata, for model calls as webhook headers, lists and objects as JSON.
"""

from __future__ import annotations

import json
from typing import Any

SERVICE_ACCOUNT_PREFIX = "service-account-"
DELEGATION = "delegation"
EXCHANGE = "exchange"


def _names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str) and v]


def person_of(claims: dict[str, Any]) -> dict[str, Any] | None:
    """The person the agent acts for, or None when it acts on its own.

    ``claims`` holds ``subject``, ``username``, ``email``, ``groups``, ``roles`` and
    ``act``, as the gateway passes them. The person is ``{"id", "username", "email",
    "groups", "roles", "via", "actor"}``: ``via`` says how the agent got their token,
    ``actor`` (with delegation) the client the person delegated to."""
    subject = claims.get("subject")
    if not subject:
        return None
    act = claims.get("act")
    username = claims.get("username")
    if isinstance(act, dict) and act:
        via = DELEGATION
    elif username and not str(username).startswith(SERVICE_ACCOUNT_PREFIX):
        via = EXCHANGE
    elif not username and claims.get("email"):
        via = EXCHANGE  # service accounts have no email address
    else:
        return None
    person: dict[str, Any] = {
        "id": str(subject),
        "username": str(username) if username else None,
        "email": str(claims["email"]) if claims.get("email") else None,
        "groups": _names(claims.get("groups")),
        "roles": _names(claims.get("roles")),
        "via": via,
    }
    if via == DELEGATION:
        person["actor"] = str(act.get("client_id") or act.get("sub") or "") or None
    return {k: v for k, v in person.items() if v is not None}


def name_of(person: dict[str, Any] | None) -> str | None:
    """How the ledger names the person: their username, else their email or ID."""
    if not person:
        return None
    return person.get("username") or person.get("email") or person.get("id")


def header_text(value: str | None) -> str | None:
    """A header value as agentgateway sent it: UTF-8 bytes, which HTTP servers decode
    as Latin-1."""
    if value is None:
        return None
    try:
        return value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value


def header_json(value: str | None) -> Any:
    """A list or an object agentgateway sent as JSON in a header (None if it isn't)."""
    text = header_text(value)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None

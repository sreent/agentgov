"""Destinations: where AgentGov hands its evidence and alerts to the security team.

SIEMs get the ledger as OCSF events (agentgov.secops.ocsf), at least once and in order:

* ``otlp``: OpenTelemetry logs (OTLP/HTTP, JSON) to an OpenTelemetry Collector, or any
  backend that takes OTLP, at <url>/v1/logs;
* ``webhook``: a JSON array of events (or JSON lines) to an HTTP input, which most SIEMs
  and log pipelines have;
* ``splunk-hec``: Splunk's HTTP Event Collector, at <url>/services/collector/event.

Chats get alerts: findings from a severity up, approval requests, and kill switches:

* ``slack``: a Slack incoming webhook;
* ``teams``: a Microsoft Teams workflow's webhook.

A destination's credential is never in the database or in what the API returns: it is a
file named after the destination in AGENTGOV_DESTINATION_SECRETS_DIR (a mounted secret),
read when AgentGov sends. For Slack and Teams it holds the webhook URL, which is the
credential; for Splunk, the HTTP Event Collector's token; for OpenTelemetry and webhooks,
HTTP headers to send (one per line, ``Authorization: Bearer ...``), and the URL itself for
inputs whose URL is the credential.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import mark_changed
from agentgov.models import DESTINATION_KINDS, Destination, LedgerHead, Team
from agentgov.registry import validation
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError

OTLP, WEBHOOK, SPLUNK_HEC, SLACK, TEAMS = DESTINATION_KINDS
SIEM = (OTLP, WEBHOOK, SPLUNK_HEC)
CHAT = (SLACK, TEAMS)
ACTIVE, PAUSED = "active", "paused"
SEVERITIES = ("info", "low", "medium", "high", "critical")
FORMATS = ("json", "ndjson")
# What a SIEM gets, by the ledger entries' kind; "changes" is everything else.
SIEM_EVENTS = ("decisions", "approvals", "findings", "access", "changes")
# What a chat gets.
CHAT_EVENTS = ("findings", "approvals", "blocks")
# The kill switches a chat hears about.
BLOCKS = frozenset(
    {
        "agent.block",
        "agent.delete",
        "toolserver.block",
        "model_provider.block",
        "identity_issuer.block",
        "platform.agent_blocked",
    }
)
FIELDS = ("description", "url", "format", "events", "min_severity", "labels")
_HEADER = re.compile(r"^([A-Za-z0-9!#$%&'*+.^_`|~-]+):\s*(.*)$")


def category(entry_type: str) -> str:
    """The kind of a ledger entry, as a SIEM destination chooses them."""
    prefix = entry_type.split(".", 1)[0]
    if prefix in ("decision", "telemetry"):
        return "decisions"
    if prefix == "approval":
        return "approvals"
    if prefix == "finding":
        return "findings"
    if prefix in ("admin", "apikey"):
        return "access"
    return "changes"


def head(session: Session) -> int:
    """The last ledger entry's sequence number."""
    row = session.get(LedgerHead, 1)
    return row.last_seq if row is not None else 0


def get(session: Session, ref: str) -> Destination:
    destination = session.get(Destination, ref) or session.scalar(
        select(Destination).where(Destination.name == ref)
    )
    if destination is None:
        raise NotFound(f"destination {ref!r} not found")
    return destination


def list_all(session: Session) -> list[Destination]:
    return list(session.scalars(select(Destination).order_by(Destination.name)))


# ------------------------------------------------------------------ credentials


def secret_path(settings: Settings, name: str) -> Path:
    return Path(settings.destination_secrets_dir) / name


def secret_need(destination: Any) -> str:
    """Whether a destination needs its secret file: required or optional. A webhook
    without a URL needs it for the URL."""
    if destination.kind in (SPLUNK_HEC, *CHAT) or (
        destination.kind == WEBHOOK and not destination.url
    ):
        return "required"
    return "optional"


@dataclass
class Credentials:
    """What the secret file gives: the URL, when it is the credential, and headers."""

    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


class SecretError(Exception):
    """The secret file is missing or unusable (the message never holds its contents)."""


def _http_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def credentials(settings: Settings, destination: Destination) -> Credentials:
    """Read the destination's secret file, when it sends."""
    path = secret_path(settings, destination.name)
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        if secret_need(destination) == "required":
            raise SecretError(f"no secret file {path}") from None
        return Credentials()
    except OSError as exc:
        raise SecretError(f"can't read the secret file {path}: {exc.strerror}") from None
    if destination.kind in CHAT:
        if not _http_url(text):
            raise SecretError(f"the secret file {path} must hold the webhook URL")
        return Credentials(url=text)
    if destination.kind == SPLUNK_HEC:
        token = text.removeprefix("Splunk ").strip()
        if not token or "\n" in token:
            raise SecretError(f"the secret file {path} must hold the HTTP Event Collector token")
        return Credentials(headers={"Authorization": f"Splunk {token}"})
    found = Credentials()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _http_url(line) and found.url is None:
            found.url = line
            continue
        header = _HEADER.match(line)
        if header is None:
            raise SecretError(
                f"line {number} of the secret file {path} is neither a header (Name: value) "
                "nor a URL"
            )
        found.headers[header[1]] = header[2]
    return found


def secret_status(settings: Settings, destination: Destination) -> dict[str, Any]:
    path = secret_path(settings, destination.name)
    return {"file": str(path), "present": path.is_file(), "need": secret_need(destination)}


# ------------------------------------------------------------------- validation


def _url(value: Any) -> str:
    text = str(value)
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValidationError(f"url must be an http(s) URL (got {value!r})")
    if parts.username or parts.password:
        raise ValidationError("url must not hold credentials: put them in the secret file")
    return text.rstrip("/")


def _events(value: Any, kind: str) -> list[str]:
    allowed = CHAT_EVENTS if kind in CHAT else SIEM_EVENTS
    events = validation.string_list(value, "events")
    # A chat may take no alerts at all: a team's channel, for the issues its team posts.
    if not events and kind not in CHAT:
        raise ValidationError(f"events takes one or more of {', '.join(allowed)}")
    unknown = [e for e in events if e not in allowed]
    if unknown:
        raise ValidationError(
            f"a {kind} destination gets {', '.join(allowed)} (not {', '.join(unknown)})"
        )
    return events


def _apply(destination: Destination, data: dict[str, Any]) -> list[str]:
    kind = destination.kind
    changed = []
    for key in FIELDS:
        if key not in data:
            continue
        value = data[key]
        if key == "url":
            value = _url(value) if value else None
        elif key == "format":
            value = (
                validation.one_of(value, FORMATS, "format")
                if value
                else "json"
                if kind == WEBHOOK
                else None
            )
        elif key == "events":
            value = _events(value, kind) if value is not None else default_events(kind)
        elif key == "min_severity":
            value = validation.one_of(value or default_severity(kind), SEVERITIES, "min_severity")
        elif key == "labels":
            value = validation.labels(value)
        elif key == "description":
            value = str(value or "")
        if getattr(destination, key) != value:
            setattr(destination, key, value)
            changed.append(key)
    _check(destination)
    return changed


def _check(destination: Destination) -> None:
    """What each kind of destination needs, and takes."""
    kind = destination.kind
    if kind in CHAT and destination.url:
        raise ValidationError(
            f"a {kind} webhook's URL is its credential: put it in the destination's secret "
            "file, not in url"
        )
    if kind in (OTLP, SPLUNK_HEC) and not destination.url:
        what = "the collector's OTLP/HTTP endpoint" if kind == OTLP else "Splunk's HEC endpoint"
        raise ValidationError(f"an {kind} destination needs url: {what}")
    if destination.format and kind != WEBHOOK:
        raise ValidationError("format is for webhook destinations only")


def default_events(kind: str) -> list[str]:
    return list(CHAT_EVENTS if kind in CHAT else SIEM_EVENTS)


def default_severity(kind: str) -> str:
    # Chats hear about what needs someone now; SIEMs keep everything.
    return "high" if kind in CHAT else "info"


# --------------------------------------------------------------------- changes


def _known(data: dict[str, Any], also: tuple[str, ...]) -> None:
    unknown = sorted(set(data) - set(FIELDS) - set(also))
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}; a destination takes "
            f"{', '.join((*also, *FIELDS))}"
        )


def create(session: Session, data: dict[str, Any], *, actor: str) -> Destination:
    _known(data, ("name", "kind", "status", "backfill"))
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(Destination).where(Destination.name == name)):
        raise Conflict(f"destination {name!r} already exists")
    kind = validation.one_of(data.get("kind"), DESTINATION_KINDS, "kind")
    backfill = bool(data.get("backfill"))
    status = validation.one_of(data.get("status") or ACTIVE, (ACTIVE, PAUSED), "status")
    if backfill and kind in CHAT:
        raise ValidationError("backfill is for SIEMs: chats get alerts as they happen")
    destination = Destination(
        id=ids.new_id(ids.DESTINATION),
        name=name,
        kind=kind,
        description="",
        url=None,
        format="json" if kind == WEBHOOK else None,
        events=default_events(kind),
        min_severity=default_severity(kind),
        status=status,
        labels={},
        # From now on, unless it should get the ledger from its start.
        cursor=0 if backfill else head(session),
        delivered=0,
        failures=0,
        created_by=actor,
    )
    _apply(destination, data)
    session.add(destination)
    session.flush()
    ledger.append(
        session,
        type="destination.created",
        actor=actor,
        resource=f"destination/{name}",
        details={
            "kind": kind,
            "url": destination.url,
            "events": destination.events,
            "min_severity": destination.min_severity,
            "backfill": backfill,
        },
    )
    mark_changed(session, "destinations")
    return destination


def update(
    session: Session, destination: Destination, data: dict[str, Any], *, actor: str
) -> list[str]:
    _known(data, ("name", "kind"))
    if "kind" in data and data["kind"] != destination.kind:
        raise ValidationError("a destination's kind can't change: add another destination")
    changed = _apply(destination, data)
    if changed:
        ledger.append(
            session,
            type="destination.updated",
            actor=actor,
            resource=f"destination/{destination.name}",
            details={k: getattr(destination, k) for k in changed},
        )
        mark_changed(session, "destinations")
    return changed


def set_status(
    session: Session, destination: Destination, action: str, *, actor: str
) -> Destination:
    """Pause a destination (it keeps its place in the ledger), or resume it."""
    if action not in ("pause", "resume"):
        raise ValidationError(f"unknown action {action!r}")
    target = PAUSED if action == "pause" else ACTIVE
    if destination.status == target:
        raise InvalidTransition(f"destination is already {target}")
    destination.status = target
    destination.retry_at = None
    ledger.append(
        session,
        type=f"destination.{action}",
        actor=actor,
        resource=f"destination/{destination.name}",
        severity="warning" if action == "pause" else "info",
    )
    mark_changed(session, "destinations")
    return destination


def replay(session: Session, destination: Destination, after: Any, *, actor: str) -> Destination:
    """Send a SIEM the ledger again, from after entry ``after`` (0: from its start)."""
    if destination.kind in CHAT:
        raise ValidationError("replay is for SIEMs: chats get alerts as they happen")
    if isinstance(after, bool) or not isinstance(after, int) or after < 0:
        raise ValidationError("after is a ledger entry's sequence number (0: from the start)")
    last = head(session)
    if after > last:
        raise ValidationError(f"the ledger ends at entry {last}")
    previous, destination.cursor = destination.cursor, after
    destination.retry_at = None
    ledger.append(
        session,
        type="destination.replay",
        actor=actor,
        resource=f"destination/{destination.name}",
        details={"from": previous, "to": after},
    )
    mark_changed(session, "destinations")
    return destination


def delete(session: Session, destination: Destination, *, actor: str) -> None:
    posting = sorted(
        t.name for t in session.scalars(select(Team)) if destination.name in (t.destinations or [])
    )
    if posting:
        raise Conflict(
            f"team(s) {', '.join(posting)} post issues to {destination.name!r}: take it out of "
            "them first"
        )
    ledger.append(
        session,
        type="destination.deleted",
        actor=actor,
        resource=f"destination/{destination.name}",
        severity="warning",
    )
    session.delete(destination)
    mark_changed(session, "destinations")


def to_dict(
    destination: Destination, settings: Settings, last_seq: int | None = None
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": destination.id,
        "name": destination.name,
        "kind": destination.kind,
        "description": destination.description or "",
        "url": destination.url,
        "format": destination.format,
        "events": list(destination.events or []),
        "min_severity": destination.min_severity,
        "status": destination.status,
        "labels": destination.labels or {},
        "secret": secret_status(settings, destination),
        "delivery": {
            "cursor": destination.cursor,
            "behind": max(last_seq - destination.cursor, 0) if last_seq is not None else None,
            "delivered": destination.delivered,
            "delivered_at": ids.isoformat(destination.delivered_at),
            "failures": destination.failures,
            "last_error": destination.last_error,
            "retry_at": ids.isoformat(destination.retry_at),
        },
        "created_by": destination.created_by,
        "created_at": ids.isoformat(destination.created_at),
        "updated_at": ids.isoformat(destination.updated_at),
    }
    return out

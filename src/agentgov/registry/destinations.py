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

Service desks get issues, as tickets they keep in step with them (agentgov.registry.desks,
agentgov.ticketing): ``servicenow``, ``jira`` and ``freshservice``.

A destination's credential is never in the database or in what the API returns: it is a
file named after the destination in AGENTGOV_DESTINATION_SECRETS_DIR (a mounted secret),
read when AgentGov sends. For Slack and Teams it holds the webhook URL, which is the
credential; for Splunk, the HTTP Event Collector's token; for OpenTelemetry and webhooks,
HTTP headers to send (one per line, ``Authorization: Bearer ...``), and the URL itself for
inputs whose URL is the credential; for a service desk, headers or the user name and
password, email address and API token, or API key it signs in with (registry.desks).

Where the deployment lists the hosts credentials may go to (AGENTGOV_CREDENTIAL_HOSTS), a
destination's URL must be on one of them: when it is set, and again when AgentGov sends.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db import lock, mark_changed
from agentgov.db.models import Destination
from agentgov.models import DESTINATION_KINDS
from agentgov.registry import desks, teams, validation
from agentgov.registry.errors import Conflict, InvalidTransition, NotFound, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

OTLP, WEBHOOK, SPLUNK_HEC, SLACK, TEAMS, SERVICENOW, JIRA, FRESHSERVICE = DESTINATION_KINDS
SIEM = (OTLP, WEBHOOK, SPLUNK_HEC)
CHAT = (SLACK, TEAMS)
DESK = desks.DESKS
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
FIELDS = ("description", "url", "format", "events", "min_severity", "labels", "tickets")
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


def head(tx: db.Where) -> int:
    """The last ledger entry's sequence number."""
    return ledger.head_seq(tx)


def get(tx: db.Where, ref: str) -> Destination:
    destination = (
        Destination.objects.filter(pk=ref).first() or Destination.objects.filter(name=ref).first()
    )
    if destination is None:
        raise NotFound(f"destination {ref!r} not found")
    return destination


def list_all(tx: db.Where) -> list[Destination]:
    return list(Destination.objects.order_by("name"))


# ------------------------------------------------------------------ credentials


def secret_path(settings: Settings, name: str) -> Path:
    return Path(settings.destination_secrets_dir) / name


def secret_need(destination: Any) -> str:
    """Whether a destination needs its secret file: required or optional. A webhook
    without a URL needs it for the URL."""
    if destination.kind in (SPLUNK_HEC, *CHAT, *DESK) or (
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


class HostNotListed(SecretError):
    """The destination's host isn't one AGENTGOV_CREDENTIAL_HOSTS lists: nothing goes there."""


def _not_listed(url: str) -> str:
    host = urlsplit(url).hostname or url
    return (
        f"AGENTGOV_CREDENTIAL_HOSTS doesn't list {host}: AgentGov sends credentials only to "
        "the hosts it lists"
    )


def _http_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def credentials(settings: Settings, destination: Destination) -> Credentials:
    """Read the destination's secret file, when it sends; refused for a host that
    AGENTGOV_CREDENTIAL_HOSTS doesn't list."""
    found = _read_credentials(settings, destination)
    target = found.url or destination.url
    if target and not settings.credentials_may_go_to(target):
        raise HostNotListed(_not_listed(target))
    return found


def _read_credentials(settings: Settings, destination: Destination) -> Credentials:
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
    if destination.kind in DESK:
        try:
            return Credentials(headers=desks.headers(destination.kind, text))
        except ValueError as exc:
            raise SecretError(f"the secret file {path}: {exc}") from None
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
    if kind in DESK:
        if events:
            raise ValidationError(
                "a service desk gets issues, as tickets: events is for SIEMs and chats"
            )
        return []
    # A chat may take no alerts at all: a team's channel, for the issues its team posts.
    if not events and kind not in CHAT:
        raise ValidationError(f"events takes one or more of {', '.join(allowed)}")
    unknown = [e for e in events if e not in allowed]
    if unknown:
        raise ValidationError(
            f"a {kind} destination gets {', '.join(allowed)} (not {', '.join(unknown)})"
        )
    return events


def _apply(
    destination: Destination, data: dict[str, Any], settings: Settings | None = None
) -> list[str]:
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
        elif key == "tickets":
            if kind not in DESK:
                raise ValidationError(
                    "tickets is for service desks: servicenow, jira, freshservice"
                )
            # Changing some settings keeps the others: null takes one out.
            merged = {**(destination.tickets or {}), **(value or {})}
            value = {k: v for k, v in merged.items() if v is not None}
            value = desks.normalize(kind, value, destination.url)
        if getattr(destination, key) != value:
            setattr(destination, key, value)
            changed.append(key)
    _check(destination, settings)
    return changed


def _check(destination: Destination, settings: Settings | None = None) -> None:
    """What each kind of destination needs, and takes; with ``settings``, a URL on a host
    AGENTGOV_CREDENTIAL_HOSTS lists."""
    kind = destination.kind
    url = destination.url
    if settings is not None and url and not settings.credentials_may_go_to(url):
        raise ValidationError(f"url: {_not_listed(url)}")
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
    if kind in DESK:
        desks.check_url(kind, destination.url)
        settings = desks.normalize(kind, destination.tickets, destination.url)
        if settings != destination.tickets:
            destination.tickets = settings


def default_events(kind: str) -> list[str]:
    if kind in DESK:
        return []
    return list(CHAT_EVENTS if kind in CHAT else SIEM_EVENTS)


def default_severity(kind: str) -> str:
    # Chats hear about what needs someone now, and desks get tickets for it; SIEMs keep
    # everything.
    return "high" if kind in (*CHAT, *DESK) else "info"


# --------------------------------------------------------------------- changes


def _known(data: dict[str, Any], also: tuple[str, ...]) -> None:
    unknown = sorted(set(data) - set(FIELDS) - set(also))
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}; a destination takes "
            f"{', '.join((*also, *FIELDS))}"
        )


def create(
    tx: db.Where, data: dict[str, Any], *, actor: str, settings: Settings | None = None
) -> Destination:
    _known(data, ("name", "kind", "status", "backfill"))
    name = validation.slug(data.get("name"), "name")
    if Destination.objects.filter(name=name).exists():
        raise Conflict(f"destination {name!r} already exists")
    kind = validation.one_of(data.get("kind"), DESTINATION_KINDS, "kind")
    backfill = bool(data.get("backfill"))
    status = validation.one_of(data.get("status") or ACTIVE, (ACTIVE, PAUSED), "status")
    if backfill and kind in CHAT:
        raise ValidationError(
            "backfill is for SIEMs and service desks: chats get alerts as they happen"
        )
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
        cursor=0 if backfill else head(tx),
        delivered=0,
        failures=0,
        created_by=actor,
    )
    _apply(destination, data, settings)
    destination.save(force_insert=True)
    if kind in DESK and not backfill:
        # Tickets for the issues that start from now on, not the ones already open.
        from agentgov.registry import tickets

        tickets.skip_open(tx, destination)
    ledger.append(
        tx,
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
    mark_changed(tx, "destinations")
    return destination


def update(
    tx: db.Where,
    destination: Destination,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
    settings: Settings | None = None,
) -> list[str]:
    start_edit(tx, destination, version, f"destination {destination.name}")
    _known(data, ("name", "kind"))
    if "kind" in data and data["kind"] != destination.kind:
        raise ValidationError("a destination's kind can't change: add another destination")
    changed = _apply(destination, data, settings)
    if changed:
        edited(destination)
    # Saved even when nothing asked for changed: checking it may have put its settings in
    # today's form.
    destination.save()
    if changed and destination.kind in DESK:
        # Tickets the desk refused may go now: try them again.
        from agentgov.registry import tickets

        tickets.retry_failed(tx, destination)
    if changed:
        ledger.append(
            tx,
            type="destination.updated",
            actor=actor,
            resource=f"destination/{destination.name}",
            details={
                **{k: getattr(destination, k) for k in changed},
                "changes": changes(destination),
            },
        )
        mark_changed(tx, "destinations")
    return changed


def set_status(tx: db.Where, destination: Destination, action: str, *, actor: str) -> Destination:
    """Pause a destination (it keeps its place in the ledger), or resume it."""
    if action not in ("pause", "resume"):
        raise ValidationError(f"unknown action {action!r}")
    target = PAUSED if action == "pause" else ACTIVE
    lock(tx, destination)
    if destination.status == target:
        raise InvalidTransition(f"destination is already {target}")
    destination.status = target
    destination.retry_at = None
    destination.save()
    ledger.append(
        tx,
        type=f"destination.{action}",
        actor=actor,
        resource=f"destination/{destination.name}",
        severity="warning" if action == "pause" else "info",
    )
    mark_changed(tx, "destinations")
    return destination


def replay(tx: db.Where, destination: Destination, after: Any, *, actor: str) -> Destination:
    """Send a SIEM the ledger again, from after entry ``after`` (0: from its start)."""
    if destination.kind not in SIEM:
        raise ValidationError("replay is for SIEMs: chats and desks get what happens as it does")
    if isinstance(after, bool) or not isinstance(after, int) or after < 0:
        raise ValidationError("after is a ledger entry's sequence number (0: from the start)")
    last = head(tx)
    if after > last:
        raise ValidationError(f"the ledger ends at entry {last}")
    if after >= destination.cursor:
        # Moved on, it would skip entries the SIEM hasn't had: they would never reach it.
        raise ValidationError(
            f"replay goes back: {destination.name} has had the ledger up to entry "
            f"{destination.cursor}, so after is less than that"
        )
    previous, destination.cursor = destination.cursor, after
    destination.retry_at = None
    destination.save()
    ledger.append(
        tx,
        type="destination.replay",
        actor=actor,
        resource=f"destination/{destination.name}",
        details={"from": previous, "to": after},
    )
    mark_changed(tx, "destinations")
    return destination


def delete(tx: db.Where, destination: Destination, *, actor: str) -> None:
    posting = sorted(
        t.name for t in teams.list_all(tx) if destination.name in (t.destinations or [])
    )
    if posting:
        raise Conflict(
            f"team(s) {', '.join(posting)} post issues to {destination.name!r}: take it out of "
            "them first"
        )
    ledger.append(
        tx,
        type="destination.deleted",
        actor=actor,
        resource=f"destination/{destination.name}",
        severity="warning",
    )
    if destination.kind in DESK:
        # Its tickets stay in the desk; AgentGov stops keeping them in step.
        from agentgov.registry import tickets

        tickets.forget(tx, destination)
    destination.delete()
    mark_changed(tx, "destinations")


def to_dict(
    destination: Destination,
    settings: Settings,
    last_seq: int | None = None,
    tickets: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": destination.id,
        "name": destination.name,
        "version": destination.version,
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
    if destination.kind in DESK:
        out["tickets"] = destination.tickets or {}
        # How many of its tickets AgentGov keeps in step, and how many it couldn't open.
        out["delivery"]["tickets"] = tickets or {}
        out["delivery"]["behind"] = None
    return out

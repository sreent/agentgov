"""Sending destinations what is new in the ledger: OCSF events to SIEMs, alerts to chats.

At least once and in order: a destination's cursor (the last ledger entry it got) moves
only once its SIEM or chat accepted what was sent, so a SIEM may get an event twice (after
a timeout, say) and drops it by its ``metadata.uid``. A destination that fails is tried
again later, waiting longer each time (up to ten minutes), and keeps its place meanwhile.

Control-plane replicas share the work: each claims a destination for a minute before it
sends, so two never send the same entries at once.

Nothing is sent while the security-operations feature is off.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from agentgov import __version__, ids, ledger
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import Agent, Destination, LedgerEntry
from agentgov.registry import destinations
from agentgov.registry.destinations import (
    ACTIVE,
    CHAT,
    DESK,
    OTLP,
    SEVERITIES,
    SLACK,
    SPLUNK_HEC,
    SecretError,
)
from agentgov.secops import alerts, formats, handoff, ocsf

log = logging.getLogger(__name__)

BATCH = 200  # ledger entries read, and at most sent, per request
MAX_BATCHES = 25  # per destination per round, so one backlog doesn't hold up the others
CHAT_AT_ONCE = 10  # alerts a chat is sent per round; beyond, one alert counts the rest
STALE_ALERT = timedelta(hours=1)  # older alerts aren't news: chats don't get them
LEASE = timedelta(seconds=60)
MAX_BACKOFF = 600


class DeliveryError(Exception):
    """A destination refused what was sent, or couldn't be reached (never holds secrets)."""


@dataclass
class _Batch:
    """Entries read for a destination, and what they become."""

    id: str
    name: str
    kind: str
    url: str | None
    format: str | None
    cursor: int
    last: int  # the last entry read
    events: list[dict[str, Any]] = field(default_factory=list)  # SIEMs
    alerts: list[tuple[int, formats.Alert]] = field(default_factory=list)  # chats


def backoff(failures: int) -> timedelta:
    return timedelta(seconds=min(5 * 2 ** max(failures - 1, 0), MAX_BACKOFF))


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<secret>")
    return text


class Delivery:
    def __init__(
        self, db: Database, settings: Settings, *, http: httpx.Client | None = None
    ) -> None:
        self.db = db
        self.settings = settings
        self.http = http or httpx.Client(timeout=10.0, follow_redirects=False)

    # -- rounds -------------------------------------------------------------------
    def run(self) -> dict[str, dict[str, Any]]:
        """Send every active destination what is new; returns what each was sent."""
        with self.db.session() as s:
            if not handoff.at_least(s, handoff.INFORM):
                return {}
            now = ids.utcnow()
            # Service desks get issues as tickets instead (agentgov.ticketing).
            due = [
                d.id
                for d in s.scalars(select(Destination).where(Destination.status == ACTIVE))
                if d.kind not in DESK and (d.retry_at is None or d.retry_at <= now)
            ]
        return {name: outcome for name, outcome in map(self.deliver, due) if name}

    def deliver(self, destination_id: str) -> tuple[str | None, dict[str, Any]]:
        """Send one destination what is new, up to MAX_BATCHES requests."""
        name, sent = None, 0
        for _ in range(MAX_BATCHES):
            batch = self._claim(destination_id)
            if batch is None:
                break
            name = batch.name
            try:
                done, count = self._send(batch)
            except (DeliveryError, SecretError) as exc:
                self._record(batch, batch.cursor, 0, str(exc))
                log.warning("destination %s: %s", batch.name, exc)
                return name, {"sent": sent, "error": str(exc)}
            except DeliveryPartial as partial:
                self._record(batch, partial.done, partial.count, str(partial.error))
                log.warning("destination %s: %s", batch.name, partial.error)
                return name, {"sent": sent + partial.count, "error": str(partial.error)}
            self._record(batch, done, count, None)
            sent += count
            if batch.last - batch.cursor < BATCH:
                break  # caught up
        return name, {"sent": sent}

    def _claim(self, destination_id: str) -> _Batch | None:
        """Read the next entries for a destination and claim it while they are sent."""
        with self.db.session() as s:
            now = ids.utcnow()
            row = s.get(Destination, destination_id)
            if row is None or row.status != ACTIVE or row.kind in DESK:
                return None
            if row.retry_at is not None and row.retry_at > now:
                return None
            if destinations.head(s) <= row.cursor:
                return None
            claimed = s.execute(
                update(Destination)
                .where(
                    Destination.id == row.id,
                    Destination.cursor == row.cursor,
                    or_(Destination.retry_at.is_(None), Destination.retry_at <= now),
                )
                .values(retry_at=now + LEASE)
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                return None  # another replica has it
            entries = s.scalars(
                select(LedgerEntry)
                .where(LedgerEntry.seq > row.cursor)
                .order_by(LedgerEntry.seq)
                .limit(BATCH)
            ).all()
            batch = _Batch(
                id=row.id,
                name=row.name,
                kind=row.kind,
                url=row.url,
                format=row.format,
                cursor=row.cursor,
                last=entries[-1].seq if entries else row.cursor,
            )
            chosen = list(
                row.events if row.events is not None else destinations.default_events(row.kind)
            )
            least = row.min_severity or destinations.default_severity(row.kind)
            if row.kind in CHAT:
                for entry in entries:
                    if now - entry.ts > STALE_ALERT:
                        continue
                    found = alerts.alert(
                        entry,
                        events=chosen,
                        min_severity=least,
                        public_url=self.settings.public_url,
                    )
                    if found is not None:
                        batch.alerts.append((entry.seq, found))
            else:
                batch.events = siem_events(s, entries, chosen, least)
            return batch

    def _record(self, batch: _Batch, done: int, count: int, error: str | None) -> None:
        with self.db.session() as s:
            now = ids.utcnow()
            row = s.get(Destination, batch.id)
            if row is None:
                return
            failures = 0 if error is None else row.failures + 1
            values: dict[str, Any] = {
                "failures": failures,
                "last_error": error[:1000] if error else None,
                "retry_at": now + backoff(failures) if error else None,
            }
            if done != batch.cursor:
                values["cursor"] = done
            if count:
                values["delivered"] = Destination.delivered + count
                values["delivered_at"] = now
            # Unless an administrator moved its cursor meanwhile (a replay): that wins.
            s.execute(
                update(Destination)
                .where(Destination.id == batch.id, Destination.cursor == batch.cursor)
                .values(**values)
                .execution_options(synchronize_session=False)
            )

    # -- sending ------------------------------------------------------------------
    def _send(self, batch: _Batch) -> tuple[int, int]:
        """Send a batch; returns the entry it was sent up to, and how many went."""
        if batch.kind in CHAT:
            return self._send_alerts(batch)
        if batch.events:
            self._post_events(batch, batch.events)
        return batch.last, len(batch.events)

    def _post_events(self, target: Any, events: list[dict[str, Any]]) -> None:
        creds = destinations.credentials(self.settings, target)
        url = creds.url or target.url
        if not url:
            raise DeliveryError("no URL: set url, or put the URL in the secret file")
        if target.kind == OTLP:
            if not url.endswith("/v1/logs"):
                url = f"{url.rstrip('/')}/v1/logs"
            body, content_type = json.dumps(formats.otlp_logs(events)), "application/json"
        elif target.kind == SPLUNK_HEC:
            if "/services/collector" not in url:
                url = f"{url.rstrip('/')}/services/collector/event"
            body, content_type = formats.splunk_hec(events), "application/json"
        elif target.format == "ndjson":
            body, content_type = formats.json_lines(events), "application/x-ndjson"
        else:
            body, content_type = formats.json_array(events), "application/json"
        self._post(url, body, content_type, creds.headers, creds.url)

    def _send_alerts(self, batch: _Batch) -> tuple[int, int]:
        pending = batch.alerts
        if len(pending) > CHAT_AT_ONCE:
            # The summary stands for the alerts from the first it counts.
            first, rest = pending[CHAT_AT_ONCE - 1][0], len(pending) - (CHAT_AT_ONCE - 1)
            summary = alerts.summary(rest, self.settings.public_url)
            pending = [*pending[: CHAT_AT_ONCE - 1], (first, summary)]
        sent = 0
        for seq, alert in pending:
            try:
                self.post_alert(batch, alert)
            except (DeliveryError, SecretError) as exc:
                # What was sent stays sent: the next round starts at this alert.
                raise DeliveryPartial(seq - 1, sent, exc) from None
            sent += 1
        return batch.last, sent

    def post_alert(self, target: Any, alert: formats.Alert) -> None:
        creds = destinations.credentials(self.settings, target)
        assert creds.url is not None
        message = (
            formats.slack_message(alert) if target.kind == SLACK else formats.teams_message(alert)
        )
        self._post(creds.url, json.dumps(message), "application/json", {}, creds.url)

    def _post(
        self,
        url: str,
        body: str,
        content_type: str,
        headers: dict[str, str],
        secret_url: str | None,
    ) -> None:
        secrets = [secret_url or "", *headers.values()]
        try:
            response = self.http.post(
                url,
                content=body.encode(),
                headers={
                    "Content-Type": content_type,
                    "User-Agent": f"AgentGov/{__version__}",
                    **headers,
                },
            )
        except httpx.HTTPError as exc:
            message = f"couldn't send: {type(exc).__name__}: {exc}"
            raise DeliveryError(_redact(message, secrets)) from None
        if response.status_code >= 300:
            text = " ".join(response.text.split())[:300]
            raise DeliveryError(_redact(f"HTTP {response.status_code}: {text}", secrets))

    # -- tests ----------------------------------------------------------------------
    def test(self, ref: str, *, actor: str) -> dict[str, Any]:
        """Send a destination a test event (SIEMs) or message (chats), now; the outcome is
        in the ledger."""
        with self.db.session() as s:
            row = destinations.get(s, ref)
            target = _Batch(
                id=row.id,
                name=row.name,
                kind=row.kind,
                url=row.url,
                format=row.format,
                cursor=row.cursor,
                last=row.cursor,
            )
        error = None
        try:
            if target.kind in CHAT:
                self.post_alert(
                    target,
                    formats.Alert(
                        title="AgentGov test message",
                        text="This channel gets AgentGov's alerts: findings, approval requests "
                        "and kill switches.",
                        link=f"{self.settings.public_url.rstrip('/')}/ui/#/secops",
                    ),
                )
            else:
                probe = LedgerEntry(
                    seq=0,
                    id=ids.new_id(ids.EVENT),
                    ts=ids.utcnow(),
                    type="destination.tested",
                    severity="info",
                    actor=actor,
                    resource=f"destination/{target.name}",
                    reason="a test event: it changes nothing",
                    details={"test": True},
                )
                self._post_events(target, [ocsf.event(probe)])
        except (DeliveryError, SecretError) as exc:
            error = str(exc)
        with self.db.session() as s:
            ledger.append(
                s,
                type="destination.tested",
                actor=actor,
                resource=f"destination/{target.name}",
                severity="warning" if error else "info",
                reason=error,
                details={"ok": error is None},
            )
        return {"ok": error is None, "error": error}


class DeliveryPartial(Exception):
    """Some of a chat's alerts went before one failed."""

    def __init__(self, done: int, count: int, error: Exception) -> None:
        super().__init__(str(error))
        self.done, self.count, self.error = done, count, error


def siem_events(
    session: Session, entries: list[LedgerEntry], chosen: list[str], min_severity: str
) -> list[dict[str, Any]]:
    """The OCSF events a SIEM gets for these entries."""
    picked = [e for e in entries if destinations.category(e.type) in chosen]
    least = SEVERITIES.index(min_severity) + 1  # OCSF severity_id: info is 1
    return [
        event
        for event in ocsf.events(picked, agent_of=lambda agent_id: session.get(Agent, agent_id))
        if event["severity_id"] >= least
    ]

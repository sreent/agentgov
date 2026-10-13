"""Sending issues' notifications (docs/issues.md): emails through the mail server
(AGENTGOV_SMTP_URL), and messages in teams' Teams and Slack channels.

A notification is tried until it goes, waiting longer after each failure, and given up
after MAX_ATTEMPTS; each one sent, and each one given up on, is in the ledger. Control-plane
replicas share the work: each claims a notification for a minute before it sends it.
Nothing is sent while the issues feature is off.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage
from types import SimpleNamespace
from urllib.parse import urlsplit

from sqlalchemy import select, update

from agentgov import ids
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import Agent, Destination, Finding, Notification
from agentgov.registry import features, findings
from agentgov.registry.destinations import ACTIVE, SecretError
from agentgov.registry.issues import EMAIL, OWNER, SPONSORS, SYSTEM
from agentgov.secops import formats
from agentgov.secops.delivery import Delivery, DeliveryError, backoff

log = logging.getLogger(__name__)

# Five seconds after the first failure, twice as long after each next one up to ten minutes:
# given up after about an hour.
MAX_ATTEMPTS = 13
PER_ROUND = 50
LEASE = timedelta(seconds=60)
_LEVELS = {OWNER: "its owner", SPONSORS: "one of its sponsors"}


class NotifyError(Exception):
    """A notification couldn't be sent (never holds secrets)."""


@dataclass
class _Due:
    id: str
    channel: str
    recipient: str
    level: str
    attempts: int
    finding_id: str
    title: str
    severity: str
    description: str
    remediation: str
    subject: str
    agent: str | None


def _who(level: str) -> str:
    return _LEVELS.get(level, "the team it escalates to")


class Notifier:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        delivery: Delivery,
        *,
        smtp: Callable[[], smtplib.SMTP] | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.delivery = delivery
        self._smtp = smtp or self._connect

    # -- rounds ---------------------------------------------------------------------
    def run(self) -> dict[str, int]:
        """Send the notifications that are due; returns how many went and how many failed."""
        with self.db.session() as s:
            if not features.is_on(s, "issues"):
                return {}
            now = ids.utcnow()
            due = list(
                s.scalars(
                    select(Notification.id)
                    .where(Notification.status == "pending", Notification.next_attempt_at <= now)
                    .order_by(Notification.created_at)
                    .limit(PER_ROUND)
                )
            )
        sent = failed = 0
        for notification_id in due:
            item = self._claim(notification_id)
            if item is None:
                continue
            try:
                self._send(item)
            except (NotifyError, DeliveryError, SecretError) as exc:
                self._failed(item, str(exc))
                failed += 1
            else:
                self._sent(item)
                sent += 1
        return {"sent": sent, "failed": failed}

    def _claim(self, notification_id: str) -> _Due | None:
        with self.db.session() as s:
            now = ids.utcnow()
            claimed = s.execute(
                update(Notification)
                .where(
                    Notification.id == notification_id,
                    Notification.status == "pending",
                    Notification.next_attempt_at <= now,
                )
                .values(next_attempt_at=now + LEASE)
            ).rowcount
            if claimed != 1:
                return None
            n = s.get(Notification, notification_id)
            f = s.get(Finding, n.finding_id) if n else None
            if n is None or f is None:
                return None
            agent = s.get(Agent, f.agent_id) if f.agent_id else None
            return _Due(
                id=n.id,
                channel=n.channel,
                recipient=n.recipient,
                level=n.level,
                attempts=n.attempts,
                finding_id=f.id,
                title=f.title,
                severity=f.severity,
                description=f.description or "",
                remediation=f.remediation or "",
                subject=f.subject,
                agent=agent.name if agent else None,
            )

    def _sent(self, item: _Due) -> None:
        with self.db.session() as s:
            n, f = s.get(Notification, item.id), s.get(Finding, item.finding_id)
            if n is None or f is None:
                return
            n.status, n.sent_at, n.attempts, n.last_error = (
                "sent",
                ids.utcnow(),
                n.attempts + 1,
                None,
            )
            findings.record(
                s,
                f,
                "notified",
                SYSTEM,
                severity="info",
                level=item.level,
                channel=item.channel,
                to=item.recipient,
            )

    def _failed(self, item: _Due, error: str) -> None:
        log.warning("notification %s to %s: %s", item.id, item.recipient, error)
        with self.db.session() as s:
            n, f = s.get(Notification, item.id), s.get(Finding, item.finding_id)
            if n is None or f is None:
                return
            n.attempts += 1
            n.last_error = error[:1000]
            if n.attempts >= MAX_ATTEMPTS:
                n.status = "failed"
                findings.record(
                    s,
                    f,
                    "notification_failed",
                    SYSTEM,
                    severity="warning",
                    level=item.level,
                    channel=item.channel,
                    to=item.recipient,
                    error=n.last_error,
                )
            else:
                n.next_attempt_at = ids.utcnow() + backoff(n.attempts)

    # -- sending ----------------------------------------------------------------------
    def _link(self, finding_id: str) -> str:
        return f"{self.settings.public_url.rstrip('/')}/ui/#/findings/{finding_id}"

    def _send(self, item: _Due) -> None:
        if item.channel == EMAIL:
            self._email(item)
        else:
            self._chat(item)

    def _email(self, item: _Due) -> None:
        if not self.settings.smtp_url or not self.settings.smtp_from:
            raise NotifyError("no mail server: set AGENTGOV_SMTP_URL and AGENTGOV_SMTP_FROM")
        about = f" about agent {item.agent}" if item.agent else ""
        message = EmailMessage()
        message["From"] = self.settings.smtp_from
        message["To"] = item.recipient
        message["Subject"] = f"[AgentGov] {item.severity.capitalize()} issue{about}: {item.title}"
        lines = [item.title, ""]
        if item.description:
            lines += [item.description, ""]
        if item.remediation:
            lines += [f"What to do: {item.remediation}", ""]
        lines += [
            f"You get this as {_who(item.level)}. In AgentGov, acknowledge it, or it goes on "
            "to the next people responsible for it. There too: say it isn't yours, ask for an "
            "exception, or say you fixed it, and AgentGov checks it again:",
            self._link(item.finding_id),
        ]
        message.set_content("\n".join(lines))
        try:
            with self._smtp() as client:
                client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise NotifyError(f"couldn't send the email: {type(exc).__name__}: {exc}") from None

    def _connect(self) -> smtplib.SMTP:
        """The mail server, over TLS: smtps from the start, smtp with STARTTLS when the
        server offers it. A password is never sent without TLS."""
        url = urlsplit(self.settings.smtp_url or "")
        host = url.hostname or "localhost"
        context = ssl.create_default_context()
        client: smtplib.SMTP
        if url.scheme == "smtps":
            client = smtplib.SMTP_SSL(host, url.port or 465, timeout=10, context=context)
            secure = True
        else:
            client = smtplib.SMTP(host, url.port or 587, timeout=10)
            client.ehlo()
            secure = client.has_extn("starttls")
            if secure:
                client.starttls(context=context)
                client.ehlo()
        if self.settings.smtp_username:
            if not secure:
                client.close()
                raise NotifyError("the mail server doesn't offer TLS: not sending the password")
            client.login(self.settings.smtp_username, self.settings.smtp_password or "")
        return client

    def _chat(self, item: _Due) -> None:
        with self.db.session() as s:
            row = s.scalar(select(Destination).where(Destination.name == item.recipient))
            if row is None:
                raise NotifyError(f"destination {item.recipient!r} no longer exists")
            if row.status != ACTIVE:
                raise NotifyError(f"destination {item.recipient!r} is paused")
            target = SimpleNamespace(name=row.name, kind=row.kind, url=row.url)
        facts = [("Severity", item.severity)]
        if item.agent:
            facts.insert(0, ("Agent", item.agent))
        self.delivery.post_alert(
            target,
            formats.Alert(
                title=f"Issue for {_who(item.level)}: {item.title}",
                text=" ".join(filter(None, [item.description, item.remediation]))[:1500]
                or item.title,
                severity=item.severity,
                facts=facts,
                link=self._link(item.finding_id),
                link_label="Answer in AgentGov",
            ),
        )

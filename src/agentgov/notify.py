"""Sending issues' notifications (docs/issues.md): emails through the mail server
(AGENTGOV_SMTP_URL), and messages in teams' Teams and Slack channels.

A notification is tried until it goes, waiting longer after each failure, and given up
after MAX_ATTEMPTS; each one sent, and each one given up on, is in the ledger. Control-plane
replicas share the work: each claims a notification for a minute before it sends it.
With AGENTGOV_ISSUES_DIGEST_AT, each address and team chat with open issues also gets a
digest of them once a day (agentgov.registry.digest). Nothing is sent while the issues
feature is off.
"""

from __future__ import annotations

import logging
import re
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.message import EmailMessage
from types import SimpleNamespace
from urllib.parse import urlsplit

from sqlalchemy import select, update

from agentgov import ids
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.models import SEVERITIES, Agent, Destination, Finding, Notification
from agentgov.registry import digest, features, findings
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
# What a header can't hold: control characters, line breaks above all, which would end it
# and start another. Titles carry names that agents, platforms and developers give.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


class NotifyError(Exception):
    """A notification couldn't be sent (never holds secrets). ``final``: it never will be,
    so it isn't tried again."""

    def __init__(self, message: str, *, final: bool = False) -> None:
        super().__init__(message)
        self.final = final


def _one_line(value: str) -> str:
    """A header's value, on one line and without control characters."""
    return " ".join(_CONTROL.sub(" ", value).split())


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


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _new(line: digest.Line) -> str:
    return " (new)" if line.new else ""


def _further(line: digest.Line, now: datetime) -> str:
    """When an issue nobody took on goes on to the next people responsible for it."""
    if line.goes_further is None:
        return ""
    hours = (line.goes_further - now).total_seconds() / 3600
    if hours <= 1:
        return ". It goes further within the hour unless someone takes it on"
    when = f"{round(hours)} hours" if hours < 48 else f"{round(hours / 24)} days"
    return f". It goes further in {when} unless someone takes it on"


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
                self._failed(item, str(exc), final=getattr(exc, "final", False))
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

    def _failed(self, item: _Due, error: str, *, final: bool = False) -> None:
        log.warning("notification %s to %s: %s", item.id, item.recipient, error)
        with self.db.session() as s:
            n, f = s.get(Notification, item.id), s.get(Finding, item.finding_id)
            if n is None or f is None:
                return
            n.attempts += 1
            n.last_error = error[:1000]
            if final or n.attempts >= MAX_ATTEMPTS:
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

    # -- the daily digest -------------------------------------------------------------
    def digest(self, now: datetime | None = None) -> dict[str, int]:
        """Send the day's digests that are due and haven't gone yet; returns how many went
        and how many failed (each tried again a little later)."""
        now = now or ids.utcnow()
        day = digest.due(self.settings, now)
        if day is None:
            return {}
        with self.db.session() as s:
            if not features.is_on(s, "issues"):
                return {}
            state = digest.start(s, day, now)
            todo = {
                target: lines
                for target, lines in digest.gather(
                    s, self.settings, digest.since(state, now)
                ).items()
                if digest.waiting(state, target, now)
            }
        sent = failed = 0
        for target, lines in todo.items():
            error = None
            try:
                if target[0] == EMAIL:
                    self._digest_email(target[1], lines, now)
                else:
                    self._digest_chat(target[1], lines, now)
            except (NotifyError, DeliveryError, SecretError) as exc:
                log.warning("digest to %s: %s", target[1], exc)
                error = str(exc)
                failed += 1
            else:
                sent += 1
            with self.db.session() as s:
                digest.record(s, day, target, lines, now=now, error=error)
        return {"digests_sent": sent, "digests_failed": failed} if todo else {}

    def _ui(self, path: str) -> str:
        return f"{self.settings.public_url.rstrip('/')}/ui/#/{path}"

    def _digest_email(self, to: str, lines: list[digest.Line], now: datetime) -> None:
        if not self.settings.smtp_url or not self.settings.smtp_from:
            raise NotifyError("no mail server: set AGENTGOV_SMTP_URL and AGENTGOV_SMTP_FROM")
        waiting = [x for x in lines if not x.taken_on]
        them = "it" if len(waiting) == 1 else "them"
        subject = f"[AgentGov] {_count(len(lines), 'open issue')} with you" + (
            f", {len(waiting)} waiting for someone to take {them} on" if waiting else ""
        )
        body = ["The issues with you in AgentGov today, the most pressing first.", ""]
        shown = lines[: digest.LISTED]
        for heading, part in (
            ("Waiting for someone to take them on", [x for x in shown if not x.taken_on]),
            ("Taken on, not fixed yet", [x for x in shown if x.taken_on]),
        ):
            if not part:
                continue
            body += [f"{heading}:", ""]
            for x in part:
                about = f", agent {x.agent}" if x.agent else ""
                body.append(
                    f"- {x.severity.capitalize()}: {x.title}{about}{_new(x)}{_further(x, now)}"
                )
                body.append(f"  {self._link(x.finding_id)}")
            body.append("")
        if len(lines) > len(shown):
            body += [f"And {_count(len(lines) - len(shown), 'more issue')}.", ""]
        body += [
            "All of them, and what you can do about each (take it on, say it isn't yours, ask "
            "to accept the risk, or say you fixed it):",
            self._ui("findings?status=mine"),
            "",
            "You get this once a day, as the owner, a sponsor or the team of the agents they "
            f"are about. Issues of {self.settings.issues_notify_severity} severity and above "
            "are also sent one by one as they come.",
        ]
        self._mail(to, subject, "\n".join(body))

    def _message(self, to: str, subject: str, body: str) -> EmailMessage:
        """The email; NotifyError, final, if what it was given can't be one."""
        try:
            message = EmailMessage()
            message["From"] = _one_line(self.settings.smtp_from or "")
            message["To"] = _one_line(to)
            message["Subject"] = _one_line(subject)
            message.set_content(body)
        except Exception as exc:  # whatever it is, one message never stops the others
            raise NotifyError(
                f"couldn't write the email: {type(exc).__name__}: {exc}", final=True
            ) from None
        return message

    def _mail(self, to: str, subject: str, body: str) -> None:
        message = self._message(to, subject, body)
        try:
            with self._smtp() as client:
                client.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise NotifyError(f"couldn't send the email: {type(exc).__name__}: {exc}") from None

    def _digest_chat(self, name: str, lines: list[digest.Line], now: datetime) -> None:
        target = self._destination(name)
        waiting = [x for x in lines if not x.taken_on]
        worst = max(lines, key=lambda x: SEVERITIES.index(x.severity)).severity
        text = "\n".join(
            f"{x.severity.capitalize()}: {x.title}"
            + (f" ({x.agent})" if x.agent else "")
            + (" (taken on)" if x.taken_on else "")
            for x in lines[:10]
        )
        if len(lines) > 10:
            text += f"\nAnd {_count(len(lines) - 10, 'more')}."
        self.delivery.post_alert(
            target,
            formats.Alert(
                title=f"{_count(len(lines), 'open issue')} with this team's people",
                text=text[:1500],
                severity=worst,
                facts=[
                    ("Waiting to be taken on", str(len(waiting))),
                    ("Taken on", str(len(lines) - len(waiting))),
                ],
                link=self._ui("findings"),
                link_label="Open in AgentGov",
            ),
        )

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
        subject = f"[AgentGov] {item.severity.capitalize()} issue{about}: {item.title}"
        lines = [item.title, ""]
        if item.description:
            lines += [item.description, ""]
        if item.remediation:
            lines += [f"What to do: {item.remediation}", ""]
        lines += [
            f"You get this as {_who(item.level)}. AgentGov is how your organisation keeps "
            "track of its AI agents and what they may do. Acknowledge the issue there, or it "
            "goes on to the next people responsible for it. There too: say it isn't yours, "
            "ask to accept the risk, or say you fixed it, and AgentGov checks it again. Sign "
            "in with your work account:",
            self._link(item.finding_id),
        ]
        self._mail(item.recipient, subject, "\n".join(lines))

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

    def _destination(self, name: str) -> SimpleNamespace:
        with self.db.session() as s:
            row = s.scalar(select(Destination).where(Destination.name == name))
            if row is None:
                raise NotifyError(f"destination {name!r} no longer exists")
            if row.status != ACTIVE:
                raise NotifyError(f"destination {name!r} is paused")
            return SimpleNamespace(name=row.name, kind=row.kind, url=row.url)

    def _chat(self, item: _Due) -> None:
        target = self._destination(item.recipient)
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

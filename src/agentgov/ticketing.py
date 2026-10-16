"""Keeping issues' tickets in step with the service desks (docs/tickets.md).

Each round, for each active desk: open the tickets waiting to be opened, read back the open
ones not read for a while, and tell the desk what changed in their issues
(agentgov.registry.tickets says what that is). A desk that can't be reached, refuses
AgentGov's credential, or asks it to slow down is left until later (as long as its
``Retry-After`` says), and what it missed goes then; a ticket the desk refuses (a field its
form requires, say) is tried again, waiting longer each time, and given up on after about
an hour, which the issue's history says. Each round does a bounded amount of work per desk,
so that a backlog goes over a few rounds rather than all at once.

Nothing is sent while the issues feature is off.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from django.db.models import F, Q

from agentgov import db, ids, ledger
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.db.models import Destination, Finding, Ticket
from agentgov.registry import desks, destinations, features, tickets
from agentgov.registry.destinations import SecretError
from agentgov.registry.tickets import CLOSED, DONE, OPEN, PENDING, Seen
from agentgov.secops.delivery import Delivery, backoff
from agentgov.servicedesks import Desk, DeskError, Remote, client

log = logging.getLogger(__name__)

TO_OPEN = 20  # tickets opened per desk and round
TO_READ = 50  # read back
TO_TELL = 50  # told what changed


class Ticketing:
    def __init__(self, db: Database, settings: Settings, delivery: Delivery) -> None:
        self.db = db
        self.settings = settings
        # The destinations' HTTP client (tests stand in for the desks there).
        self.delivery = delivery
        # What the desk refused last in a round, for its own state when nothing went.
        self.last_error: str | None = None

    def _client(self, row: Destination) -> Desk:
        creds = destinations.credentials(self.settings, row)
        return client(row.kind, self.delivery.http, row.url or "", creds.headers, row.tickets or {})

    # -- rounds ---------------------------------------------------------------------
    def run(self, now: datetime | None = None) -> dict[str, int]:
        """Open, read back and update the desks' tickets; returns how many of each."""
        with self.db.transaction() as tx:
            if not features.is_on(db.orm(tx), "issues"):
                return {}
            planned = tickets.plan(tx, self.settings)
        now = now or ids.utcnow()  # after planning: what it planned is due now
        with self.db.transaction() as tx:
            desks = tickets.active_desks(tx)
            due = [d.id for d in desks if d.retry_at is None or d.retry_at <= now]
        totals: Counter[str] = Counter()
        for desk_id in due:
            totals.update(self._desk(desk_id, now))
        out = {k: v for k, v in totals.items() if v}
        if planned:
            out["tickets_planned"] = planned
        return out

    def _desk(self, desk_id: str, now: datetime) -> Counter[str]:
        done: Counter[str] = Counter()
        with self.db.transaction():
            row = Destination.objects.filter(pk=desk_id).first()
            if row is None:
                return done
            name = row.name
            try:
                desk = self._client(row)
            except SecretError as exc:
                problem = str(exc)
            else:
                problem = None
            mine = Ticket.objects.filter(destination_id=desk_id, next_attempt_at__lte=now)
            to_open = list(
                mine.filter(status=PENDING)
                .order_by("created_at")
                .values_list("id", flat=True)[:TO_OPEN]
            )
            unread = Q(synced_at__isnull=True) | Q(synced_at__lte=now - tickets.READ_EVERY)
            to_read = list(
                mine.filter(unread, status=OPEN)
                .order_by(F("synced_at").asc(nulls_first=True))
                .values_list("id", flat=True)[:TO_READ]
            )
            # Those whose issue changed since the desk was last told (read back first, below,
            # so that what the desk did is known before AgentGov tells it anything).
            live = list(mine.filter(status=OPEN).order_by("updated_at"))
            issues = Finding.objects.in_bulk({t.finding_id for t in live})
            to_tell = [
                t.id
                for t in live
                if t.finding_id in issues and tickets.work(t, issues[t.finding_id])
            ][:TO_TELL]
        if problem is not None:
            self._desk_failed(desk_id, problem, None, now)
            return done
        self.last_error = None
        try:
            for ticket_id in to_open:
                done[self._open(desk, desk_id, ticket_id)] += 1
            for ticket_id in to_read:
                done[self._read(desk, desk_id, ticket_id, now)] += 1
            for ticket_id in to_tell:
                outcome = self._tell(desk, desk_id, ticket_id)
                if outcome:
                    done[outcome] += 1
        except DeskError as exc:
            log.warning("service desk %s: %s", name, exc)
            self._desk_failed(desk_id, str(exc), exc.retry_after, now)
            done["desk_failures"] += 1
            return done
        went = done["tickets_opened"] + done["tickets_updated"] + done["tickets_read"]
        went += done["tickets_changed_there"] + done["tickets_closed"]
        if went:
            self._desk_ok(desk_id, done["tickets_opened"] + done["tickets_updated"], now)
        elif self.last_error:
            # Nothing went, and the desk refused something: its settings may be at fault.
            self._desk_failed(desk_id, self.last_error, None, now, whole=False)
        return done

    # -- the desk's own state, as on the Security operations page ----------------------
    def _desk_failed(
        self,
        desk_id: str,
        error: str,
        retry_after: float | None,
        now: datetime,
        *,
        whole: bool = True,
    ) -> None:
        """The desk failed; ``whole``: as a whole (it is left alone until it is tried again),
        rather than refusing its tickets one by one."""
        with self.db.transaction():
            row = Destination.objects.filter(pk=desk_id).first()
            if row is None:
                return
            row.failures += 1
            row.last_error = error[:1000]
            if whole:
                row.retry_at = now + (
                    timedelta(seconds=retry_after) if retry_after else backoff(row.failures)
                )
            row.save()

    def _desk_ok(self, desk_id: str, count: int, now: datetime) -> None:
        with self.db.transaction():
            row = Destination.objects.filter(pk=desk_id).first()
            if row is None:
                return
            row.failures, row.last_error, row.retry_at = 0, None, None
            if count:
                row.delivered += count
                row.delivered_at = now
            row.save()

    # -- opening ------------------------------------------------------------------------
    def _open(self, desk: Desk, desk_id: str, ticket_id: str) -> str:
        with self.db.transaction() as tx:
            t, d = _ticket(ticket_id), Destination.objects.filter(pk=desk_id).first()
            if t is None or d is None or t.status != PENDING:
                return "tickets_skipped"
            f = Finding.objects.filter(pk=t.finding_id).first()
            if f is None or f.status != "open":
                t.status = CLOSED  # gone, or over, before it was opened
                t.save()
                return "tickets_skipped"
            new = tickets.new_ticket(tx, self.settings, d, t, f)
            state = tickets.snapshot(f)
            # Tried before, or stopped midway (the desk may have opened it without AgentGov
            # hearing back): it may be there already.
            look_first = t.attempts > 0 or bool((t.told or {}).get("opening"))
            t.told = {"opening": True}
            t.save()
        try:
            remote = desk.find(new.marker) if look_first else None
            if remote is None:
                remote = desk.create(new)
        except DeskError as exc:
            if exc.whole_desk:
                raise
            return self._ticket_failed(desk_id, ticket_id, str(exc))
        with self.db.transaction() as tx:
            t, d = _ticket(ticket_id), Destination.objects.filter(pk=desk_id).first()
            if t is None or d is None:
                return "tickets_skipped"
            tickets.opened(
                tx,
                d,
                t,
                Finding.objects.filter(pk=t.finding_id).first(),
                key=remote.key,
                remote_id=remote.remote_id,
                url=remote.url,
                state=state,
            )
        return "tickets_opened"

    def _ticket_failed(self, desk_id: str, ticket_id: str, error: str) -> str:
        log.info("ticket %s: %s", ticket_id, error)
        self.last_error = error
        with self.db.transaction() as tx:
            t, d = _ticket(ticket_id), Destination.objects.filter(pk=desk_id).first()
            if t is not None and d is not None:
                tickets.failed(tx, d, t, Finding.objects.filter(pk=t.finding_id).first(), error)
        return "tickets_failing"

    # -- reading back -------------------------------------------------------------------
    def _read(self, desk: Desk, desk_id: str, ticket_id: str, now: datetime) -> str:
        with self.db.transaction():
            t = _ticket(ticket_id)
            if t is None or t.status != OPEN or not t.remote_id:
                return "tickets_skipped"
            remote = Remote(t.remote_id, t.key or t.remote_id, t.url)
        try:
            seen = desk.read(remote)
        except DeskError as exc:
            if exc.whole_desk:
                raise
            if not exc.missing:
                self.last_error = str(exc)
                with self.db.transaction():
                    t = _ticket(ticket_id)
                    if t is not None:
                        t.synced_at, t.last_error = now, str(exc)[:1000]
                        t.save()
                return "tickets_failing"
            seen = Seen("deleted there", DONE)
        with self.db.transaction() as tx:
            t, d = _ticket(ticket_id), Destination.objects.filter(pk=desk_id).first()
            if t is None or d is None:
                return "tickets_skipped"
            f = Finding.objects.filter(pk=t.finding_id).first()
            if f is None:
                t.status = CLOSED
                t.save()
                return "tickets_skipped"
            happened = tickets.seen(tx, self.settings, d, t, f, seen, now)
        return "tickets_read" if not happened else "tickets_changed_there"

    # -- telling ------------------------------------------------------------------------
    def _tell(self, desk: Desk, desk_id: str, ticket_id: str) -> str | None:
        with self.db.transaction():
            t, d = _ticket(ticket_id), Destination.objects.filter(pk=desk_id).first()
            if t is None or d is None or t.status != OPEN or not t.remote_id:
                return None
            f = Finding.objects.filter(pk=t.finding_id).first()
            if f is None:
                t.status = CLOSED
                t.save()
                return None
            todo = tickets.work(t, f)
            if not todo:
                return None
            remote = Remote(t.remote_id, t.key or t.remote_id, t.url)
            there = t.phase  # what the desk said last
            settings = dict(d.tickets or {})
            kind = d.kind
            link = tickets.link(self.settings, f)
        try:
            self._send(desk, remote, todo, there, settings, kind, link)
        except DeskError as exc:
            if exc.whole_desk:
                raise
            if exc.missing:
                # Deleted there: AgentGov stops keeping it in step.
                with self.db.transaction():
                    t = _ticket(ticket_id)
                    if t is not None:
                        t.status, t.phase, t.state = CLOSED, DONE, "deleted there"
                        t.save()
                return "tickets_closed"
            return self._ticket_failed(desk_id, ticket_id, str(exc))
        with self.db.transaction() as tx:
            t, d = _ticket(ticket_id), Destination.objects.filter(pk=desk_id).first()
            f = Finding.objects.filter(pk=t.finding_id).first() if t is not None else None
            if t is None or d is None or f is None:
                return None
            tickets.told(tx, d, t, f, todo)
        return "tickets_updated"

    def _send(
        self,
        desk: Desk,
        remote: Remote,
        todo: tickets.Work,
        there: str,
        settings: dict[str, Any],
        kind: str,
        link: str,
    ) -> None:
        if there == DONE:
            return  # over in the desk: nothing more to say there (see tickets.seen)
        if todo.ended:
            if desks.resolves(settings):
                desk.resolve(remote, todo.ended, link)
            else:
                desk.note(remote, todo.ended, link)
            return
        notes = list(todo.notes)
        if todo.severity:
            fields = desks.priorities(kind, settings, todo.severity)
            if fields:
                try:
                    desk.set_priority(remote, fields)
                except DeskError as exc:
                    if exc.whole_desk or exc.missing:
                        raise
                    notes.append(f"(AgentGov couldn't change its priority: {exc})")
        if notes:
            desk.note(remote, "\n".join(notes), link)

    # -- tests --------------------------------------------------------------------------
    def test(self, ref: str, *, actor: str) -> dict[str, Any]:
        """Sign in to a desk and look at where its tickets go, now; changes nothing there.
        The outcome is in the ledger."""
        error = message = None
        with self.db.transaction() as tx:
            row = destinations.get(tx, ref)
            name = row.name
            try:
                desk: Desk | None = self._client(row)
            except SecretError as exc:
                desk, error = None, str(exc)
        if desk is not None:
            try:
                message = desk.test()
            except DeskError as exc:
                error = str(exc)
        with self.db.transaction() as tx:
            ledger.append(
                tx,
                type="destination.tested",
                actor=actor,
                resource=f"destination/{name}",
                severity="warning" if error else "info",
                reason=error,
                details={"ok": error is None},
            )
        return {"ok": error is None, "error": error, "message": message}


def _ticket(ticket_id: str) -> Ticket | None:
    return Ticket.objects.filter(pk=ticket_id).first()

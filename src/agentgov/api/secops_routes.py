"""Security operations: what AgentGov hands to the security team's tools, and where."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from sqlalchemy import select

from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.api.versions import if_match
from agentgov.models import LedgerEntry
from agentgov.registry import destinations, tickets
from agentgov.registry.errors import Conflict, NotFound, ValidationError
from agentgov.secops import handoff
from agentgov.secops.delivery import siem_events

router = APIRouter(prefix="/v1", tags=["secops"])
read = require(*READ_ROLES)
admin = require("admin")
MAX_EVENTS = 1000


def _rt(request: Request) -> Any:
    return request.app.state.rt


@router.get("/secops")
def secops_status(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """The hand-off level, what it lets the secops role do, and the destinations' state."""
    rt = _rt(request)
    with rt.db.session() as s:
        last = destinations.head(s)
        counts = tickets.counts(s)
        return {
            **handoff.describe(s),
            "ledger_head": last,
            "destinations": [
                destinations.to_dict(d, rt.settings, last, counts.get(d.id))
                for d in destinations.list_all(s)
            ],
            "events_api": "/v1/secops/events",
        }


@router.get("/secops/events")
def secops_events(
    request: Request,
    after: int = 0,
    limit: int = 200,
    events: str | None = None,
    min_severity: str = "info",
    _: Principal = Depends(read),
) -> dict[str, Any]:
    """The ledger as OCSF events, for SIEMs that collect rather than receive: from after
    ledger entry ``after``; ``next`` is where to go on from. ``events`` (comma-separated)
    chooses decisions, approvals, findings, access and changes; all by default."""
    if after < 0:
        raise ValidationError("after is a ledger entry's sequence number (0: from the start)")
    limit = max(1, min(limit, MAX_EVENTS))
    chosen = [e.strip() for e in (events or "").split(",") if e.strip()]
    unknown = [e for e in chosen if e not in destinations.SIEM_EVENTS]
    if unknown:
        raise ValidationError(f"events takes {', '.join(destinations.SIEM_EVENTS)}")
    if min_severity not in destinations.SEVERITIES:
        raise ValidationError(f"min_severity takes {', '.join(destinations.SEVERITIES)}")
    with _rt(request).db.session() as s:
        if not handoff.at_least(s, handoff.INFORM):
            raise Conflict(
                "the hand-off to security operations is off: an administrator turns it on "
                f"(the {handoff.FEATURE} feature, inform or above)"
            )
        entries = s.scalars(
            select(LedgerEntry)
            .where(LedgerEntry.seq > after)
            .order_by(LedgerEntry.seq)
            .limit(limit)
        ).all()
        last = entries[-1].seq if entries else after
        return {
            "events": siem_events(
                s, list(entries), chosen or list(destinations.SIEM_EVENTS), min_severity
            ),
            "next": last,
            "more": destinations.head(s) > last,
        }


# ---------------------------------------------------------------- destinations


@router.get("/tickets")
def list_tickets(
    request: Request,
    desk: str | None = None,
    status: str | None = None,
    _: Principal = Depends(read),
) -> list[dict[str, Any]]:
    """Issues' tickets in the service desks, newest first (docs/tickets.md): ``desk`` and
    ``status`` (pending, open, closed, failed) narrow them."""
    if status and status not in tickets.STATUSES:
        raise ValidationError(f"status is one of {', '.join(tickets.STATUSES)}")
    with _rt(request).db.session() as s:
        return tickets.listing(s, desk=desk, status=status)


@router.get("/destinations")
def list_destinations(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    rt = _rt(request)
    with rt.db.session() as s:
        last = destinations.head(s)
        counts = tickets.counts(s)
        return [
            destinations.to_dict(d, rt.settings, last, counts.get(d.id))
            for d in destinations.list_all(s)
        ]


@router.post("/destinations", status_code=201)
def create_destination(
    request: Request, body: dict[str, Any] = Body(...), principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Send a SIEM the ledger, a chat alerts, or a service desk issues as tickets. Its
    credential goes in its secret file."""
    rt = _rt(request)
    with rt.db.session() as s:
        destination = destinations.create(s, body, actor=principal.actor)
        return destinations.to_dict(destination, rt.settings, destinations.head(s))


@router.get("/destinations/{ref}")
def get_destination(request: Request, ref: str, _: Principal = Depends(read)) -> dict[str, Any]:
    rt = _rt(request)
    with rt.db.session() as s:
        destination = destinations.get(s, ref)
        counts = tickets.counts(s).get(destination.id)
        return destinations.to_dict(destination, rt.settings, destinations.head(s), counts)


@router.patch("/destinations/{ref}")
def update_destination(
    request: Request,
    ref: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    rt = _rt(request)
    with rt.db.session() as s:
        destination = destinations.get(s, ref)
        destinations.update(s, destination, body, actor=principal.actor, version=if_match(request))
        return destinations.to_dict(destination, rt.settings, destinations.head(s))


@router.post("/destinations/{ref}/{action}")
def destination_action(
    request: Request,
    ref: str,
    action: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(admin),
) -> dict[str, Any]:
    """``pause`` and ``resume`` (it keeps its place in the ledger meanwhile); ``replay``
    sends a SIEM the ledger again from after entry ``after`` (0: the start); ``test``
    sends a test event or message now, whatever the hand-off level, or signs in to a
    service desk and looks at where its tickets go (changing nothing there)."""
    rt = _rt(request)
    if action == "test":
        with rt.db.session() as s:
            desk = destinations.get(s, ref).kind in destinations.DESK
        if desk:
            return rt.ticketing.test(ref, actor=principal.actor)
        return rt.delivery.test(ref, actor=principal.actor)
    if action not in ("pause", "resume", "replay"):
        raise NotFound(f"no action {action!r}: pause, resume, replay or test")
    with rt.db.session() as s:
        destination = destinations.get(s, ref)
        if action == "replay":
            destinations.replay(s, destination, body.get("after", 0), actor=principal.actor)
        else:
            destinations.set_status(s, destination, action, actor=principal.actor)
        return destinations.to_dict(destination, rt.settings, destinations.head(s))


@router.delete("/destinations/{ref}", status_code=204)
def delete_destination(request: Request, ref: str, principal: Principal = Depends(admin)) -> None:
    with _rt(request).db.session() as s:
        destinations.delete(s, destinations.get(s, ref), actor=principal.actor)

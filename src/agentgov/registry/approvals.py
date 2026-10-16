"""Human-in-the-loop approvals for individual tool calls.

When policy returns ``require_approval``, the governance processor asks the
control plane to check for an approval matching (agent, action, resource,
arguments, and the person the agent acts for). An approved request is
single-use: it is consumed by the retried call it authorises.

AgentGov's approvers decide requests, unless the agent acted for a person and its
blueprint sends such requests to that person (``approvals_by: person``, while the
``approvals-by-person`` feature is on). Administrators can always decide.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from agentgov import db, ids, ledger
from agentgov.db import lock
from agentgov.db.models import ApprovalRequest
from agentgov.identity import people
from agentgov.models import Agent
from agentgov.registry import features, risk
from agentgov.registry.errors import InvalidTransition, NotFound

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"
USED = "used"
CANCELLED = "cancelled"
# Who decides a request.
APPROVERS = "approvers"
PERSON = "person"


def arguments_hash(arguments: Any) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _expire_stale() -> None:
    ApprovalRequest.objects.filter(
        status__in=(PENDING, APPROVED), expires_at__lt=ids.utcnow()
    ).update(status=EXPIRED)


def deciders_for(tx: db.Where, agent: Agent, person: dict[str, Any] | None) -> str:
    """Who decides a request the agent makes, for the person or on its own."""
    if (
        person
        and agent.blueprint is not None
        and agent.blueprint.approvals_by == PERSON
        and features.is_on(tx, "approvals-by-person")
    ):
        return PERSON
    return APPROVERS


def check_or_request(
    tx: db.Where,
    *,
    agent: Agent,
    action: str,
    resource: str,
    arguments: Any,
    reasons: list[str],
    ttl_seconds: int,
    redacted_arguments: Any = None,
    person: dict[str, Any] | None = None,
) -> tuple[str, ApprovalRequest]:
    """Return ``(outcome, request)`` where outcome is one of:

    * ``approved`` - an approval matched and has been consumed
    * ``pending``  - an identical request is already waiting for review
    * ``denied``   - an identical request was denied
    * ``created``  - a new approval request was opened

    A call for a person matches only requests made for that person.
    """
    _expire_stale()
    digest = arguments_hash(arguments)
    person_id = person.get("id") if person else None
    candidates = list(
        ApprovalRequest.objects.filter(
            agent_id=agent.id,
            action=action,
            resource=resource,
            arguments_hash=digest,
            status__in=(PENDING, APPROVED, DENIED),
            on_behalf_of_id=person_id or None,
        )
        .order_by("-requested_at")
        # Two identical calls at once: one of them uses an approval.
        .select_for_update()
    )
    for status in (APPROVED, PENDING, DENIED):
        match = next((r for r in candidates if r.status == status), None)
        if match is None:
            continue
        if status == APPROVED:
            match.status = USED
            match.used_at = ids.utcnow()
            match.save()
            ledger.append(
                tx,
                type="approval.used",
                actor=f"agent:{agent.name}",
                agent=agent,
                action=action,
                resource=resource,
                decision="allow",
                reason=f"approved by {match.decided_by}",
                details={"approval_id": match.id},
                on_behalf_of=match.on_behalf_of,
            )
            return "approved", match
        return status, match

    req = ApprovalRequest(
        id=ids.new_id(ids.APPROVAL),
        agent_id=agent.id,
        agent_name=agent.name,
        action=action,
        resource=resource,
        arguments=redacted_arguments if redacted_arguments is not None else arguments,
        arguments_hash=digest,
        reasons=reasons,
        status=PENDING,
        expires_at=ids.utcnow() + timedelta(seconds=ttl_seconds),
        on_behalf_of=people.name_of(person),
        on_behalf_of_id=person_id,
        deciders=deciders_for(tx, agent, person),
    )
    req.save(force_insert=True)
    ledger.append(
        tx,
        type="approval.requested",
        actor=f"agent:{agent.name}",
        agent=agent,
        action=action,
        resource=resource,
        decision="require_approval",
        reason="; ".join(reasons),
        details={"approval_id": req.id, "deciders": req.deciders},
        on_behalf_of=req.on_behalf_of,
    )
    return "created", req


def get(tx: db.Where, approval_id: str) -> ApprovalRequest:
    req = ApprovalRequest.objects.filter(pk=approval_id).first()
    if req is None:
        raise NotFound(f"approval {approval_id} not found")
    return req


def list_requests(
    tx: db.Where,
    status: str | None = None,
    limit: int = 200,
    agent_ids: set[str] | None = None,
) -> list[ApprovalRequest]:
    """The newest requests; with ``agent_ids``, those agents' only."""
    _expire_stale()
    found = ApprovalRequest.objects.order_by("-requested_at")
    if status:
        found = found.filter(status=status)
    if agent_ids is not None:
        found = found.filter(agent_id__in=agent_ids)
    return list(found[:limit])


def list_for_person(
    tx: db.Where, subject: str | None, status: str | None = None, limit: int = 200
) -> list[ApprovalRequest]:
    """The requests that wait for this person (or did), by their ID."""
    if not subject:
        return []
    _expire_stale()
    found = ApprovalRequest.objects.filter(deciders=PERSON, on_behalf_of_id=subject)
    if status:
        found = found.filter(status=status)
    return list(found.order_by("-requested_at")[:limit])


def may_decide(
    req: ApprovalRequest, roles: frozenset[str], subject: str | None, *, secops: bool = False
) -> bool:
    """Administrators decide any request; the person decides requests sent to them, and
    approvers the others (and the secops role, when the hand-off to security operations
    is at decide: ``secops``)."""
    if "admin" in roles:
        return True
    if req.deciders == PERSON:
        return bool(subject) and subject == req.on_behalf_of_id
    return "approver" in roles or (secops and "secops" in roles)


def decide(
    tx: db.Where, req: ApprovalRequest, *, approve: bool, actor: str, note: str | None = None
) -> ApprovalRequest:
    _expire_stale()
    lock(tx, req)
    if req.status != PENDING:
        raise InvalidTransition(f"approval {req.id} is {req.status}, not pending")
    req.status = APPROVED if approve else DENIED
    req.decided_by = actor
    req.decided_at = ids.utcnow()
    req.decision_note = note
    req.save()
    ledger.append(
        tx,
        type="approval.approved" if approve else "approval.denied",
        actor=actor,
        agent_id=req.agent_id,
        agent_name=req.agent_name,
        action=req.action,
        resource=req.resource,
        decision="allow" if approve else "deny",
        reason=note,
        details={"approval_id": req.id},
        on_behalf_of=req.on_behalf_of,
    )
    if not approve:
        risk.add_signal(tx, req.agent_id, "approval_denied", req.resource)
    return req


def cancel_for_agent(tx: db.Where, agent: Agent, *, actor: str, reason: str) -> int:
    """Withdraw an agent's open requests and unused approvals (it was blocked or deleted)."""
    open_requests = list(
        ApprovalRequest.objects.filter(agent_id=agent.id, status__in=(PENDING, APPROVED))
        .order_by("requested_at")
        .select_for_update()
    )
    for req in open_requests:
        req.status = CANCELLED
        req.decided_by = actor
        req.decided_at = ids.utcnow()
        req.decision_note = reason
        req.save()
        ledger.append(
            tx,
            type="approval.cancelled",
            actor=actor,
            agent=agent,
            action=req.action,
            resource=req.resource,
            reason=reason,
            details={"approval_id": req.id},
            on_behalf_of=req.on_behalf_of,
        )
    return len(open_requests)


def to_dict(req: ApprovalRequest) -> dict[str, Any]:
    return {
        "id": req.id,
        "agent_id": req.agent_id,
        "agent_name": req.agent_name,
        "action": req.action,
        "resource": req.resource,
        "arguments": req.arguments,
        "reasons": req.reasons or [],
        "status": req.status,
        "requested_at": ids.isoformat(req.requested_at),
        "expires_at": ids.isoformat(req.expires_at),
        "decided_by": req.decided_by,
        "decided_at": ids.isoformat(req.decided_at),
        "decision_note": req.decision_note,
        "used_at": ids.isoformat(req.used_at),
        "on_behalf_of": req.on_behalf_of,
        "deciders": req.deciders,
    }

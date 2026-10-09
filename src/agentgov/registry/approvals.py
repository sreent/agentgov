"""Human-in-the-loop approvals for individual tool calls.

When policy returns ``require_approval``, the governance processor asks the
control plane to check for an approval matching (agent, action, resource,
arguments). An approved request is single-use: it is consumed by the retried
call it authorises.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.models import Agent, ApprovalRequest
from agentgov.registry import risk
from agentgov.registry.errors import InvalidTransition, NotFound

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
EXPIRED = "expired"
USED = "used"
CANCELLED = "cancelled"


def arguments_hash(arguments: Any) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _expire_stale(session: Session) -> None:
    now = ids.utcnow()
    for req in session.scalars(
        select(ApprovalRequest).where(
            ApprovalRequest.status.in_((PENDING, APPROVED)), ApprovalRequest.expires_at < now
        )
    ):
        req.status = EXPIRED


def check_or_request(
    session: Session,
    *,
    agent: Agent,
    action: str,
    resource: str,
    arguments: Any,
    reasons: list[str],
    ttl_seconds: int,
    redacted_arguments: Any = None,
) -> tuple[str, ApprovalRequest]:
    """Return ``(outcome, request)`` where outcome is one of:

    * ``approved`` - an approval matched and has been consumed
    * ``pending``  - an identical request is already waiting for review
    * ``denied``   - an identical request was denied
    * ``created``  - a new approval request was opened
    """
    _expire_stale(session)
    digest = arguments_hash(arguments)
    candidates = session.scalars(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.agent_id == agent.id,
            ApprovalRequest.action == action,
            ApprovalRequest.resource == resource,
            ApprovalRequest.arguments_hash == digest,
            ApprovalRequest.status.in_((PENDING, APPROVED, DENIED)),
        )
        .order_by(ApprovalRequest.requested_at.desc())
    ).all()
    for status in (APPROVED, PENDING, DENIED):
        match = next((r for r in candidates if r.status == status), None)
        if match is None:
            continue
        if status == APPROVED:
            match.status = USED
            match.used_at = ids.utcnow()
            ledger.append(
                session,
                type="approval.used",
                actor=f"agent:{agent.name}",
                agent=agent,
                action=action,
                resource=resource,
                decision="allow",
                reason=f"approved by {match.decided_by}",
                details={"approval_id": match.id},
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
    )
    session.add(req)
    session.flush()
    ledger.append(
        session,
        type="approval.requested",
        actor=f"agent:{agent.name}",
        agent=agent,
        action=action,
        resource=resource,
        decision="require_approval",
        reason="; ".join(reasons),
        details={"approval_id": req.id},
    )
    return "created", req


def get(session: Session, approval_id: str) -> ApprovalRequest:
    req = session.get(ApprovalRequest, approval_id)
    if req is None:
        raise NotFound(f"approval {approval_id} not found")
    return req


def list_requests(
    session: Session, status: str | None = None, limit: int = 200
) -> list[ApprovalRequest]:
    _expire_stale(session)
    stmt = select(ApprovalRequest).order_by(ApprovalRequest.requested_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(ApprovalRequest.status == status)
    return list(session.scalars(stmt))


def decide(
    session: Session, req: ApprovalRequest, *, approve: bool, actor: str, note: str | None = None
) -> ApprovalRequest:
    _expire_stale(session)
    if req.status != PENDING:
        raise InvalidTransition(f"approval {req.id} is {req.status}, not pending")
    req.status = APPROVED if approve else DENIED
    req.decided_by = actor
    req.decided_at = ids.utcnow()
    req.decision_note = note
    ledger.append(
        session,
        type="approval.approved" if approve else "approval.denied",
        actor=actor,
        agent_id=req.agent_id,
        agent_name=req.agent_name,
        action=req.action,
        resource=req.resource,
        decision="allow" if approve else "deny",
        reason=note,
        details={"approval_id": req.id},
    )
    if not approve:
        risk.add_signal(session, req.agent_id, "approval_denied", req.resource)
    return req


def cancel_for_agent(session: Session, agent: Agent, *, actor: str, reason: str) -> int:
    """Withdraw an agent's open requests and unused approvals (it was blocked or deleted)."""
    open_requests = session.scalars(
        select(ApprovalRequest).where(
            ApprovalRequest.agent_id == agent.id,
            ApprovalRequest.status.in_((PENDING, APPROVED)),
        )
    ).all()
    for req in open_requests:
        req.status = CANCELLED
        req.decided_by = actor
        req.decided_at = ids.utcnow()
        req.decision_note = reason
        ledger.append(
            session,
            type="approval.cancelled",
            actor=actor,
            agent=agent,
            action=req.action,
            resource=req.resource,
            reason=reason,
            details={"approval_id": req.id},
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
    }

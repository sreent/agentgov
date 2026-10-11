"""Governance endpoints: approvals, findings, posture, ledger, overview, map, manifests."""

from __future__ import annotations

import fnmatch
import json
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import anyio.to_thread
import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import func, select

from agentgov import ids, ledger
from agentgov.api.auth import READ_ROLES, Principal, require, signed_in
from agentgov.models import (
    DELETED,
    DISCOVERED,
    Agent,
    AgentActivity,
    ApprovalRequest,
    Finding,
    LedgerEntry,
    ToolServer,
)
from agentgov.registry import agents, approvals, discovery, findings, issues, manifests
from agentgov.registry.errors import ValidationError
from agentgov.secops import handoff

router = APIRouter(prefix="/v1")
read = require(*READ_ROLES)
admin = require("admin")


def _rt(request: Request) -> Any:
    return request.app.state.rt


# -------------------------------------------------------------------- approvals


@router.get("/approvals", tags=["approvals"])
def list_approvals(
    request: Request, status: str | None = None, _: Principal = Depends(read)
) -> list[dict[str, Any]]:
    with _rt(request).db.session() as s:
        return [approvals.to_dict(r) for r in approvals.list_requests(s, status=status)]


@router.get("/me/approvals", tags=["approvals"])
def my_approvals(
    request: Request, status: str | None = None, principal: Principal = Depends(signed_in)
) -> list[dict[str, Any]]:
    """The approval requests sent to the person signed in: those an agent made while it
    acted for them, where its blueprint sends them to the person."""
    with _rt(request).db.session() as s:
        rows = approvals.list_for_person(s, principal.subject, status=status)
        return [approvals.to_dict(r) for r in rows]


@router.get("/approvals/{approval_id}", tags=["approvals"])
def get_approval(
    request: Request, approval_id: str, principal: Principal = Depends(signed_in)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        req = approvals.get(s, approval_id)
        # Everyone who reads AgentGov, and the person it was sent to.
        if not principal.roles & set(READ_ROLES) and not approvals.may_decide(
            req, principal.roles, principal.subject
        ):
            raise HTTPException(403, f"role {principal.role!r} may not do this")
        return approvals.to_dict(req)


@router.post("/approvals/{approval_id}/{verdict}", tags=["approvals"])
def decide_approval(
    request: Request,
    approval_id: str,
    verdict: str,
    body: dict[str, Any] = Body(default={}),
    principal: Principal = Depends(signed_in),
) -> dict[str, Any]:
    if verdict not in ("approve", "deny"):
        raise HTTPException(404, "verdict must be approve or deny")
    with _rt(request).db.session() as s:
        req = approvals.get(s, approval_id)
        secops = handoff.at_least(s, handoff.DECIDE)
        if not approvals.may_decide(req, principal.roles, principal.subject, secops=secops):
            if req.deciders != approvals.PERSON:
                handoff.check(s, principal, handoff.DECIDE, also=("approver",))
            who = (
                f"{req.on_behalf_of}, whom the agent acted for,"
                if req.deciders == approvals.PERSON
                else "an approver"
            )
            raise HTTPException(403, f"{who} or an administrator decides this request")
        req = approvals.decide(
            s, req, approve=verdict == "approve", actor=principal.actor, note=body.get("note")
        )
        return approvals.to_dict(req)


# --------------------------------------------------------------------- findings


@router.get("/findings", tags=["findings"])
def list_findings(
    request: Request,
    status: str | None = "open",
    severity: str | None = None,
    type: str | None = None,
    agent: str | None = None,
    _: Principal = Depends(read),
) -> list[dict[str, Any]]:
    with _rt(request).db.session() as s:
        stmt = select(Finding).order_by(Finding.last_seen.desc()).limit(500)
        if status and status != "all":
            stmt = stmt.where(Finding.status == status)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if type:
            stmt = stmt.where(Finding.type == type)
        if agent:
            stmt = stmt.where(Finding.agent_id == agents.get(s, agent).id)
        return [findings.to_dict(f) for f in s.scalars(stmt)]


def _triages(session: Any, principal: Principal) -> bool:
    """Approvers and administrators, and the secops role from triage on."""
    return bool(principal.roles & {"admin", "approver"}) or (
        "secops" in principal.roles and handoff.at_least(session, handoff.TRIAGE)
    )


@router.get("/me/issues", tags=["findings"])
def my_issues(
    request: Request, status: str | None = "open", principal: Principal = Depends(signed_in)
) -> list[dict[str, Any]]:
    """The issues that reached the person signed in: about agents they own or sponsor, or
    sent to a team they are in (docs/issues.md)."""
    if status not in (None, "all", *findings.STATUSES):
        raise ValidationError(f"status is {', '.join(findings.STATUSES)} or all")
    with _rt(request).db.session() as s:
        return [findings.to_dict(f) for f in issues.for_person(s, principal.name, status=status)]


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(
    request: Request, finding_id: str, principal: Principal = Depends(signed_in)
) -> dict[str, Any]:
    """A finding, with the people and teams it goes to, the messages sent about it, and
    what happened to it. For everyone who reads AgentGov, and the people it reached."""
    with _rt(request).db.session() as s:
        finding = findings.get(s, finding_id)
        mine = issues.may_act(s, finding, principal.name)
        if not principal.roles & set(READ_ROLES) and not mine:
            raise HTTPException(403, f"role {principal.role!r} may not do this")
        agent = s.get(Agent, finding.agent_id) if finding.agent_id else None
        return {
            **findings.to_dict(finding),
            "agent_name": agent.name if agent else None,
            "chain": issues.describe(s, finding),
            "notifications": issues.notifications(s, finding),
            "history": [ledger.to_dict(e) for e in issues.history(s, finding)],
            "yours": mine,
        }


@router.post("/findings/{finding_id}/acknowledge", tags=["findings"])
def acknowledge_finding(
    request: Request, finding_id: str, principal: Principal = Depends(signed_in)
) -> dict[str, Any]:
    """Take an issue on: it goes no further up its chain. For the people it reached,
    approvers and administrators (and the secops role from triage on)."""
    with _rt(request).db.session() as s:
        finding = findings.get(s, finding_id)
        if not _triages(s, principal) and not issues.may_act(s, finding, principal.name):
            raise HTTPException(
                403, "the people it went to, approvers and administrators acknowledge it"
            )
        return findings.to_dict(issues.acknowledge(s, finding, actor=principal.actor))


@router.post("/findings/{finding_id}/accept", tags=["findings"])
def accept_finding(
    request: Request,
    finding_id: str,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(require("approver", "secops")),
) -> dict[str, Any]:
    """Accept the risk until a date (``until``: a date, a time or a number of days), saying
    why (``reason``): it goes to nobody until then, and opens again then if it still
    holds. The people responsible for an agent don't accept its risks: approvers do."""
    unknown = sorted(set(body) - {"reason", "until"})
    if unknown:
        raise ValidationError(f"unknown field(s) {', '.join(unknown)}: send reason and until")
    with _rt(request).db.session() as s:
        handoff.check(s, principal, handoff.TRIAGE, also=("approver",))
        finding = findings.get(s, finding_id)
        accepted = issues.accept(
            s, finding, reason=body.get("reason"), until=body.get("until"), actor=principal.actor
        )
        return findings.to_dict(accepted)


@router.post("/findings/{finding_id}/{action}", tags=["findings"])
def finding_action(
    request: Request,
    finding_id: str,
    action: str,
    principal: Principal = Depends(require("approver", "secops")),
) -> dict[str, Any]:
    status = {"resolve": "resolved", "dismiss": "dismissed", "reopen": "open"}.get(action)
    if status is None:
        raise HTTPException(404, "action must be resolve, dismiss, reopen, acknowledge or accept")
    with _rt(request).db.session() as s:
        # The security team's tools, as far as the hand-off lets them.
        handoff.check(s, principal, handoff.TRIAGE, also=("approver",))
        return findings.to_dict(findings.set_status(s, finding_id, status, principal.actor))


@router.post("/posture/scan", tags=["findings"])
def posture_scan(request: Request, _: Principal = Depends(admin)) -> dict[str, Any]:
    result = _rt(request).run_posture_scan()
    if result is None:
        raise HTTPException(409, "posture checks are off: turn them on in Features first")
    return result


# ----------------------------------------------------------------------- ledger


@router.get("/ledger", tags=["ledger"])
def list_ledger(
    request: Request,
    type: str | None = None,
    agent: str | None = None,
    user: str | None = None,
    decision: str | None = None,
    before_seq: int | None = None,
    limit: int = 100,
    _: Principal = Depends(read),
) -> list[dict[str, Any]]:
    with _rt(request).db.session() as s:
        stmt = select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(min(max(limit, 1), 500))
        if type:
            stmt = stmt.where(LedgerEntry.type.like(type.replace("*", "%")))
        if agent:
            stmt = stmt.where(LedgerEntry.agent_id == agents.get(s, agent).id)
        if user:
            # The person an agent acted for.
            stmt = stmt.where(LedgerEntry.on_behalf_of == user)
        if decision == "monitored":
            # Calls that went through because a control was in monitor mode.
            stmt = stmt.where(LedgerEntry.reason.like("monitored:%"))
        elif decision:
            stmt = stmt.where(LedgerEntry.decision == decision)
        if before_seq:
            stmt = stmt.where(LedgerEntry.seq < before_seq)
        trace_url = _rt(request).settings.trace_url
        return [ledger.with_trace_link(ledger.to_dict(e), trace_url) for e in s.scalars(stmt)]


@router.get("/ledger/verify", tags=["ledger"])
def verify_ledger(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        return ledger.verify(s)


@router.get("/ledger/export", tags=["ledger"])
def export_ledger(request: Request, _: Principal = Depends(read)) -> StreamingResponse:
    """The full chain as JSON Lines, for SIEM import or offline verification."""
    db = _rt(request).db

    def lines() -> Iterator[bytes]:
        with db.session() as s:
            for entry in ledger.iter_entries(s):
                yield (json.dumps(ledger.to_dict(entry), sort_keys=True) + "\n").encode()

    return StreamingResponse(lines(), media_type="application/x-ndjson")


# --------------------------------------------------------------- overview & map


@router.get("/overview", tags=["overview"])
def overview(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    rt = _rt(request)
    now = ids.utcnow()
    # Built before opening our own session: nested sessions would deadlock on
    # SQLite, where every transaction takes the write lock up front.
    bundle_revision = rt.bundles.current().revision
    with rt.db.session() as s:
        all_agents = s.scalars(select(Agent).where(Agent.status != DELETED)).unique().all()
        by_status = Counter(a.status for a in all_agents)
        risky = sorted(
            (a for a in all_agents if a.risk_level in ("high", "critical")),
            key=lambda a: -a.risk_score,
        )
        servers = s.scalars(select(ToolServer)).all()
        open_findings = s.execute(
            select(Finding.severity, func.count())
            .where(Finding.status == "open")
            .group_by(Finding.severity)
        ).all()
        pending_approvals = s.scalar(
            select(func.count())
            .select_from(ApprovalRequest)
            .where(ApprovalRequest.status == "pending")
        )
        since_day = (now - timedelta(days=13)).strftime("%Y-%m-%d")
        activity_rows = s.execute(
            select(
                AgentActivity.day,
                func.sum(AgentActivity.tool_calls),
                func.sum(AgentActivity.denied),
                func.sum(AgentActivity.model_calls),
            )
            .where(AgentActivity.day >= since_day)
            .group_by(AgentActivity.day)
        ).all()
        by_day = {d: (int(t or 0), int(n or 0), int(m or 0)) for d, t, n, m in activity_rows}
        days = [(now - timedelta(days=13 - i)).strftime("%Y-%m-%d") for i in range(14)]
        decisions = s.execute(
            select(LedgerEntry.decision, func.count())
            .where(
                LedgerEntry.type == "decision.request", LedgerEntry.ts >= now - timedelta(hours=24)
            )
            .group_by(LedgerEntry.decision)
        ).all()
        # Policy decisions only: a held call is also recorded as approval.requested.
        recent = s.scalars(
            select(LedgerEntry)
            .where(
                LedgerEntry.type.like("decision.%"),
                LedgerEntry.decision.in_(("deny", "require_approval")),
            )
            .order_by(LedgerEntry.seq.desc())
            .limit(10)
        ).all()
        head = rt.ledger_integrity.check(s)
        return {
            "agents": {
                "total": len(all_agents),
                "by_status": dict(by_status),
                "without_owner": sum(
                    1 for a in all_agents if not a.owner and a.status != DISCOVERED
                ),
                "unmanaged": by_status.get(DISCOVERED, 0),
                "at_risk": len(risky),
            },
            "toolservers": {
                "total": len(servers),
                "pending": sum(1 for t in servers if t.status == "pending"),
                "blocked": sum(1 for t in servers if t.status == "blocked"),
                "tools": sum(len(t.tools or []) for t in servers),
            },
            "approvals": {"pending": pending_approvals or 0},
            "findings": {
                "open": sum(c for _, c in open_findings),
                "by_severity": dict(open_findings),
            },
            "decisions_24h": {d or "none": c for d, c in decisions},
            "activity": [
                {
                    "day": d,
                    "tool_calls": by_day.get(d, (0, 0, 0))[0],
                    "denied": by_day.get(d, (0, 0, 0))[1],
                    "model_calls": by_day.get(d, (0, 0, 0))[2],
                }
                for d in days
            ],
            "top_risky": [
                {"id": a.id, "name": a.name, "risk_score": a.risk_score, "risk_level": a.risk_level}
                for a in risky[:5]
            ],
            "recent_blocks": [
                ledger.with_trace_link(ledger.to_dict(e), rt.settings.trace_url) for e in recent
            ],
            "ledger": head,
            "opa": {
                "last_status_at": rt.bundles.last_status_at,
                "bundle_revision": bundle_revision,
            },
        }


@router.get("/graph", tags=["overview"])
def agent_map(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """People, agents and tool servers with sponsorship, grants and observed usage; and
    the agents that may call, or did call, other agents."""
    with _rt(request).db.session() as s:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        servers = s.scalars(select(ToolServer).where(ToolServer.gateway.is_(True))).all()
        for ts in servers:
            nodes[f"server:{ts.name}"] = {
                "id": f"server:{ts.name}",
                "kind": "server",
                "label": ts.name,
                "status": ts.status,
                "classification": ts.data_classification,
                "trust": ts.trust_level,
            }
        since = ids.utcnow() - timedelta(days=30)
        usage_rows = s.execute(
            select(LedgerEntry.agent_id, LedgerEntry.resource, LedgerEntry.decision, func.count())
            .where(LedgerEntry.type == "decision.request", LedgerEntry.ts >= since)
            .group_by(LedgerEntry.agent_id, LedgerEntry.resource, LedgerEntry.decision)
        ).all()
        usage: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for agent_id, resource, decision, count in usage_rows:
            if agent_id and resource:
                usage[(agent_id, resource.split("/", 1)[0])][decision or "none"] += count
        # Calls between agents, by caller and the called agent's name.
        a2a_rows = s.execute(
            select(LedgerEntry.agent_id, LedgerEntry.resource, LedgerEntry.decision, func.count())
            .where(LedgerEntry.type == "decision.a2a.request", LedgerEntry.ts >= since)
            .group_by(LedgerEntry.agent_id, LedgerEntry.resource, LedgerEntry.decision)
        ).all()
        a2a_usage: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for agent_id, target, decision, count in a2a_rows:
            if agent_id and target:
                a2a_usage[(agent_id, target)][decision or "none"] += count
        listed = list(s.scalars(select(Agent).where(Agent.status != DELETED)).unique())
        by_name = {a.name: a for a in listed}
        for a in listed:
            nodes[f"agent:{a.id}"] = {
                "id": f"agent:{a.id}",
                "kind": "agent",
                "label": a.name,
                "status": a.status,
                "risk_level": a.risk_level,
                "blueprint": a.blueprint.name if a.blueprint else None,
            }
            people = [("owner", a.owner)] if a.owner else []
            people += [("sponsor", p) for p in a.sponsors or []]
            for relation, person in people:
                pid = f"person:{person}"
                nodes.setdefault(pid, {"id": pid, "kind": "person", "label": person})
                edges.append({"from": pid, "to": f"agent:{a.id}", "kind": relation})
            granted_servers = set()
            for grant in agents.effective_grants(a):
                for ts in servers:
                    if _glob(grant["server"], ts.name):
                        granted_servers.add(ts.name)
            used = {srv for (aid, srv) in usage if aid == a.id}
            for srv in sorted(granted_servers | used):
                counts = usage.get((a.id, srv), Counter())
                edges.append(
                    {
                        "from": f"agent:{a.id}",
                        "to": f"server:{srv}",
                        "kind": "granted" if srv in granted_servers else "ungranted",
                        "calls": sum(counts.values()),
                        "denied": counts.get("deny", 0),
                    }
                )
                nodes.setdefault(
                    f"server:{srv}",
                    {
                        "id": f"server:{srv}",
                        "kind": "server",
                        "label": srv,
                        "status": "unregistered",
                    },
                )
            granted_agents = {b.name for b in listed if agents.may_call(a, b)}
            called = {name for (aid, name) in a2a_usage if aid == a.id and name in by_name}
            for name in sorted(granted_agents | called):
                counts = a2a_usage.get((a.id, name), Counter())
                edges.append(
                    {
                        "from": f"agent:{a.id}",
                        "to": f"agent:{by_name[name].id}",
                        "kind": "calls" if name in granted_agents else "calls-ungranted",
                        "calls": sum(counts.values()),
                        "denied": counts.get("deny", 0),
                    }
                )
        return {"nodes": list(nodes.values()), "edges": edges}


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value, pattern)


# --------------------------------------------------------------- what-if & GitOps


@router.post("/policies/evaluate", tags=["policies"])
def evaluate_policy(
    request: Request, body: dict[str, Any] = Body(...), _: Principal = Depends(read)
) -> dict[str, Any]:
    """What-if: evaluate a hypothetical MCP call against the live policies in OPA."""
    rt = _rt(request)
    if not rt.settings.opa_url:
        raise HTTPException(409, "OPA is not configured (AGENTGOV_OPA_URL)")
    path = body.get("path", "agentgov/mcp/decision")
    if not isinstance(path, str) or not path.replace("/", "").replace("_", "").isalnum():
        raise ValidationError("path must look like agentgov/mcp/decision")
    try:
        resp = httpx.post(
            f"{rt.settings.opa_url.rstrip('/')}/v1/data/{path}",
            json={"input": body.get("input", {})},
            timeout=5,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"OPA unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise HTTPException(502, f"OPA returned {resp.status_code}: {resp.text[:200]}")
    return {"path": path, "result": resp.json().get("result")}


@router.post("/apply", tags=["manifests"])
async def apply_manifests(
    request: Request, principal: Principal = Depends(admin)
) -> dict[str, Any]:
    """Apply YAML (or JSON ``{"documents": [...]}``) manifests idempotently."""
    rt = _rt(request)
    raw = (await request.body()).decode()
    if request.headers.get("content-type", "").startswith("application/json"):
        payload = json.loads(raw or "{}")
        docs = payload.get("documents", payload if isinstance(payload, list) else [])
        for i, doc in enumerate(docs):
            manifests.validate(doc, i)
    else:
        docs = manifests.parse(raw)

    def run() -> list[dict[str, str]]:
        with rt.db.session() as s:
            return manifests.apply(s, rt.settings, docs, actor=principal.actor)

    return {"results": await anyio.to_thread.run_sync(run)}


@router.get("/export", tags=["manifests"])
def export_manifests(request: Request, _: Principal = Depends(read)) -> PlainTextResponse:
    with _rt(request).db.session() as s:
        return PlainTextResponse(manifests.dump(manifests.export(s)), media_type="application/yaml")


@router.post("/discovery/import", tags=["discovery"])
def import_discovery(
    request: Request,
    body: dict[str, Any] = Body(...),
    principal: Principal = Depends(require("registrar", "service")),
) -> dict[str, Any]:
    """Import scanner output, e.g. the Agent Governance Toolkit's agent-discovery JSON."""
    items = body.get("items") or body.get("agents") or []
    if not isinstance(items, list):
        raise ValidationError("items must be a list")
    with _rt(request).db.session() as s:
        return discovery.import_scan(s, items, source=str(body.get("source") or "scanner"))

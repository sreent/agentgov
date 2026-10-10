"""Turns enforcement outcomes into evidence, activity, risk signals and findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import Agent
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, findings, risk


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return ids.utcnow()


def record_mcp_decisions(
    session: Session, settings: Settings, records: list[dict[str, Any]]
) -> int:
    """Store decision records sent by the governance processor."""
    touched: dict[str, Agent] = {}
    for rec in records:
        agent_info = rec.get("agent") or {}
        agent = session.get(Agent, agent_info.get("id")) if agent_info.get("id") else None
        identity = rec.get("identity") or {}
        phase = rec.get("phase", "request")
        effect = rec.get("effect")
        detections = rec.get("detections") or {}
        categories = set(detections.get("categories") or [])
        when = _parse_ts(rec.get("ts"))
        resource = rec.get("resource")
        actor = (
            f"agent:{agent.name}" if agent else f"client:{identity.get('client_id') or 'unknown'}"
        )
        ledger.append(
            session,
            type=f"decision.{phase}",
            actor=actor,
            agent=agent,
            agent_name=None if agent else identity.get("client_id"),
            severity="warning" if effect in ("deny", "require_approval") else "info",
            action=rec.get("method"),
            resource=resource,
            decision=effect,
            reason="; ".join(rec.get("reasons") or []) or None,
            details={
                "redacted": rec.get("redacted") or [],
                "detections": {
                    k: detections.get(k)
                    for k in (
                        "categories",
                        "entities",
                        "prompt_injection",
                        "injection_score",
                        "injection_reasons",
                        "truncated",
                    )
                    if k in detections
                },
                "approval_id": rec.get("approval_id"),
                "opa_decision_id": rec.get("opa_decision_id"),
                "latency_ms": rec.get("latency_ms"),
                "identity": identity,
            },
            ts=when,
        )
        if agent is None:
            continue
        agent.last_seen_at = when
        touched[agent.id] = agent
        if phase == "request":
            discovery.record_activity(
                session, agent.id, when=when, tool_calls=1, denied=1 if effect == "deny" else 0
            )
            if effect == "deny":
                risk.add_signal(session, agent.id, "policy_denied", resource)
            if "secret" in categories:
                risk.add_signal(session, agent.id, "secret_detected", resource)
                findings.raise_finding(
                    session,
                    type="agent.credential_exfiltration_attempt",
                    severity="high",
                    subject=agent.id,
                    agent_id=agent.id,
                    category=findings.THREAT,
                    title=f"{agent.name} tried to send credentials to a tool",
                    description=f"Credentials ({', '.join(detections.get('entities') or [])}) were "
                    f"found in arguments for {resource}; the call was blocked.",
                    remediation="Check the agent's prompt and context sources for leaked secrets "
                    "and rotate them.",
                )
        elif detections.get("prompt_injection"):
            risk.add_signal(session, agent.id, "prompt_injection", resource)
            findings.raise_finding(
                session,
                type="toolserver.prompt_injection",
                severity="high",
                subject=str(resource),
                category=findings.THREAT,
                title=f"Prompt-injection payload returned by {resource}",
                description="A tool result contained instructions aimed at the agent ("
                + ", ".join(detections.get("injection_reasons") or [])
                + "). It was withheld.",
                remediation="Find where the tool's data came from; untrusted content may be "
                "targeting your agents.",
            )
    for agent in touched.values():
        agents_svc.refresh_risk(session, settings, agent)
    return len(records)


def record_opa_decisions(session: Session, events: list[dict[str, Any]]) -> int:
    """Store OPA decision-log events (in-process enforcement via the toolkit)."""
    stored = 0
    for event in events:
        inp = event.get("input") or {}
        result = event.get("result")
        agent = discovery.find(session, name=inp.get("agent_id")) if inp.get("agent_id") else None
        allowed = result is True or (isinstance(result, dict) and result.get("allow") is True)
        ledger.append(
            session,
            type="decision.inprocess",
            actor="service:opa",
            agent=agent,
            agent_name=None if agent else inp.get("agent_id"),
            severity="info" if allowed else "warning",
            action=inp.get("action_type") or event.get("path"),
            resource=inp.get("tool_name"),
            decision="allow" if allowed else "deny",
            details={
                "path": event.get("path"),
                "opa_decision_id": event.get("decision_id"),
                "bundles": event.get("bundles"),
                "masked": event.get("masked"),
            },
            ts=_parse_ts(event.get("timestamp")),
        )
        if agent is not None:
            discovery.record_activity(session, agent.id, tool_calls=1, denied=0 if allowed else 1)
            if not allowed:
                risk.add_signal(session, agent.id, "policy_denied", inp.get("tool_name"))
        stored += 1
    return stored

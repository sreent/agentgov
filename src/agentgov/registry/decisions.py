"""Turns enforcement outcomes into evidence, activity, risk signals and findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.identity import people
from agentgov.models import Agent
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, findings, risk


def _trace_id(value: Any) -> str | None:
    """A W3C trace ID (32 lowercase hex digits), or None."""
    if isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value):
        return value
    return None


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
    """Store decision records sent by the governance processor: on tool calls, and on
    model calls (``kind: "model"``), whose activity the gateway's access logs count."""
    touched: dict[str, Agent] = {}
    for rec in records:
        model_call = rec.get("kind") == "model"
        agent_info = rec.get("agent") or {}
        agent = session.get(Agent, agent_info.get("id")) if agent_info.get("id") else None
        identity = rec.get("identity") or {}
        # The person the agent acted for, if it acted for one.
        user = rec["user"] if isinstance(rec.get("user"), dict) else None
        phase = rec.get("phase", "request")
        effect = rec.get("effect")
        detections = rec.get("detections") or {}
        categories = set(detections.get("categories") or [])
        when = _parse_ts(rec.get("ts"))
        resource = rec.get("resource")
        # What controls in monitor mode would have done (the call went through).
        monitored = [str(m) for m in rec.get("monitored") or []]
        actor = (
            f"agent:{agent.name}" if agent else f"client:{identity.get('client_id') or 'unknown'}"
        )
        reason = "; ".join(rec.get("reasons") or []) or None
        if reason is None and monitored:
            reason = "monitored: " + "; ".join(monitored)
        ledger.append(
            session,
            type=f"decision.model.{phase}" if model_call else f"decision.{phase}",
            actor=actor,
            agent=agent,
            agent_name=None if agent else identity.get("client_id"),
            severity="warning" if effect in ("deny", "require_approval") or monitored else "info",
            action=rec.get("method"),
            resource=resource,
            decision=effect,
            reason=reason,
            details={
                "redacted": rec.get("redacted") or [],
                "monitored": monitored,
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
                **({"user": user} if user else {}),
            },
            trace_id=_trace_id(rec.get("trace_id")),
            on_behalf_of=people.name_of(user),
            ts=when,
        )
        if agent is None:
            continue
        agent.last_seen_at = when
        touched[agent.id] = agent
        if model_call:
            _model_signals(session, agent, phase, effect, detections, resource, user)
        elif phase == "request":
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
                    f"found in arguments for {resource}; "
                    + (
                        "the call was blocked."
                        if effect == "deny"
                        else "the call went through: data protection is not enforced."
                    ),
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
                + (
                    "). It was withheld."
                    if effect == "deny"
                    else "). It reached the agent: prompt-injection defence is not enforced."
                ),
                remediation="Find where the tool's data came from; untrusted content may be "
                "targeting your agents.",
            )
    for agent in touched.values():
        agents_svc.refresh_risk(session, settings, agent)
    return len(records)


def _model_signals(
    session: Session,
    agent: Agent,
    phase: str,
    effect: str | None,
    detections: dict[str, Any],
    resource: Any,
    user: dict[str, Any] | None = None,
) -> None:
    """Risk signals and findings from a decision on a prompt or an answer."""
    categories = set(detections.get("categories") or [])
    if phase == "request" and effect == "deny":
        risk.add_signal(session, agent.id, "policy_denied", resource)
    if phase == "request" and "secret" in categories:
        risk.add_signal(session, agent.id, "secret_detected", resource)
        findings.raise_finding(
            session,
            type="agent.credential_exfiltration_attempt",
            severity="high",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"{agent.name} tried to send credentials to a model provider",
            description=f"Credentials ({', '.join(detections.get('entities') or [])}) were found "
            f"in a prompt for {resource}; "
            + (
                "it was not sent."
                if effect == "deny"
                else "it was sent: data protection is not enforced."
            ),
            remediation="Check the agent's prompt and context sources for leaked secrets and "
            "rotate them.",
        )
    if phase == "request" and detections.get("prompt_injection"):
        risk.add_signal(session, agent.id, "prompt_injection", resource)
        findings.raise_finding(
            session,
            type="agent.prompt_injection",
            severity="high",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"A tool result tried to give {agent.name} instructions",
            description="A tool result in one of its conversations contained instructions "
            "aimed at the agent ("
            + ", ".join(detections.get("injection_reasons") or [])
            + (
                "). The model call was refused."
                if effect == "deny"
                else "). The model call went through: prompt-injection defence is not enforced."
            ),
            remediation="Find which of the agent's tools returned it: untrusted content may be "
            "targeting your agents. Tools called through the MCP gateway are checked as they "
            "answer.",
        )
    if phase == "request" and detections.get("jailbreak"):
        risk.add_signal(session, agent.id, "jailbreak_attempt", resource)
        findings.raise_finding(
            session,
            type="agent.jailbreak_attempts",
            severity="medium",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"People tried to jailbreak {agent.name}",
            description=f"A prompt {agent.name} sent to {resource}"
            + (f" on behalf of {people.name_of(user)}" if user else "")
            + " tried to set aside the model's instructions or safety rules ("
            + ", ".join(detections.get("jailbreak_reasons") or [])
            + (
                "). The model call was refused."
                if effect == "deny"
                else "). The model call went through: jailbreak detection is not enforced."
            ),
            remediation=(
                f"Ask {people.name_of(user)} about it"
                if user
                else "Find who sent it in the agent's conversations"
            )
            + ", and check that the agent's instructions hold up against such prompts.",
        )


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

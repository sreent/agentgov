"""Turns enforcement outcomes into evidence, activity, risk signals and findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.identity import people
from agentgov.models import Agent
from agentgov.opa import WHAT_IF
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
        kind = rec.get("kind")
        if kind == "classifier":
            touched |= {a.id: a for a in _classified(session, rec)}
            continue
        model_call = kind == "model"
        a2a = kind == "a2a"
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
        # Why the call couldn't be checked, when it went through unchecked
        # (AGENTGOV_GATEWAY_FAILURE_MODE).
        unchecked = str(rec["unchecked"])[:500] if rec.get("unchecked") else None
        actor = (
            f"agent:{agent.name}" if agent else f"client:{identity.get('client_id') or 'unknown'}"
        )
        reason = "; ".join(rec.get("reasons") or []) or None
        if reason is None and monitored:
            reason = "monitored: " + "; ".join(monitored)
        delegation = rec["delegation"] if isinstance(rec.get("delegation"), dict) else None
        ledger.append(
            session,
            type=f"decision.{kind}.{phase}" if model_call or a2a else f"decision.{phase}",
            actor=actor,
            agent=agent,
            agent_name=None if agent else identity.get("client_id"),
            severity="warning"
            if effect in ("deny", "require_approval") or monitored or unchecked
            else "info",
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
                        "jailbreak",
                        "jailbreak_reasons",
                        "classifier",
                        "truncated",
                    )
                    if k in detections
                },
                **({"unchecked": unchecked} if unchecked else {}),
                "approval_id": rec.get("approval_id"),
                "opa_decision_id": rec.get("opa_decision_id"),
                "latency_ms": rec.get("latency_ms"),
                "identity": identity,
                **({"user": user} if user else {}),
                # A call between agents: whom it called.
                **({"a2a": rec["a2a"]} if a2a and isinstance(rec.get("a2a"), dict) else {}),
                # Work another agent handed down: the chain, from its head to this call.
                **(_chain(delegation, agent, identity, rec) if delegation else {}),
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
        elif a2a and phase == "response":
            answered = _answer_signals(session, agent, rec, effect, detections, resource)
            if answered is not None:
                touched[answered.id] = answered
        elif a2a:
            discovery.record_activity(
                session, agent.id, when=when, tool_calls=0, denied=1 if effect == "deny" else 0
            )
            if effect == "deny":
                risk.add_signal(session, agent.id, "policy_denied", resource)
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


def _chain(
    delegation: dict[str, Any], agent: Agent | None, identity: dict[str, Any], rec: dict[str, Any]
) -> dict[str, Any]:
    """The delegation a call was made under (or, between agents, the one it gave), and the
    whole chain: who handed the work down, the agent calling, and the agent it called."""
    caller = {
        "type": "agent",
        "id": agent.id if agent else str(identity.get("client_id") or ""),
        "name": agent.name if agent else str(identity.get("client_id") or "unknown"),
    }
    links = [x for x in delegation.get("chain") or [] if isinstance(x, dict)] + [caller]
    if rec.get("kind") == "a2a":
        target = rec.get("a2a") or {}
        links.append(
            {
                "type": "agent",
                "id": str(target.get("target_id") or ""),
                "name": str(rec.get("target")),
            }
        )
    out: dict[str, Any] = {"chain": links}
    ids_ = {k: delegation.get(k) for k in ("uid", "parent_uid") if delegation.get(k)}
    if ids_:
        out["delegation"] = ids_
    return out


def _answered_by(session: Session, rec: dict[str, Any]) -> Agent | None:
    """The agent that sent an answer (a decision on an answer names it under "a2a")."""
    target = rec.get("a2a") if isinstance(rec.get("a2a"), dict) else {}
    target_id = target.get("target_id")
    return session.get(Agent, target_id) if target_id else None


def _injected_answer(
    session: Session, called: Agent, caller: Agent, resource: Any, how: str
) -> None:
    risk.add_signal(session, called.id, "prompt_injection", resource)
    findings.raise_finding(
        session,
        type="agent.prompt_injection_in_answers",
        severity="high",
        subject=called.id,
        agent_id=called.id,
        category=findings.THREAT,
        title=f"Answers from {called.name} carry instructions for the agents that read them",
        description=f"An answer {called.name} sent {caller.name} contained instructions aimed "
        f"at the agent reading it. {how}",
        remediation=f"Find what {called.name} read that carried them: untrusted content can "
        "pass from agent to agent.",
    )


def _answer_signals(
    session: Session,
    caller: Agent,
    rec: dict[str, Any],
    effect: str | None,
    detections: dict[str, Any],
    resource: Any,
) -> Agent | None:
    """Risk signals and findings from a decision on an answer one agent sent another:
    about the agent that answered, which it returns."""
    called = _answered_by(session, rec)
    if called is None:
        return None
    if detections.get("prompt_injection"):
        reasons = ", ".join(detections.get("injection_reasons") or [])
        outcome = (
            "It was withheld."
            if effect == "deny"
            else f"It reached {caller.name}: prompt-injection defence is not enforced."
        )
        _injected_answer(session, called, caller, resource, f"({reasons}) {outcome}")
    if "secret" in set(detections.get("categories") or []):
        risk.add_signal(session, called.id, "secret_detected", resource)
        masked = "secret" in (rec.get("redacted") or [])
        findings.raise_finding(
            session,
            type="agent.credentials_in_answers",
            severity="high",
            subject=called.id,
            agent_id=called.id,
            category=findings.THREAT,
            title=f"{called.name} sent credentials to another agent",
            description=f"Credentials ({', '.join(detections.get('entities') or [])}) were "
            f"found in an answer {called.name} sent {caller.name}; "
            + (
                "they were masked."
                if masked or effect == "deny"
                else "they reached it: data protection is not enforced."
            ),
            remediation=f"Find where {called.name} got them, and rotate them.",
        )
    return called


# What the classifier finds, by its criterion (agentgov.processor.classifier).
_FOUND = {"injection": "instructions aimed at the agent", "jailbreak": "a jailbreak attempt"}


def _classified(session: Session, rec: dict[str, Any]) -> list[Agent]:
    """A verdict the classifier gave in the background, after the call went on: the
    ledger has it, and what it flagged is a risk signal and a finding, as what the rules
    flag is. The agents whose risk it changed."""
    agent_info = rec.get("agent") or {}
    agent = session.get(Agent, agent_info.get("id")) if agent_info.get("id") else None
    identity = rec.get("identity") or {}
    user = rec["user"] if isinstance(rec.get("user"), dict) else None
    verdict = rec.get("classifier") if isinstance(rec.get("classifier"), dict) else {}
    criterion = str(verdict.get("criterion") or "injection")
    subject = str(rec.get("subject") or "tool result")
    resource = rec.get("resource")
    found = _FOUND.get(criterion, criterion)
    caller = identity.get("client_id") or "unknown"
    ledger.append(
        session,
        type="detection.classifier",
        actor=f"agent:{agent.name}" if agent else f"client:{caller}",
        agent=agent,
        agent_name=None if agent else identity.get("client_id"),
        severity="warning",
        action=subject,
        resource=resource,
        reason=f"The classifier found {found} in {'an' if subject[0] in 'aeiou' else 'a'} "
        f"{subject}, after it went on",
        details={
            "type": f"classifier.{criterion}",
            "severity": "medium" if criterion == "jailbreak" else "high",
            "classifier": verdict,
            "phase": rec.get("phase"),
            "identity": identity,
            **({"user": user} if user else {}),
        },
        trace_id=_trace_id(rec.get("trace_id")),
        on_behalf_of=people.name_of(user),
        ts=_parse_ts(rec.get("ts")),
    )
    if agent is None:
        return []
    after = (
        "It answered in the background, after the call went on: it is monitored, or the "
        "check it supports is."
    )
    if subject == "answer":
        # Another agent's answer: the agent that answered carries it.
        called = _answered_by(session, rec)
        if called is None:
            return []
        _injected_answer(session, called, agent, resource, f"The classifier found them. {after}")
        return [called]
    if criterion == "jailbreak":
        risk.add_signal(session, agent.id, "jailbreak_attempt", resource)
        findings.raise_finding(
            session,
            type="agent.jailbreak_attempts",
            severity="medium",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"People tried to jailbreak {agent.name}",
            description=f"The classifier found a jailbreak attempt in a prompt {agent.name} "
            f"sent to {resource}"
            + (f" on behalf of {people.name_of(user)}" if user else "")
            + f". {after}",
            remediation=(
                f"Ask {people.name_of(user)} about it"
                if user
                else "Find who sent it in the agent's conversations"
            )
            + ", and check that the agent's instructions hold up against such prompts.",
        )
        return [agent]
    risk.add_signal(session, agent.id, "prompt_injection", resource)
    if rec.get("phase") == "response":
        # A tool's result: the tool server's data carries it.
        findings.raise_finding(
            session,
            type="toolserver.prompt_injection",
            severity="high",
            subject=str(resource),
            category=findings.THREAT,
            title=f"Prompt-injection payload returned by {resource}",
            description=f"The classifier found instructions aimed at the agent in a result "
            f"{resource} returned to {agent.name}. {after}",
            remediation="Find where the tool's data came from; untrusted content may be "
            "targeting your agents.",
        )
    else:
        findings.raise_finding(
            session,
            type="agent.prompt_injection",
            severity="high",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"A tool result tried to give {agent.name} instructions",
            description="The classifier found instructions aimed at the agent in a tool result "
            f"in one of its conversations with {resource}. {after}",
            remediation="Find which of the agent's tools returned it: untrusted content may be "
            "targeting your agents. Tools called through the MCP gateway are checked as they "
            "answer.",
        )
    return [agent]


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


def record_dropped(session: Session, count: int) -> None:
    """A governance processor lost decision records: its queue overflowed while the control
    plane couldn't take them. The calls were decided; the ledger misses their records, and
    says so."""
    ledger.append(
        session,
        type="decisions.dropped",
        actor="service:processor",
        severity="warning",
        reason=f"{count} decision record(s) lost: the processor's queue overflowed while the "
        "control plane couldn't take them",
        details={"count": count},
    )


def in_process(event: Any) -> bool:
    """Whether an OPA decision-log event is an agent's own decision: one the Agent
    Governance Toolkit asked for (agentos). The processor and the control plane record the
    decisions they ask OPA for themselves, and OPA can still send theirs (a bundle from
    before it dropped them); what-if questions from the policies page aren't decisions."""
    if not isinstance(event, dict) or not str(event.get("path") or "").startswith("agentos"):
        return False
    inp = event.get("input")
    return not (isinstance(inp, dict) and inp.get(WHAT_IF) is True)


def record_opa_decisions(session: Session, events: list[dict[str, Any]]) -> dict[str, int]:
    """Store OPA decision-log events of in-process enforcement (the toolkit's); skip the
    rest."""
    stored = skipped = 0
    for event in events:
        if not in_process(event):
            skipped += 1
            continue
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
    return {"stored": stored, "skipped": skipped}

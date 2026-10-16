"""Copilot Studio's threat detection: AgentGov decides about each tool call.

Once a Power Platform admin connects AgentGov to an environment, Copilot Studio
asks it before each tool call an agent with generative orchestration makes
(``POST <endpoint>/analyze-tool-execution``), sending the tool, its inputs, the
earlier tool results in the plan and who is using the agent. AgentGov looks the
agent up in its registry, checks the inputs for credentials and the earlier
results for injected instructions, and asks OPA
(``data.agentgov.copilotstudio.decision``).

* In ``monitor`` mode AgentGov always lets the call go, and records what its
  policies would have decided.
* In ``enforce`` mode it blocks the calls its policies deny.

Copilot Studio waits less than a second for an answer, so the decision uses
only the registry and OPA, and everything is recorded after answering. When
AgentGov cannot decide in time (OPA unavailable), it answers as
``AGENTGOV_COPILOT_STUDIO_ON_ERROR`` says.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import Database, Where
from agentgov.db.models import Agent, IntegrationState
from agentgov.identity.entra_calls import EntraCallers
from agentgov.processor.detectors import scan_local
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, features, findings, microsoft_signals, risk

log = logging.getLogger(__name__)

DECISION_PATH = "agentgov/copilotstudio/decision"
# Of Copilot Studio's second: what the policy engine may take.
OPA_TIMEOUT_SECONDS = 0.5
STATE_KEY = "threat-detection"
FEATURE = "copilot-studio-threat-detection"
# Reason codes in AgentGov's answers (Copilot Studio passes them on as they are).
REASON_POLICY = 100
REASON_UNAVAILABLE = 500
# A Power Platform connector's API name, e.g. shared_office365.
_CONNECTOR = re.compile(r"\b(shared_[a-z0-9_]+)\b", re.IGNORECASE)


@dataclass
class Verdict:
    """What AgentGov decided about one tool call, and what it answered."""

    block: bool
    effect: str  # what the policies decided: "allow", "deny" or "error"
    reasons: list[str]
    mode: str
    call: dict[str, Any]
    agent_id: str | None = None
    agent_name: str | None = None
    detections: dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    # What controls in monitor mode would have done.
    monitored: list[str] = field(default_factory=list)

    def answer(self) -> dict[str, Any]:
        if not self.block:
            return {"blockAction": False}
        if self.effect == "error":
            return {
                "blockAction": True,
                "reasonCode": REASON_UNAVAILABLE,
                "reason": "AgentGov could not check this action, so it was stopped.",
            }
        return {
            "blockAction": True,
            "reasonCode": REASON_POLICY,
            "reason": "Blocked by your organisation's AgentGov policies: "
            + "; ".join(self.reasons),
        }


def connector_of(tool: dict[str, Any]) -> str | None:
    """The Power Platform connector behind a tool, when the tool names one."""
    for key in ("connectorId", "connector", "apiId", "apiName", "id"):
        value = tool.get(key)
        if isinstance(value, str):
            match = _CONNECTOR.search(value)
            if match:
                return match.group(1).lower()
    return None


def _call(payload: dict[str, Any]) -> dict[str, Any]:
    """The parts of Copilot Studio's request AgentGov uses (it tolerates the rest)."""
    tool = payload.get("toolDefinition") if isinstance(payload.get("toolDefinition"), dict) else {}
    meta = payload.get("conversationMetadata")
    meta = meta if isinstance(meta, dict) else {}
    agent = meta.get("agent") if isinstance(meta.get("agent"), dict) else {}
    user = meta.get("user") if isinstance(meta.get("user"), dict) else {}
    planner = payload.get("plannerContext")
    planner = planner if isinstance(planner, dict) else {}
    inputs = payload.get("inputValues") if isinstance(payload.get("inputValues"), dict) else {}
    earlier = planner.get("previousToolOutputs") or planner.get("previousToolsOutputs") or []
    return {
        "agent": {
            "platform_id": str(agent.get("id") or ""),
            "environment_id": agent.get("environmentId"),
            "tenant_id": agent.get("tenantId"),
            "published": agent.get("isPublished"),
        },
        "user": {"id": user.get("id")},
        "tool": {
            "id": tool.get("id"),
            "type": tool.get("type"),
            "name": str(tool.get("name") or tool.get("id") or "unnamed tool"),
            "connector": connector_of(tool),
        },
        "arguments": inputs,
        "earlier_results": [o.get("outputs") for o in earlier if isinstance(o, dict)],
        "conversation_id": meta.get("conversationId"),
        "plan_id": meta.get("planId"),
        "plan_step_id": meta.get("planStepId"),
    }


class AgentLookup:
    """Registry agents by any ID Copilot Studio may send for them (its bot ID, its
    Entra agent ID, its app registration), from an index refreshed every minute
    so each decision costs one lookup rather than a scan."""

    REFRESH_SECONDS = 60.0
    # An unknown ID may be a new agent: look again, but not more than this often.
    MISS_REFRESH_SECONDS = 10.0

    def __init__(self) -> None:
        self._index: dict[str, str] = {}
        self._built = float("-inf")
        self._lock = threading.Lock()

    def find(self, db: Database, platform_id: str) -> tuple[str, str] | None:
        """``(agent id, name)`` for the agent, or None when AgentGov doesn't know it."""
        if not platform_id:
            return None
        age = time.monotonic() - self._built
        agent_id = microsoft_signals.match_agent(self._index, platform_id)
        if age > self.REFRESH_SECONDS or (agent_id is None and age > self.MISS_REFRESH_SECONDS):
            with self._lock, db.transaction() as tx:
                self._index = microsoft_signals.agent_index(tx)
                self._built = time.monotonic()
            agent_id = microsoft_signals.match_agent(self._index, platform_id)
        if agent_id is None:
            return None
        with db.transaction():
            return Agent.objects.filter(pk=agent_id).values_list("id", "name").first()


class ThreatDetection:
    def __init__(
        self,
        settings: Settings,
        *,
        opa_http: httpx.Client | None = None,
        keys_http: httpx.Client | None = None,
    ) -> None:
        self.settings = settings
        self.callers = EntraCallers(
            tenant_id=settings.copilot_studio_tenant() or "",
            audiences=settings.copilot_studio_token_audiences(),
            app_ids=settings.copilot_studio_callers(),
            login_url=settings.entra_login_url,
            http=keys_http,
        )
        identity = settings.tls()
        self._opa = opa_http or httpx.Client(
            timeout=OPA_TIMEOUT_SECONDS, transport=identity.transport() if identity else None
        )
        self.agents = AgentLookup()

    @staticmethod
    def mode(db: Database) -> str:
        """The feature's mode: "off", "monitor" or "enforce"."""
        with db.transaction() as tx:
            return features.mode(tx, FEATURE)

    def decide(self, db: Database, payload: dict[str, Any]) -> Verdict:
        started = time.monotonic()
        call = _call(payload)
        with db.transaction() as tx:
            modes = features.modes(tx)
        mode = modes[FEATURE]
        # Short reads: no transaction stays open while OPA decides.
        known = self.agents.find(db, call["agent"]["platform_id"])
        # AgentGov's own detectors, as far as their controls are on: credentials in the
        # inputs, and instructions aimed at the agent in what earlier tools returned
        # (indirect prompt injection).
        secrets, _ = scan_local(
            call["arguments"],
            check_injection=False,
            check_secrets=modes["data-protection"] != features.OFF,
        )
        injected, _ = scan_local(
            call["earlier_results"] if modes["prompt-injection"] != features.OFF else [],
            check_injection=True,
            check_secrets=False,
        )
        threshold = self.settings.prompt_injection_threshold
        detections = {
            "categories": sorted(secrets.categories()),
            "entities": sorted({s.entity for s in secrets.spans}),
            "prompt_injection": injected.injection_score >= threshold,
            "injection_score": round(injected.injection_score, 3),
            "injection_reasons": injected.injection_reasons,
        }
        policy_input = {
            "platform": "copilot-studio",
            "agent": {**call["agent"], **({"id": known[0]} if known else {})},
            "user": call["user"],
            "tool": {k: v for k, v in call["tool"].items() if v is not None},
            "arguments": call["arguments"],
            "detections": detections,
        }
        monitored: list[str] = []
        try:
            effect, reasons, monitored = self._evaluate(policy_input)
        except RuntimeError as exc:
            log.warning("threat detection could not decide: %s", exc)
            effect, reasons = "error", [str(exc)]
        if mode == features.ENFORCE:
            block = effect == "deny" or (
                effect == "error" and self.settings.copilot_studio_on_error == "block"
            )
        else:
            block = False
        return Verdict(
            block=block,
            effect=effect,
            reasons=reasons,
            mode=mode,
            call=call,
            agent_id=known[0] if known else None,
            agent_name=known[1] if known else None,
            detections=detections,
            latency_ms=int((time.monotonic() - started) * 1000),
            monitored=monitored,
        )

    def _evaluate(self, policy_input: dict[str, Any]) -> tuple[str, list[str], list[str]]:
        if not self.settings.opa_url:
            raise RuntimeError("OPA is not configured (AGENTGOV_OPA_URL)")
        try:
            resp = self._opa.post(
                f"{self.settings.opa_url.rstrip('/')}/v1/data/{DECISION_PATH}",
                json={"input": policy_input},
                timeout=OPA_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"OPA unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise RuntimeError(f"OPA returned {resp.status_code}")
        result = resp.json().get("result")
        if not isinstance(result, dict) or result.get("effect") not in ("allow", "deny"):
            raise RuntimeError(f"data.{DECISION_PATH.replace('/', '.')} is undefined")
        return (
            result["effect"],
            [str(r) for r in result.get("reasons") or []],
            [str(m) for m in result.get("monitored") or []],
        )


def record(tx: Where, settings: Settings, verdict: Verdict, *, correlation_id: str) -> None:
    """The evidence for one decision: a ledger entry, the agent's activity and risk."""
    call = verdict.call
    tool = call["tool"]
    agent = Agent.objects.filter(pk=verdict.agent_id).first() if verdict.agent_id else None
    platform_id = call["agent"]["platform_id"]
    when = ids.utcnow()
    resource = f"{tool.get('connector') or 'copilot-studio'}/{tool['name']}"
    would_block = verdict.effect == "deny" and not verdict.block
    # A call that went through only because something is monitored says so.
    reason = "; ".join(verdict.reasons) or None
    if would_block:
        reason = f"monitored: {reason}"
    elif verdict.monitored and not verdict.block:
        reason = "monitored: " + "; ".join(verdict.monitored)
    ledger.append(
        tx,
        type="decision.copilot_studio",
        actor=f"agent:{agent.name}" if agent else f"copilot-studio:{platform_id or 'unknown'}",
        agent=agent,
        agent_name=None if agent else platform_id or None,
        severity="warning"
        if verdict.block or verdict.effect != "allow" or verdict.monitored
        else "info",
        action="tool_call",
        resource=resource,
        decision="deny" if verdict.block else "allow",
        reason=reason,
        details={
            "mode": verdict.mode,
            "policy": verdict.effect,
            "would_block": would_block,
            "tool": tool,
            "environment_id": call["agent"].get("environment_id"),
            "user_id": call["user"].get("id"),
            "conversation_id": call.get("conversation_id"),
            "plan_id": call.get("plan_id"),
            "correlation_id": correlation_id,
            "latency_ms": verdict.latency_ms,
            "detections": verdict.detections,
            "monitored": verdict.monitored,
        },
    )
    _count(tx, blocked=verdict.block, would_block=would_block)
    if agent is None:
        findings.raise_finding(
            tx,
            type="copilot_studio.unknown_agent",
            severity="medium",
            subject=platform_id or "unknown",
            category=findings.THREAT,
            title="A Copilot Studio agent AgentGov doesn't know is calling tools",
            description=f"Copilot Studio agent {platform_id or '(no ID)'} in environment "
            f"{call['agent'].get('environment_id') or '(unknown)'} is not in the registry.",
            remediation="Sync or import the Copilot Studio inventory on the Platforms page.",
            details={
                "agent_id": platform_id,
                "environment_id": call["agent"].get("environment_id"),
            },
        )
        return
    agent.last_seen_at = when
    agent.save()
    discovery.record_activity(
        tx, agent.id, when=when, tool_calls=1, denied=1 if verdict.block else 0
    )
    if verdict.block:
        risk.add_signal(tx, agent.id, "policy_denied", resource)
    if "secret" in verdict.detections.get("categories", []):
        risk.add_signal(tx, agent.id, "secret_detected", resource)
        findings.raise_finding(
            tx,
            type="agent.credential_exfiltration_attempt",
            severity="high",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"{agent.name} tried to send credentials to a tool",
            description=f"Credentials ({', '.join(verdict.detections.get('entities') or [])}) "
            f"were found in the inputs to {resource}"
            + ("; the call was blocked." if verdict.block else "."),
            remediation="Check the agent's instructions and knowledge sources for leaked "
            "secrets and rotate them.",
        )
    if verdict.detections.get("prompt_injection"):
        risk.add_signal(tx, agent.id, "prompt_injection", resource)
        findings.raise_finding(
            tx,
            type="copilot_studio.prompt_injection",
            severity="high",
            subject=agent.id,
            agent_id=agent.id,
            category=findings.THREAT,
            title=f"A tool result tried to give {agent.name} instructions",
            description="An earlier tool result in one of its conversations contained "
            "instructions aimed at the agent ("
            + ", ".join(verdict.detections.get("injection_reasons") or [])
            + ")"
            + ("; the next tool call was blocked." if verdict.block else "."),
            remediation="Find where that tool's data comes from: untrusted content may be "
            "targeting your agents.",
        )
    agents_svc.refresh_risk(tx, settings, agent)


def _count(tx: Where, *, blocked: bool, would_block: bool) -> None:
    state = IntegrationState.objects.filter(pk=STATE_KEY).first()
    state = state or IntegrationState(key=STATE_KEY, data={})
    data = dict(state.data or {})
    data["calls"] = int(data.get("calls", 0)) + 1
    data["blocked"] = int(data.get("blocked", 0)) + (1 if blocked else 0)
    data["would_block"] = int(data.get("would_block", 0)) + (1 if would_block else 0)
    data["last_call_at"] = ids.isoformat(ids.utcnow())
    state.data, state.updated_at = data, ids.utcnow()
    state.save(force_insert=state._state.adding)


def summary(tx: Where, mode: str) -> dict[str, Any]:
    """How threat detection is doing, for the Platforms page."""
    state = IntegrationState.objects.filter(pk=STATE_KEY).first()
    data = dict(state.data or {}) if state is not None else {}
    return {
        "mode": mode,
        **{k: data.get(k) for k in ("calls", "blocked", "would_block")},
        "last_call_at": data.get("last_call_at"),
    }

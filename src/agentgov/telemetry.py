"""OpenTelemetry ingestion: GenAI spans feed discovery, activity and detective controls.

Agents (or an OTel Collector in front of them) export OTLP/HTTP traces to the
control plane. Spans that follow the OpenTelemetry GenAI semantic conventions
(``gen_ai.operation.name`` = ``invoke_agent``, ``execute_tool``, ``chat``, ...)
are matched to registered agents by ``gen_ai.agent.id`` / ``gen_ai.agent.name``
or ``service.name``. These are the same conventions Agent 365's observability
uses, so agents instrumented for it can report here unchanged.

* Unknown agents are registered as *discovered* (shadow AI).
* Tool executions by registered agents are checked against their grants. A
  call to a tool the agent was never granted shows the agent is reaching tools
  without going through the gateway, and raises a finding.
* Agents that capture message content report their instructions
  (``gen_ai.system_instructions``), which are checked for unsafe content.
"""

from __future__ import annotations

import base64
import fnmatch
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from agentgov import ledger
from agentgov.models import ACTIVE
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, features, findings, instructions
from agentgov.registry.errors import ValidationError

GENAI_OPERATIONS = {
    "invoke_agent",
    "create_agent",
    "invoke_workflow",
    "execute_tool",
    "chat",
    "text_completion",
    "generate_content",
    "embeddings",
}
MODEL_OPERATIONS = {"chat", "text_completion", "generate_content", "embeddings"}
# Infrastructure that emits GenAI attributes but is not an agent.
IGNORED_SERVICES = {"agentgateway", "agentgov-processor", "agentgov-control-plane"}


def _value(v: dict[str, Any]) -> Any:
    if "stringValue" in v:
        return v["stringValue"]
    if "intValue" in v:
        return int(v["intValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "boolValue" in v:
        return bool(v["boolValue"])
    if "arrayValue" in v:
        return [_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {kv["key"]: _value(kv.get("value", {})) for kv in v["kvlistValue"].get("values", [])}
    return None


def _attrs(items: list[dict[str, Any]] | None) -> dict[str, Any]:
    return {a["key"]: _value(a.get("value") or {}) for a in items or [] if "key" in a}


def iter_spans(payload: dict[str, Any]) -> Iterator[tuple[dict[str, Any], str, dict[str, Any]]]:
    for rs in payload.get("resourceSpans") or []:
        resource = _attrs((rs.get("resource") or {}).get("attributes"))
        for ss in rs.get("scopeSpans") or rs.get("instrumentationLibrarySpans") or []:
            scope = (ss.get("scope") or ss.get("instrumentationLibrary") or {}).get("name", "")
            for span in ss.get("spans") or []:
                yield resource, scope, span


def _ts(span: dict[str, Any]) -> datetime | None:
    raw = span.get("startTimeUnixNano")
    try:
        return datetime.fromtimestamp(int(raw) / 1e9, tz=UTC) if raw else None
    except (TypeError, ValueError):
        return None


def _hex_id(raw: Any) -> str | None:
    if not raw or not isinstance(raw, str):
        return None
    if all(c in "0123456789abcdefABCDEF" for c in raw):
        return raw.lower()
    try:  # protobuf-to-JSON conversion encodes bytes as base64
        return base64.b64decode(raw).hex()
    except ValueError:
        return None


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def instruction_text(value: Any) -> str | None:
    """Text of ``gen_ai.system_instructions``: message parts, as JSON or structured, or text."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return value.strip() or None
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return None
    texts = [
        part.get("content") or part.get("text")
        for part in value
        if isinstance(part, dict) and part.get("type", "text") == "text"
    ]
    return "\n\n".join(t.strip() for t in texts if isinstance(t, str) and t.strip()) or None


def system_instructions(attrs: dict[str, Any], span: dict[str, Any]) -> str | None:
    """The instructions on a span, or on one of its events (OTel GenAI conventions)."""
    value = attrs.get("gen_ai.system_instructions")
    if value is None:
        for event in span.get("events") or []:
            value = _attrs(event.get("attributes")).get("gen_ai.system_instructions")
            if value is not None:
                break
    return instruction_text(value) if value is not None else None


def granted(grants: list[dict[str, Any]], server: str, tool: str) -> bool:
    return any(
        fnmatch.fnmatchcase(server, g["server"])
        and any(fnmatch.fnmatchcase(tool, p) for p in g["tools"])
        for g in grants
    )


def ingest(session: Session, payload: dict[str, Any], *, classify: bool = False) -> dict[str, Any]:
    stats = {
        "spans": 0,
        "genai_spans": 0,
        "agents": 0,
        "discovered": 0,
        "ungranted": 0,
        "instructions": 0,
    }
    seen_agents: set[str] = set()
    reported: dict[str, str] = {}
    modes = features.modes(session)
    for resource, scope, span in iter_spans(payload):
        stats["spans"] += 1
        attrs = _attrs(span.get("attributes"))
        op = attrs.get("gen_ai.operation.name") or (span.get("name") or "").split(" ", 1)[0]
        if op not in GENAI_OPERATIONS:
            continue
        service = resource.get("service.name")
        if service in IGNORED_SERVICES:
            continue
        stats["genai_spans"] += 1
        agent_id = attrs.get("gen_ai.agent.id") or resource.get("gen_ai.agent.id")
        name = attrs.get("gen_ai.agent.name") or resource.get("gen_ai.agent.name") or service
        before = discovery.find(session, agent_id=agent_id, name=name)
        when = _ts(span)
        model = attrs.get("gen_ai.request.model") if op in MODEL_OPERATIONS else None
        agent = discovery.observe(
            session,
            source="otel",
            agent_id=agent_id,
            name=name,
            framework=resource.get("telemetry.sdk.name") if scope == "" else scope,
            model=model,
            details={"service.name": service} if service else None,
            seen_at=when,
            discover=modes["discovery"] != features.OFF,
        )
        if agent is None:
            continue
        if before is None:
            stats["discovered"] += 1
        seen_agents.add(agent.id)
        system = system_instructions(attrs, span)
        if system and reported.get(agent.id) != system:
            reported[agent.id] = system
            try:
                instructions.report(
                    session,
                    agent,
                    source="telemetry",
                    text=system,
                    actor="system:otel",
                    classify=classify,
                )
                stats["instructions"] += 1
            except ValidationError:
                pass  # too long to keep: the rest of the span still counts
        if op == "execute_tool":
            tool = attrs.get("gen_ai.tool.name") or "unknown"
            server = attrs.get("agentgov.server") or "local"
            discovery.record_activity(session, agent.id, when=when, tool_calls=1)
            if (
                modes["least-privilege"] != features.OFF
                and agent.status == ACTIVE
                and not granted(agents_svc.effective_grants(agent), server, tool)
            ):
                stats["ungranted"] += 1
                ledger.append(
                    session,
                    type="telemetry.ungranted_tool_use",
                    actor="system:otel",
                    agent=agent,
                    severity="warning",
                    action="execute_tool",
                    resource=f"{server}/{tool}",
                    decision="observed",
                    reason="tool executed outside the gateway without a grant",
                    trace_id=_hex_id(span.get("traceId")),
                )
                findings.raise_finding(
                    session,
                    type="agent.ungranted_tool_use",
                    severity="high",
                    subject=f"{agent.id}:{server}/{tool}",
                    agent_id=agent.id,
                    category=findings.THREAT,
                    title=f"{agent.name} used {server}/{tool} without a grant",
                    description="Telemetry shows a tool execution that the agent's blueprint does "
                    "not allow, so the call did not go through the governed gateway.",
                    remediation="Route the agent's tools through agentgateway, or grant the tool "
                    "if the use is legitimate.",
                )
        elif op in MODEL_OPERATIONS:
            discovery.record_activity(
                session,
                agent.id,
                when=when,
                model_calls=1,
                input_tokens=_int(attrs.get("gen_ai.usage.input_tokens")),
                output_tokens=_int(attrs.get("gen_ai.usage.output_tokens")),
            )
    stats["agents"] = len(seen_agents)
    return stats


def decode_protobuf(body: bytes) -> dict[str, Any]:
    """Decode an OTLP protobuf export (requires the otlp-protobuf extra)."""
    from google.protobuf import json_format
    from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

    request = trace_service_pb2.ExportTraceServiceRequest()
    request.ParseFromString(body)
    return json_format.MessageToDict(request)

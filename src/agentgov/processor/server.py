"""The governance processor: agentgateway's MCP-aware external policy server.

agentgateway calls this service (``ExtMcp`` over gRPC) for every governed MCP
operation. For each one the processor:

1. identifies the caller from claims agentgateway already validated,
2. inspects the content (secrets locally, PII with Presidio, prompt injection
   and tool poisoning heuristics),
3. asks OPA for a decision (data.agentgov.mcp.*), and
4. enforces it: pass, rewrite (redaction or tools/list filtering), reject, or
   route the call to a human approver,

then records the outcome in the control plane's evidence ledger.

Decisions are made on the JSON-RPC body agentgateway parsed, never on the
``Mcp-Method``/``Mcp-Name`` headers, so header spoofing on older protocol
revisions cannot change what is authorised.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

import grpc
from google.protobuf import json_format, struct_pb2

from agentgov import ids
from agentgov.config import Settings
from agentgov.opa.client import OpaClient, OpaError
from agentgov.processor import detectors
from agentgov.processor.control_plane import (
    ControlPlaneClient,
    ControlPlaneError,
    DecisionRecorder,
)
from agentgov.processor.presidio import PresidioClient, PresidioError
from agentgov.processor.proto import ext_mcp_pb2 as pb
from agentgov.processor.proto import ext_mcp_pb2_grpc as pb_grpc

log = logging.getLogger(__name__)

DENIED = pb.AuthorizationError.PERMISSION_DENIED
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


def trace_id_of(context: Any, headers: Any = ()) -> str | None:
    """The W3C trace ID of the call, from agentgateway's ``traceparent``.

    agentgateway sends its tracing context with every ExtMcp call as gRPC
    metadata; when the agent propagated its own trace, the gateway continues it,
    so this is the agent's trace too. The forwarded HTTP headers are a fallback.
    """
    values: list[str] = []
    metadata = getattr(context, "invocation_metadata", None)
    if callable(metadata):
        values += [str(v) for k, v in metadata() or () if k == "traceparent"]
    values += [h.value.decode("latin-1") for h in headers if h.key.lower() == "traceparent"]
    for value in values:
        match = _TRACEPARENT.match(value.strip().lower())
        if match and match.group(1) != "0" * 32:
            return match.group(1)
    return None


def _struct(message: Any) -> dict[str, Any]:
    if message is None or not message.ListFields():
        return {}
    return json_format.MessageToDict(message)


def _target(method: str, params: dict[str, Any]) -> tuple[str | None, Any]:
    """The governed object of a request and the payload to inspect."""
    if method == "tools/call":
        return params.get("name"), params.get("arguments") or {}
    if method == "prompts/get":
        return params.get("name"), params.get("arguments") or {}
    if method == "resources/read":
        return params.get("uri"), {"uri": params.get("uri")}
    return None, None


def _pass_request(context: dict[str, Any] | None = None) -> pb.McpRequestResult:
    result = pb.McpRequestResult(**{"pass": pb.Pass()})
    if context:
        result.metadata.CopyFrom(_to_struct(context))
    return result


def _to_struct(values: dict[str, Any]) -> struct_pb2.Struct:
    struct = struct_pb2.Struct()
    struct.update({k: v for k, v in values.items() if v is not None})
    return struct


def _pass_response() -> pb.McpResponseResult:
    return pb.McpResponseResult(**{"pass": pb.Pass()})


def _error_payload(effect: str, reasons: list[str], approval_id: str | None) -> bytes:
    data: dict[str, Any] = {"effect": effect, "reasons": reasons}
    if approval_id:
        data["approval_id"] = approval_id
    return json.dumps({"agentgov": data}).encode()


class Inspection:
    """Result of content inspection for one payload."""

    def __init__(self, scan: detectors.ScanResult, threshold: float) -> None:
        self.scan = scan
        self.summary = scan.summary(threshold)


class GovernanceProcessor(pb_grpc.ExtMcpServicer):
    def __init__(
        self,
        settings: Settings,
        *,
        opa: OpaClient,
        control_plane: ControlPlaneClient,
        recorder: DecisionRecorder,
        presidio: PresidioClient | None = None,
    ) -> None:
        self.settings = settings
        self.opa = opa
        self.cp = control_plane
        self.recorder = recorder
        self.presidio = presidio
        self._background: set[asyncio.Task[Any]] = set()

    # ------------------------------------------------------------------ helpers
    def _spawn(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _inspect(self, payload: Any, *, check_injection: bool) -> Inspection:
        scan, strings = detectors.scan_local(payload, check_injection=check_injection)
        if self.presidio is not None and strings:
            try:
                pii, skipped = await self.presidio.find_pii(strings)
                scan.spans.extend(pii)
                scan.truncated = scan.truncated or skipped
            except PresidioError as exc:
                scan.pii_error = str(exc)
                log.warning("PII inspection failed: %s", exc)
        return Inspection(scan, self.settings.prompt_injection_threshold)

    def _record(self, **fields: Any) -> None:
        self.recorder.record({"ts": ids.isoformat(ids.utcnow()), **fields})

    @staticmethod
    def _identity(meta: dict[str, Any]) -> dict[str, Any]:
        return {k: meta[k] for k in ("client_id", "agent_id", "subject") if meta.get(k)}

    async def _observe_unknown(self, identity: dict[str, Any], server: str, method: str) -> None:
        try:
            await self.cp.observe(
                {
                    "source": "gateway",
                    "client_id": identity.get("client_id"),
                    "agent_id": identity.get("agent_id"),
                    "name": identity.get("client_id") or identity.get("subject"),
                    "details": {"server": server, "method": method},
                }
            )
        except ControlPlaneError as exc:
            log.warning("could not report unknown caller: %s", exc)

    # ------------------------------------------------------------ request side
    async def CheckRequest(self, request: pb.McpRequest, context: Any) -> pb.McpRequestResult:
        try:
            return await self._check_request(request, trace_id_of(context, request.headers))
        except Exception:
            log.exception("CheckRequest failed; denying")
            return pb.McpRequestResult(
                error=pb.AuthorizationError(
                    code=pb.AuthorizationError.UNKNOWN,
                    reason="Governance processor error; the call was not forwarded",
                )
            )

    async def _check_request(
        self, request: pb.McpRequest, trace_id: str | None = None
    ) -> pb.McpRequestResult:
        started = time.perf_counter()
        method = request.method
        meta = _struct(request.metadata_context)
        server = (list(request.service_names) or [meta.get("server")])[0] or "unknown"
        params = json.loads(request.mcp_request) if request.HasField("mcp_request") else {}
        target, payload = _target(method, params)
        if target is None:
            return _pass_request()
        identity = self._identity(meta)
        inspection = await self._inspect(payload, check_injection=False)
        resource = f"{server}/{target}"

        def finish(
            effect: str,
            reasons: list[str],
            *,
            agent: dict[str, Any] | None = None,
            approval_id: str | None = None,
            redacted: list[str] | None = None,
            decision_id: str | None = None,
        ) -> None:
            self._record(
                phase="request",
                method=method,
                server=server,
                target=target,
                resource=resource,
                agent=agent,
                identity=identity,
                effect=effect,
                reasons=reasons,
                redacted=redacted or [],
                detections=inspection.summary,
                approval_id=approval_id,
                opa_decision_id=decision_id,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                trace_id=trace_id,
            )

        def reject(
            effect: str, reasons: list[str], approval_id: str | None = None
        ) -> pb.McpRequestResult:
            return pb.McpRequestResult(
                error=pb.AuthorizationError(
                    code=DENIED,
                    reason="; ".join(reasons),
                    mcp_error=_error_payload(effect, reasons, approval_id),
                )
            )

        if inspection.scan.pii_error and self.settings.presidio_failure_mode == "closed":
            reasons = ["Content inspection is unavailable, so the call was not forwarded"]
            finish("deny", reasons)
            return reject("deny", reasons)

        opa_input = {
            "phase": "request",
            "method": method,
            "agent": identity,
            "resource": {"server": server, "name": target},
            "arguments": payload,
            "detections": inspection.summary,
        }
        try:
            decision, decision_id = await self.opa.evaluate("agentgov/mcp/decision", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            reasons = ["Policy engine unavailable; the call was not forwarded"]
            finish("deny", reasons)
            return reject("deny", reasons)

        effect = decision.get("effect", "deny")
        reasons = list(decision.get("reasons") or [])
        agent = decision.get("agent")

        if agent is None and self.settings.unknown_agent_mode == "monitor":
            self._spawn(self._observe_unknown(identity, server, method))
            finish(
                "allow", ["monitor mode: caller is not a registered agent"], decision_id=decision_id
            )
            return _pass_request({"agentgov_target": target, "agentgov_method": method})

        approval_id = None
        if effect == "require_approval" and agent is not None:
            redacted_args = detectors.redact(payload, inspection.scan.spans, {"secret", "pii"})
            try:
                outcome = await self.cp.check_approval(
                    {
                        "agent_id": agent["id"],
                        "action": method,
                        "resource": resource,
                        "arguments": payload,
                        "redacted_arguments": redacted_args,
                        "reasons": reasons,
                    }
                )
            except ControlPlaneError as exc:
                log.error("approval check failed: %s", exc)
                reasons = ["Approval service unavailable; the call was not forwarded"]
                finish("deny", reasons, agent=agent, decision_id=decision_id)
                return reject("deny", reasons)
            approval_id = outcome["approval"]["id"]
            status = outcome["outcome"]
            if status == "approved":
                effect = "allow"
                reasons = [f"approved by {outcome['approval'].get('decided_by')}"]
            elif status == "denied":
                effect, reasons = "deny", [f"A reviewer denied this call (approval {approval_id})"]
            else:
                reasons = [
                    f"Human approval required: {'; '.join(reasons)}. Approval request "
                    f"{approval_id} is pending; retry the same call once it is approved."
                ]
                finish(
                    "require_approval",
                    reasons,
                    agent=agent,
                    approval_id=approval_id,
                    decision_id=decision_id,
                )
                return reject("require_approval", reasons, approval_id)

        if effect != "allow":
            finish("deny", reasons, agent=agent, approval_id=approval_id, decision_id=decision_id)
            return reject("deny", reasons, approval_id)

        # Returned to agentgateway and handed back on the response side as
        # metadata_context["request"]: the response message itself has no params.
        context = {"agentgov_target": target, "agentgov_method": method}
        redact = set(decision.get("redact") or []) & inspection.scan.categories()
        if redact and isinstance(payload, dict) and method != "resources/read":
            new_params = {
                **params,
                "arguments": detectors.redact(payload, inspection.scan.spans, redact),
            }
            finish(
                "allow",
                reasons,
                agent=agent,
                approval_id=approval_id,
                redacted=sorted(redact),
                decision_id=decision_id,
            )
            result = pb.McpRequestResult(mutated=json.dumps(new_params).encode())
            result.metadata.CopyFrom(_to_struct(context))
            return result
        finish("allow", reasons, agent=agent, approval_id=approval_id, decision_id=decision_id)
        return _pass_request(context)

    # ----------------------------------------------------------- response side
    async def CheckResponse(self, request: pb.McpResponse, context: Any) -> pb.McpResponseResult:
        try:
            return await self._check_response(request, trace_id_of(context))
        except Exception:
            log.exception("CheckResponse failed; withholding the result")
            return pb.McpResponseResult(
                error=pb.AuthorizationError(
                    code=pb.AuthorizationError.UNKNOWN,
                    reason="Governance processor error; the result was withheld",
                )
            )

    async def _check_response(
        self, request: pb.McpResponse, trace_id: str | None = None
    ) -> pb.McpResponseResult:
        method = request.method
        meta = _struct(request.metadata_context)
        server = (list(request.service_names) or [meta.get("server")])[0] or "unknown"
        result = json.loads(request.mcp_response) if request.mcp_response else {}
        identity = self._identity(meta)
        if method == "tools/list":
            return await self._filter_tools(server, identity, result)
        if method not in ("tools/call", "resources/read"):
            return _pass_response()

        started = time.perf_counter()
        target = (meta.get("request") or {}).get("agentgov_target") or "unknown"
        inspection = await self._inspect(result, check_injection=True)

        def finish(
            effect: str,
            reasons: list[str],
            *,
            agent: dict[str, Any] | None = None,
            redacted: list[str] | None = None,
            decision_id: str | None = None,
        ) -> None:
            self._record(
                phase="response",
                method=method,
                server=server,
                target=target,
                resource=f"{server}/{target}",
                agent=agent,
                identity=identity,
                effect=effect,
                reasons=reasons,
                redacted=redacted or [],
                detections=inspection.summary,
                opa_decision_id=decision_id,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                trace_id=trace_id,
            )

        def withhold(reasons: list[str]) -> pb.McpResponseResult:
            return pb.McpResponseResult(
                error=pb.AuthorizationError(
                    code=DENIED,
                    reason="; ".join(reasons),
                    mcp_error=_error_payload("deny", reasons, None),
                )
            )

        if inspection.scan.pii_error and self.settings.presidio_failure_mode == "closed":
            reasons = ["Content inspection is unavailable, so the result was withheld"]
            finish("deny", reasons)
            return withhold(reasons)

        opa_input = {
            "phase": "response",
            "method": method,
            "agent": identity,
            "resource": {"server": server, "name": target},
            "detections": inspection.summary,
        }
        try:
            decision, decision_id = await self.opa.evaluate("agentgov/mcp/decision", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            reasons = ["Policy engine unavailable; the result was withheld"]
            finish("deny", reasons)
            return withhold(reasons)

        agent = decision.get("agent")
        if agent is None and self.settings.unknown_agent_mode == "monitor":
            finish(
                "allow", ["monitor mode: caller is not a registered agent"], decision_id=decision_id
            )
            return _pass_response()
        if decision.get("effect") == "deny":
            reasons = list(decision.get("reasons") or [])
            finish("deny", reasons, agent=agent, decision_id=decision_id)
            return withhold(reasons)
        redact = set(decision.get("redact") or []) & inspection.scan.categories()
        if redact:
            finish("allow", [], agent=agent, redacted=sorted(redact), decision_id=decision_id)
            mutated = detectors.redact(result, inspection.scan.spans, redact)
            return pb.McpResponseResult(mutated=json.dumps(mutated).encode())
        finish("allow", [], agent=agent, decision_id=decision_id)
        return _pass_response()

    async def _filter_tools(
        self, server: str, identity: dict[str, Any], result: dict[str, Any]
    ) -> pb.McpResponseResult:
        tools = [t for t in result.get("tools") or [] if isinstance(t, dict)]
        poisoned = detectors.scan_tool_definitions(tools)
        self._spawn(self._report_catalog(server, tools, poisoned))
        opa_input = {
            "phase": "response",
            "method": "tools/list",
            "agent": identity,
            "resource": {"server": server},
            "tools": [{"name": t.get("name")} for t in tools],
            "poisoned": poisoned,
        }
        try:
            view, _ = await self.opa.evaluate("agentgov/mcp/list_view", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed for tools/list: %s", exc)
            view = {"agent": None, "visible": []}
        if view.get("agent") is None and self.settings.unknown_agent_mode == "monitor":
            self._spawn(self._observe_unknown(identity, server, "tools/list"))
            visible = {t.get("name") for t in tools} - set(poisoned)
        else:
            visible = set(view.get("visible") or [])
        filtered = [t for t in tools if t.get("name") in visible]
        if len(filtered) == len(tools):
            return _pass_response()
        # The filtered list is specific to this agent: never let a shared cache reuse it.
        mutated = {**result, "tools": filtered}
        if "cacheScope" in result:
            mutated["cacheScope"] = "private"
        return pb.McpResponseResult(mutated=json.dumps(mutated).encode())

    async def _report_catalog(
        self, server: str, tools: list[dict[str, Any]], poisoned: dict[str, list[str]]
    ) -> None:
        try:
            await self.cp.report_catalog({"server": server, "tools": tools, "poisoned": poisoned})
        except ControlPlaneError as exc:
            log.warning("catalog report for %s failed: %s", server, exc)


async def serve(settings: Settings) -> None:
    """Run the processor until cancelled."""
    import httpx

    http = httpx.AsyncClient(timeout=5.0)
    opa = OpaClient(settings.opa_url or "http://localhost:8181", http=http)
    control_plane = ControlPlaneClient(
        settings.control_plane_url, settings.service_token, http=http
    )
    recorder = DecisionRecorder(control_plane)
    presidio = (
        PresidioClient(
            settings.presidio_url,
            settings.pii_thresholds(),
            max_chars=settings.presidio_max_chars,
            http=httpx.AsyncClient(timeout=10.0),
        )
        if settings.presidio_url
        else None
    )
    server = grpc.aio.server(
        options=[
            ("grpc.max_receive_message_length", 64 * 1024 * 1024),
            ("grpc.max_send_message_length", 64 * 1024 * 1024),
        ]
    )
    pb_grpc.add_ExtMcpServicer_to_server(
        GovernanceProcessor(
            settings, opa=opa, control_plane=control_plane, recorder=recorder, presidio=presidio
        ),
        server,
    )
    server.add_insecure_port(settings.processor_listen)
    recorder.start()
    await server.start()
    log.info("governance processor listening on %s", settings.processor_listen)
    try:
        await server.wait_for_termination()
    finally:
        await server.stop(grace=5)
        await recorder.stop()
        await http.aclose()

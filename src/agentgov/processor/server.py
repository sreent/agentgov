"""The governance processor: agentgateway's MCP-aware external policy server.

agentgateway calls this service (``ExtMcp`` over gRPC) for every governed MCP
operation. For each one the processor:

1. identifies the caller from claims agentgateway already validated, and the
   person it acts for, if any (``agentgov.identity.people``),
2. inspects the content (secrets locally, PII with Presidio, prompt injection
   and tool poisoning heuristics, and IBM Granite Guardian's second opinion where it
   is configured: ``agentgov.processor.classifier``),
3. asks OPA for a decision (data.agentgov.mcp.*), and
4. enforces it: pass, rewrite (redaction or tools/list filtering), reject, or
   route the call to a human approver,

then records the outcome in the control plane's evidence ledger.

Decisions are made on the JSON-RPC body agentgateway parsed, never on the
``Mcp-Method``/``Mcp-Name`` headers, so header spoofing on older protocol
revisions cannot change what is authorised.

The same port serves agentgateway's external processing of the answers agents send each
other (``agentgov.processor.a2a_answers``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Iterable
from typing import Any

import grpc
from google.protobuf import json_format, struct_pb2

from agentgov import authzen, ids
from agentgov.config import Settings
from agentgov.identity import chains, people
from agentgov.opa.client import OpaClient, OpaError
from agentgov.processor import classifier, detectors
from agentgov.processor.control_plane import (
    ControlPlaneClient,
    ControlPlaneError,
    DecisionRecorder,
)
from agentgov.processor.modes import FeatureModes
from agentgov.processor.presidio import PresidioClient, PresidioError
from agentgov.processor.proto import ext_mcp_pb2 as pb
from agentgov.processor.proto import ext_mcp_pb2_grpc as pb_grpc

log = logging.getLogger(__name__)

DENIED = pb.AuthorizationError.PERMISSION_DENIED
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$")


def trace_id_from(traceparents: Iterable[str]) -> str | None:
    """The W3C trace ID in the first valid ``traceparent`` value."""
    for value in traceparents:
        match = _TRACEPARENT.match(value.strip().lower())
        if match and match.group(1) != "0" * 32:
            return match.group(1)
    return None


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
    return trace_id_from(values)


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


def _header(headers: Any, name: str) -> str | None:
    """A request header agentgateway forwarded to the processor."""
    for h in headers:
        if h.key.lower() == name:
            value = h.value
            return value.decode("latin-1") if isinstance(value, bytes) else str(value)
    return None


def _delegation(chain: chains.Chain | None) -> dict[str, Any] | None:
    """What the ledger keeps of the delegation a call was made under."""
    if chain is None:
        return None
    return {"chain": chain.links, "uid": chain.uid, "parent_uid": chain.parent}


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

    def add_verdict(self, verdict: classifier.Verdict) -> None:
        """The classifier's verdict, waited for: what it flags counts as what the rules
        flag does."""
        self.summary["classifier"] = verdict.summary()
        if verdict.flagged:
            flag, reasons = _FLAGS[verdict.criterion]
            self.summary[flag] = True
            self.summary[reasons] = [*(self.summary.get(reasons) or []), "classifier"]


# Where a criterion's verdict goes in the detections: its flag and its reasons.
_FLAGS = {
    classifier.INJECTION: ("prompt_injection", "injection_reasons"),
    classifier.JAILBREAK: ("jailbreak", "jailbreak_reasons"),
}


class GovernanceProcessor(pb_grpc.ExtMcpServicer):
    def __init__(
        self,
        settings: Settings,
        *,
        opa: OpaClient,
        control_plane: ControlPlaneClient,
        recorder: DecisionRecorder,
        presidio: PresidioClient | None = None,
        traffic_classifier: classifier.TrafficClassifier | None = None,
        decision_point: authzen.AuthZenClient | None = None,
    ) -> None:
        self.settings = settings
        self.opa = opa
        # The organisation's own AuthZEN decision point, asked beside AgentGov's policies.
        self.authzen = decision_point or (
            authzen.AuthZenClient(
                settings.authzen_url,
                token=settings.authzen_token,
                timeout=settings.authzen_timeout_seconds,
            )
            if settings.authzen_url
            else None
        )
        self.cp = control_plane
        self.recorder = recorder
        self.presidio = presidio
        self.classifier = traffic_classifier
        self.features = FeatureModes(opa)
        # Signs and checks the delegations agents carry from agent to agent.
        self.chain_keys = chains.keys(settings.service_token)
        self._background: set[asyncio.Task[Any]] = set()

    # ------------------------------------------------------------------ helpers
    async def decide(
        self, path: str, opa_input: dict[str, Any], *, kind: str
    ) -> tuple[dict[str, Any], str | None]:
        """AgentGov's decision on a call (OPA's), with, as the external-decision-point
        feature says, the organisation's own AuthZEN decision point's beside it
        (agentgov.authzen): asked about calls AgentGov lets through, its denial stands
        when it is enforced, and is recorded as monitored otherwise."""
        decision, decision_id = await self.opa.evaluate(path, opa_input)
        if (
            self.authzen is None
            or decision.get("effect") == "deny"
            or opa_input.get("phase", "request") != "request"
        ):
            return decision, decision_id
        mode = (await self.features.current()).get("external-decision-point", "off")
        if mode == "off":
            return decision, decision_id

        def monitored(note: str) -> dict[str, Any]:
            return {**decision, "monitored": [*(decision.get("monitored") or []), note]}

        request = authzen.request_for(kind, opa_input, agent=decision.get("agent"))
        try:
            verdict = authzen.interpret(
                await self.authzen.evaluate(request, request_id=decision_id)
            )
        except authzen.AuthZenError as exc:
            log.warning("external decision point: %s", exc)
            if mode == "enforce":
                reasons = [
                    f"Your decision point can't be asked ({exc}); the call was not forwarded"
                ]
                return {**decision, "effect": "deny", "reasons": reasons}, decision_id
            return monitored(f"external-decision-point: couldn't be asked ({exc})"), decision_id
        if verdict.effect == "allow":
            if not verdict.redact:
                return decision, decision_id
            if mode == "enforce":
                redact = sorted({*(decision.get("redact") or []), *verdict.redact})
                return {**decision, "redact": redact}, decision_id
            masked = ", ".join(sorted(verdict.redact))
            return monitored(f"external-decision-point: would mask {masked}"), decision_id
        said = "; ".join(verdict.reasons)
        if mode != "enforce":
            would = "deny" if verdict.effect == "deny" else "ask for approval"
            return monitored(f"external-decision-point: would {would}: {said}"), decision_id
        if verdict.effect == "deny":
            reasons = [f"Your decision point denied it: {r}" for r in verdict.reasons]
            return {**decision, "effect": "deny", "reasons": reasons}, decision_id
        asked = list(decision.get("reasons") or []) if decision.get("effect") != "allow" else []
        reasons = [*asked, f"Your decision point asks for approval: {said}"]
        return {**decision, "effect": "require_approval", "reasons": reasons}, decision_id

    def _spawn(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _inspect(self, payload: Any, *, protect: bool, check_injection: bool) -> Inspection:
        """Look for credentials and personal data (``protect``: data protection is on)
        and, with ``check_injection``, for instructions aimed at the agent."""
        scan, strings = detectors.scan_local(
            payload, check_injection=check_injection, check_secrets=protect
        )
        if protect and self.presidio is not None and strings:
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

    def classifier_mode(self, modes: dict[str, str], check: str) -> str:
        """How the classifier takes part in ``check`` (a feature): "inline" where both are
        enforced, "background" where both are on otherwise, else "off"."""
        mine, checked = modes.get("traffic-classifier", "off"), modes.get(check, "off")
        if self.classifier is None or "off" in (mine, checked):
            return "off"
        return "inline" if mine == checked == "enforce" else "background"

    async def second_opinion(self, inspection: Inspection, text: str, criterion: str) -> None:
        """The classifier's verdict on ``text``, waited for, into ``inspection``."""
        assert self.classifier is not None
        inspection.add_verdict(await self.classifier.inline(text, criterion))

    def classify_later(self, text: str, criterion: str, **context: Any) -> None:
        """The classifier's verdict in the background: what it flags goes to the ledger,
        and the control plane raises a finding (``context``: what was classified, the
        call's resource, agent, identity, person and trace)."""
        assert self.classifier is not None

        def report(verdict: classifier.Verdict) -> None:
            if verdict.flagged:
                self._record(kind="classifier", classifier=verdict.summary(), **context)

        if not self.classifier.later(text, criterion, report):
            log.warning("the classifier is busy: a %s went unclassified", context.get("subject"))

    def _fail_closed(self, modes: dict[str, str]) -> bool:
        """Whether a call must stop when personal data can't be looked for: only while
        data protection is enforced, and AGENTGOV_PRESIDIO_FAILURE_MODE says so."""
        return (
            modes["data-protection"] == "enforce"
            and self.settings.presidio_failure_mode == "closed"
        )

    @staticmethod
    def _identity(meta: dict[str, Any]) -> dict[str, Any]:
        return {k: meta[k] for k in ("client_id", "agent_id", "subject") if meta.get(k)}

    @staticmethod
    def holder(identity: dict[str, Any]) -> dict[str, Any] | None:
        """The agent a call's token names, for refusals made before policy looks it up:
        a delegation an agent can't use is that agent's doing."""
        return {"id": identity["agent_id"]} if identity.get("agent_id") else None

    def delegation(
        self, token: str | None, identity: dict[str, Any], person: dict[str, Any] | None
    ) -> tuple[chains.Chain | None, str | None]:
        """The delegation a call carries (None without one), or why it can't be used: an
        agent calls with one when another agent handed it the work (agentgov.identity.chains)."""
        if not token:
            return None, None
        try:
            chain = chains.verify(self.chain_keys, token, holder=identity.get("agent_id"))
        except chains.ChainError as exc:
            return None, f"The call can't be accepted: {exc}"
        if not chains.same_person(person, chain.person):
            return None, (
                "The call can't be accepted: the agent acts for one person, and the "
                "delegation it carries is for another"
            )
        return chain, None

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
        person = people.person_of(meta)
        # Work another agent handed down: the chain, and the person at its head.
        chain, unusable = self.delegation(_header(request.headers, chains.HEADER), identity, person)
        if chain is not None and person is None:
            person = chain.person
        modes = await self.features.current()
        inspection = await self._inspect(
            payload, protect=modes["data-protection"] != "off", check_injection=False
        )
        resource = f"{server}/{target}"
        monitored: list[str] = []  # what monitored controls would have done

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
                user=person,
                effect=effect,
                reasons=reasons,
                redacted=redacted or [],
                detections=inspection.summary,
                approval_id=approval_id,
                monitored=monitored,
                opa_decision_id=decision_id,
                latency_ms=round((time.perf_counter() - started) * 1000, 1),
                trace_id=trace_id,
                delegation=_delegation(chain),
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

        if unusable:
            finish("deny", [unusable], agent=self.holder(identity))
            return reject("deny", [unusable])
        if inspection.scan.pii_error and self._fail_closed(modes):
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
        if person:
            opa_input["user"] = person
        if chain is not None:
            opa_input["chain"] = chain.links
        try:
            decision, decision_id = await self.decide(
                "agentgov/mcp/decision", opa_input, kind="tool"
            )
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            reasons = ["Policy engine unavailable; the call was not forwarded"]
            finish("deny", reasons)
            return reject("deny", reasons)

        effect = decision.get("effect", "deny")
        reasons = list(decision.get("reasons") or [])
        agent = decision.get("agent")
        monitored = list(decision.get("monitored") or [])

        if agent is None and modes["unknown-callers"] == "monitor":
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
                        "user": person,
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
                approval = outcome["approval"]
                waiting = (
                    f" for {approval['on_behalf_of']} to approve at {outcome['url']}"
                    if approval.get("deciders") == "person" and outcome.get("url")
                    else ""
                )
                reasons = [
                    f"Human approval required: {'; '.join(reasons)}. Approval request "
                    f"{approval_id} is pending{waiting}; retry the same call once it is "
                    "approved."
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
        person = people.person_of(meta)
        if method == "tools/list":
            return await self._filter_tools(server, identity, person, result)
        if method not in ("tools/call", "resources/read"):
            return _pass_response()

        started = time.perf_counter()
        target = (meta.get("request") or {}).get("agentgov_target") or "unknown"
        modes = await self.features.current()
        inspection = await self._inspect(
            result,
            protect=modes["data-protection"] != "off",
            check_injection=modes["prompt-injection"] != "off",
        )
        # The classifier's second opinion on a result the rules let through: waited for,
        # or asked once the result went on.
        how = self.classifier_mode(modes, "prompt-injection")
        text = ""
        if how != "off" and not inspection.summary.get("prompt_injection"):
            text = classifier.text_of(result)
        if how == "inline" and text.strip():
            await self.second_opinion(inspection, text, classifier.INJECTION)
        monitored: list[str] = []

        def later(agent: dict[str, Any] | None) -> None:
            if how == "background" and text.strip():
                self.classify_later(
                    text,
                    classifier.INJECTION,
                    subject="tool result",
                    phase="response",
                    method=method,
                    server=server,
                    target=target,
                    resource=f"{server}/{target}",
                    agent=agent,
                    identity=identity,
                    user=person,
                    trace_id=trace_id,
                )

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
                user=person,
                effect=effect,
                reasons=reasons,
                redacted=redacted or [],
                detections=inspection.summary,
                monitored=monitored,
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

        if inspection.scan.pii_error and self._fail_closed(modes):
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
        if person:
            opa_input["user"] = person
        try:
            decision, decision_id = await self.opa.evaluate("agentgov/mcp/decision", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            reasons = ["Policy engine unavailable; the result was withheld"]
            finish("deny", reasons)
            return withhold(reasons)

        agent = decision.get("agent")
        monitored = list(decision.get("monitored") or [])
        if agent is None and modes["unknown-callers"] == "monitor":
            finish(
                "allow", ["monitor mode: caller is not a registered agent"], decision_id=decision_id
            )
            later(None)
            return _pass_response()
        if decision.get("effect") == "deny":
            reasons = list(decision.get("reasons") or [])
            finish("deny", reasons, agent=agent, decision_id=decision_id)
            return withhold(reasons)
        redact = set(decision.get("redact") or []) & inspection.scan.categories()
        later(agent)
        if redact:
            finish("allow", [], agent=agent, redacted=sorted(redact), decision_id=decision_id)
            mutated = detectors.redact(result, inspection.scan.spans, redact)
            return pb.McpResponseResult(mutated=json.dumps(mutated).encode())
        finish("allow", [], agent=agent, decision_id=decision_id)
        return _pass_response()

    async def _filter_tools(
        self,
        server: str,
        identity: dict[str, Any],
        person: dict[str, Any] | None,
        result: dict[str, Any],
    ) -> pb.McpResponseResult:
        tools = [t for t in result.get("tools") or [] if isinstance(t, dict)]
        modes = await self.features.current()
        integrity = modes["tool-integrity"]
        poisoned = detectors.scan_tool_definitions(tools) if integrity != "off" else {}
        self._spawn(self._report_catalog(server, tools, poisoned))
        opa_input = {
            "phase": "response",
            "method": "tools/list",
            "agent": identity,
            "resource": {"server": server},
            "tools": [{"name": t.get("name")} for t in tools],
            "poisoned": poisoned,
        }
        if person:
            opa_input["user"] = person
        try:
            view, _ = await self.opa.evaluate("agentgov/mcp/list_view", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed for tools/list: %s", exc)
            view = {"agent": None, "visible": []}
        if view.get("agent") is None and modes["unknown-callers"] == "monitor":
            self._spawn(self._observe_unknown(identity, server, "tools/list"))
            quarantined = set(poisoned) if integrity == "enforce" else set()
            visible = {t.get("name") for t in tools} - quarantined
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

    # Mutual TLS with the other components (agentgov.tls), when it has a certificate: OPA
    # and the control plane are called with it, and agentgateway must show its own.
    identity = settings.tls()
    http = httpx.AsyncClient(
        timeout=5.0, transport=identity.async_transport() if identity else None
    )
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
        ],
        # With AGENTGOV_TLS_PEERS, only those callers (agentgateway's certificate).
        interceptors=identity.grpc_interceptors() if identity else None,
    )
    # IBM Granite Guardian's second opinion on traffic, where it is configured.
    traffic_classifier = classifier.TrafficClassifier(settings) if settings.guardian_url else None
    processor = GovernanceProcessor(
        settings,
        opa=opa,
        control_plane=control_plane,
        recorder=recorder,
        presidio=presidio,
        traffic_classifier=traffic_classifier,
    )
    pb_grpc.add_ExtMcpServicer_to_server(processor, server)
    # Agents' answers to other agents: agentgateway's external processing, on the same port.
    from agentgov.processor import a2a_answers
    from agentgov.processor.proto import ext_proc_pb2_grpc

    ext_proc_pb2_grpc.add_ExternalProcessorServicer_to_server(
        a2a_answers.AnswerChecks(processor), server
    )
    if identity:
        server.add_secure_port(settings.processor_listen, identity.grpc_credentials())
    else:
        server.add_insecure_port(settings.processor_listen)
    # Model calls: agentgateway's guardrail webhook, over HTTP.
    from agentgov.processor import model_guard

    webhook = model_guard.server(
        model_guard.ModelGuard(processor), settings.processor_webhook_listen, tls=identity
    )
    recorder.start()
    await server.start()
    webhook_task = asyncio.create_task(webhook.serve())
    log.info(
        "governance processor listening on %s (tool calls, agents' answers) and %s (model calls)%s",
        settings.processor_listen,
        settings.processor_webhook_listen,
        ", over mutual TLS" if identity else "",
    )
    try:
        await server.wait_for_termination()
    finally:
        webhook.should_exit = True
        await webhook_task
        await server.stop(grace=5)
        if traffic_classifier is not None:
            await traffic_classifier.aclose()
        await recorder.stop()
        await http.aclose()

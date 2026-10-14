"""The governance processor's checks on the answers agents send each other
(docs/agent-to-agent.md).

agentgateway hands the processor the answers an agent called through an A2A route sends
back, as they stream (Envoy's external processing API, on the processor's gRPC port): a
JSON-RPC response, or server-sent events that carry one each (streamed messages, task
updates). The processor:

1. holds an answer until its end, and each event until it is whole, both up to MAX_HELD
   bytes;
2. looks in it for credentials and personal data, and for instructions aimed at the
   agent that will read it (the rules, and the classifier's second opinion where it is
   configured: ``agentgov.processor.classifier``), as it does in a tool result;
3. asks OPA (``data.agentgov.a2a.decision``, with ``phase: "response"``); and
4. passes it on, with credentials and personal data masked as the decision says, or
   withholds it: a JSON-RPC error with the answer's id goes in its place, and in a
   stream nothing follows it.

Answers are checked whatever their content type says, as A2A's clients read JSON whatever
the label: a JSON-RPC response in its result or its error, any other JSON whole. The
agent's card passes as it is (agentgateway pointed it at itself already), and so do
failures and answers that aren't JSON, gRPC's among them. The gateway asks agents for
answers that aren't compressed; one compressed anyway can't be read, and, like one too
long to hold, is withheld while a control that looks at answers is enforced (unless
AGENTGOV_GATEWAY_FAILURE_MODE is open), and passes on unchecked otherwise. Answers in
which something was found, masked or withheld are in the ledger
(decision.a2a.response), linked to their call by its trace.

While a2a-masking is enforced, the gateway sends the messages agents send each other (the
requests) here too, once the call was decided (agentgov.processor.a2a_guard, which records
what is masked): each is held until its end, and the personal data in it that the agent
called may not have is masked before it goes on.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from google.protobuf import json_format

from agentgov.identity import people
from agentgov.opa.client import OpaError
from agentgov.processor import classifier, detectors
from agentgov.processor.proto import ext_proc_pb2 as pb
from agentgov.processor.proto import ext_proc_pb2_grpc as pb_grpc
from agentgov.processor.server import trace_id_from

if TYPE_CHECKING:
    from agentgov.processor.server import GovernanceProcessor

log = logging.getLogger(__name__)

# The namespace of the metadata agentgateway sends with each answer (agentgov.gateway).
NAMESPACE = "agentgov"
CARD = "/.well-known/agent-card.json"
# gRPC's binding: not JSON, and the gateway publishes JSON-RPC's.
GRPC = "application/grpc"
# A JSON answer, or an event, held at most. Past it, the answer is withheld while a
# control that looks at answers is enforced (unless AGENTGOV_GATEWAY_FAILURE_MODE is open),
# and passes on unchecked otherwise.
MAX_HELD = 4 * 1024 * 1024
# The JSON-RPC error a withheld answer becomes (as a refused call's, agentgov.processor.
# a2a_guard).
REFUSED = -32600
_SEPARATORS = (b"\r\n\r\n", b"\n\n", b"\r\r")


def _metadata(req: pb.ProcessingRequest) -> dict[str, str]:
    fields = req.metadata_context.filter_metadata.get(NAMESPACE)
    if fields is None:
        return {}
    return {k: str(v) for k, v in json_format.MessageToDict(fields).items() if v}


def _json(value: str | None) -> Any:
    try:
        return json.loads(value) if value else None
    except ValueError:
        return None


def _next_event(held: bytes) -> tuple[bytes, bytes] | None:
    """The first whole event in ``held`` (with its blank line), and the rest."""
    ends = [(i, sep) for sep in _SEPARATORS if (i := held.find(sep)) >= 0]
    if not ends:
        return None
    i, sep = min(ends)
    return held[: i + len(sep)], held[i + len(sep) :]


def _event_data(event: bytes) -> tuple[list[bytes], bytes]:
    """An event's lines other than its data, and its data (data lines joined)."""
    other: list[bytes] = []
    data: list[bytes] = []
    for line in event.splitlines():
        if line.startswith(b"data:"):
            data.append(line[5:].removeprefix(b" "))
        elif line:
            other.append(line)
    return other, b"\n".join(data)


def _person(meta: dict[str, str]) -> dict[str, Any] | None:
    """The person the caller acts for, from the claims of its token."""
    return people.person_of(
        {
            "subject": meta.get("subject"),
            "username": meta.get("username"),
            "email": meta.get("email"),
            "groups": _json(meta.get("groups")),
            "roles": _json(meta.get("roles")),
            "act": _json(meta.get("act")),
            "sign_in": _json(meta.get("sign_in")),
            "client_id": meta.get("client_id"),
        }
    )


def _withheld(rpc_id: Any, reasons: list[str]) -> dict[str, Any]:
    data = {"@type": "agentgov.dev/Decision", "effect": "deny", "reasons": reasons}
    error = {"code": REFUSED, "message": "AgentGov: " + "; ".join(reasons), "data": [data]}
    return {"jsonrpc": "2.0", "id": rpc_id, "error": error}


def _streamed(data: bytes, end: bool) -> pb.BodyResponse:
    out = pb.BodyResponse()
    out.response.body_mutation.streamed_response.body = data
    out.response.body_mutation.streamed_response.end_of_stream = end
    return out


def _headers(headers: pb.HttpHeaders) -> dict[str, str]:
    return {
        h.key.lower(): h.value or h.raw_value.decode("latin-1") for h in headers.headers.headers
    }


def _identity(meta: dict[str, Any]) -> dict[str, Any]:
    """The caller, as the gateway names it (agentgov.gateway._answer_checks): the agent and
    client AgentGov's own tokens name, or another issuer's token's issuer and subject."""
    found = {k: meta[k] for k in ("agent_id", "client_id", "issuer") if meta.get(k)}
    if found.get("issuer") and meta.get("subject"):
        found["subject"] = meta["subject"]
    return found


class AnswerChecks(pb_grpc.ExternalProcessorServicer):
    """agentgateway's external processing on the A2A routes: answers, as they come; and
    while a2a-masking is enforced, the messages sent (requests), to mask them."""

    def __init__(self, processor: GovernanceProcessor) -> None:
        self.p = processor

    async def Process(
        self, requests: AsyncIterator[pb.ProcessingRequest], context: Any
    ) -> AsyncIterator[pb.ProcessingResponse]:
        message: Message | None = None
        answer: Answer | None = None
        async for req in requests:
            kind = req.WhichOneof("request")
            if kind == "request_headers":
                message = Message(self.p, _metadata(req), _headers(req.request_headers))
                reply = pb.HeadersResponse()
                if message.checked:
                    reply.response.header_mutation.remove_headers.append("content-length")
                yield pb.ProcessingResponse(request_headers=reply)
            elif kind == "response_headers":
                answer = Answer(self.p, _metadata(req), _headers(req.response_headers))
                reply = pb.HeadersResponse()
                reply.response.header_mutation.remove_headers.extend(await answer.start())
                yield pb.ProcessingResponse(response_headers=reply)
            elif kind in ("response_body", "request_body"):
                body = getattr(req, kind)
                data = body.body
                if kind == "response_body" and answer is not None:
                    data = await answer.feed(body.body, body.end_of_stream)
                elif kind == "request_body" and message is not None:
                    data = await message.feed(body.body, body.end_of_stream)
                yield pb.ProcessingResponse(**{kind: _streamed(data, body.end_of_stream)})
            elif kind in ("response_trailers", "request_trailers"):
                # A body that ended with its trailers: what is held of it goes first.
                held = answer if kind == "response_trailers" else message
                if held is not None and not held.ended:
                    rest = await held.feed(b"", True)
                    if rest:
                        body_kind = kind.replace("trailers", "body")
                        yield pb.ProcessingResponse(**{body_kind: _streamed(rest, False)})
                yield pb.ProcessingResponse(**{kind: pb.TrailersResponse()})


def _message_of(value: Any) -> dict[str, Any] | None:
    """The message a request sends: a JSON-RPC call's (SendMessage,
    SendStreamingMessage), or the REST binding's."""
    if not isinstance(value, dict):
        return None
    params = value.get("params") if "method" in value else value
    message = params.get("message") if isinstance(params, dict) else None
    return message if isinstance(message, dict) else None


class Message:
    """A message one agent sends another (a request), held until its end and masked as
    the decision says. The gateway sends requests here only while a2a-masking is enforced;
    the call itself was decided already (agentgov.processor.a2a_guard), which recorded what
    is masked."""

    def __init__(
        self, processor: GovernanceProcessor, meta: dict[str, str], headers: dict[str, str]
    ) -> None:
        self.p = processor
        # Compressed, it can't be read: neither can the call's check, which saw no personal
        # data in it to mask.
        encoding = headers.get("content-encoding", "").strip().lower()
        self.checked = encoding in ("", "identity")
        self.held = b""
        self.ended = False
        self.target = meta.get("agent") or "unknown"
        self.identity = _identity(meta)
        self._resolved = False
        self.person = _person(meta)

    async def _caller(self) -> dict[str, Any]:
        """The caller, with its agent's ID where its token names its workload identity
        (GovernanceProcessor.caller): looked up once."""
        if not self._resolved:
            self.identity, self._resolved = await self.p.caller(self.identity), True
        return self.identity

    async def feed(self, data: bytes, end: bool) -> bytes:
        """What passes on of the message, given its next piece."""
        self.ended = self.ended or end
        if not self.checked:
            return data
        self.held += data
        if len(self.held) > MAX_HELD:
            # The gateway refuses messages this long before they are checked (A2A_MAX_BODY).
            held, self.held = self.held, b""
            self.checked = False
            return held
        if not end:
            return b""
        body, self.held = self.held, b""
        try:
            return await self._mask(body)
        except Exception as exc:
            if self.p.unchecked(self.p.features.last(self.identity)):
                log.exception("masking a message to agent %s failed; it goes on", self.target)
                self.p.note_unchecked(
                    f"masking it failed: {type(exc).__name__}",
                    kind="a2a",
                    phase="request",
                    method="message",
                    server=self.target,
                    target=self.target,
                    resource=self.target,
                    identity=self.identity,
                    user=self.person,
                )
                return body
            # Enforced masking that can't be done: the call fails rather than go unmasked.
            log.exception("masking a message to agent %s failed", self.target)
            raise

    async def _mask(self, body: bytes) -> bytes:
        value = _json(body.decode("utf-8", "replace"))
        message = _message_of(value)
        parts = message.get("parts") if message is not None else None
        if not isinstance(parts, list) or not parts:
            return body
        modes = await self.p.features.for_caller(await self._caller())
        if modes["a2a-masking"] != "enforce" or modes["data-protection"] == "off":
            return body
        inspection = await self.p._inspect(parts, protect=True, check_injection=False)
        if not inspection.scan.categories():
            return body
        opa_input: dict[str, Any] = {
            "kind": "a2a",
            "phase": "request",
            "method": str(value.get("method") or "SendMessage"),
            "agent": self.identity,
            "target": self.target,
            "detections": inspection.summary,
        }
        if self.person:
            opa_input["user"] = self.person
        decision, _ = await self.p.opa.evaluate("agentgov/a2a/decision", opa_input)
        redact = set(decision.get("redact") or []) & inspection.scan.categories()
        if not redact:
            return body
        assert message is not None
        message["parts"] = detectors.redact(parts, inspection.scan.spans, redact)
        return json.dumps(value).encode()


class Answer:
    """One answer as it streams: what is held of it, and whether it was withheld."""

    def __init__(
        self, processor: GovernanceProcessor, meta: dict[str, str], headers: dict[str, str]
    ) -> None:
        self.p = processor
        self.meta = meta
        content_type = headers.get("content-type", "").lower()
        self.events = "text/event-stream" in content_type
        status = headers.get(":status", "200")
        self.checked = (
            status.startswith("2")
            and not content_type.startswith(GRPC)
            and not meta.get("path", "").endswith(CARD)
        )
        # Compressed in spite of the gateway's asking for it plain (accept-encoding:
        # identity, agentgov.gateway): the processor can't read it.
        encoding = headers.get("content-encoding", "").strip().lower()
        self.encoding = encoding if encoding not in ("", "identity") else None
        self.unreadable: list[str] = []
        self.held = b""
        self.ended = False
        # A withheld answer, or event, ends what passes on.
        self.closed = False
        self.target = meta.get("agent") or "unknown"
        self.identity = _identity(meta)
        self._resolved = False
        self.person = _person(meta)
        self.trace_id = trace_id_from([meta.get("traceparent") or ""])

    async def _caller(self) -> dict[str, Any]:
        """The caller, with its agent's ID where its token names its workload identity
        (GovernanceProcessor.caller): looked up once."""
        if not self._resolved:
            self.identity, self._resolved = await self.p.caller(self.identity), True
        return self.identity

    async def start(self) -> list[str]:
        """The headers to remove from the answer before it passes on."""
        if not self.checked:
            return []
        if self.encoding is None:
            return ["content-length"]  # what passes on may differ in length
        if not await self._withheld_unchecked():
            self.checked = False  # nothing enforced looks at it: it passes, unchecked
            return []
        self.unreadable = [f"The answer is compressed ({self.encoding}), so it can't be checked"]
        return ["content-length", "content-encoding"]  # what replaces it is neither

    async def feed(self, data: bytes, end: bool) -> bytes:
        """What passes on of the answer, given its next piece."""
        self.ended = self.ended or end
        if not self.checked:
            return data
        if self.closed:
            return b""
        try:
            if self.unreadable:
                return self._refuse(self.unreadable)
            return await self._feed(data, end)
        except Exception:
            log.exception("checking an answer from agent %s failed; withholding it", self.target)
            self.closed = True
            error = _withheld(None, ["Governance processor error; the answer was withheld"])
            return self._frame(json.dumps(error).encode())

    async def _feed(self, data: bytes, end: bool) -> bytes:
        self.held += data
        if not self.events:
            if len(self.held) > MAX_HELD:
                return await self._too_long()
            if not end:
                return b""
            body, self.held = self.held, b""
            return await self._answer(body)
        out: list[bytes] = []
        while not self.closed and (split := _next_event(self.held)) is not None:
            event, self.held = split
            out.append(await self._event(event))
        if end and self.held.strip() and not self.closed:
            out.append(await self._event(self.held + b"\n\n"))
            self.held = b""
        elif len(self.held) > MAX_HELD and not self.closed:
            out.append(await self._too_long())
        return b"".join(out)

    def _frame(self, data: bytes) -> bytes:
        return b"data: " + data + b"\n\n" if self.events else data

    async def _withheld_unchecked(self) -> bool:
        """Whether an answer that can't be checked is withheld: while a control that
        looks at answers is enforced, unless AGENTGOV_GATEWAY_FAILURE_MODE is open."""
        modes = await self.p.features.for_caller(await self._caller())
        enforced = "enforce" in (modes["data-protection"], modes["prompt-injection"])
        return enforced and not self.p.unchecked(modes)

    def _refuse(self, reasons: list[str]) -> bytes:
        """The answer withheld without a look at it: an error, and nothing after it."""
        self.closed = True
        self._record("deny", reasons, {}, None, None)
        return self._frame(json.dumps(_withheld(None, reasons)).encode())

    async def _too_long(self) -> bytes:
        held, self.held = self.held, b""
        if await self._withheld_unchecked():
            return self._refuse([f"The answer is longer than {MAX_HELD} bytes, too long to check"])
        # Nothing enforced looks at it: it passes on, unchecked, from what was held.
        self.checked = False
        return held

    async def _answer(self, body: bytes) -> bytes:
        value = _json(body.decode("utf-8", "replace"))
        if value is None:
            return body  # not JSON: no A2A client reads it as an answer
        checked = await self._check(value)
        return body if checked is value else json.dumps(checked).encode()

    async def _event(self, event: bytes) -> bytes:
        other, data = _event_data(event)
        value = _json(data.decode("utf-8", "replace"))
        if value is None:
            return event  # comments, keep-alives, and what isn't JSON
        checked = await self._check(value)
        if checked is value:
            return event
        lines = [*other, b"data: " + json.dumps(checked).encode()]
        return b"\n".join(lines) + b"\n\n"

    async def _check(self, value: Any) -> Any:
        """The answer to pass on: ``value`` itself, masked as decided, or an error in its
        place (and then nothing more of a stream passes). A JSON-RPC response is looked at
        in its result, or its error; anything else (A2A's REST binding) whole. When it
        can't be checked, it passes as it is if AGENTGOV_GATEWAY_FAILURE_MODE says so."""
        try:
            return await self._decide(value)
        except Exception as exc:
            if not self.p.unchecked(self.p.features.last(self.identity)):
                raise
            log.exception("checking an answer from agent %s failed; it goes on", self.target)
            why = f"the governance processor failed: {type(exc).__name__}"
            self._record("allow", [self.p.unchecked_reason(why)], {}, None, None, unchecked=why)
            return value

    async def _decide(self, value: Any) -> Any:
        started = time.perf_counter()
        rpc = value if isinstance(value, dict) else {}
        key = next((k for k in ("result", "error") if k in rpc), None)
        content = value[key] if key else value
        modes = await self.p.features.for_caller(await self._caller())
        inspection = await self.p._inspect(
            content,
            protect=modes["data-protection"] != "off",
            check_injection=modes["prompt-injection"] != "off",
        )
        how = self.p.classifier_mode(modes, "prompt-injection")
        text = ""
        if how != "off" and not inspection.summary.get("prompt_injection"):
            text = classifier.text_of(content)
        if how == "inline" and text.strip():
            await self.p.second_opinion(inspection, text, classifier.INJECTION)

        def withhold(reasons: list[str], agent: Any = None, called: Any = None, **kw: Any) -> Any:
            self._record("deny", reasons, inspection.summary, agent, called, started=started, **kw)
            self.closed = self.events
            return _withheld(rpc.get("id"), reasons)

        if inspection.scan.pii_error and self.p._fail_closed(modes):
            return withhold(["Content inspection is unavailable, so the answer was withheld"])
        if self.p.classifier_closed(inspection):
            return withhold(
                [
                    f"The classifier gave no verdict ({inspection.classifier_error}), so the "
                    "answer was withheld"
                ]
            )
        opa_input: dict[str, Any] = {
            "kind": "a2a",
            "phase": "response",
            "method": "answer",
            "agent": self.identity,
            "target": self.target,
            "detections": inspection.summary,
        }
        if self.person:
            opa_input["user"] = self.person
        try:
            decision, decision_id = await self.p.opa.evaluate("agentgov/a2a/decision", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            if self.p.unchecked(modes):
                why = f"the policy engine is unavailable: {exc}"
                self._record(
                    "allow",
                    [self.p.unchecked_reason(why)],
                    inspection.summary,
                    None,
                    None,
                    started=started,
                    unchecked=why,
                )
                return value
            return withhold(["Policy engine unavailable; the answer was withheld"])
        agent, called = decision.get("agent"), decision.get("target")
        monitored = list(decision.get("monitored") or [])
        # A caller the registry doesn't know passes while unknown callers are monitored.
        unknown_passes = agent is None and modes["unknown-callers"] == "monitor"
        if decision.get("effect") == "deny" and not unknown_passes:
            reasons = list(decision.get("reasons") or [])
            return withhold(reasons, agent, called, monitored=monitored, decision_id=decision_id)
        redact = set(decision.get("redact") or []) & inspection.scan.categories()
        if how == "background" and text.strip():
            self.p.classify_later(
                text,
                classifier.INJECTION,
                subject="answer",
                phase="response",
                method="answer",
                server=self.target,
                target=self.target,
                resource=self.target,
                agent=agent,
                identity=self.identity,
                user=self.person,
                trace_id=self.trace_id,
                a2a={"target": self.target, "target_id": (called or {}).get("id")},
            )
        found = inspection.summary.get("categories") or inspection.summary.get("prompt_injection")
        if redact or found or monitored:
            self._record(
                "allow",
                [],
                inspection.summary,
                agent,
                called,
                started=started,
                redacted=sorted(redact),
                monitored=monitored,
                decision_id=decision_id,
            )
        if not redact:
            return value
        masked = detectors.redact(content, inspection.scan.spans, redact)
        return {**rpc, key: masked} if key else masked

    def _record(
        self,
        effect: str,
        reasons: list[str],
        detections: dict[str, Any],
        agent: Any,
        called: Any,
        *,
        started: float | None = None,
        redacted: list[str] | None = None,
        monitored: list[str] | None = None,
        decision_id: str | None = None,
        unchecked: str | None = None,
    ) -> None:
        self.p._record(
            kind="a2a",
            phase="response",
            method="answer",
            server=self.target,
            target=self.target,
            resource=self.target,
            agent=agent,
            identity=self.identity,
            user=self.person,
            effect=effect,
            reasons=reasons,
            redacted=redacted or [],
            detections=detections,
            monitored=monitored or [],
            opa_decision_id=decision_id,
            latency_ms=round((time.perf_counter() - started) * 1000, 1) if started else None,
            trace_id=self.trace_id,
            a2a={"target": self.target, "target_id": (called or {}).get("id")},
            unchecked=unchecked,
        )

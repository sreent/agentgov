"""The governance processor's checks on model calls: agentgateway's guardrail webhook.

Each approved model provider is a route on the gateway (``agentgov.gateway``).
agentgateway sends the processor every prompt before it leaves for the provider
(``POST /request``) and every answer before it reaches the agent
(``POST /response``), with the caller's identity (and the person it acts for, if
any), the provider and the model in headers it computes from the validated token.
For each one the processor:

1. looks for credentials and personal data in the conversation, for
   instructions aimed at the agent in the tool results the conversation holds,
   and for a jailbreak in its latest message from the user role,
2. asks OPA (``data.agentgov.models.decision``), and
3. answers: go ahead; go ahead with personal data masked; or refuse the prompt
   (or withhold the answer),

then records the outcome in the ledger, as it does for tool calls.

agentgateway shows the processor the conversation as text and takes a masked
conversation back as text, so masking would drop tool calls: the policy refuses
to mask a conversation that holds them rather than break it. Answers are never
masked, only withheld: an answer can arrive as a stream, which agentgateway can
stop but not rewrite.
"""

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from agentgov.identity import chains, people
from agentgov.opa.client import OpaError
from agentgov.processor import detectors, jailbreak
from agentgov.processor.server import Inspection, _delegation, trace_id_from

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentgov.processor.server import GovernanceProcessor

log = logging.getLogger(__name__)

# Headers agentgateway sets on webhook calls (agentgov.gateway renders them).
AGENT_ID = "x-agentgov-agent-id"
CLIENT_ID = "x-agentgov-client-id"
PROVIDER = "x-agentgov-provider"
MODEL = "x-agentgov-model"
# The person the agent acts for: the token's claims (agentgov.gateway.PERSON_HEADERS).
SUBJECT = "x-agentgov-subject"
USERNAME = "x-agentgov-username"
EMAIL = "x-agentgov-email"
GROUPS = "x-agentgov-groups"
ROLES = "x-agentgov-roles"
ACT = "x-agentgov-act"

PASS: dict[str, Any] = {"action": {}}
# The HTTP methods agentgateway checks A2A requests with (their own).
A2A_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def refuse(status: int, reasons: list[str], effect: str = "deny") -> dict[str, Any]:
    """Refuse a prompt or withhold an answer; the agent gets an OpenAI-style error."""
    message = "; ".join(reasons)
    error = {
        "message": message,
        "type": "agentgov_policy",
        "code": effect,
        "agentgov": {"effect": effect, "reasons": reasons},
    }
    return {
        "action": {"body": json.dumps({"error": error}), "status_code": status, "reason": message}
    }


def mask(messages: list[dict[str, Any]], categories: list[str]) -> dict[str, Any]:
    return {"action": {"body": {"messages": messages}, "reason": f"masked {', '.join(categories)}"}}


def holds_tool_calls(messages: list[dict[str, Any]]) -> bool:
    """Whether the conversation holds tool calls: agentgateway shows a tool result as a
    message from the role ``tool`` and a tool call as an assistant message without text."""
    return any(
        m.get("role") == "tool" or (m.get("role") == "assistant" and not m.get("content"))
        for m in messages
    )


class ModelGuard:
    """Answers agentgateway's guardrail webhook, with the processor's detectors, OPA
    client, feature modes and decision recorder."""

    def __init__(self, processor: GovernanceProcessor) -> None:
        self.p = processor

    def app(self) -> Starlette:
        # Calls between agents: agentgateway's external authorization, on the same server.
        from agentgov.processor.a2a_guard import A2AGuard

        a2a = A2AGuard(self.p)
        return Starlette(
            routes=[
                Route("/request", self._on_request, methods=["POST"]),
                Route("/response", self._on_response, methods=["POST"]),
                Route("/a2a/check/{target}", a2a.check, methods=list(A2A_METHODS)),
                Route("/healthz", lambda _: PlainTextResponse("ok"), methods=["GET"]),
            ]
        )

    async def _on_request(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
            return JSONResponse(await self.check_prompt(payload, request.headers))
        except Exception:
            log.exception("checking a prompt failed; refusing it")
            return JSONResponse(
                refuse(503, ["Governance processor error; the prompt was not sent"])
            )

    async def _on_response(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
            return JSONResponse(await self.check_answer(payload, request.headers))
        except Exception:
            log.exception("checking an answer failed; withholding it")
            return JSONResponse(
                refuse(503, ["Governance processor error; the answer was withheld"])
            )

    @staticmethod
    def _identity(headers: Any) -> dict[str, Any]:
        return {
            key: headers.get(header)
            for key, header in (("agent_id", AGENT_ID), ("client_id", CLIENT_ID))
            if headers.get(header)
        }

    @staticmethod
    def _person(headers: Any) -> dict[str, Any] | None:
        return people.person_of(
            {
                "subject": people.header_text(headers.get(SUBJECT)),
                "username": people.header_text(headers.get(USERNAME)),
                "email": people.header_text(headers.get(EMAIL)),
                "groups": people.header_json(headers.get(GROUPS)),
                "roles": people.header_json(headers.get(ROLES)),
                "act": people.header_json(headers.get(ACT)),
            }
        )

    def _recorder(
        self, phase: str, headers: Any, inspection: Inspection, monitored: list[str]
    ) -> Callable[..., None]:
        """Records the decision on one prompt or answer, when called with its outcome.

        agentgateway names the model only while it handles the prompt, so a decision on an
        answer names the provider; its trace ID links it to the prompt's decision."""
        started = time.perf_counter()
        provider, model = headers.get(PROVIDER) or "unknown", headers.get(MODEL) or ""
        identity = self._identity(headers)
        person = self._person(headers)
        chain, _ = self.p.delegation(headers.get(chains.HEADER), identity, person)
        if chain is not None and person is None:
            person = chain.person
        trace_id = trace_id_from([headers.get("traceparent") or ""])

        def finish(
            effect: str,
            reasons: list[str],
            *,
            agent: dict[str, Any] | None = None,
            redacted: list[str] | None = None,
            decision_id: str | None = None,
        ) -> None:
            self.p._record(
                kind="model",
                phase=phase,
                method="chat",
                server=provider,
                target=model,
                resource=f"{provider}/{model}" if model else provider,
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
                delegation=_delegation(chain),
            )

        return finish

    # ------------------------------------------------------------------ prompts
    async def check_prompt(self, payload: dict[str, Any], headers: Any) -> dict[str, Any]:
        messages = [
            m for m in (payload.get("body") or {}).get("messages") or [] if isinstance(m, dict)
        ]
        provider, model = headers.get(PROVIDER) or "unknown", headers.get(MODEL) or ""
        identity = self._identity(headers)
        modes = await self.p.features.current()
        inspection = await self.p._inspect(
            messages, protect=modes["data-protection"] != "off", check_injection=False
        )
        if modes["prompt-injection"] != "off":
            # Indirect prompt injection arrives in tool results.
            results = [m.get("content") for m in messages if m.get("role") == "tool"]
            injected, _ = detectors.scan_local(results, check_injection=True, check_secrets=False)
            inspection.scan.injection_score = injected.injection_score
            inspection.scan.injection_reasons = injected.injection_reasons
            inspection.summary = inspection.scan.summary(self.p.settings.prompt_injection_threshold)
        if modes["jailbreak-detection"] != "off":
            score, reasons = jailbreak.score(jailbreak.latest_prompt(messages))
            inspection.summary.update(
                jailbreak=score >= self.p.settings.prompt_injection_threshold,
                jailbreak_score=round(score, 3),
                jailbreak_reasons=reasons,
            )
        monitored: list[str] = []
        finish = self._recorder("request", headers, inspection, monitored)

        person = self._person(headers)
        chain, unusable = self.p.delegation(headers.get(chains.HEADER), identity, person)
        if unusable:
            finish("deny", [unusable], agent=self.p.holder(identity))
            return refuse(403, [unusable])
        if inspection.scan.pii_error and self.p._fail_closed(modes):
            reasons = ["Content inspection is unavailable, so the prompt was not sent"]
            finish("deny", reasons)
            return refuse(503, reasons)
        opa_input = {
            "kind": "model",
            "phase": "request",
            "agent": identity,
            "provider": provider,
            "model": model,
            "detections": inspection.summary,
            "tool_calls": holds_tool_calls(messages),
        }
        person = person or (chain.person if chain else None)
        if person:
            opa_input["user"] = person
        if chain is not None:
            opa_input["chain"] = chain.links
        try:
            decision, decision_id = await self.p.opa.evaluate("agentgov/models/decision", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            reasons = ["Policy engine unavailable; the prompt was not sent"]
            finish("deny", reasons)
            return refuse(503, reasons)

        agent = decision.get("agent")
        monitored.extend(decision.get("monitored") or [])
        if agent is None and modes["unknown-callers"] == "monitor":
            self.p._spawn(self.p._observe_unknown(identity, f"llm/{provider}", "chat"))
            finish(
                "allow", ["monitor mode: caller is not a registered agent"], decision_id=decision_id
            )
            return PASS
        reasons = list(decision.get("reasons") or [])
        if decision.get("effect") != "allow":
            finish("deny", reasons, agent=agent, decision_id=decision_id)
            return refuse(403, reasons)
        redact = set(decision.get("redact") or []) & inspection.scan.categories()
        if redact:
            finish("allow", [], agent=agent, redacted=sorted(redact), decision_id=decision_id)
            return mask(detectors.redact(messages, inspection.scan.spans, redact), sorted(redact))
        finish("allow", [], agent=agent, decision_id=decision_id)
        return PASS

    # ------------------------------------------------------------------ answers
    async def check_answer(self, payload: dict[str, Any], headers: Any) -> dict[str, Any]:
        modes = await self.p.features.current()
        if modes["data-protection"] == "off":
            return PASS  # the only control that looks at answers
        choices = [
            c for c in (payload.get("body") or {}).get("choices") or [] if isinstance(c, dict)
        ]
        contents = [(c.get("message") or {}).get("content") for c in choices]
        scan, _ = detectors.scan_local(contents, check_injection=False)
        if not scan.spans:
            return PASS  # nothing to decide; the prompt's decision is in the ledger
        inspection = Inspection(scan, self.p.settings.prompt_injection_threshold)
        monitored: list[str] = []
        finish = self._recorder("response", headers, inspection, monitored)
        opa_input = {
            "kind": "model",
            "phase": "response",
            "agent": self._identity(headers),
            "provider": headers.get(PROVIDER) or "unknown",
            "model": headers.get(MODEL) or "",
            "detections": inspection.summary,
        }
        person = self._person(headers)
        if person:
            opa_input["user"] = person
        try:
            decision, decision_id = await self.p.opa.evaluate("agentgov/models/decision", opa_input)
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            reasons = ["Policy engine unavailable; the answer was withheld"]
            finish("deny", reasons)
            return refuse(503, reasons)
        agent = decision.get("agent")
        monitored.extend(decision.get("monitored") or [])
        if agent is None and modes["unknown-callers"] == "monitor":
            finish(
                "allow", ["monitor mode: caller is not a registered agent"], decision_id=decision_id
            )
            return PASS
        reasons = list(decision.get("reasons") or [])
        if decision.get("effect") != "allow":
            finish("deny", reasons, agent=agent, decision_id=decision_id)
            return refuse(403, reasons)
        finish("allow", [], agent=agent, decision_id=decision_id)
        return PASS


class EmbeddedServer(uvicorn.Server):
    """uvicorn in the processor's event loop, beside its gRPC server: the process
    handles signals itself."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def server(guard: ModelGuard, listen: str) -> EmbeddedServer:
    host, _, port = listen.rpartition(":")
    config = uvicorn.Config(
        guard.app(),
        host=host or "0.0.0.0",  # noqa: S104 - the processor listens on its pod's network
        port=int(port),
        log_level="warning",
        access_log=False,
        lifespan="off",
    )
    return EmbeddedServer(config)

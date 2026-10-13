"""The governance processor's checks on calls between agents: agentgateway's external
authorization for the A2A routes (``/a2a/<agent>``, ``agentgov.gateway``).

agentgateway asks the processor about each request an agent sends another agent through
the gateway (``/a2a/check/<agent>``), with the caller's identity (and the person it acts
for, if any) in headers it computes from the validated token, the delegation the caller
carries, and the request's JSON-RPC body. The processor:

1. checks the delegation, if the caller carries one (``agentgov.identity.chains``): the
   chain of agents that handed the work down, and the person at its head;
2. looks for credentials and personal data in the message;
3. asks OPA (``data.agentgov.a2a.decision``), and asks for approval when an organisation
   policy wants one; and
4. answers: go ahead, with a new delegation for the called agent and who handed the call
   to it in headers agentgateway passes on (overwriting any the caller set); or refuse
   (403, with a JSON-RPC error the caller's A2A client shows).

It records each decision in the ledger, as it does for tool and model calls.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from agentgov.identity import chains, people
from agentgov.opa.client import OpaError
from agentgov.processor import detectors
from agentgov.processor.control_plane import ControlPlaneError
from agentgov.processor.model_guard import ModelGuard
from agentgov.processor.server import trace_id_from

if TYPE_CHECKING:
    from agentgov.processor.server import GovernanceProcessor

log = logging.getLogger(__name__)

# The request agentgateway forwards (its path on the gateway) and the incoming delegation.
PATH = "x-agentgov-path"
CARD = "/.well-known/agent-card.json"
# What the called agent gets, set on every allowed call so that no caller can forge them.
PASSED_ON = (chains.HEADER, chains.CALLER_HEADER, chains.PERSON_HEADER, chains.CHAIN_HEADER)
# A2A's JSON-RPC error for a request AgentGov refuses (an invalid request, to its client).
REFUSED = -32600


def _rpc(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body) if body else {}
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def refuse(
    rpc_id: Any, effect: str, reasons: list[str], approval_id: str | None = None
) -> Response:
    data: dict[str, Any] = {"@type": "agentgov.dev/Decision", "effect": effect, "reasons": reasons}
    if approval_id:
        data["approval_id"] = approval_id
    error = {"code": REFUSED, "message": "AgentGov: " + "; ".join(reasons), "data": [data]}
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": error}, status_code=403)


class A2AGuard:
    def __init__(self, processor: GovernanceProcessor) -> None:
        self.p = processor

    async def check(self, request: Request) -> Response:
        target = request.path_params["target"]
        try:
            return await self._check(target, request)
        except Exception as exc:
            if self.p.unchecked(self.p.features.last(ModelGuard._identity(request.headers))):
                log.exception("checking a call to agent %s failed; letting it through", target)
                self.p.note_unchecked(
                    f"the governance processor failed: {type(exc).__name__}",
                    kind="a2a",
                    phase="request",
                    method=request.method,
                    server=target,
                    target=target,
                    resource=target,
                    identity=ModelGuard._identity(request.headers),
                )
                # Without a delegation, and with none the caller may have set.
                return self._pass_on(None, None, [], None, None, {})
            log.exception("checking a call to agent %s failed; refusing it", target)
            return refuse(None, "deny", ["Governance processor error; the call was not passed on"])

    async def _check(self, target: str, request: Request) -> Response:
        started = time.perf_counter()
        headers = request.headers
        path = headers.get(PATH) or ""
        body = await request.body()
        rpc = _rpc(body) if request.method == "POST" else {}
        method = (
            "GetAgentCard"
            if request.method == "GET" and path.endswith(CARD)
            else str(rpc.get("method") or request.method)
        )
        rpc_id = rpc.get("id")
        params = rpc.get("params") if isinstance(rpc.get("params"), dict) else {}
        message = params.get("message") if isinstance(params.get("message"), dict) else {}
        identity = await self.p.caller(ModelGuard._identity(headers))
        person = ModelGuard._person(headers)
        trace_id = trace_id_from([headers.get("traceparent") or ""])
        parts = message.get("parts") if isinstance(message.get("parts"), list) else []
        modes = await self.p.features.for_caller(identity)
        inspection = await self.p._inspect(
            parts, protect=modes["data-protection"] != "off", check_injection=False
        )
        chain, unusable = self.p.delegation(headers.get(chains.HEADER), identity, person)
        if chain is not None and person is None:
            person = chain.person
        handed_down = chain.links if chain else ([chains.person_link(person)] if person else [])
        monitored: list[str] = []
        issued: dict[str, Any] = {}

        def finish(
            effect: str,
            reasons: list[str],
            *,
            agent: dict[str, Any] | None = None,
            called: dict[str, Any] | None = None,
            approval_id: str | None = None,
            decision_id: str | None = None,
            redacted: list[str] | None = None,
            unchecked: str | None = None,
        ) -> None:
            self.p._record(
                kind="a2a",
                phase="request",
                method=method,
                server=target,
                target=target,
                resource=target,
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
                a2a={
                    "target": target,
                    "target_id": (called or {}).get("id"),
                    "context_id": message.get("contextId"),
                    "task_id": message.get("taskId") or params.get("id"),
                },
                delegation={
                    "chain": handed_down,
                    "uid": issued.get("uid"),
                    "parent_uid": chain.uid if chain else None,
                },
                unchecked=unchecked,
            )

        if unusable:
            finish("deny", [unusable], agent=self.p.holder(identity))
            return refuse(rpc_id, "deny", [unusable])
        if inspection.scan.pii_error and self.p._fail_closed(modes):
            reasons = ["Content inspection is unavailable, so the call was not passed on"]
            finish("deny", reasons)
            return refuse(rpc_id, "deny", reasons)
        opa_input: dict[str, Any] = {
            "kind": "a2a",
            "method": method,
            "agent": identity,
            "target": target,
            "chain": handed_down,
            "detections": inspection.summary,
        }
        if person:
            opa_input["user"] = person
        try:
            decision, decision_id = await self.p.decide(
                "agentgov/a2a/decision", opa_input, kind="agent"
            )
        except OpaError as exc:
            log.error("policy evaluation failed: %s", exc)
            if self.p.unchecked(modes):
                # Without a delegation of its own: the agent called doesn't know it was checked.
                why = f"the policy engine is unavailable: {exc}"
                finish("allow", [self.p.unchecked_reason(why)], unchecked=why)
                return self._pass_on(None, None, handed_down, chain, person, issued)
            reasons = ["Policy engine unavailable; the call was not passed on"]
            finish("deny", reasons)
            return refuse(rpc_id, "deny", reasons)

        effect = decision.get("effect", "deny")
        reasons = list(decision.get("reasons") or [])
        agent = decision.get("agent")
        called = decision.get("target")
        monitored.extend(decision.get("monitored") or [])
        if agent is None and modes["unknown-callers"] == "monitor":
            self.p._spawn(self.p._observe_unknown(identity, f"a2a/{target}", method))
            finish("allow", ["monitor mode: caller is not a registered agent"], called=called)
            return self._pass_on(None, called, handed_down, chain, person, issued)

        approval_id = None
        if effect == "require_approval" and agent is not None:
            arguments = {"parts": parts}
            try:
                outcome = await self.p.cp.check_approval(
                    {
                        "agent_id": agent["id"],
                        "action": method,
                        "resource": f"a2a/{target}",
                        "arguments": arguments,
                        "redacted_arguments": detectors.redact(
                            arguments, inspection.scan.spans, {"secret", "pii"}
                        ),
                        "reasons": reasons,
                        "user": person,
                    }
                )
            except ControlPlaneError as exc:
                log.error("approval check failed: %s", exc)
                reasons = ["Approval service unavailable; the call was not passed on"]
                finish("deny", reasons, agent=agent, called=called, decision_id=decision_id)
                return refuse(rpc_id, "deny", reasons)
            approval_id = outcome["approval"]["id"]
            if outcome["outcome"] == "approved":
                effect = "allow"
                reasons = [f"approved by {outcome['approval'].get('decided_by')}"]
            elif outcome["outcome"] == "denied":
                effect, reasons = "deny", [f"A reviewer denied this call (approval {approval_id})"]
            else:
                reasons = [
                    f"Human approval required: {'; '.join(reasons)}. Approval request "
                    f"{approval_id} is pending; send the same message again once it is "
                    "approved."
                ]
                finish(
                    "require_approval",
                    reasons,
                    agent=agent,
                    called=called,
                    approval_id=approval_id,
                    decision_id=decision_id,
                )
                return refuse(rpc_id, "require_approval", reasons, approval_id)

        if effect != "allow":
            finish(
                "deny",
                reasons,
                agent=agent,
                called=called,
                approval_id=approval_id,
                decision_id=decision_id,
            )
            return refuse(rpc_id, "deny", reasons, approval_id)
        response = self._pass_on(agent, called, handed_down, chain, person, issued)
        # What the gateway masks in the message on its way (a2a-masking enforced;
        # agentgov.processor.a2a_answers does it).
        redacted = set(decision.get("redact") or []) & inspection.scan.categories()
        finish(
            "allow",
            reasons,
            agent=agent,
            called=called,
            approval_id=approval_id,
            decision_id=decision_id,
            redacted=sorted(redacted),
        )
        return response

    def _pass_on(
        self,
        agent: dict[str, Any] | None,
        called: dict[str, Any] | None,
        handed_down: list[dict[str, str]],
        chain: chains.Chain | None,
        person: dict[str, Any] | None,
        issued: dict[str, Any],
    ) -> Response:
        """Go ahead: the called agent gets a delegation of its own, and who called it."""
        response = Response(status_code=200)
        links = [*handed_down]
        if agent is not None:
            links.append(chains.link("agent", agent.get("id"), agent.get("name")))
        token = ""
        if agent is not None and called is not None and self.p.chain_keys is not None:
            # For the agent called, by its ID and its name: an agent checking it knows one.
            token, new = chains.issue(
                self.p.chain_keys,
                links=links,
                audience=[str(called["id"]), str(called["name"])],
                person=person,
                parent=chain.uid if chain else None,
            )
            issued["uid"] = new.uid
        values = {
            chains.HEADER: token,
            chains.CALLER_HEADER: (agent or {}).get("name") or "",
            chains.PERSON_HEADER: people.name_of(person) or "",
            chains.CHAIN_HEADER: chains.describe(links),
        }
        for name in PASSED_ON:
            # Plain ASCII in headers: names are slugs; people's names may not be.
            response.headers[name] = values[name].encode("utf-8").decode("latin-1")
        return response

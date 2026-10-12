"""AuthZEN: AgentGov's decisions in the OpenID AuthZEN Authorization API (1.0), both ways
(docs/policies.md#authzen).

* **AgentGov as a decision point.** The control plane answers AuthZEN evaluations
  (``POST /access/v1/evaluation``, ``/access/v1/evaluations``, and
  ``/.well-known/authzen-configuration``) with AgentGov's policies, through
  ``data.agentgov.authzen.evaluation``: any enforcement point that speaks AuthZEN can ask
  whether an agent may call a tool, a model or another agent.
* **Another decision point beside AgentGov's.** With the ``external-decision-point``
  feature, the governance processor also asks an AuthZEN decision point of the
  organisation's (Cedar, Cerbos, Topaz, OpenFGA, Keycloak, another AgentGov...) about each
  call AgentGov's own policies let through: monitored, what it would deny is recorded;
  enforced, its denials stand.

A call, in AuthZEN's terms (as the COAZ MCP binding has them, with the tool's server in
its ID, since one gateway fronts many servers): the person, or the agent when it acts on
its own, as the subject; the method (``tools/call``, ``chat``, ``SendMessage``) as the
action; the tool (``<server>/<tool>``), the model (``<provider>/<model>``) or the agent
called as the resource; and the agent acting, the chain that handed it the work and what
the processor found in the call (categories, not content) as the context.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

EVALUATION = "/access/v1/evaluation"
EVALUATIONS = "/access/v1/evaluations"
DISCOVERY = "/.well-known/authzen-configuration"
# The batch semantics AuthZEN defines.
SEMANTICS = ("execute_all", "deny_on_first_deny", "permit_on_first_permit")
# AgentGov's own obligation: mask these categories of what the call carries.
VENDOR = "agentgov"


class AuthZenError(Exception):
    """The decision point couldn't be asked, or didn't answer as AuthZEN says."""


# ------------------------------------------------------------- what is asked


def _subject(opa_input: dict[str, Any], agent: dict[str, Any] | None) -> dict[str, Any]:
    person = opa_input.get("user")
    if isinstance(person, dict) and (person.get("id") or person.get("username")):
        keep = ("username", "email", "groups", "roles")
        return {
            "type": "user",
            "id": str(person.get("id") or person.get("username")),
            "properties": {k: person[k] for k in keep if person.get(k)},
        }
    identity = opa_input.get("agent") or {}
    ident = (agent or {}).get("id") or identity.get("agent_id") or identity.get("client_id")
    properties = {"client_id": identity.get("client_id")} if identity.get("client_id") else {}
    if agent and agent.get("name"):
        properties["name"] = agent["name"]
    return {"type": "agent", "id": str(ident or "unknown"), "properties": properties}


def _resource(kind: str, opa_input: dict[str, Any]) -> dict[str, Any]:
    if kind == "model":
        provider, model = str(opa_input.get("provider", "")), str(opa_input.get("model", ""))
        return {
            "type": "model",
            "id": f"{provider}/{model}",
            "properties": {"provider": provider, "model": model},
        }
    if kind == "agent":
        return {"type": "agent", "id": str(opa_input.get("target", ""))}
    target = opa_input.get("resource") or {}
    server, name = str(target.get("server", "")), str(target.get("name", ""))
    return {
        "type": "tool",
        "id": f"{server}/{name}",
        "properties": {"server": server, "name": name},
    }


def request_for(
    kind: str,
    opa_input: dict[str, Any],
    *,
    agent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The AuthZEN evaluation request for a call the processor checks (``kind``: tool,
    model or agent), from AgentGov's input to its policies, and the agent it knows. Only
    what the call is, and what was found in it, goes: never its arguments or message."""
    identity = opa_input.get("agent") or {}
    detections = opa_input.get("detections") or {}
    context: dict[str, Any] = {
        "agent": {
            k: v
            for k, v in {
                "id": (agent or {}).get("id") or identity.get("agent_id"),
                "client_id": identity.get("client_id"),
                "name": (agent or {}).get("name"),
                "status": (agent or {}).get("status"),
                "risk_level": (agent or {}).get("risk_level"),
            }.items()
            if v
        },
        "detections": {
            "categories": sorted(detections.get("categories") or []),
            **{
                k: bool(detections[k]) for k in ("prompt_injection", "jailbreak") if k in detections
            },
        },
        "supported_obligations": ["custom"],
    }
    if opa_input.get("chain"):
        context["chain"] = [link.get("name") or link.get("id") for link in opa_input["chain"]]
    method = opa_input.get("method") or ("chat" if kind == "model" else "tools/call")
    return {
        "subject": _subject(opa_input, agent),
        "action": {"name": str(method)},
        "resource": _resource(kind, opa_input),
        "context": context,
    }


# ------------------------------------------------------------ what it answers


@dataclass
class Verdict:
    """An AuthZEN answer, as AgentGov acts on it."""

    effect: str  # "allow", "deny" or "require_approval"
    reasons: list[str] = field(default_factory=list)
    redact: set[str] = field(default_factory=set)


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):  # {"en": "..."} or {"reason": "..."}
        for key in ("en", "reason", "message"):
            if isinstance(value.get(key), str):
                return value[key]
    return None


def interpret(answer: dict[str, Any]) -> Verdict:
    """What AgentGov does with an AuthZEN answer: allowed, denied (with why), or approval
    required (the Access Request and Approval profile's ``approval_required``). An
    obligation it can't fulfil, on a permit, denies the call, as the Obligations profile
    says; it masks what AgentGov's own redact obligation lists."""
    if not isinstance(answer, dict) or not isinstance(answer.get("decision"), bool):
        raise AuthZenError("its answer has no decision (true or false)")
    context = answer.get("context") if isinstance(answer.get("context"), dict) else {}
    reasons = [str(r) for r in context.get("reasons") or [] if r]
    for key in ("reason_admin", "reason_user"):
        said = _text(context.get(key))
        if said and said not in reasons:
            reasons.append(said)
    if answer["decision"]:
        redact: set[str] = set()
        for obligation in context.get("obligations") or []:
            if not isinstance(obligation, dict):
                obligation = {"type": str(obligation)}
            props = obligation.get("properties") or {}
            if (
                obligation.get("type") == "custom"
                and props.get("vendor") == VENDOR
                and props.get("action") == "redact"
            ):
                redact |= {str(c) for c in props.get("categories") or []}
                continue
            what = obligation.get("type")
            return Verdict("deny", [f"it asks for an obligation AgentGov can't fulfil ({what})"])
        return Verdict("allow", reasons, redact)
    approval = context.get("reason") == "approval_required" or "access_request" in context
    if approval:
        return Verdict("require_approval", reasons or ["it asks for approval"])
    return Verdict("deny", reasons or ["it denied the call"])


# ----------------------------------------------------------------- the client


class AuthZenClient:
    """Asks an AuthZEN decision point (its base URL), with a bearer token if it needs one."""

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        timeout: float = 2.0,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self._http = http or httpx.AsyncClient(timeout=timeout)

    async def evaluate(self, request: dict[str, Any], request_id: str | None = None) -> dict:
        headers = {"X-Request-ID": request_id or uuid.uuid4().hex}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = await self._http.post(self.url + EVALUATION, json=request, headers=headers)
        except httpx.HTTPError as exc:
            raise AuthZenError(f"{self.url} can't be reached: {exc}") from None
        if resp.status_code != 200:
            raise AuthZenError(f"{self.url} answered HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            raise AuthZenError(f"{self.url} didn't answer JSON") from None


# --------------------------------------------- batches (AgentGov as the decision point)


def items(batch: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    """A batch's evaluations, each with the batch's defaults filled in, and how to run
    them (execute_all, unless the batch says otherwise)."""
    defaults = {k: batch[k] for k in ("subject", "action", "resource", "context") if k in batch}
    listed = batch.get("evaluations")
    if listed is None:
        return [defaults], "execute_all"
    if not isinstance(listed, list):
        raise AuthZenError("evaluations is a list")
    semantic = ((batch.get("options") or {}).get("evaluations_semantic")) or "execute_all"
    if semantic not in SEMANTICS:
        raise AuthZenError(f"evaluations_semantic is one of {', '.join(SEMANTICS)}")
    return [{**defaults, **(item or {})} for item in listed], semantic


def stops(semantic: str, decision: bool) -> bool:
    """Whether a batch run this way stops after a decision like this one."""
    return (semantic == "deny_on_first_deny" and not decision) or (
        semantic == "permit_on_first_permit" and decision
    )


def configuration(base_url: str) -> dict[str, str]:
    """AgentGov's metadata as an AuthZEN decision point."""
    base = base_url.rstrip("/")
    return {
        "policy_decision_point": base,
        "access_evaluation_endpoint": base + EVALUATION,
        "access_evaluations_endpoint": base + EVALUATIONS,
    }

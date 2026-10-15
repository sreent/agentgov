"""AgentGov as an AuthZEN decision point (docs/policies.md#authzen): its policies answer
OpenID AuthZEN 1.0 evaluations, for enforcement points other than AgentGov's gateway,
while the authzen-decision-point feature is on. OPA decides, through
``data.agentgov.authzen.evaluation``; the enforcement point that asks enforces, and keeps
its own record."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
from django.http import HttpRequest, HttpResponse
from ninja import Body

from agentgov import authzen
from agentgov.api.auth import READ_ROLES
from agentgov.registry import features
from agentgov.web.api import HTTPException, Router, json_response
from agentgov.web.auth import require, runtime

router = Router(tags=["authzen"])
# Whoever may read AgentGov may ask what it would decide, and its own components.
asker = require(*READ_ROLES, "service")
FEATURE = "authzen-decision-point"
PATH = "agentgov/authzen/evaluation"


def _on(request: HttpRequest) -> None:
    with runtime(request).db.session() as s:
        if not features.is_on(s, FEATURE):
            raise HTTPException(404, "AgentGov isn't an AuthZEN decision point here")


def _ask(request: HttpRequest, evaluation: dict[str, Any]) -> dict[str, Any]:
    rt = runtime(request)
    if not rt.settings.opa_url:
        raise HTTPException(503, "OPA is not configured (AGENTGOV_OPA_URL)")
    try:
        resp = httpx.post(
            f"{rt.settings.opa_url.rstrip('/')}/v1/data/{PATH}",
            json={"input": evaluation},
            timeout=5,
            verify=rt.tls.client_context() if rt.tls else True,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"OPA unreachable: {exc}") from exc
    result = resp.json().get("result") if resp.status_code == 200 else None
    if not isinstance(result, dict) or not isinstance(result.get("decision"), bool):
        raise HTTPException(502, f"OPA didn't decide (HTTP {resp.status_code})")
    return result


def _request_id(request: HttpRequest) -> dict[str, str]:
    return {"X-Request-ID": request.headers.get("x-request-id") or uuid.uuid4().hex}


@router.get(authzen.DISCOVERY)
def configuration(request: HttpRequest) -> dict[str, str]:
    """AgentGov's metadata as an AuthZEN decision point."""
    _on(request)
    return authzen.configuration(runtime(request).settings.public_url)


@router.post(authzen.EVALUATION, auth=asker)
def evaluation(request: HttpRequest, body: dict[str, Any] = Body(...)) -> HttpResponse:
    """Whether the subject may do the action on the resource, as AgentGov decides."""
    _on(request)
    return json_response(_ask(request, body), headers=_request_id(request))


@router.post(authzen.EVALUATIONS, auth=asker)
def evaluations(request: HttpRequest, body: dict[str, Any] = Body(...)) -> HttpResponse:
    """Several evaluations at once, the batch's subject, action, resource and context
    filling in what each leaves out, run as its options say."""
    _on(request)
    try:
        asked, semantic = authzen.items(body)
    except authzen.AuthZenError as exc:
        raise HTTPException(400, str(exc)) from None
    answers = []
    for one in asked:
        answers.append(_ask(request, one))
        if authzen.stops(semantic, answers[-1]["decision"]):
            break
    return json_response({"evaluations": answers}, headers=_request_id(request))

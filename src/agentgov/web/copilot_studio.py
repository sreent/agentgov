"""Copilot Studio's threat detection calls (see agentgov.platforms.threat_detection).

A Power Platform admin connects AgentGov to an environment with the endpoint
``<AGENTGOV_PUBLIC_URL>/integrations/copilot-studio``; Copilot Studio appends
``/validate`` (once, when the admin connects it) and ``/analyze-tool-execution``
(before each tool call). These routes answer in Copilot Studio's format, not
AgentGov's API's, and accept only Microsoft Entra tokens from the app
registrations AgentGov was told about.
"""

from __future__ import annotations

import json
import logging
from functools import partial
from typing import Any

from django.http import HttpRequest, HttpResponse, HttpResponseBase

from agentgov.identity.entra_calls import CallerRejected
from agentgov.platforms import threat_detection
from agentgov.platforms.threat_detection import ThreatDetection, Verdict
from agentgov.web import RUNTIME
from agentgov.web.api import HTTPException, Router, json_response
from agentgov.web.asgi import after, before_body
from agentgov.web.auth import runtime

log = logging.getLogger(__name__)
router = Router(tags=["copilot-studio"])
VALIDATE = "/integrations/copilot-studio/validate"
ANALYZE = "/integrations/copilot-studio/analyze-tool-execution"
# Copilot Studio sends the tool's inputs and the earlier tool results in the plan.
MAX_BODY_BYTES = 4 * 1024 * 1024
# Where a request's scope keeps the detection, once its caller passed.
CHECKED = "agentgov.copilot_studio"


def _detection(rt: Any) -> ThreatDetection:
    if rt.threat_detection is None or rt.threat_detection.mode(rt.db) == "off":
        raise HTTPException(404, "Copilot Studio threat detection is off")
    return rt.threat_detection


def _refused(detection: ThreatDetection, authorization: str | None) -> HttpResponse | None:
    try:
        detection.callers.check(authorization)
    except CallerRejected as exc:
        log.warning("refused a threat detection call: %s", exc)
        return json_response(
            {"errorCode": 2003, "message": f"Not authorised: {exc}", "httpStatus": 401}, 401
        )
    return None


def _caller(scope: dict[str, Any]) -> HttpResponseBase | None:
    """The endpoints face the internet, so the caller is checked from the headers before
    anything reads the body, and the body is read only within a limit
    (agentgov.web.asgi)."""
    headers: dict[str, str] = {}
    for name, value in scope["headers"]:
        headers.setdefault(name.decode("latin-1").lower(), value.decode("latin-1"))
    try:
        detection = _detection(scope[RUNTIME])
    except HTTPException as exc:
        return json_response({"detail": exc.detail}, exc.status_code)
    refused = _refused(detection, headers.get("authorization"))
    if refused is not None:
        return refused
    declared = headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return json_response({"detail": "the request is too large"}, 413)
    scope[CHECKED] = detection
    return None


before_body("POST", VALIDATE, _caller, MAX_BODY_BYTES)
before_body("POST", ANALYZE, _caller, MAX_BODY_BYTES)


def _checked(request: HttpRequest) -> ThreatDetection | HttpResponseBase:
    """The detection, its caller checked: before the body was read, or now."""
    scope = request.scope  # type: ignore[attr-defined]
    if CHECKED not in scope:
        refused = _caller(scope)
        if refused is not None:
            return refused
    return scope[CHECKED]


@router.post(VALIDATE)
def validate(request: HttpRequest) -> Any:
    """Copilot Studio checks that AgentGov is reachable when an admin connects it."""
    detection = _checked(request)
    if isinstance(detection, HttpResponseBase):
        return detection
    mode = detection.mode(runtime(request).db)
    return {"isSuccessful": True, "status": f"OK: AgentGov is in {mode} mode"}


def _payload(request: HttpRequest) -> dict[str, Any]:
    """The JSON body, read only once the caller is known, and within a limit."""
    try:
        payload = json.loads(request.body)
    except ValueError as exc:
        raise HTTPException(400, "the request is not JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(400, "the request is not a JSON object")
    return payload


@router.post(ANALYZE)
def analyze_tool_execution(request: HttpRequest, response: HttpResponse) -> Any:
    """Allow or block one tool call; the evidence is recorded after answering."""
    detection = _checked(request)
    if isinstance(detection, HttpResponseBase):
        return detection
    payload = _payload(request)
    rt = runtime(request)
    verdict = detection.decide(rt.db, payload)
    correlation_id = request.headers.get("x-ms-correlation-id", "")
    after(response, partial(_record, rt, verdict, correlation_id))
    return verdict.answer()


def _record(rt: Any, verdict: Verdict, correlation_id: str) -> None:
    try:
        with rt.db.transaction() as tx:
            threat_detection.record(tx, rt.settings, verdict, correlation_id=correlation_id)
    except Exception:  # the answer has gone; never let the evidence fail loudly
        log.exception("could not record a Copilot Studio decision")

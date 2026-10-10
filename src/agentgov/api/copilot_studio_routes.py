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
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from agentgov.identity.entra_calls import CallerRejected
from agentgov.platforms import threat_detection
from agentgov.platforms.threat_detection import ThreatDetection, Verdict

log = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations/copilot-studio", tags=["copilot-studio"])
# Copilot Studio sends the tool's inputs and the earlier tool results in the plan.
MAX_BODY_BYTES = 4 * 1024 * 1024


def _detection(request: Request) -> ThreatDetection:
    detection = request.app.state.rt.threat_detection
    if detection is None:
        raise HTTPException(404, "Copilot Studio threat detection is off")
    return detection


def _refused(detection: ThreatDetection, request: Request) -> JSONResponse | None:
    try:
        detection.callers.check(request.headers.get("authorization"))
    except CallerRejected as exc:
        log.warning("refused a threat detection call: %s", exc)
        return JSONResponse(
            status_code=401,
            content={"errorCode": 2003, "message": f"Not authorised: {exc}", "httpStatus": 401},
        )
    return None


@router.post("/validate")
def validate(request: Request) -> Any:
    """Copilot Studio checks that AgentGov is reachable when an admin connects it."""
    detection = _detection(request)
    refused = _refused(detection, request)
    if refused is not None:
        return refused
    return {"isSuccessful": True, "status": f"OK: AgentGov is in {detection.mode} mode"}


async def _payload(request: Request) -> dict[str, Any]:
    """The JSON body, read only once the caller is known, and within a limit."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, "the request is too large")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "the request is too large")
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise HTTPException(400, "the request is not JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(400, "the request is not a JSON object")
    return payload


@router.post("/analyze-tool-execution")
async def analyze_tool_execution(request: Request, background: BackgroundTasks) -> Any:
    """Allow or block one tool call; the evidence is recorded after answering.

    The endpoint faces the internet, so the caller's token is checked before the
    body is read.
    """
    detection = _detection(request)
    refused = await run_in_threadpool(_refused, detection, request)
    if refused is not None:
        return refused
    payload = await _payload(request)
    rt = request.app.state.rt
    verdict = await run_in_threadpool(detection.decide, rt.db, payload)
    correlation_id = request.headers.get("x-ms-correlation-id", "")
    background.add_task(_record, rt, verdict, correlation_id)
    return verdict.answer()


def _record(rt: Any, verdict: Verdict, correlation_id: str) -> None:
    try:
        with rt.db.session() as s:
            threat_detection.record(s, rt.settings, verdict, correlation_id=correlation_id)
    except Exception:  # the answer has gone; never let the evidence fail loudly
        log.exception("could not record a Copilot Studio decision")

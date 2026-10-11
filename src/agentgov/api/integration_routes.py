"""Endpoints used by the composed components rather than by people.

* OPA        - bundle downloads (with long polling), decision logs, status.
* Gateway    - agentgateway's configuration, where it can't share a file.
* Processor  - approvals, decision records, tool catalog, unknown callers.
* Telemetry  - OTLP/HTTP traces (JSON, or protobuf with the otlp-protobuf extra).
"""

from __future__ import annotations

import asyncio
import gzip
import json
from typing import Any

import anyio.to_thread
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response

from agentgov.api.auth import Principal, require
from agentgov.gateway import etag_of
from agentgov.opa.bundle import BUNDLE_CONTENT_TYPE, parse_prefer_wait, record_status
from agentgov.registry import (
    agents,
    approvals,
    decisions,
    discovery,
    features,
    findings,
    model_usage,
    toolservers,
)
from agentgov.registry.errors import NotFound, ValidationError
from agentgov.telemetry import decode_protobuf, ingest

router = APIRouter()
service = require("service")


def _rt(request: Request) -> Any:
    return request.app.state.rt


async def _json_body(request: Request) -> Any:
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        raw = gzip.decompress(raw)
    try:
        return json.loads(raw or b"null")
    except ValueError as exc:
        raise HTTPException(400, f"invalid JSON: {exc}") from exc


# ---------------------------------------------------------------------------- OPA


@router.get("/v1/opa/bundles/agentgov.tar.gz", tags=["opa"])
async def opa_bundle(request: Request, _: Principal = Depends(service)) -> Response:
    rt = _rt(request)
    etag = request.headers.get("if-none-match")
    wait = parse_prefer_wait(request.headers.get("prefer"))
    if etag and wait:
        timeout = max(1.0, min(wait - 1, rt.settings.bundle_long_poll_seconds))
        bundle = await rt.bundles.wait_for_change(etag, timeout)
    else:
        bundle = await asyncio.to_thread(rt.bundles.current)
        if bundle.etag == etag:
            bundle = None
    if bundle is None:
        return Response(
            status_code=304, headers={"ETag": etag or "", "Content-Type": BUNDLE_CONTENT_TYPE}
        )
    return Response(
        content=bundle.body, media_type=BUNDLE_CONTENT_TYPE, headers={"ETag": bundle.etag}
    )


# ------------------------------------------------------------------------ gateway


@router.get("/v1/gateway/config", tags=["gateway"])
async def gateway_config(request: Request, _: Principal = Depends(service)) -> Response:
    """agentgateway's configuration, generated from the registry, for gateways that
    don't share a volume with the control plane (see ``agentgov gateway-config``)."""
    content = await asyncio.to_thread(_rt(request).gateway.render_current)
    etag = etag_of(content)
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(content=content, media_type="application/yaml", headers={"ETag": etag})


@router.post("/v1/opa/logs", tags=["opa"])
async def opa_decision_logs(request: Request, _: Principal = Depends(service)) -> dict[str, int]:
    rt = _rt(request)
    events = await _json_body(request)
    if not isinstance(events, list):
        raise HTTPException(400, "expected a JSON array of decision events")

    def store() -> int:
        with rt.db.session() as s:
            return decisions.record_opa_decisions(s, events)

    return {"stored": await anyio.to_thread.run_sync(store)}


@router.post("/v1/opa/status", tags=["opa"])
async def opa_status(request: Request, _: Principal = Depends(service)) -> dict[str, str]:
    rt = _rt(request)
    status = await _json_body(request) or {}
    errors = {
        name: b.get("errors") or b.get("message")
        for name, b in (status.get("bundles") or {}).items()
        if b.get("code") or b.get("errors")
    }

    def store() -> None:
        with rt.db.session() as s:
            record_status(s, status)
            if errors:
                findings.raise_finding(
                    s,
                    type="opa.bundle_error",
                    severity="critical",
                    subject=str((status.get("labels") or {}).get("id", "opa")),
                    category=findings.THREAT,
                    title="OPA failed to activate the policy bundle",
                    description=json.dumps(errors)[:2000],
                    remediation="OPA keeps enforcing its last good bundle; fix the policy error "
                    "so registry changes (including blocks) propagate.",
                )
            else:
                findings.resolve_absent(s, types={"opa.bundle_error"}, present_keys=set())

    await anyio.to_thread.run_sync(store)
    return {"status": "ok"}


# ---------------------------------------------------------------------- processor


@router.post("/v1/internal/approvals/check", tags=["internal"])
def internal_approval_check(
    request: Request, body: dict[str, Any] = Body(...), _: Principal = Depends(service)
) -> dict[str, Any]:
    rt = _rt(request)
    # The person the agent acts for, if it acts for one.
    person = body.get("user") if isinstance(body.get("user"), dict) else None
    with rt.db.session() as s:
        agent = agents.get(s, body["agent_id"])
        outcome, req = approvals.check_or_request(
            s,
            agent=agent,
            action=str(body.get("action")),
            resource=str(body.get("resource")),
            arguments=body.get("arguments"),
            redacted_arguments=body.get("redacted_arguments"),
            reasons=list(body.get("reasons") or []),
            ttl_seconds=rt.settings.approval_ttl_seconds,
            person=person if person and person.get("id") else None,
        )
        return {
            "outcome": outcome,
            "approval": approvals.to_dict(req),
            # Where the person, or an approver, decides it.
            "url": f"{rt.settings.public_url.rstrip('/')}/ui/#/approvals",
        }


@router.post("/v1/internal/decisions", tags=["internal"])
def internal_decisions(
    request: Request, body: dict[str, Any] = Body(...), _: Principal = Depends(service)
) -> dict[str, int]:
    rt = _rt(request)
    records = body.get("records") or []
    if not isinstance(records, list):
        raise ValidationError("records must be a list")
    with rt.db.session() as s:
        return {"stored": decisions.record_mcp_decisions(s, rt.settings, records)}


@router.post("/v1/internal/catalog", tags=["internal"])
def internal_catalog(
    request: Request, body: dict[str, Any] = Body(...), _: Principal = Depends(service)
) -> dict[str, Any]:
    rt = _rt(request)
    with rt.db.session() as s:
        try:
            ts = toolservers.get(s, str(body.get("server")))
        except NotFound:
            return {"ignored": "unknown server"}
        return toolservers.record_catalog(
            s, ts, list(body.get("tools") or []), poisoned=dict(body.get("poisoned") or {})
        )


@router.post("/v1/internal/observe", tags=["internal"])
def internal_observe(
    request: Request, body: dict[str, Any] = Body(...), _: Principal = Depends(service)
) -> dict[str, Any]:
    with _rt(request).db.session() as s:
        agent = discovery.observe(
            s,
            source=str(body.get("source") or "gateway"),
            agent_id=body.get("agent_id"),
            client_id=body.get("client_id"),
            name=body.get("name"),
            details=body.get("details"),
            discover=features.is_on(s, "discovery"),
        )
        return {"agent": agent.id if agent else None}


# ---------------------------------------------------------------------- telemetry


async def _otlp(request: Request, signal: str = "traces") -> Response:
    rt = _rt(request)
    content_type = request.headers.get("content-type", "")
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        raw = gzip.decompress(raw)
    protobuf = content_type.startswith("application/x-protobuf")
    if protobuf:
        try:
            payload = decode_protobuf(raw, signal)
        except ImportError as exc:
            raise HTTPException(
                415, "OTLP protobuf needs the otlp-protobuf extra; use OTLP/HTTP JSON"
            ) from exc
    else:
        try:
            payload = json.loads(raw or b"{}")
        except ValueError as exc:
            raise HTTPException(400, f"invalid OTLP JSON: {exc}") from exc

    def store() -> dict[str, Any]:
        with rt.db.session() as s:
            if signal == "logs":
                return model_usage.ingest_logs(s, payload)
            return ingest(s, payload, classify=rt.guardian is not None)

    await anyio.to_thread.run_sync(store)
    if protobuf:
        return Response(content=b"", media_type="application/x-protobuf")
    return Response(content=b"{}", media_type="application/json")


@router.post("/v1/otlp/v1/traces", tags=["telemetry"])
async def otlp_traces(request: Request, _: Principal = Depends(service)) -> Response:
    return await _otlp(request)


@router.post("/v1/otlp/v1/logs", tags=["telemetry"])
async def otlp_logs(request: Request, _: Principal = Depends(service)) -> Response:
    """agentgateway's access logs, through the OpenTelemetry Collector: model usage."""
    return await _otlp(request, "logs")

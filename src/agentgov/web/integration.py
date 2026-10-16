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

from django.http import HttpRequest, HttpResponse
from ninja import Body

from agentgov import health
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
from agentgov.web.api import (
    HTTPException,
    Router,
    raw_response,
)
from agentgov.web.auth import arequire, require, runtime

router = Router()
# What components read: the service role, and administrators.
service = require("service")
# What components report (decisions, observations, OPA's decision logs, telemetry): the
# service role alone, so that what the evidence ledger says the data plane did comes from
# the data plane (with mutual TLS, from components with AgentGov's certificates).
component = require("service", admin=False)


def _json_body(request: HttpRequest) -> Any:
    raw = request.body
    if request.headers.get("content-encoding", "").lower() == "gzip":
        raw = gzip.decompress(raw)
    try:
        return json.loads(raw or b"null")
    except ValueError as exc:
        raise HTTPException(400, f"invalid JSON: {exc}") from exc


# ---------------------------------------------------------------------------- OPA


# On the server's event loop, where a bundle's change wakes the requests waiting for it.
@router.get("/v1/opa/bundles/agentgov.tar.gz", tags=["opa"], auth=arequire("service"))
async def opa_bundle(request: HttpRequest) -> HttpResponse:
    rt = runtime(request)
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
        return raw_response(
            status_code=304, headers={"ETag": etag or "", "Content-Type": BUNDLE_CONTENT_TYPE}
        )
    return raw_response(
        content=bundle.body, media_type=BUNDLE_CONTENT_TYPE, headers={"ETag": bundle.etag}
    )


# ------------------------------------------------------------------------ gateway


@router.get("/v1/gateway/config", tags=["gateway"], auth=service)
def gateway_config(request: HttpRequest) -> HttpResponse:
    """agentgateway's configuration, generated from the registry, for gateways that
    don't share a volume with the control plane (see ``agentgov gateway-config``)."""
    content = runtime(request).gateway.render_current()
    etag = etag_of(content)
    if request.headers.get("if-none-match") == etag:
        return raw_response(status_code=304, headers={"ETag": etag})
    return raw_response(content=content, media_type="application/yaml", headers={"ETag": etag})


@router.post("/v1/opa/logs", tags=["opa"], auth=component)
def opa_decision_logs(request: HttpRequest) -> dict[str, int]:
    events = _json_body(request)
    if not isinstance(events, list):
        raise HTTPException(400, "expected a JSON array of decision events")
    with runtime(request).db.transaction() as tx:
        return decisions.record_opa_decisions(tx, events)


@router.post("/v1/opa/status", tags=["opa"], auth=component)
def opa_status(request: HttpRequest) -> dict[str, str]:
    status = _json_body(request) or {}
    errors = {
        name: b.get("errors") or b.get("message")
        for name, b in (status.get("bundles") or {}).items()
        if b.get("code") or b.get("errors")
    }

    with runtime(request).db.transaction() as tx:
        record_status(tx, status)
        if errors:
            findings.raise_finding(
                tx,
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
            findings.resolve_absent(tx, types={"opa.bundle_error"}, present_keys=set())
    return {"status": "ok"}


# ---------------------------------------------------------------------- processor


@router.post("/v1/internal/approvals/check", tags=["internal"], auth=component)
def internal_approval_check(
    request: HttpRequest, body: dict[str, Any] = Body(...)
) -> dict[str, Any]:
    rt = runtime(request)
    if not isinstance(body.get("agent_id"), str) or not body["agent_id"]:
        raise ValidationError("agent_id is required: the agent asking")
    # The person the agent acts for, if it acts for one.
    person = body.get("user") if isinstance(body.get("user"), dict) else None
    with rt.db.transaction() as tx:
        agent = agents.get(tx, body["agent_id"])
        outcome, req = approvals.check_or_request(
            tx,
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


@router.post("/v1/internal/decisions", tags=["internal"], auth=component)
def internal_decisions(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, int]:
    rt = runtime(request)
    records = body.get("records") or []
    if not isinstance(records, list):
        raise ValidationError("records must be a list")
    dropped = body.get("dropped") or 0
    if isinstance(dropped, bool) or not isinstance(dropped, int) or dropped < 0:
        raise ValidationError("dropped must be a count")
    if dropped:
        # In a transaction of its own: recorded whatever becomes of the batch.
        with rt.db.transaction() as tx:
            decisions.record_dropped(tx, dropped)
    with rt.db.transaction() as tx:
        stored, rejected = decisions.record_mcp_decisions(tx, rt.settings, records)
    return {"stored": stored, **({"rejected": rejected} if rejected else {})}


@router.post("/v1/internal/components", tags=["internal"], auth=component)
def internal_components(request: HttpRequest, body: Any = Body(...)) -> dict[str, Any]:
    """A governance processor's report of what it can reach (agentgov.health). The answer
    gives it the features' modes, which it otherwise reads from OPA: it then knows them
    while OPA can't be asked."""
    with runtime(request).db.transaction() as tx:
        health.record(tx, body)
        return {"recorded": "ok", "features": features.modes(tx)}


@router.post("/v1/internal/catalog", tags=["internal"], auth=component)
def internal_catalog(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    rt = runtime(request)
    with rt.db.transaction() as tx:
        try:
            ts = toolservers.get(tx, str(body.get("server")))
        except NotFound:
            return {"ignored": "unknown server"}
        return toolservers.record_catalog(
            tx, ts, list(body.get("tools") or []), poisoned=dict(body.get("poisoned") or {})
        )


@router.post("/v1/internal/observe", tags=["internal"], auth=component)
def internal_observe(request: HttpRequest, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    with runtime(request).db.transaction() as tx:
        agent = discovery.observe(
            tx,
            source=str(body.get("source") or "gateway"),
            agent_id=body.get("agent_id"),
            client_id=body.get("client_id"),
            name=body.get("name"),
            details=body.get("details"),
            discover=features.is_on(tx, "discovery"),
            issuer=body.get("issuer"),
            subject=body.get("subject"),
        )
        return {"agent": agent.id if agent else None}


# ---------------------------------------------------------------------- telemetry


def _otlp(request: HttpRequest, signal: str = "traces") -> HttpResponse:
    rt = runtime(request)
    content_type = request.headers.get("content-type", "")
    raw = request.body
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

    with rt.db.transaction() as tx:
        if signal == "logs":
            model_usage.ingest_logs(tx, payload)
        else:
            ingest(tx, payload, classify=rt.guardian is not None)
    if protobuf:
        return raw_response(content=b"", media_type="application/x-protobuf")
    return raw_response(content=b"{}", media_type="application/json")


@router.post("/v1/otlp/v1/traces", tags=["telemetry"], auth=component)
def otlp_traces(request: HttpRequest) -> HttpResponse:
    return _otlp(request)


@router.post("/v1/otlp/v1/logs", tags=["telemetry"], auth=component)
def otlp_logs(request: HttpRequest) -> HttpResponse:
    """agentgateway's access logs, through the OpenTelemetry Collector: model usage."""
    return _otlp(request, "logs")

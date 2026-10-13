"""Evidence: the ledger's checkpoints and their time-stamps, retention, and compliance
reports (docs/evidence.md)."""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import select

from agentgov import compliance, ids, ledger, retention, timestamping, transparency
from agentgov.api.auth import READ_ROLES, Principal, require
from agentgov.models import LedgerCheckpoint
from agentgov.runtime import JOB_WAIT_SECONDS

router = APIRouter(prefix="/v1", tags=["evidence"])
read = require(*READ_ROLES)
admin = require("admin")


def _rt(request: Request) -> Any:
    return request.app.state.rt


@router.get("/ledger/checkpoints")
def list_checkpoints(
    request: Request, limit: int = 100, _: Principal = Depends(read)
) -> list[dict[str, Any]]:
    """The ledger's checkpoints, newest first: their time-stamps and archives."""
    with _rt(request).db.session() as s:
        rows = s.scalars(
            select(LedgerCheckpoint)
            .order_by(LedgerCheckpoint.seq.desc())
            .limit(max(1, min(limit, 1000)))
        )
        return [ledger.checkpoint_dict(c) for c in rows]


@router.post("/ledger/checkpoints", status_code=201)
def make_checkpoint(request: Request, _: Principal = Depends(admin)) -> dict[str, Any]:
    """Keep the chain's head as a checkpoint now, and have it time-stamped if an authority
    is set."""
    rt = _rt(request)
    point = rt.make_checkpoint(wait=JOB_WAIT_SECONDS)
    if point is None:
        raise HTTPException(409, "the ledger is empty")
    return point


@router.get("/ledger/checkpoints/{seq}/timestamp")
def checkpoint_timestamp(request: Request, seq: int, _: Principal = Depends(read)) -> Response:
    """The authority's time-stamp of a checkpoint (a TimeStampResp), for
    ``openssl ts -verify -in checkpoint.tsr -data statement.txt -CAfile ...``."""
    with _rt(request).db.session() as s:
        point = s.get(LedgerCheckpoint, seq)
        if point is None:
            raise HTTPException(404, f"no checkpoint at entry {seq}")
        if point.timestamp is None:
            raise HTTPException(404, f"checkpoint {seq} isn't time-stamped")
        return Response(
            base64.b64decode(point.timestamp),
            media_type=timestamping.REPLY,
            headers={"Content-Disposition": f'attachment; filename="checkpoint-{seq}.tsr"'},
        )


@router.get("/ledger/checkpoints/{seq}/log-entry")
def checkpoint_log_entry(request: Request, seq: int, _: Principal = Depends(read)) -> Response:
    """A checkpoint's entry in the transparency log, as a Sigstore bundle, for
    ``cosign verify-blob --key agentgov.pub --bundle ... --trusted-root ... statement.txt``
    or ``agentgov ledger verify-log-entry``."""
    with _rt(request).db.session() as s:
        point = s.get(LedgerCheckpoint, seq)
        if point is None:
            raise HTTPException(404, f"no checkpoint at entry {seq}")
        if point.tlog_entry is None:
            raise HTTPException(404, f"checkpoint {seq} isn't in a transparency log")
        try:
            found = transparency.bundle(point.tlog_entry, ledger.statement(point.seq, point.hash))
        except transparency.TransparencyError as exc:
            raise HTTPException(409, f"checkpoint {seq}'s log entry can't be read: {exc}") from None
        return JSONResponse(
            found,
            headers={
                "Content-Disposition": f'attachment; filename="checkpoint-{seq}.sigstore.json"'
            },
        )


@router.get("/ledger/transparency-log")
def transparency_log(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """The transparency log checkpoints go into, and what checks their entries offline:
    AgentGov's public key, the log's, and a trusted root with the log for cosign."""
    settings = _rt(request).settings
    url = settings.ledger_rekor_url
    if not url:
        return {"url": None}
    origin = settings.ledger_rekor_origin or transparency.origin_of(url)
    out: dict[str, Any] = {"url": url, "origin": origin, "signer_key": None, "log_key": None}
    out["trusted_root"] = None
    try:
        key = transparency.load_signing_key(settings.ledger_rekor_signing_key_file or "")
        out["signer_key"] = transparency.public_pem(key).decode()
        if settings.ledger_rekor_log_key_file:
            log_key = transparency.load_log_key(settings.ledger_rekor_log_key_file)
            out["log_key"] = transparency.public_pem(log_key).decode()
            out["trusted_root"] = transparency.trusted_root(url, origin, log_key)
    except transparency.TransparencyError as exc:
        out["error"] = str(exc)
    return out


@router.get("/ledger/retention")
def retention_view(request: Request, _: Principal = Depends(read)) -> dict[str, Any]:
    """How long the ledger and the operational records are kept, and where the chain in
    the database starts."""
    rt = _rt(request)
    settings = rt.settings
    with rt.db.session() as s:
        floor, floor_hash = ledger.base(s)
        archived = s.scalars(
            select(LedgerCheckpoint)
            .where(LedgerCheckpoint.pruned_at.is_not(None))
            .order_by(LedgerCheckpoint.seq.desc())
            .limit(1)
        ).first()
        latest = retention.latest_checkpoint(s)
        return {
            "ledger_retention_days": settings.ledger_retention_days,
            "archive_dir": bool(settings.ledger_archive_dir),
            "checkpoint_hours": settings.ledger_checkpoint_hours,
            "tsa_url": settings.ledger_tsa_url,
            "rekor_url": settings.ledger_rekor_url,
            "data_retention_days": settings.data_retention_days,
            "chain_from": floor,
            "chain_from_hash": floor_hash if floor else None,
            "last_archive": ledger.checkpoint_dict(archived) if archived else None,
            "latest_checkpoint": ledger.checkpoint_dict(latest) if latest else None,
        }


@router.post("/ledger/retention/run")
def run_retention(request: Request, _: Principal = Depends(admin)) -> dict[str, Any]:
    """Do now what the hourly retention round does."""
    return _rt(request).run_retention(wait=JOB_WAIT_SECONDS)


# --------------------------------------------------------------- compliance


def _days(days: int) -> int:
    if not 1 <= days <= compliance.MAX_DAYS:
        raise HTTPException(422, f"days is from 1 to {compliance.MAX_DAYS}")
    return days


@router.get("/evidence/frameworks")
def frameworks(_: Principal = Depends(read)) -> list[dict[str, Any]]:
    """The frameworks AgentGov reports on."""
    return [
        {"key": f.key, "title": f.title, "url": f.url, "note": f.note}
        for f in compliance.FRAMEWORKS.values()
    ]


@router.get("/evidence/report")
def evidence_report(
    request: Request,
    framework: str = "eu-ai-act",
    days: int = 90,
    _: Principal = Depends(read),
) -> dict[str, Any]:
    """What AgentGov does towards a framework's controls, how far it is set up here, and the
    evidence over the last ``days`` days. It doesn't say that the organisation complies."""
    if framework not in compliance.FRAMEWORKS:
        raise HTTPException(
            404, f"framework is one of {', '.join(compliance.FRAMEWORKS)} (got {framework!r})"
        )
    rt = _rt(request)
    with rt.db.session() as s:
        return compliance.report(compliance.facts(s, rt.settings, _days(days)), framework)


@router.get("/evidence/register")
def classification_register(request: Request, _: Principal = Depends(read)) -> list[dict[str, Any]]:
    """The classification register: every agent but deleted ones, with its classification
    under the EU AI Act (category, role, basis, purpose), who classified it and when."""
    from agentgov.registry import agents, classification

    with _rt(request).db.session() as s:
        return [classification.row(a) for a in agents.list_agents(s)]


@router.get("/evidence/pack")
def evidence_pack(
    request: Request, days: int = 90, _: Principal = Depends(read)
) -> StreamingResponse:
    """The reports, the ledger for the period, the checkpoints and their time-stamps, the
    inventory and the registry as code, in one zip, for whoever assesses compliance."""
    rt = _rt(request)
    with rt.db.session() as s:
        zipped = compliance.pack(s, rt.settings, _days(days))
    stamp = ids.utcnow().strftime("%Y%m%d-%H%M%S")

    def chunks() -> Any:
        with zipped:
            while chunk := zipped.read(1024 * 1024):
                yield chunk

    return StreamingResponse(
        chunks(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="agentgov-evidence-{stamp}.zip"'},
    )

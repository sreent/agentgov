"""Evidence: the ledger's checkpoints and their time-stamps, retention, and compliance
reports (docs/evidence.md)."""

from __future__ import annotations

import base64
from typing import Any

from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from sqlalchemy import select

from agentgov import compliance, ids, ledger, retention, timestamping, transparency, witness
from agentgov.api.auth import READ_ROLES
from agentgov.models import LedgerCheckpoint
from agentgov.runtime import JOB_WAIT_SECONDS
from agentgov.web.api import (
    HTTPException,
    Router,
    json_response,
    raw_response,
    stream_response,
)
from agentgov.web.auth import require, runtime

router = Router(tags=["evidence"])
read = require(*READ_ROLES)
admin = require("admin")


@router.get("/v1/ledger/checkpoints", auth=read)
def list_checkpoints(request: HttpRequest, limit: int = 100) -> list[dict[str, Any]]:
    """The ledger's checkpoints, newest first: their time-stamps and archives."""
    with runtime(request).db.session() as s:
        rows = s.scalars(
            select(LedgerCheckpoint)
            .order_by(LedgerCheckpoint.seq.desc())
            .limit(max(1, min(limit, 1000)))
        )
        return [ledger.checkpoint_dict(c) for c in rows]


@router.post("/v1/ledger/checkpoints", status_code=201, auth=admin)
def make_checkpoint(request: HttpRequest) -> dict[str, Any]:
    """Keep the chain's head as a checkpoint now, and have it time-stamped if an authority
    is set."""
    rt = runtime(request)
    point = rt.make_checkpoint(wait=JOB_WAIT_SECONDS)
    if point is None:
        raise HTTPException(409, "the ledger is empty")
    return point


@router.get("/v1/ledger/witness", auth=read)
def ledger_witness(request: HttpRequest) -> dict[str, Any]:
    """The database's ledger against its head kept outside it (docs/backup.md): whether it
    lost entries, or holds another history, since AgentGov last looked."""
    rt = runtime(request)
    path = rt.settings.witness_file()
    if path is None:
        return {"configured": False}
    with rt.db.session() as s:
        return {"configured": True, **witness.compare(s, path).to_dict()}


@router.post("/v1/ledger/witness/accept", auth=admin)
def accept_rewind(request: HttpRequest) -> dict[str, Any]:
    """Accept that the ledger lost entries (a database restored on purpose): what is missing
    is written into the ledger (``ledger.rewound``), and it goes on from the head it has."""
    principal = request.auth
    status = runtime(request).accept_rewind(actor=principal.actor)
    return {"configured": True, **status.to_dict()}


@router.get("/v1/ledger/checkpoints/{seq}/timestamp", auth=read)
def checkpoint_timestamp(request: HttpRequest, seq: int) -> HttpResponse:
    """The authority's time-stamp of a checkpoint (a TimeStampResp), for
    ``openssl ts -verify -in checkpoint.tsr -data statement.txt -CAfile ...``."""
    with runtime(request).db.session() as s:
        point = s.get(LedgerCheckpoint, seq)
        if point is None:
            raise HTTPException(404, f"no checkpoint at entry {seq}")
        if point.timestamp is None:
            raise HTTPException(404, f"checkpoint {seq} isn't time-stamped")
        return raw_response(
            base64.b64decode(point.timestamp),
            media_type=timestamping.REPLY,
            headers={"Content-Disposition": f'attachment; filename="checkpoint-{seq}.tsr"'},
        )


@router.get("/v1/ledger/checkpoints/{seq}/log-entry", auth=read)
def checkpoint_log_entry(request: HttpRequest, seq: int) -> HttpResponse:
    """A checkpoint's entry in the transparency log, as a Sigstore bundle, for
    ``cosign verify-blob --key agentgov.pub --bundle ... --trusted-root ... statement.txt``
    or ``agentgov ledger verify-log-entry``."""
    with runtime(request).db.session() as s:
        point = s.get(LedgerCheckpoint, seq)
        if point is None:
            raise HTTPException(404, f"no checkpoint at entry {seq}")
        if point.tlog_entry is None:
            raise HTTPException(404, f"checkpoint {seq} isn't in a transparency log")
        try:
            found = transparency.bundle(point.tlog_entry, ledger.statement(point.seq, point.hash))
        except transparency.TransparencyError as exc:
            raise HTTPException(409, f"checkpoint {seq}'s log entry can't be read: {exc}") from None
        return json_response(
            found,
            headers={
                "Content-Disposition": f'attachment; filename="checkpoint-{seq}.sigstore.json"'
            },
        )


@router.get("/v1/ledger/transparency-log", auth=read)
def transparency_log(request: HttpRequest) -> dict[str, Any]:
    """The transparency log checkpoints go into, and what checks their entries offline:
    AgentGov's public key, the log's, and a trusted root with the log for cosign."""
    settings = runtime(request).settings
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


@router.get("/v1/ledger/retention", auth=read)
def retention_view(request: HttpRequest) -> dict[str, Any]:
    """How long the ledger and the operational records are kept, and where the chain in
    the database starts."""
    rt = runtime(request)
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
            # Whether its time-stamps are checked against the authority's certificates.
            "tsa_ca": bool(settings.ledger_tsa_ca_file),
            "rekor_url": settings.ledger_rekor_url,
            # Where the ledger's head is kept outside the database, if anywhere.
            "witness_file": settings.witness_file(),
            "data_retention_days": settings.data_retention_days,
            "chain_from": floor,
            "chain_from_hash": floor_hash if floor else None,
            "last_archive": ledger.checkpoint_dict(archived) if archived else None,
            "latest_checkpoint": ledger.checkpoint_dict(latest) if latest else None,
        }


@router.post("/v1/ledger/retention/run", auth=admin)
def run_retention(request: HttpRequest) -> dict[str, Any]:
    """Do now what the hourly retention round does."""
    return runtime(request).run_retention(wait=JOB_WAIT_SECONDS)


# --------------------------------------------------------------- compliance


def _days(days: int) -> int:
    if not 1 <= days <= compliance.MAX_DAYS:
        raise HTTPException(422, f"days is from 1 to {compliance.MAX_DAYS}")
    return days


@router.get("/v1/evidence/frameworks", auth=read)
def frameworks(request: HttpRequest) -> list[dict[str, Any]]:
    """The frameworks AgentGov reports on."""
    return [
        {"key": f.key, "title": f.title, "url": f.url, "note": f.note}
        for f in compliance.FRAMEWORKS.values()
    ]


@router.get("/v1/evidence/report", auth=read)
def evidence_report(
    request: HttpRequest, framework: str = "eu-ai-act", days: int = 90
) -> dict[str, Any]:
    """What AgentGov does towards a framework's controls, how far it is set up here, and the
    evidence over the last ``days`` days. It doesn't say that the organisation complies."""
    if framework not in compliance.FRAMEWORKS:
        raise HTTPException(
            404, f"framework is one of {', '.join(compliance.FRAMEWORKS)} (got {framework!r})"
        )
    rt = runtime(request)
    with rt.db.session() as s:
        return compliance.report(compliance.facts(s, rt.settings, _days(days)), framework)


@router.get("/v1/evidence/register", auth=read)
def classification_register(request: HttpRequest) -> list[dict[str, Any]]:
    """The classification register: every agent but deleted ones, with its classification
    under the EU AI Act (category, role, basis, purpose), who classified it and when."""
    from agentgov.registry import agents, classification

    with runtime(request).db.session() as s:
        return [classification.row(a) for a in agents.list_agents(s)]


@router.get("/v1/evidence/pack", auth=read)
def evidence_pack(request: HttpRequest, days: int = 90) -> StreamingHttpResponse:
    """The reports, the ledger for the period, the checkpoints and their time-stamps, the
    inventory and the registry as code, in one zip, for whoever assesses compliance."""
    rt = runtime(request)
    with rt.db.session() as s:
        zipped = compliance.pack(s, rt.settings, _days(days))
    stamp = ids.utcnow().strftime("%Y%m%d-%H%M%S")

    def chunks() -> Any:
        with zipped:
            while chunk := zipped.read(1024 * 1024):
                yield chunk

    return stream_response(
        chunks(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="agentgov-evidence-{stamp}.zip"'},
    )

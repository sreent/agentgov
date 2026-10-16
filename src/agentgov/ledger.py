"""Tamper-evident evidence ledger.

Every governance-relevant event (lifecycle changes, admin actions, policy
decisions, approvals, OPA decision logs) is appended to a hash chain. Each
entry's hash covers the previous entry's hash, so editing or deleting any
stored entry is detectable by :func:`verify`.

Checkpoints keep points of the chain for good (docs/evidence.md). Once the entries
up to a checkpoint are archived and removed (agentgov.retention), the chain in the
database goes on from it, and :func:`verify_records` checks the archives offline.

The functions here run in the caller's transaction (agentgov.db), on Django's ORM.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.db.models import F, Max, QuerySet, Subquery

from agentgov import db, ids, timestamping
from agentgov.db import mark_changed
from agentgov.db.models import Agent, LedgerCheckpoint, LedgerEntry, LedgerHead

if TYPE_CHECKING:
    from agentgov.config import Settings

GENESIS = "0" * 64
# A transaction's entries, until it commits.
_PENDING = "agentgov.ledger.pending"
# What archiving writes into the chain (agentgov.retention): the range it archived and
# removed, so that the chain itself says where it may start; and each checkpoint's
# time-stamp, so that one replaced later shows.
ARCHIVED = "ledger.archived"
STAMPED = "ledger.timestamped"
# Problems and warnings a verification lists, at most.
MAX_PROBLEMS = 50
# The retention job's round (agentgov.runtime): it makes a checkpoint that is due, has it
# time-stamped, and asks the authority again each round while it fails.
STAMP_ROUND = timedelta(hours=1)
CHECKPOINT_HOURS = 24
# The columns' lengths, which what is stored is cut to.
_LENGTHS = {f.column: f.max_length for f in LedgerEntry._meta.concrete_fields}


def ensure_head(tx: db.Transaction) -> None:
    LedgerHead.objects.get_or_create(id=1, defaults={"last_seq": 0, "last_hash": GENESIS})


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _payload(entry: LedgerEntry) -> dict[str, Any]:
    payload = {
        "seq": entry.seq,
        "id": entry.id,
        "ts": ids.isoformat(entry.ts),
        "type": entry.type,
        "severity": entry.severity,
        "actor": entry.actor,
        "agent_id": entry.agent_id,
        "agent_name": entry.agent_name,
        "action": entry.action,
        "resource": entry.resource,
        "decision": entry.decision,
        "reason": entry.reason,
        "details": entry.details or {},
        "trace_id": entry.trace_id,
    }
    # Added later: hashed only when set, so earlier entries keep their hashes.
    if entry.on_behalf_of is not None:
        payload["on_behalf_of"] = entry.on_behalf_of
    return payload


def compute_hash(prev_hash: str, entry: LedgerEntry) -> str:
    return hashlib.sha256(prev_hash.encode() + _canonical(_payload(entry))).hexdigest()


def record_hash(prev_hash: str, record: dict[str, Any]) -> str:
    """The hash of an entry as :func:`to_dict` writes it (an export's or an archive's line)."""
    payload = {k: v for k, v in record.items() if k not in ("prev_hash", "hash")}
    if payload.get("on_behalf_of") is None:
        payload.pop("on_behalf_of", None)
    return hashlib.sha256(prev_hash.encode() + _canonical(payload)).hexdigest()


# -------------------------------------------------------- what is stored is hashed


def storable(value: Any, length: int | None = None) -> str | None:
    """``value`` as a text column stores it: text, NUL (which PostgreSQL refuses) and
    halves of surrogate pairs (which no database encodes) replaced, cut to the column's
    length. An entry is hashed before it is stored: what the database would change or
    refuse would break the chain, or the transaction."""
    if value is None:
        return None
    text = (value if isinstance(value, str) else str(value)).replace("\x00", "�")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    if length is not None and len(text) > length:
        text = text[: length - 1] + "…"
    return text


def _json(value: Any) -> Any:
    """``value`` as a JSON column gives it back: text keys, lists for tuples and sets, and
    text for what JSON has no form for (a time, a float that isn't a number)."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return storable(value)
    if isinstance(value, dict):
        return {_key(k): _json(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_json(v) for v in value]
    if isinstance(value, datetime):
        return ids.isoformat(_utc(value))
    return storable(value)


def _key(key: Any) -> str | None:
    """A JSON object's key, as json.dumps writes one that isn't text."""
    if isinstance(key, str):
        return storable(key)
    return storable(json.dumps(key) if key is None or isinstance(key, bool | int | float) else key)


def _utc(value: datetime | None) -> datetime | None:
    """A time as the database keeps it: in UTC, one without a zone taken as UTC (as the
    database reads it back), not as the server's local time."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def append(
    tx: db.Transaction,
    *,
    type: str,
    actor: str,
    severity: str = "info",
    agent: Agent | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    decision: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
    trace_id: str | None = None,
    on_behalf_of: str | None = None,
    ts: datetime | None = None,
) -> LedgerEntry:
    """Append an entry with the caller's transaction.

    The entry is written as the transaction commits, after everything else it changed:
    appenders lock the chain's head to extend it one at a time, and the head is then the
    last row a transaction locks, so two transactions that lock the same rows can't
    deadlock over it. An entry rolled back with its transaction, or with a savepoint it was
    appended in, isn't written. Until the commit it has no seq or hash, and the
    transaction's own queries don't see it. Its values are taken as the database will
    store them, whatever the caller passed (a number for text, say): what is hashed is
    what is stored.
    """
    entry = LedgerEntry(
        id=ids.new_id(ids.EVENT),
        ts=_utc(ts),
        type=storable(type, _LENGTHS["type"]),
        severity=storable(severity, _LENGTHS["severity"]),
        actor=storable(actor, _LENGTHS["actor"]),
        agent_id=storable(agent.id if agent else agent_id, _LENGTHS["agent_id"]),
        agent_name=storable(agent.name if agent else agent_name, _LENGTHS["agent_name"]),
        action=storable(action, _LENGTHS["action"]),
        resource=storable(resource, _LENGTHS["resource"]),
        decision=storable(decision, _LENGTHS["decision"]),
        reason=storable(reason, _LENGTHS["reason"]),
        details=_json(details or {}),
        trace_id=storable(trace_id, _LENGTHS["trace_id"]),
        on_behalf_of=storable(on_behalf_of, _LENGTHS["on_behalf_of"]),
    )
    tx.info.setdefault(_PENDING, []).append(entry)
    # For what sends the ledger on (agentgov.secops.delivery), once this commits.
    mark_changed(tx, "ledger")
    return entry


def _write_pending(tx: db.Transaction) -> None:
    """Write the transaction's entries, in the order they were appended. Updating the head
    row first takes a write lock held until the commit: appenders take turns."""
    pending: list[LedgerEntry] | None = tx.info.pop(_PENDING, None)
    if not pending:
        return
    ensure_head(tx)
    heads = LedgerHead.objects.filter(id=1)
    heads.update(last_seq=F("last_seq"))
    head = heads.get()
    for entry in pending:
        entry.seq = head.last_seq + 1
        # When it was written, unless the caller said when it happened: in the chain's order.
        entry.ts = entry.ts or ids.utcnow()
        entry.prev_hash = head.last_hash
        entry.hash = compute_hash(head.last_hash, entry)
        head.last_seq, head.last_hash = entry.seq, entry.hash
    LedgerEntry.objects.bulk_create(pending)
    heads.update(last_seq=head.last_seq, last_hash=head.last_hash)


db.WRITE_LAST.append(_write_pending)


def _savepoint(tx: db.Transaction) -> Callable[[], None]:
    """Entries appended in a savepoint (Transaction.savepoint) go if it rolls back; those of
    a transaction that rolls back go with it."""
    start = len(tx.info.get(_PENDING) or ())

    def undo() -> None:
        pending = tx.info.get(_PENDING)
        if pending is not None:
            del pending[start:]

    return undo


db.SAVEPOINTS.append(_savepoint)


def iter_entries(
    tx: db.Transaction, *, batch: int = 1000, after: int = 0, until: int | None = None
) -> Iterator[LedgerEntry]:
    last = after
    while True:
        rows = LedgerEntry.objects.filter(seq__gt=last)
        if until is not None:
            rows = rows.filter(seq__lte=until)
        page = list(rows.order_by("seq")[:batch])
        if not page:
            return
        yield from page
        last = page[-1].seq


def _chain_head(tx: db.Transaction) -> tuple[int, str] | None:
    """The chain's head as the database has it now: its last entry's seq and hash."""
    return LedgerHead.objects.filter(id=1).values_list("last_seq", "last_hash").first()


def head_seq(tx: db.Transaction) -> int:
    """Where the chain ends: rows stored past it aren't the ledger's."""
    head = _chain_head(tx)
    return head[0] if head is not None else 0


def chain() -> QuerySet[LedgerEntry]:
    """The entries the chain's head accounts for. A row stored past the head was written
    around the chain: nothing verifies it, so nothing serves or counts it as the ledger's."""
    return LedgerEntry.objects.filter(
        seq__lte=Subquery(LedgerHead.objects.filter(id=1).values("last_seq"))
    )


def of_type(entries: QuerySet[LedgerEntry], pattern: str) -> QuerySet[LedgerEntry]:
    """The entries whose type is ``pattern``, where ``*`` stands for any text
    (``decision.*``)."""
    if "*" not in pattern:
        return entries.filter(type=pattern)
    return entries.filter(type__regex="^" + ".*".join(map(re.escape, pattern.split("*"))) + "$")


def base(tx: db.Transaction) -> tuple[int, str]:
    """Where the chain in the database starts: the checkpoint the entries before it were
    archived up to, or the beginning."""
    return _floor(LedgerCheckpoint.objects.all())


def _previous_floor(tx: db.Transaction, seq: int) -> tuple[int, str]:
    return _floor(LedgerCheckpoint.objects.filter(seq__lt=seq))


def _floor(points: QuerySet[LedgerCheckpoint]) -> tuple[int, str]:
    """The last of ``points`` the entries before were archived up to, or the beginning."""
    found = (
        points.filter(pruned_at__isnull=False).order_by("-seq").values_list("seq", "hash").first()
    )
    return found if found is not None else (0, GENESIS)


def _vouching(
    tx: db.Transaction, floor: tuple[int, str], archived: list[LedgerEntry]
) -> tuple[tuple[int, str] | None, str | None]:
    """Whether one of the chain's ``ledger.archived`` entries (``archived``, after the
    floor) says the entries up to the floor were archived: exactly that range, up to that
    hash, going on from the archive before. A checkpoint marked as the chain's start
    without one isn't: the entries before it were removed, not archived. Returns a
    problem (seq, what), and a warning for an entry written before entries named the hash
    their range goes on from."""
    seq, hash_ = floor
    named = [e for e in archived if (e.details or {}).get("to") == seq]
    if not named:
        return (
            seq,
            f"the chain in the database starts after entry {seq}, but no ledger.archived "
            "entry in it says the entries up to there were archived: they were removed",
        ), None
    entry = named[-1]
    details = entry.details or {}
    previous = _previous_floor(tx, seq)
    point = LedgerCheckpoint.objects.filter(seq=seq).first()
    if details.get("hash") != hash_ or details.get("from") != previous[0] + 1:
        return (
            entry.seq,
            f"ledger.archived entry {entry.seq} names entries {details.get('from')} to {seq} "
            f"up to another hash or from another place than the checkpoints say",
        ), None
    if point is not None and details.get("sha256") != point.archive_sha256:
        return (
            entry.seq,
            f"the checkpoint at entry {seq} names another archive than ledger.archived entry "
            f"{entry.seq}",
        ), None
    if "follows" not in details:
        return None, (
            f"ledger.archived entry {entry.seq} was written before AgentGov named the hash "
            f"an archive goes on from: the chain vouches for where entries {details['from']} "
            f"to {seq} end, not where they start"
        )
    if details["follows"] != previous[1]:
        return (
            entry.seq,
            f"ledger.archived entry {entry.seq} says entries {details['from']} to {seq} go on "
            f"from another hash than the checkpoint at entry {previous[0]}",
        ), None
    return None, None


def vouched_floor(tx: db.Transaction) -> tuple[int, str] | None:
    """Where the chain in the database starts, when the chain says the entries before it
    were archived (or nothing was): None when it doesn't, which :func:`verify` reports."""
    floor = base(tx)
    if floor[0] == 0:
        return floor
    archived = list(chain().filter(type=ARCHIVED, seq__gt=floor[0]).order_by("seq"))
    problem, _ = _vouching(tx, floor, archived)
    return None if problem else floor


def stamp_window(checkpoint_hours: int) -> timedelta:
    """How much later than its entry a checkpoint's time-stamp comes when all goes well:
    the checkpoints' period (its entry can be that old when it is made), a round to make
    it, and a round to ask the authority again."""
    return timedelta(hours=checkpoint_hours) + 2 * STAMP_ROUND


def verify(
    tx: db.Transaction,
    *,
    start: tuple[int, str] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Recompute the chain and report what doesn't hold: every break (up to
    MAX_PROBLEMS), then the head, where the chain starts and the checkpoints, checked
    whatever broke before them. A chain rewritten with its hashes worked out again holds
    together: the checkpoints made before, time-stamped by an authority, don't.

    ``start`` is the ``(seq, hash)`` of an entry that was already verified: only the
    entries after it are checked. Only a full verification detects later edits to
    entries before ``start``. A full verification starts where the chain in the
    database does: after the entries archived (``from``). ``settings`` give the
    authority's certificates its time-stamps are checked against
    (AGENTGOV_LEDGER_TSA_CA_FILE) and the checkpoints' period.
    """
    trust = timestamping.trust(settings.ledger_tsa_ca_file) if settings else timestamping.Trust()
    hours = settings.ledger_checkpoint_hours if settings else CHECKPOINT_HOURS
    # The head is read first and the chain checked up to it: entries committed while
    # we read are beyond it, so concurrent appends cannot look like a broken chain.
    head = _chain_head(tx)
    floor = base(tx)
    incremental = start is not None and start[0] >= floor[0]
    checked, prev = start if start is not None and incremental else floor
    since = checked if incremental else 0
    points = {p.seq: p for p in LedgerCheckpoint.objects.filter(seq__gt=since)}
    problems: list[tuple[int | None, str]] = []
    # Past MAX_PROBLEMS, the chain's breaks are counted, not kept: they come in its order.
    uncounted = 0
    warnings: list[str] = []
    archived: list[LedgerEntry] = []
    recorded: dict[int, list[tuple[int, dict[str, Any]]]] = {}
    hashes: dict[int, str] = {}
    times: dict[int, datetime] = {}
    expected = checked + 1
    for entry in iter_entries(tx, after=checked, until=head[0] if head else None):
        broken = []
        if entry.seq != expected:
            broken.append((entry.seq, f"missing entry before seq {entry.seq}"))
        elif entry.prev_hash != prev:
            broken.append((entry.seq, "prev_hash does not match the previous entry"))
        if compute_hash(entry.prev_hash, entry) != entry.hash:
            broken.append((entry.seq, "entry contents do not match its hash"))
        kept = max(MAX_PROBLEMS - len(problems), 0)
        problems += broken[:kept]
        uncounted += len(broken[kept:])
        details = entry.details or {}
        if entry.type == ARCHIVED:
            archived.append(entry)
        elif entry.type == STAMPED and isinstance(details.get("checkpoint"), int):
            recorded.setdefault(details["checkpoint"], []).append((entry.seq, details))
        if entry.seq in points:
            hashes[entry.seq], times[entry.seq] = entry.hash, entry.ts
        prev, checked, expected = entry.hash, entry.seq, entry.seq + 1
    if head is None and checked:
        problems.append((None, "chain head is missing"))
    if head is not None and head != (checked, prev):
        problems.append(
            (checked + 1, "chain head does not match the last entry (entries removed?)")
        )
    # Past the head: rows nothing appended through the chain, or checkpoints of a chain
    # that was longer. Appends committed since the head was read account for theirs.
    ceiling = head[0] if head is not None else checked
    top = LedgerEntry.objects.aggregate(top=Max("seq"))["top"] or 0
    if head is not None and (top > ceiling or any(seq > ceiling for seq in points)):
        now = _chain_head(tx)
        ceiling = now[0] if now is not None else ceiling
    if top > ceiling:
        problems.append(
            (
                top,
                f"entries after the chain's head (entry {ceiling}): stored around the chain, "
                "not through it",
            )
        )
    for seq in sorted(s for s in points if s > ceiling):
        problems.append(
            (
                seq,
                f"checkpoint {seq} is beyond the chain's head (entry {ceiling}): the ledger was "
                "longer when it was made",
            )
        )
    if not incremental and floor[0]:
        remaining = LedgerEntry.objects.filter(seq__lte=floor[0]).aggregate(seq=Max("seq"))["seq"]
        if remaining is not None:
            problems.append(
                (
                    remaining,
                    f"entry {remaining} is still in the database, though the entries up to "
                    f"{floor[0]} left it with an archive",
                )
            )
        problem, warning = _vouching(tx, floor, archived)
        problems += [problem] if problem else []
        warnings += [warning] if warning else []
    found = check_checkpoints(
        hashes,
        [(p.seq, p.hash, _token(p)) for p in points.values() if p.seq <= ceiling],
        roots=trust.roots,
        times=times,
        window=stamp_window(hours),
    )
    problems += found["problems"]
    for seq, stamps in sorted(recorded.items()):
        point = LedgerCheckpoint.objects.filter(seq=seq).first()
        problems += recorded_problems(
            seq, stamps, (point.hash, _token(point)) if point is not None else None
        )
    warnings += stamp_warnings(found, trust, "AGENTGOV_LEDGER_TSA_CA_FILE")
    problems.sort(key=lambda p: (p[0] is None, p[0] or 0))
    return {
        "valid": not problems,
        "checked": checked,
        "broken_at": problems[0][0] if problems else None,
        "problem": problems[0][1] if problems else None,
        "problems": [{"seq": s, "problem": p} for s, p in problems[:MAX_PROBLEMS]],
        "more_problems": max(len(problems) - MAX_PROBLEMS, 0) + uncounted,
        "warnings": warnings[:MAX_PROBLEMS],
        "head": prev,
        "from": floor[0],
        "checkpoints": len(found["vouched"]),
    }


def _token(point: LedgerCheckpoint) -> bytes | None:
    return base64.b64decode(point.timestamp) if point.timestamp else None


def verify_records(records: Any, *, start: tuple[int, str] | None = None) -> dict[str, Any]:
    """Check a run of entries as :func:`to_dict` writes them (an export, or archives in
    order), without the database: each links to the one before and matches its hash.
    ``start`` is the ``(seq, hash)`` the first must follow; by default, whatever its own
    ``prev_hash`` says (a checkpoint or another archive vouches for that)."""
    count, first, last = 0, None, None
    expected: tuple[int, str] | None = start
    for record in records:
        seq, prev = record.get("seq"), record.get("prev_hash")
        if expected is None:
            expected = (seq - 1, prev)
        problem = None
        if seq != expected[0] + 1:
            problem = f"missing entry before seq {seq}"
        elif prev != expected[1]:
            problem = "prev_hash does not match the previous entry"
        elif record_hash(prev, record) != record.get("hash"):
            problem = "entry contents do not match its hash"
        if problem:
            return {"valid": False, "checked": count, "broken_at": seq, "problem": problem}
        first = seq if first is None else first
        expected, last = (seq, record["hash"]), record
        count += 1
    return {
        "valid": True,
        "checked": count,
        "first": first,
        "follows": start[1] if start else None,
        "last": last["seq"] if last else None,
        "head": last["hash"] if last else None,
    }


def statement(seq: int, hash_: str) -> bytes:
    """What a time-stamping authority signs for a checkpoint: the head it vouches for."""
    return f"agentgov ledger checkpoint seq={seq} hash={hash_}\n".encode()


STATEMENT = re.compile(r"^agentgov ledger checkpoint seq=(\d+) hash=([0-9a-f]{64})\n?$")


def read_statement(data: bytes) -> tuple[int, str]:
    """A checkpoint's statement: ``(seq, hash)``."""
    found = STATEMENT.match(data.decode("utf-8", "replace"))
    if found is None:
        raise ValueError("not a checkpoint statement")
    return int(found[1]), found[2]


def check_checkpoints(
    hashes: dict[int, str],
    points: list[tuple[int, str, bytes | None]],
    *,
    roots: tuple[Any, ...] | list[Any] = (),
    times: dict[int, datetime] | None = None,
    window: timedelta | None = None,
) -> dict[str, Any]:
    """Entries (their hashes, by seq) against checkpoints ``(seq, hash, time-stamp)``.

    A chain that holds together can still have been rewritten, with every hash after the
    change worked out again. The checkpoints were made before: each one the entries reach
    must name its entry's hash, and its time-stamp, if it has one, must cover its statement
    and carry the authority's signature (checked against ``roots``, the authority's
    certificates, when given). Returns the checkpoints that vouch for the entries, the
    problems found (seq, what), the time-stamped checkpoints the entries don't reach
    (``unreached``), the ones whose time-stamp came more than ``window`` after their entry
    (``late``: seq and the time it gives, which is when they vouch from), and how many
    time-stamps were checked."""
    vouched: list[int] = []
    problems: list[tuple[int | None, str]] = []
    unreached: list[int] = []
    late: list[tuple[int, datetime]] = []
    stamped = 0
    for seq, hash_, answer in sorted(points):
        stamp = None
        if answer is not None:
            digest = hashlib.sha256(statement(seq, hash_)).digest()
            try:
                stamp = timestamping.read_response(answer, digest, None, roots=tuple(roots))
            except timestamping.TimestampError as exc:
                problems.append((seq, f"checkpoint {seq}'s time-stamp doesn't check out: {exc}"))
                continue
            stamped += 1
        if seq not in hashes:
            if answer is not None:
                unreached.append(seq)
            continue
        if hashes[seq] != hash_:
            problems.append(
                (
                    seq,
                    f"entry {seq} doesn't match checkpoint {seq}: the ledger was changed after "
                    "the checkpoint was made",
                )
            )
            continue
        vouched.append(seq)
        entry_ts = (times or {}).get(seq)
        if stamp and window is not None and entry_ts is not None and stamp.time - entry_ts > window:
            late.append((seq, stamp.time))
    return {
        "vouched": vouched,
        "problems": problems,
        "unreached": unreached,
        "late": late,
        "stamped": stamped,
        "authority": bool(roots),
    }


def stamp_warnings(found: dict[str, Any], trust: timestamping.Trust, setting: str) -> list[str]:
    """What :func:`check_checkpoints` found that doesn't break the chain but limits what
    the time-stamps prove: late ones vouch only from when they were made, and without the
    authority's certificates (``setting``) a signature shows the token whole, not who
    signed it."""
    out = [
        f"checkpoint {seq} vouches only from {ids.isoformat(when)}: its time-stamp came long "
        "after its entry was written"
        for seq, when in found["late"]
    ]
    if trust.error:
        out.append(f"{setting}: {trust.error}")
    if found["stamped"] and not found["authority"]:
        out.append(
            f"the authority isn't checked: without {setting}, each time-stamp's signature is "
            "checked against the certificate it carries, which shows it whole, not who signed it"
        )
    return out


def recorded_problems(
    seq: int, stamps: list[tuple[int, dict[str, Any]]], point: tuple[str, bytes | None] | None
) -> list[tuple[int | None, str]]:
    """Checkpoint ``seq`` (its hash and time-stamp, None when there is no such checkpoint)
    against the time-stamps the ledger recorded for it (``ledger.timestamped`` entries:
    their seq and details). A checkpoint is time-stamped once: a second record, or a
    time-stamp that isn't the one recorded, was replaced."""
    at, details = stamps[0]
    name = f"checkpoint {seq}"
    if len(stamps) > 1:
        again = stamps[1][0]
        why = f"{name} was time-stamped again at entry {again}, after entry {at}: replaced"
        return [(again, why)]
    if point is None:
        return [(at, f"{name}, time-stamped at entry {at}, is gone")]
    if point[1] is None:
        return [(at, f"{name}'s time-stamp, recorded at entry {at}, is gone")]
    if details.get("hash") != point[0]:
        return [(at, f"{name} names another hash than the one time-stamped at entry {at}")]
    if details.get("token") != hashlib.sha256(point[1]).hexdigest():
        return [(at, f"{name}'s time-stamp isn't the one recorded at entry {at}: replaced")]
    return []


def checkpoint(tx: db.Transaction) -> LedgerCheckpoint | None:
    """Keep the chain's current head as a checkpoint (the one there already is, if the
    chain hasn't grown since). None while the ledger is empty."""
    head = _chain_head(tx)
    if head is None or head[0] == 0:
        return None
    seq, hash_ = head
    existing = LedgerCheckpoint.objects.filter(seq=seq).first()
    if existing is not None:
        return existing
    written = LedgerEntry.objects.filter(seq=seq).values_list("ts", flat=True).first()
    return LedgerCheckpoint.objects.create(
        seq=seq, hash=hash_, entry_ts=written if written is not None else ids.utcnow()
    )


def checkpoint_dict(point: LedgerCheckpoint) -> dict[str, Any]:
    return {
        "seq": point.seq,
        "hash": point.hash,
        "entry_ts": ids.isoformat(point.entry_ts),
        "created_at": ids.isoformat(point.created_at),
        "statement": statement(point.seq, point.hash).decode(),
        "tsa_url": point.tsa_url,
        "timestamped": point.timestamp is not None,
        "timestamped_at": ids.isoformat(point.timestamped_at),
        "timestamp_error": point.timestamp_error,
        # Its entry in the transparency log, if it has one.
        "log": {
            "url": point.tlog_url,
            "logged": point.tlog_entry is not None,
            "index": point.tlog_index,
            "logged_at": ids.isoformat(point.tlog_logged_at),
            "checked": point.tlog_checked,
            "error": point.tlog_error,
        },
        "archive": point.archive,
        "archive_sha256": point.archive_sha256,
        "archived_from": point.archived_from,
        "pruned_at": ids.isoformat(point.pruned_at),
    }


class IntegrityMonitor:
    """Ledger integrity for dashboards, without re-hashing the whole chain on every request.

    New entries are verified incrementally; the whole chain is re-verified when the last
    full check is older than ``full_every`` seconds, or after a failed check.
    """

    def __init__(self, full_every: float = 300.0, *, settings: Settings | None = None) -> None:
        self.full_every = full_every
        self.settings = settings
        self._lock = threading.Lock()
        self._last: dict[str, Any] | None = None
        self._full_at = 0.0

    def check(self, tx: db.Transaction) -> dict[str, Any]:
        with self._lock:
            last, now = self._last, time.monotonic()
            if last is None or not last["valid"] or now - self._full_at >= self.full_every:
                result = verify(tx, settings=self.settings)
                self._full_at = now
            else:
                result = verify(tx, start=(last["checked"], last["head"]), settings=self.settings)
            self._last = result
            return dict(result)


def with_trace_link(entry: dict[str, Any], trace_url: str | None) -> dict[str, Any]:
    """Add ``trace_url`` to an entry recorded with a trace ID, when a viewer is configured."""
    if trace_url and entry.get("trace_id"):
        entry["trace_url"] = trace_url.replace("{trace_id}", entry["trace_id"])
    return entry


def to_dict(entry: LedgerEntry) -> dict[str, Any]:
    data = _payload(entry)
    data["prev_hash"] = entry.prev_hash
    data["hash"] = entry.hash
    return data

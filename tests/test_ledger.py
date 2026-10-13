from __future__ import annotations

import time
from datetime import UTC, datetime

from sqlalchemy import delete, select, update

from agentgov import ids, ledger
from agentgov.models import LedgerCheckpoint, LedgerEntry, LedgerHead
from tests.conftest import ADMIN


def _append(rt, n: int) -> None:
    with rt.db.session() as s:
        for i in range(n):
            ledger.append(
                s, type="test.event", actor="tester", details={"i": i, "nested": {"x": [1, 2]}}
            )


def test_chain_verifies(rt) -> None:
    _append(rt, 5)
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is True
    assert result["checked"] == 5


def test_each_entry_links_to_previous(rt) -> None:
    _append(rt, 3)
    with rt.db.session() as s:
        entries = list(ledger.iter_entries(s))
    assert entries[0].prev_hash == ledger.GENESIS
    assert [e.prev_hash for e in entries[1:]] == [e.hash for e in entries[:-1]]


def test_tampering_with_contents_is_detected(rt) -> None:
    _append(rt, 4)
    with rt.db.session() as s:
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 2).values(reason="edited later"))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False
    assert result["broken_at"] == 2


def test_deleting_an_entry_is_detected(rt) -> None:
    _append(rt, 4)
    with rt.db.session() as s:
        s.execute(delete(LedgerEntry).where(LedgerEntry.seq == 3))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False
    assert result["broken_at"] == 4


def test_truncating_the_tail_is_detected(rt) -> None:
    _append(rt, 4)
    with rt.db.session() as s:
        s.execute(delete(LedgerEntry).where(LedgerEntry.seq == 4))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False
    assert "head" in result["problem"]


def test_entries_are_written_as_the_transaction_commits(rt) -> None:
    with rt.db.session() as s:
        first = ledger.append(s, type="test.event", actor="tester")
        second = ledger.append(s, type="test.event", actor="tester")
        assert first.seq is None  # not before the commit
    assert (first.seq, second.seq) == (1, 2) and second.prev_hash == first.hash
    assert first.ts <= second.ts


def test_entries_go_with_a_savepoint_that_rolls_back(rt) -> None:
    with rt.db.session() as s:
        ledger.append(s, type="test.kept", actor="tester")
        try:
            with s.begin_nested():
                ledger.append(s, type="test.undone", actor="tester")
                raise RuntimeError("undo the savepoint")
        except RuntimeError:
            pass
        with s.begin_nested():
            ledger.append(s, type="test.saved", actor="tester")
    with rt.db.session() as s:
        assert [e.type for e in ledger.iter_entries(s)] == ["test.kept", "test.saved"]
        assert ledger.verify(s)["valid"] is True


def test_rolled_back_appends_leave_no_gap(rt) -> None:
    _append(rt, 1)
    try:
        with rt.db.session() as s:
            ledger.append(s, type="test.event", actor="tester")
            raise RuntimeError("abort the transaction")
    except RuntimeError:
        pass
    _append(rt, 1)
    with rt.db.session() as s:
        assert ledger.verify(s)["valid"] is True
        assert [e.seq for e in ledger.iter_entries(s)] == [1, 2]


def test_verification_can_resume_from_a_checkpoint(rt) -> None:
    _append(rt, 3)
    with rt.db.session() as s:
        first = ledger.verify(s)
    _append(rt, 2)
    with rt.db.session() as s:
        resumed = ledger.verify(s, start=(first["checked"], first["head"]))
        full = ledger.verify(s)
    assert resumed == full
    assert resumed["checked"] == 5


def test_integrity_monitor_checks_new_entries_and_periodically_everything(rt) -> None:
    monitor = ledger.IntegrityMonitor(full_every=3600)
    _append(rt, 3)
    with rt.db.session() as s:
        assert monitor.check(s)["valid"] is True
    _append(rt, 2)
    with rt.db.session() as s:
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 5).values(reason="edited later"))
    with rt.db.session() as s:
        result = monitor.check(s)
    assert result["valid"] is False
    assert result["broken_at"] == 5

    # Edits behind the checkpoint are only caught by the next full verification.
    with rt.db.session() as s:
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 5).values(reason=None))
    with rt.db.session() as s:
        assert monitor.check(s)["valid"] is True
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 1).values(reason="edited later"))
    with rt.db.session() as s:
        assert monitor.check(s)["valid"] is True
        monitor.full_every = 0
        assert monitor.check(s)["broken_at"] == 1


def test_appends_committed_during_verification_are_not_reported_as_tampering(
    rt, monkeypatch
) -> None:
    _append(rt, 3)
    with rt.db.session() as s:
        head = s.get(LedgerHead, 1)
        stale = (head.last_seq, head.last_hash)
        # A concurrent append commits its entry and the head with it, after the reader
        # loaded the head (on PostgreSQL; SQLite lets one writer in at a time).
        s.add(
            LedgerEntry(
                seq=4,
                id="evt_concurrent",
                ts=ids.utcnow(),
                type="test.event",
                severity="info",
                actor="tester",
                details={},
                prev_hash=head.last_hash,
                hash="0" * 64,
            )
        )
        head.last_seq, head.last_hash = 4, "0" * 64
        s.flush()
        reads = iter([stale])
        real = ledger._chain_head
        monkeypatch.setattr(ledger, "_chain_head", lambda s: next(reads, None) or real(s))
        result = ledger.verify(s, start=None)
        s.rollback()
    assert result["valid"] is True
    assert result["checked"] == 3


def test_a_missing_head_is_reported(rt) -> None:
    _append(rt, 2)
    with rt.db.session() as s:
        s.execute(delete(LedgerHead))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False
    assert result["problem"] == "chain head is missing"


def test_the_person_an_agent_acted_for_is_hashed_when_there_is_one(rt) -> None:
    with rt.db.session() as s:
        ledger.append(s, type="decision.request", actor="agent:bot", on_behalf_of="alice")
        ledger.append(s, type="decision.request", actor="agent:bot")
    with rt.db.session() as s:
        with_person, without = list(ledger.iter_entries(s))
        assert ledger.to_dict(with_person)["on_behalf_of"] == "alice"
        # Entries without a person hash as they did before the column existed.
        assert "on_behalf_of" not in ledger.to_dict(without)
        assert ledger.verify(s)["valid"] is True
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 1).values(on_behalf_of="mallory"))
    with rt.db.session() as s:
        assert ledger.verify(s)["broken_at"] == 1


def _rewrite(s, seq: int, reason: str) -> None:
    """Edit one entry and work out its hash and every later one's again, head and all:
    the chain still holds together."""
    s.execute(update(LedgerEntry).where(LedgerEntry.seq == seq).values(reason=reason))
    s.expire_all()
    prev = s.get(LedgerEntry, seq).prev_hash
    for entry in ledger.iter_entries(s, after=seq - 1):
        entry.prev_hash = prev
        entry.hash = prev = ledger.compute_hash(prev, entry)
    s.execute(update(LedgerHead).where(LedgerHead.id == 1).values(last_hash=prev))


def test_a_rewrite_with_its_hashes_worked_out_again_is_caught_by_a_checkpoint(rt) -> None:
    _append(rt, 4)
    with rt.db.session() as s:
        ledger.checkpoint(s)  # entry 4's hash, kept apart
    _append(rt, 2)
    with rt.db.session() as s:
        _rewrite(s, 2, "a denial, now an allow")
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False
    assert result["problem"].startswith("entry 4 doesn't match checkpoint 4")
    # After the last checkpoint, nothing outside the ledger vouches for the entries yet.
    _append(rt, 1)
    with rt.db.session() as s:
        _rewrite(s, 6, "edited after the checkpoint")
    with rt.db.session() as s:
        assert ledger.verify(s, start=(4, s.get(LedgerEntry, 4).hash))["valid"] is True


# ------------------------------------------------------------- what is hashed


def test_what_is_hashed_is_what_is_stored(rt, monkeypatch) -> None:
    """A value of another type than its column's, a time without a zone, or text the
    database can't hold as it is: what the chain hashes is what is stored."""
    monkeypatch.setenv("TZ", "Europe/Berlin")  # where a time without a zone isn't UTC
    time.tzset()
    try:
        with rt.db.session() as s:
            # As an agent's own OPA can send them (decision.inprocess).
            ledger.append(
                s, type="decision.inprocess", actor="service:opa", resource=5, agent_name=7
            )
            ledger.append(
                s,
                type="test.event",
                actor="tester",
                reason="a\x00b",
                resource="x\ud800y",
                action="m" * 500,
                details={"t": (1, 2), 3: "three", "nan": float("nan"), "at": datetime(2026, 1, 2)},
                ts=datetime(2026, 10, 13, 10, 0),
            )
        with rt.db.session() as s:
            result = ledger.verify(s)
            first, second = ledger.iter_entries(s)
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()
    assert result["valid"] is True, result
    assert (first.resource, first.agent_name) == ("5", "7")
    assert (second.reason, second.resource) == ("a�b", "x�y")
    assert len(second.action) == 128 and second.action.endswith("…")
    assert second.details == {
        "t": [1, 2],
        "3": "three",
        "nan": "nan",
        "at": "2026-01-02T00:00:00Z",
    }
    assert second.ts == datetime(2026, 10, 13, 10, 0, tzinfo=UTC)


def test_every_break_is_reported_and_the_checks_go_on(rt) -> None:
    """One break doesn't hide the next: an entry broken first, by whatever means, mustn't
    cover an edit made later."""
    _append(rt, 6)
    with rt.db.session() as s:
        ledger.checkpoint(s)
    _append(rt, 2)
    with rt.db.session() as s:
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 2).values(reason="edited"))
        s.execute(update(LedgerEntry).where(LedgerEntry.seq == 7).values(reason="edited later"))
        s.execute(delete(LedgerEntry).where(LedgerEntry.seq == 8))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert (result["valid"], result["broken_at"]) == (False, 2)
    assert [(p["seq"], p["problem"]) for p in result["problems"]] == [
        (2, "entry contents do not match its hash"),
        (7, "entry contents do not match its hash"),
        (8, "chain head does not match the last entry (entries removed?)"),
    ]
    # The checkpoint still vouches for entry 6: only contents changed before it.
    assert result["checkpoints"] == 1


# --------------------------------------------------------- where the chain starts


def test_the_chain_starts_only_where_an_archive_says(rt) -> None:
    """Marking a checkpoint as where the chain in the database starts (as archiving does)
    and removing what came before isn't archiving: the ledger.archived entry that archiving
    writes into the chain must say so."""
    _append(rt, 10)
    with rt.db.session() as s:
        ledger.checkpoint(s)
    _append(rt, 5)
    with rt.db.session() as s:
        s.get(LedgerCheckpoint, 10).pruned_at = ids.utcnow()
        s.execute(delete(LedgerEntry).where(LedgerEntry.seq <= 10))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False and result["from"] == 10
    assert "no ledger.archived entry" in result["problem"]
    # The whole ledger, gone behind a checkpoint made up at its head: the same.
    with rt.db.session() as s:
        head = s.get(LedgerHead, 1)
        s.add(
            LedgerCheckpoint(
                seq=head.last_seq,
                hash=head.last_hash,
                entry_ts=ids.utcnow(),
                pruned_at=ids.utcnow(),
            )
        )
        s.execute(delete(LedgerEntry))
    with rt.db.session() as s:
        assert "no ledger.archived entry" in ledger.verify(s)["problem"]


# ------------------------------------------------------------ where it ends


def test_the_chain_ends_at_its_head(rt) -> None:
    """Cut back to before a checkpoint, the head with it, the chain still holds: the
    checkpoint, still in the database, says it was longer."""
    _append(rt, 5)
    with rt.db.session() as s:
        ledger.checkpoint(s)
    _append(rt, 5)
    with rt.db.session() as s:
        ledger.checkpoint(s)
    _append(rt, 5)
    with rt.db.session() as s:
        keep = s.get(LedgerEntry, 7)
        s.execute(delete(LedgerEntry).where(LedgerEntry.seq > 7))
        s.execute(
            update(LedgerHead).where(LedgerHead.id == 1).values(last_seq=7, last_hash=keep.hash)
        )
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert result["valid"] is False
    assert result["problem"].startswith("checkpoint 10 is beyond the chain's head (entry 7)")


def past_the_head(rt) -> int:
    """A row stored far past the chain's head, as someone writing to the database could."""
    with rt.db.session() as s:
        seq = s.get(LedgerHead, 1).last_seq + 1_000_000
        s.add(
            LedgerEntry(
                seq=seq,
                id="evt_aroundthechain",
                ts=ids.utcnow(),
                type="decision.request",
                severity="info",
                actor="agent:bot",
                decision="allow",
                reason="approved by alice",
                details={},
                prev_hash="ab" * 32,
                hash="cd" * 32,
            )
        )
    return seq


def test_entries_past_the_head_are_not_the_ledgers(client) -> None:
    """A row stored past the head isn't in the chain: never verified, so nothing serves it
    as the ledger's either."""
    client.post("/v1/teams", json={"name": "t"}, headers=ADMIN).raise_for_status()
    rt = client.app.state.rt
    seq = past_the_head(rt)
    verified = client.get("/v1/ledger/verify", headers=ADMIN).json()
    assert verified["valid"] is False
    assert verified["problem"].startswith("entries after the chain's head")
    assert all(e["seq"] != seq for e in client.get("/v1/ledger", headers=ADMIN).json())
    assert "evt_aroundthechain" not in client.get("/v1/ledger/export", headers=ADMIN).text
    pack = client.get("/v1/evidence/pack", params={"days": 7}, headers=ADMIN).content
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(pack)) as z:
        assert b"evt_aroundthechain" not in z.read("ledger.jsonl")
    report = client.get("/v1/evidence/report", params={"days": 7}, headers=ADMIN).json()
    assert report["ledger"]["valid"] is False
    with rt.db.session() as s:
        head = s.get(LedgerHead, 1).last_seq
        newest = select(LedgerEntry.seq).where(ledger.in_chain()).order_by(LedgerEntry.seq.desc())
        assert s.scalar(newest.limit(1)) == head


def test_a_chain_broken_everywhere_lists_the_first_breaks_and_counts_the_rest(rt) -> None:
    _append(rt, ledger.MAX_PROBLEMS + 5)
    with rt.db.session() as s:
        s.execute(update(LedgerEntry).values(reason="edited"))
    with rt.db.session() as s:
        result = ledger.verify(s)
    assert len(result["problems"]) == ledger.MAX_PROBLEMS
    assert result["more_problems"] == 5 and result["broken_at"] == 1

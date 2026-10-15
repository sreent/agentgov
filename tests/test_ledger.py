from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from agentgov import ids, ledger
from agentgov.db.models import LedgerCheckpoint, LedgerEntry, LedgerHead
from tests.conftest import ADMIN


def _append(rt, n: int) -> None:
    with rt.db.transaction() as tx:
        for i in range(n):
            ledger.append(
                tx, type="test.event", actor="tester", details={"i": i, "nested": {"x": [1, 2]}}
            )


def test_chain_verifies(rt) -> None:
    _append(rt, 5)
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is True
    assert result["checked"] == 5


def test_each_entry_links_to_previous(rt) -> None:
    _append(rt, 3)
    with rt.db.transaction() as tx:
        entries = list(ledger.iter_entries(tx))
    assert entries[0].prev_hash == ledger.GENESIS
    assert [e.prev_hash for e in entries[1:]] == [e.hash for e in entries[:-1]]


def test_tampering_with_contents_is_detected(rt) -> None:
    _append(rt, 4)
    with rt.db.transaction() as tx:
        LedgerEntry.objects.filter(seq=2).update(reason="edited later")
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False
    assert result["broken_at"] == 2


def test_deleting_an_entry_is_detected(rt) -> None:
    _append(rt, 4)
    with rt.db.transaction() as tx:
        LedgerEntry.objects.filter(seq=3).delete()
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False
    assert result["broken_at"] == 4


def test_truncating_the_tail_is_detected(rt) -> None:
    _append(rt, 4)
    with rt.db.transaction() as tx:
        LedgerEntry.objects.filter(seq=4).delete()
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False
    assert "head" in result["problem"]


def test_entries_are_written_as_the_transaction_commits(rt) -> None:
    with rt.db.transaction() as tx:
        first = ledger.append(tx, type="test.event", actor="tester")
        second = ledger.append(tx, type="test.event", actor="tester")
        assert first.seq is None  # not before the commit
    assert (first.seq, second.seq) == (1, 2) and second.prev_hash == first.hash
    assert first.ts <= second.ts


def test_entries_go_with_a_savepoint_that_rolls_back(rt) -> None:
    with rt.db.transaction() as tx:
        ledger.append(tx, type="test.kept", actor="tester")
        with pytest.raises(RuntimeError), rt.db.transaction():
            ledger.append(tx, type="test.undone", actor="tester")
            raise RuntimeError("undo the savepoint")
        with rt.db.transaction():
            ledger.append(tx, type="test.saved", actor="tester")
    with rt.db.transaction() as tx:
        assert [e.type for e in ledger.iter_entries(tx)] == ["test.kept", "test.saved"]
        assert ledger.verify(tx)["valid"] is True


def test_entries_go_with_a_sqlalchemy_savepoint_that_rolls_back(rt) -> None:
    """As the modules still on SQLAlchemy take savepoints (Session.begin_nested)."""
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
    with rt.db.transaction() as tx:
        assert [e.type for e in ledger.iter_entries(tx)] == ["test.kept", "test.saved"]
        assert ledger.verify(tx)["valid"] is True


def test_rolled_back_appends_leave_no_gap(rt) -> None:
    _append(rt, 1)
    try:
        with rt.db.transaction() as tx:
            ledger.append(tx, type="test.event", actor="tester")
            raise RuntimeError("abort the transaction")
    except RuntimeError:
        pass
    _append(rt, 1)
    with rt.db.transaction() as tx:
        assert ledger.verify(tx)["valid"] is True
        assert [e.seq for e in ledger.iter_entries(tx)] == [1, 2]


def test_verification_can_resume_from_a_checkpoint(rt) -> None:
    _append(rt, 3)
    with rt.db.transaction() as tx:
        first = ledger.verify(tx)
    _append(rt, 2)
    with rt.db.transaction() as tx:
        resumed = ledger.verify(tx, start=(first["checked"], first["head"]))
        full = ledger.verify(tx)
    assert resumed == full
    assert resumed["checked"] == 5


def test_integrity_monitor_checks_new_entries_and_periodically_everything(rt) -> None:
    monitor = ledger.IntegrityMonitor(full_every=3600)
    _append(rt, 3)
    with rt.db.transaction() as tx:
        assert monitor.check(tx)["valid"] is True
    _append(rt, 2)
    with rt.db.transaction() as tx:
        LedgerEntry.objects.filter(seq=5).update(reason="edited later")
    with rt.db.transaction() as tx:
        result = monitor.check(tx)
    assert result["valid"] is False
    assert result["broken_at"] == 5

    # Edits behind the checkpoint are only caught by the next full verification.
    with rt.db.transaction() as tx:
        LedgerEntry.objects.filter(seq=5).update(reason=None)
    with rt.db.transaction() as tx:
        assert monitor.check(tx)["valid"] is True
        LedgerEntry.objects.filter(seq=1).update(reason="edited later")
    with rt.db.transaction() as tx:
        assert monitor.check(tx)["valid"] is True
        monitor.full_every = 0
        assert monitor.check(tx)["broken_at"] == 1


def test_appends_committed_during_verification_are_not_reported_as_tampering(
    rt, monkeypatch
) -> None:
    _append(rt, 3)
    with rt.db.transaction() as tx:
        stale = ledger._chain_head(tx)
        # A concurrent append commits its entry and the head with it, after the reader
        # loaded the head (on PostgreSQL; SQLite lets one writer in at a time).
        LedgerEntry.objects.create(
            seq=4,
            id="evt_concurrent",
            ts=ids.utcnow(),
            type="test.event",
            severity="info",
            actor="tester",
            details={},
            prev_hash=stale[1],
            hash="0" * 64,
        )
        LedgerHead.objects.filter(id=1).update(last_seq=4, last_hash="0" * 64)
        reads = iter([stale])
        real = ledger._chain_head
        monkeypatch.setattr(ledger, "_chain_head", lambda tx: next(reads, None) or real(tx))
        result = ledger.verify(tx, start=None)
    assert result["valid"] is True
    assert result["checked"] == 3


def test_a_missing_head_is_reported(rt) -> None:
    _append(rt, 2)
    with rt.db.transaction() as tx:
        LedgerHead.objects.all().delete()
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False
    assert result["problem"] == "chain head is missing"


def test_the_person_an_agent_acted_for_is_hashed_when_there_is_one(rt) -> None:
    with rt.db.transaction() as tx:
        ledger.append(tx, type="decision.request", actor="agent:bot", on_behalf_of="alice")
        ledger.append(tx, type="decision.request", actor="agent:bot")
    with rt.db.transaction() as tx:
        with_person, without = list(ledger.iter_entries(tx))
        assert ledger.to_dict(with_person)["on_behalf_of"] == "alice"
        # Entries without a person hash as they did before the column existed.
        assert "on_behalf_of" not in ledger.to_dict(without)
        assert ledger.verify(tx)["valid"] is True
        LedgerEntry.objects.filter(seq=1).update(on_behalf_of="mallory")
    with rt.db.transaction() as tx:
        assert ledger.verify(tx)["broken_at"] == 1


def _rewrite(tx, seq: int, reason: str) -> None:
    """Edit one entry and work out its hash and every later one's again, head and all:
    the chain still holds together."""
    entries = list(ledger.iter_entries(tx, after=seq - 1))
    entries[0].reason = reason
    prev = entries[0].prev_hash
    for entry in entries:
        entry.prev_hash = prev
        entry.hash = prev = ledger.compute_hash(prev, entry)
        entry.save()
    LedgerHead.objects.filter(id=1).update(last_hash=prev)


def test_a_rewrite_with_its_hashes_worked_out_again_is_caught_by_a_checkpoint(rt) -> None:
    _append(rt, 4)
    with rt.db.transaction() as tx:
        ledger.checkpoint(tx)  # entry 4's hash, kept apart
    _append(rt, 2)
    with rt.db.transaction() as tx:
        _rewrite(tx, 2, "a denial, now an allow")
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False
    assert result["problem"].startswith("entry 4 doesn't match checkpoint 4")
    # After the last checkpoint, nothing outside the ledger vouches for the entries yet.
    _append(rt, 1)
    with rt.db.transaction() as tx:
        _rewrite(tx, 6, "edited after the checkpoint")
    with rt.db.transaction() as tx:
        assert ledger.verify(tx, start=(4, LedgerEntry.objects.get(seq=4).hash))["valid"] is True


# ------------------------------------------------------------- what is hashed


def test_what_is_hashed_is_what_is_stored(rt, monkeypatch) -> None:
    """A value of another type than its column's, a time without a zone, or text the
    database can't hold as it is: what the chain hashes is what is stored."""
    monkeypatch.setenv("TZ", "Europe/Berlin")  # where a time without a zone isn't UTC
    time.tzset()
    try:
        with rt.db.transaction() as tx:
            # As an agent's own OPA can send them (decision.inprocess).
            ledger.append(
                tx, type="decision.inprocess", actor="service:opa", resource=5, agent_name=7
            )
            ledger.append(
                tx,
                type="test.event",
                actor="tester",
                reason="a\x00b",
                resource="x\ud800y",
                action="m" * 500,
                details={"t": (1, 2), 3: "three", "nan": float("nan"), "at": datetime(2026, 1, 2)},
                ts=datetime(2026, 10, 13, 10, 0),
            )
        with rt.db.transaction() as tx:
            result = ledger.verify(tx)
            first, second = ledger.iter_entries(tx)
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
    with rt.db.transaction() as tx:
        ledger.checkpoint(tx)
    _append(rt, 2)
    with rt.db.transaction() as tx:
        LedgerEntry.objects.filter(seq=2).update(reason="edited")
        LedgerEntry.objects.filter(seq=7).update(reason="edited later")
        LedgerEntry.objects.filter(seq=8).delete()
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
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
    with rt.db.transaction() as tx:
        ledger.checkpoint(tx)
    _append(rt, 5)
    with rt.db.transaction() as tx:
        LedgerCheckpoint.objects.filter(seq=10).update(pruned_at=ids.utcnow())
        LedgerEntry.objects.filter(seq__lte=10).delete()
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False and result["from"] == 10
    assert "no ledger.archived entry" in result["problem"]
    # The whole ledger, gone behind a checkpoint made up at its head: the same.
    with rt.db.transaction() as tx:
        head = LedgerHead.objects.get(id=1)
        LedgerCheckpoint.objects.create(
            seq=head.last_seq,
            hash=head.last_hash,
            entry_ts=ids.utcnow(),
            pruned_at=ids.utcnow(),
        )
        LedgerEntry.objects.all().delete()
    with rt.db.transaction() as tx:
        assert "no ledger.archived entry" in ledger.verify(tx)["problem"]


# ------------------------------------------------------------ where it ends


def test_the_chain_ends_at_its_head(rt) -> None:
    """Cut back to before a checkpoint, the head with it, the chain still holds: the
    checkpoint, still in the database, says it was longer."""
    _append(rt, 5)
    with rt.db.transaction() as tx:
        ledger.checkpoint(tx)
    _append(rt, 5)
    with rt.db.transaction() as tx:
        ledger.checkpoint(tx)
    _append(rt, 5)
    with rt.db.transaction() as tx:
        keep = LedgerEntry.objects.get(seq=7)
        LedgerEntry.objects.filter(seq__gt=7).delete()
        LedgerHead.objects.filter(id=1).update(last_seq=7, last_hash=keep.hash)
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert result["valid"] is False
    assert result["problem"].startswith("checkpoint 10 is beyond the chain's head (entry 7)")


def past_the_head(rt) -> int:
    """A row stored far past the chain's head, as someone writing to the database could."""
    with rt.db.transaction():
        seq = LedgerHead.objects.get(id=1).last_seq + 1_000_000
        LedgerEntry.objects.create(
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
    with rt.db.transaction():
        head = LedgerHead.objects.get(id=1).last_seq
        assert ledger.chain().order_by("-seq").values_list("seq", flat=True).first() == head


def test_a_chain_broken_everywhere_lists_the_first_breaks_and_counts_the_rest(rt) -> None:
    _append(rt, ledger.MAX_PROBLEMS + 5)
    with rt.db.transaction() as tx:
        LedgerEntry.objects.update(reason="edited")
    with rt.db.transaction() as tx:
        result = ledger.verify(tx)
    assert len(result["problems"]) == ledger.MAX_PROBLEMS
    assert result["more_problems"] == 5 and result["broken_at"] == 1

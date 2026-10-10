from __future__ import annotations

from sqlalchemy import delete, update

from agentgov import ids, ledger
from agentgov.models import LedgerEntry, LedgerHead


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


def test_appends_committed_during_verification_are_not_reported_as_tampering(rt) -> None:
    _append(rt, 3)
    with rt.db.session() as s:
        head = s.get(LedgerHead, 1)
        # As seen by a reader that loaded the head before a concurrent append committed.
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
        s.flush()
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

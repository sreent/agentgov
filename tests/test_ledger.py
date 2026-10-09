from __future__ import annotations

from sqlalchemy import delete, update

from agentgov import ledger
from agentgov.models import LedgerEntry


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

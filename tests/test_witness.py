"""The ledger's head kept outside the database, and a database restored from an older backup
noticed (agentgov.witness, docs/backup.md)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agentgov import ids
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.runtime import Runtime
from tests.conftest import ADMIN, seed
from tests.test_api import key


@pytest.fixture
def head_file(tmp_path: Path) -> Path:
    return tmp_path / "witness" / "ledger-head.json"


@pytest.fixture
def kept(settings: Settings, head_file: Path) -> Iterator[TestClient]:
    """A control plane that keeps the ledger's head in ``head_file``."""
    settings = settings.with_overrides(ledger_witness_file=str(head_file))
    app = create_app(settings, runtime=Runtime(settings), background=False)
    with TestClient(app) as client:
        yield client


def rt_of(client: TestClient) -> Runtime:
    return client.app.state.rt  # type: ignore[attr-defined,no-any-return]


def witness(client: TestClient) -> dict:  # type: ignore[type-arg]
    return client.get("/v1/ledger/witness", headers=ADMIN).json()  # type: ignore[no-any-return]


def test_not_kept_unless_set(client: TestClient) -> None:
    assert witness(client) == {"configured": False}
    assert client.get("/v1/overview", headers=ADMIN).json()["witness"] is None


def test_kept_from_the_start_and_kept_up(kept: TestClient, head_file: Path) -> None:
    first = json.loads(head_file.read_text())
    seed(kept)
    assert witness(kept)["state"] == "ok"
    rt_of(kept).check_witness()
    later = json.loads(head_file.read_text())
    assert later["seq"] > first["seq"]


def test_a_restored_database_is_noticed_and_accepted(kept: TestClient, head_file: Path) -> None:
    seed(kept)
    rt = rt_of(kept)
    rt.check_witness()
    head = json.loads(head_file.read_text())
    # The database goes back: the file still names entries it no longer has.
    ahead = {"seq": head["seq"] + 40, "hash": "ab" * 32, "at": "2026-10-01T09:00:00Z"}
    head_file.write_text(json.dumps(ahead))
    status = rt.check_witness()
    assert status is not None and status.state == "behind"
    assert json.loads(head_file.read_text()) == ahead  # left as it is
    seen = witness(kept)
    assert seen["rewound"] and f"entries {head['seq'] + 1}" in seen["message"]
    found = kept.get("/v1/findings", params={"type": "ledger.rewound"}, headers=ADMIN).json()
    assert [(f["severity"], f["status"]) for f in found] == [("critical", "open")]
    report = kept.get("/v1/evidence/report", params={"framework": "eu-ai-act"}, headers=ADMIN)
    art12 = next(c for c in report.json()["controls"] if c["id"] == "Art. 12")
    assert art12["status"] == "attention" and "restored from an older backup" in art12["gaps"][0]
    assert kept.get("/v1/overview", headers=ADMIN).json()["witness"]["rewound"]
    # Only an administrator accepts it.
    refused = kept.post("/v1/ledger/witness/accept", headers=key(kept, "approver"))
    assert refused.status_code == 403
    accepted = kept.post("/v1/ledger/witness/accept", headers=ADMIN)
    assert accepted.status_code == 200 and accepted.json()["state"] == "ok"
    entry = kept.get("/v1/ledger", params={"type": "ledger.rewound"}, headers=ADMIN).json()[0]
    assert entry["severity"] == "critical"
    assert entry["details"]["missing"] == [head["seq"] + 1, head["seq"] + 40]
    assert entry["details"]["witness"]["at"] == "2026-10-01T09:00:00Z"
    found = kept.get(
        "/v1/findings", params={"type": "ledger.rewound", "status": "resolved"}, headers=ADMIN
    ).json()
    assert [f["status"] for f in found] == ["resolved"]
    # Nothing more to accept.
    assert kept.post("/v1/ledger/witness/accept", headers=ADMIN).status_code == 409


def test_the_gap_stays_where_it_was_noticed(kept: TestClient, head_file: Path) -> None:
    seed(kept)
    rt = rt_of(kept)
    rt.check_witness()
    head = json.loads(head_file.read_text())
    head_file.write_text(json.dumps({**head, "seq": head["seq"] + 10}))
    rt.check_witness()
    gap = f"entries {head['seq'] + 1} to {head['seq'] + 10}"
    assert gap in witness(kept)["message"]
    # Dismissed instead of accepted, and the ledger goes on meanwhile: the same entries
    # are still missing.
    found = kept.get("/v1/findings", params={"type": "ledger.rewound"}, headers=ADMIN).json()
    dismissed = kept.post(
        f"/v1/findings/{found[0]['id']}/dismiss", json={"reason": "later"}, headers=ADMIN
    )
    assert dismissed.status_code == 200, dismissed.text
    for name in ("ops", "cx", "risk"):
        kept.post("/v1/teams", json={"name": name}, headers=ADMIN).raise_for_status()
    rt.check_witness()
    assert gap in witness(kept)["message"]
    accepted = kept.post("/v1/ledger/witness/accept", headers=ADMIN)
    assert accepted.status_code == 200, accepted.text
    entry = kept.get("/v1/ledger", params={"type": "ledger.rewound"}, headers=ADMIN).json()[0]
    assert entry["details"]["missing"] == [head["seq"] + 1, head["seq"] + 10]
    # A later restore is another gap, from where that one was noticed.
    later = json.loads(head_file.read_text())
    head_file.write_text(json.dumps({**later, "seq": later["seq"] + 5}))
    rt.check_witness()
    assert f"entries {later['seq'] + 1} to {later['seq'] + 5}" in witness(kept)["message"]


def test_another_history(kept: TestClient, head_file: Path) -> None:
    seed(kept)
    rt = rt_of(kept)
    rt.check_witness()
    head = json.loads(head_file.read_text())
    head_file.write_text(json.dumps({**head, "hash": "cd" * 32}))
    status = rt.check_witness()
    assert status is not None and status.state == "forked"
    assert "another history" in witness(kept)["message"]


def test_a_file_it_cant_read_is_said_and_left(kept: TestClient, head_file: Path) -> None:
    head_file.write_text("not json")
    status = rt_of(kept).check_witness()
    assert status is not None and status.error and "isn't AgentGov's ledger head" in status.error
    assert head_file.read_text() == "not json"
    assert witness(kept)["error"]


def test_the_cli(kept: TestClient, head_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agentgov import cli
    from tests.test_cli import _Shared, runner

    monkeypatch.setattr(cli, "_client", lambda: _Shared(kept, "test-admin"))
    out = runner.invoke(cli.app, ["ledger", "witness"])
    assert out.exit_code == 0 and "goes on from the head" in out.output, out.output
    head = json.loads(head_file.read_text())
    head_file.write_text(json.dumps({**head, "seq": head["seq"] + 3}))
    rt_of(kept).check_witness()
    out = runner.invoke(cli.app, ["ledger", "witness"])
    assert out.exit_code == 1 and "aren't in it" in out.output, out.output
    out = runner.invoke(cli.app, ["ledger", "accept-restore", "--yes"])
    assert out.exit_code == 0 and "accepted" in out.output, out.output


def test_entries_gone_behind_a_made_up_archive_are_noticed(
    kept: TestClient, head_file: Path
) -> None:
    """The entry the file names is gone, and no archive accounts for it: entries were
    removed, not archived, and the database holds another history."""
    from agentgov.db.models import LedgerCheckpoint, LedgerEntry, LedgerHead

    seed(kept)
    rt = rt_of(kept)
    rt.check_witness()
    head = json.loads(head_file.read_text())
    assert head["ts"]  # when that entry was written: an archive can't have taken it yet
    with rt.db.transaction():
        last = LedgerHead.objects.get(id=1)
        LedgerCheckpoint.objects.create(
            seq=last.last_seq,
            hash=last.last_hash,
            entry_ts=ids.utcnow(),
            pruned_at=ids.utcnow(),
        )
        LedgerEntry.objects.all().delete()
    status = rt.check_witness()
    assert status is not None and status.state == "forked"
    assert json.loads(head_file.read_text()) == head  # left as it is


def test_an_entry_archived_since_is_accounted_for(settings: Settings, tmp_path: Path) -> None:
    """Archiving takes the entries older than the retention period, the one the file names
    too when the ledger was quiet that long: the chain says so, and that is no restore."""
    from datetime import timedelta

    from agentgov import ledger, retention

    archive = tmp_path / "archive"
    rt = Runtime(
        settings.with_overrides(ledger_retention_days=183, ledger_archive_dir=str(archive))
    )
    rt.init_db()
    with rt.db.transaction() as tx:
        for i in range(3):
            ledger.append(tx, type="test.old", actor="t", ts=ids.utcnow() - timedelta(days=300 - i))
    rt.check_witness()
    path = archive / "ledger-head.json"
    head = json.loads(path.read_text())
    assert head["seq"] == 3
    with rt.db.transaction() as tx:
        assert retention.archive(tx, rt.settings)["to"] == 3
    assert rt.check_witness().state == "ok"
    # The same entry, said to have been written recently: it can't have been archived.
    path.write_text(json.dumps({**head, "ts": ids.isoformat(ids.utcnow())}))
    with rt.db.transaction() as tx:
        from agentgov import witness as kept_head

        assert kept_head.compare(tx, str(path)).state == "forked"
    rt.db.dispose()

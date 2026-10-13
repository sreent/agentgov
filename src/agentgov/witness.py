"""The ledger's head, kept outside the database (docs/backup.md#a-rewound-ledger).

A database restored from an older backup, or rolled back to a point in time, loses the
ledger entries written after it, and the checkpoints that vouch for them, without a trace
in the database itself: the chain still verifies, only shorter. So the control plane keeps
the head it last saw in a file, on storage that restoring the database doesn't touch
(AGENTGOV_LEDGER_WITNESS_FILE), and compares the two when it starts and every hour:

* the database's ledger ends before the head in the file: entries are missing (``behind``);
* its entry at that place isn't the one the file names: its history isn't the one AgentGov
  wrote (``forked``).

Either is a critical finding, and the file is left as it is, until an administrator who
knows why (a restore, after a failed upgrade, say) accepts it: AgentGov then writes what
is missing into the ledger itself (``ledger.rewound``), so that the gap is part of the
evidence, and goes on from the head it has.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.models import Finding, LedgerCheckpoint, LedgerEntry, LedgerHead

OK, BEHIND, FORKED, NEW = "ok", "behind", "forked", "new"
FINDING = "ledger.rewound"


class WitnessError(Exception):
    """The file can't be read or written."""


@dataclass
class Status:
    """The database's ledger against the head the file keeps."""

    state: str  # OK, BEHIND, FORKED, or NEW (no file yet)
    file: str
    head_seq: int
    head_hash: str | None
    witness_seq: int | None = None
    witness_hash: str | None = None
    witness_at: str | None = None
    # Where the database's ledger ended when AgentGov first noticed (entries written since,
    # the finding about it among them, are another history).
    restored_at: int | None = None
    error: str | None = None  # the file couldn't be read

    @property
    def rewound(self) -> bool:
        return self.state in (BEHIND, FORKED)

    def missing(self) -> list[int] | None:
        """The entries AgentGov wrote that the database doesn't have, first and last."""
        if not self.rewound or self.witness_seq is None:
            return None
        start = (self.restored_at if self.restored_at is not None else self.head_seq) + 1
        return [start, self.witness_seq] if start <= self.witness_seq else None

    def message(self) -> str:
        gap = self.missing()
        if gap is not None:
            return (
                f"AgentGov wrote up to entry {self.witness_seq} ({self.witness_at}), but the "
                f"database's ledger ended at entry {gap[0] - 1} when it looked again: entries "
                f"{gap[0]} to {gap[1]} aren't in it. It was restored from an older backup, or "
                "rolled back."
            )
        if self.rewound:
            return (
                f"The ledger's entry {self.witness_seq} isn't the one AgentGov wrote "
                f"({self.witness_at}): the database holds another history than the one it "
                "kept."
            )
        return "The ledger goes on from the head AgentGov last saw."

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "rewound": self.rewound, "message": self.message()}


def read(path: str) -> dict[str, Any] | None:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise WitnessError(f"can't read {path}: {exc.strerror}") from None
    try:
        data = json.loads(text)
        return {"seq": int(data["seq"]), "hash": str(data["hash"]), "at": str(data.get("at"))}
    except (ValueError, KeyError, TypeError):
        raise WitnessError(f"{path} isn't AgentGov's ledger head") from None


def write(path: str, seq: int, hash_: str | None) -> None:
    """Keep the head, replacing the file whole (never half written)."""
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=target.parent, prefix=".ledger-head-")
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump({"seq": seq, "hash": hash_, "at": ids.isoformat(ids.utcnow())}, out)
            out.write("\n")
        os.replace(temp, target)
    except OSError as exc:
        raise WitnessError(f"can't write {path}: {exc.strerror}") from None


def head(session: Session) -> tuple[int, str | None]:
    row = session.get(LedgerHead, 1, populate_existing=True)
    return (row.last_seq, row.last_hash) if row is not None else (0, None)


def compare(session: Session, path: str) -> Status:
    """The database's ledger against the file."""
    seq, hash_ = head(session)
    status = Status(NEW, path, seq, hash_)
    try:
        kept = read(path)
    except WitnessError as exc:
        status.error = str(exc)
        return status
    if kept is None:
        return status
    status.witness_seq, status.witness_hash, status.witness_at = (
        kept["seq"],
        kept["hash"],
        kept["at"],
    )
    if kept["seq"] > seq:
        status.state = BEHIND
    else:
        entry = session.get(LedgerEntry, kept["seq"])
        if entry is not None:
            status.state = OK if entry.hash == kept["hash"] else FORKED
        else:
            # Archived since (retention): its checkpoint, if any, still names it.
            point = session.get(LedgerCheckpoint, kept["seq"])
            status.state = FORKED if point is not None and point.hash != kept["hash"] else OK
    if status.rewound:
        # Noticed before, about this same head (whatever became of the finding since: it is
        # kept until an administrator accepts the restore, which writes a new head).
        noticed = session.scalar(select(Finding).where(Finding.key == f"{FINDING}:ledger"))
        details = (noticed.details or {}) if noticed is not None else {}
        if details.get("witness") == kept_head(status):
            status.restored_at = details.get("restored_at")
    return status


def kept_head(status: Status) -> dict[str, Any]:
    """The head the file keeps, as the finding about it records it."""
    return {"seq": status.witness_seq, "hash": status.witness_hash}

"""Ledger checkpoints: points of the ledger's hash chain kept for good, with their
time-stamps from a time-stamping authority and the archives of the entries before them.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ledger_checkpoints",
        sa.Column("seq", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("entry_ts", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("tsa_url", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.Text(), nullable=True),
        sa.Column("timestamped_at", sa.DateTime(), nullable=True),
        sa.Column("timestamp_error", sa.Text(), nullable=True),
        sa.Column("archive", sa.Text(), nullable=True),
        sa.Column("archive_sha256", sa.String(length=64), nullable=True),
        sa.Column("archived_from", sa.Integer(), nullable=True),
        sa.Column("pruned_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("seq", name=op.f("ledger_checkpoints_pkey")),
    )


def downgrade() -> None:
    op.drop_table("ledger_checkpoints")

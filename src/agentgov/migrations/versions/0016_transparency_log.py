"""Ledger checkpoints in a transparency log: each checkpoint's entry there, as the log
answered, and whether its proof was checked (agentgov.transparency).

Revision ID: 0016
Revises: 0015
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ledger_checkpoints", schema=None) as batch_op:
        batch_op.add_column(sa.Column("tlog_url", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("tlog_entry", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("tlog_index", sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column("tlog_logged_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("tlog_checked", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("tlog_error", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("ledger_checkpoints", schema=None) as batch_op:
        for column in (
            "tlog_error",
            "tlog_checked",
            "tlog_logged_at",
            "tlog_index",
            "tlog_entry",
            "tlog_url",
        ):
            batch_op.drop_column(column)

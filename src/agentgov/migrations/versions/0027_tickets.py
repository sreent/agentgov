"""Service desks as destinations, and issues' tickets in them (docs/tickets.md).

Revision ID: 0027
Revises: 0026
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("destinations", schema=None) as batch_op:
        batch_op.add_column(sa.Column("tickets", sa.JSON(), nullable=True))

    op.create_table(
        "tickets",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("destination_id", sa.String(length=32), nullable=False),
        sa.Column("round", sa.Integer(), nullable=False),
        sa.Column("team", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=True),
        sa.Column("remote_id", sa.String(length=64), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("state", sa.String(length=64), nullable=True),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("assignee", sa.String(length=200), nullable=True),
        sa.Column("told", sa.JSON(), nullable=False),
        sa.Column("replaces", sa.String(length=64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("done_seen_at", sa.DateTime(), nullable=True),
        sa.Column("synced_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("tickets_pkey")),
    )
    with op.batch_alter_table("tickets", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_tickets_destination_id"), ["destination_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_tickets_finding_id"), ["finding_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_tickets_status"), ["status"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("tickets", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tickets_status"))
        batch_op.drop_index(batch_op.f("ix_tickets_finding_id"))
        batch_op.drop_index(batch_op.f("ix_tickets_destination_id"))

    op.drop_table("tickets")
    with op.batch_alter_table("destinations", schema=None) as batch_op:
        batch_op.drop_column("tickets")

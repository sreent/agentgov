"""Destinations: where AgentGov hands its evidence and alerts to the security team (SIEMs,
Teams and Slack), with how far each has been sent.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "destinations",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("format", sa.String(length=16), nullable=True),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("min_severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("cursor", sa.Integer(), nullable=False),
        sa.Column("delivered", sa.Integer(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("retry_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("destinations_pkey")),
    )
    with op.batch_alter_table("destinations", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_destinations_name"), ["name"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("destinations", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_destinations_name"))

    op.drop_table("destinations")

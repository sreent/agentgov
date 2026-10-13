"""What each instance of a component last said it can reach: a governance processor's OPA,
Presidio, Granite Guardian and decision point of your own (agentgov.health).

Revision ID: 0021
Revises: 0020
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "component_reports",
        sa.Column("component", sa.String(length=32), nullable=False),
        sa.Column("instance", sa.String(length=200), nullable=False),
        sa.Column("reported_at", sa.DateTime(), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("interval", sa.Integer(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("component", "instance", name=op.f("component_reports_pkey")),
    )


def downgrade() -> None:
    op.drop_table("component_reports")

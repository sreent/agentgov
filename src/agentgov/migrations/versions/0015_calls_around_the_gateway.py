"""Calls around the gateway: what agents' owners say stops calls that don't come through
the gateway, and what AgentGov found when it called an agent's A2A URL itself
(registry/reachability).

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("a2a_protection", sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column("a2a_probe", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("a2a_probe")
        batch_op.drop_column("a2a_protection")

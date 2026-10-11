"""Agent to agent: where each agent serves A2A, and the other agents an agent, or a
blueprint's agents, may call.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("a2a_url", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("agent_access", sa.JSON(), server_default="[]", nullable=False)
        )

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("agent_access", sa.JSON(), server_default="[]", nullable=False)
        )


def downgrade() -> None:
    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.drop_column("agent_access")

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("agent_access")
        batch_op.drop_column("a2a_url")

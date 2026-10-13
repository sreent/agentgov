"""A control's exceptions: its mode for the agents in a scope (docs/features.md#exceptions).

Revision ID: 0022
Revises: 0021
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("feature_settings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("scopes", sa.JSON(), server_default="[]", nullable=False))


def downgrade() -> None:
    with op.batch_alter_table("feature_settings", schema=None) as batch_op:
        batch_op.drop_column("scopes")

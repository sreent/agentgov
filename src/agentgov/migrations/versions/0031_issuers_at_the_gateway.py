"""Identity issuers the gateway trusts

Revision ID: 0031
Revises: 0030
Created: 2026-10-13 17:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

COLUMNS = ("gateway", "gateway_keys", "keys_at", "keys_error")


def upgrade() -> None:
    # The gateway takes an issuer's tokens itself, with the keys AgentGov fetched from it.
    with op.batch_alter_table("identity_issuers", schema=None) as batch_op:
        batch_op.add_column(sa.Column("gateway", sa.Boolean(), server_default="0", nullable=False))
        batch_op.add_column(sa.Column("gateway_keys", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("keys_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("keys_error", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("identity_issuers", schema=None) as batch_op:
        for column in reversed(COLUMNS):
            batch_op.drop_column(column)

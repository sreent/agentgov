"""Public clients: agents people sign in to on their own machines, such as developers' MCP
clients, which reach the gateway with the person's own token (identity/keycloak).

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("client_type", sa.String(length=16), nullable=False, server_default="service")
        )
        batch_op.add_column(
            sa.Column("redirect_uris", sa.JSON(), nullable=False, server_default="[]")
        )


def downgrade() -> None:
    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("redirect_uris")
        batch_op.drop_column("client_type")

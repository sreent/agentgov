"""Identity assertions (ID-JAG) for MCP servers outside the gateway: the authorization
server a tool server takes access tokens from, and the client AgentGov's agents are there
(identity/assertions).

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tool_servers", schema=None) as batch_op:
        batch_op.add_column(sa.Column("authorization_server", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("oauth_client_id", sa.String(length=200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("tool_servers", schema=None) as batch_op:
        batch_op.drop_column("oauth_client_id")
        batch_op.drop_column("authorization_server")

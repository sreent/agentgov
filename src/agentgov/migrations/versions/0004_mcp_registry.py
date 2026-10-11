"""The enterprise MCP registry: tool servers listed for developers' MCP clients, servers
only for developers (packages they run), and the MCP servers developers have set up.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("tool_servers", schema=None) as batch_op:
        batch_op.add_column(sa.Column("gateway", sa.Boolean(), server_default="1", nullable=False))
        batch_op.add_column(
            sa.Column("developers", sa.Boolean(), server_default="0", nullable=False)
        )
        batch_op.add_column(sa.Column("registry_name", sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column("packages", sa.JSON(), server_default="[]", nullable=False))
        batch_op.add_column(sa.Column("revision", sa.Integer(), server_default="0", nullable=False))

    op.create_table(
        "mcp_sightings",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("machine", sa.String(length=200), nullable=False),
        sa.Column("os_user", sa.String(length=200), nullable=False),
        sa.Column("client", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("identity", sa.String(length=400), nullable=False),
        sa.Column("transport", sa.String(length=16), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("command", sa.JSON(), nullable=False),
        sa.Column("env", sa.JSON(), nullable=False),
        sa.Column("headers", sa.JSON(), nullable=False),
        sa.Column("reported_by", sa.String(length=200), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("mcp_sightings_pkey")),
    )
    with op.batch_alter_table("mcp_sightings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_mcp_sightings_identity"), ["identity"], unique=False)
        batch_op.create_index("ix_mcp_sightings_machine", ["machine", "os_user"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("mcp_sightings", schema=None) as batch_op:
        batch_op.drop_index("ix_mcp_sightings_machine")
        batch_op.drop_index(batch_op.f("ix_mcp_sightings_identity"))
    op.drop_table("mcp_sightings")

    with op.batch_alter_table("tool_servers", schema=None) as batch_op:
        batch_op.drop_column("revision")
        batch_op.drop_column("packages")
        batch_op.drop_column("registry_name")
        batch_op.drop_column("developers")
        batch_op.drop_column("gateway")

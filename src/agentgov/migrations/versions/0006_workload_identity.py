"""Agents' own identities: identity issuers whose tokens agents authenticate with instead
of client secrets (Kubernetes, SPIFFE, OpenID Connect), each agent's workload identity,
and blueprints that require one.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_issuers",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("keys_url", sa.Text(), nullable=True),
        sa.Column("audience", sa.String(length=512), nullable=True),
        sa.Column("allow_reuse", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("synced_at", sa.DateTime(), nullable=True),
        sa.Column("sync_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("identity_issuers_pkey")),
        sa.UniqueConstraint("issuer", name=op.f("identity_issuers_issuer_key")),
    )
    with op.batch_alter_table("identity_issuers", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_identity_issuers_name"), ["name"], unique=True)

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("workload_issuer", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("workload_subject", sa.String(length=512), nullable=True))
        batch_op.create_index(
            "ix_agents_workload_identity", ["workload_issuer", "workload_subject"], unique=True
        )

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("require_workload_identity", sa.Boolean(), server_default="0", nullable=False)
        )


def downgrade() -> None:
    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.drop_column("require_workload_identity")

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_index("ix_agents_workload_identity")
        batch_op.drop_column("workload_subject")
        batch_op.drop_column("workload_issuer")

    with op.batch_alter_table("identity_issuers", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_identity_issuers_name"))

    op.drop_table("identity_issuers")

"""Govern model calls: model providers, their usage, and which models agents may call
(model_access) within how many tokens a day (daily_token_budget).

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "model_providers",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=True),
        sa.Column("key_file", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("trust_level", sa.String(length=16), nullable=False),
        sa.Column("prices", sa.JSON(), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("model_providers_pkey")),
    )
    with op.batch_alter_table("model_providers", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_model_providers_name"), ["name"], unique=True)

    op.create_table(
        "model_usage",
        sa.Column("agent_id", sa.String(length=32), nullable=False),
        sa.Column("day", sa.String(length=10), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("calls", sa.Integer(), nullable=False),
        sa.Column("refused", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint(
            "agent_id", "day", "provider", "model", name=op.f("model_usage_pkey")
        ),
    )
    with op.batch_alter_table("model_usage", schema=None) as batch_op:
        batch_op.create_index("ix_model_usage_day", ["day"], unique=False)

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("model_access", sa.JSON(), server_default="[]", nullable=False)
        )
        batch_op.add_column(sa.Column("daily_token_budget", sa.Integer(), nullable=True))

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("model_access", sa.JSON(), server_default="[]", nullable=False)
        )
        batch_op.add_column(sa.Column("daily_token_budget", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.drop_column("daily_token_budget")
        batch_op.drop_column("model_access")

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("daily_token_budget")
        batch_op.drop_column("model_access")

    with op.batch_alter_table("model_usage", schema=None) as batch_op:
        batch_op.drop_index("ix_model_usage_day")

    op.drop_table("model_usage")
    with op.batch_alter_table("model_providers", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_model_providers_name"))

    op.drop_table("model_providers")

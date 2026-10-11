"""Management rules: conditions on agents and what to do about the agents that meet them
(raise an issue, assign an owner, block, delete, revoke access packages), and the agents
each rule matches.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "management_rules",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("after_days", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("max_actions", sa.Integer(), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("management_rules_pkey")),
    )
    with op.batch_alter_table("management_rules", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_management_rules_name"), ["name"], unique=True)

    op.create_table(
        "rule_matches",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("agent_id", sa.String(length=32), nullable=False),
        sa.Column("since", sa.DateTime(), nullable=False),
        sa.Column("warned_at", sa.DateTime(), nullable=True),
        sa.Column("monitored_at", sa.DateTime(), nullable=True),
        sa.Column("acted_at", sa.DateTime(), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("rule_matches_pkey")),
    )
    with op.batch_alter_table("rule_matches", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_rule_matches_agent_id"), ["agent_id"], unique=False)
        batch_op.create_index("ix_rule_matches_once", ["rule_id", "agent_id"], unique=True)
        batch_op.create_index(batch_op.f("ix_rule_matches_rule_id"), ["rule_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("rule_matches", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_rule_matches_rule_id"))
        batch_op.drop_index("ix_rule_matches_once")
        batch_op.drop_index(batch_op.f("ix_rule_matches_agent_id"))

    op.drop_table("rule_matches")
    with op.batch_alter_table("management_rules", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_management_rules_name"))

    op.drop_table("management_rules")

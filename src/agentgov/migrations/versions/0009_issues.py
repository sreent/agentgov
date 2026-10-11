"""Issues: findings routed to the people responsible for them (owners, sponsors and teams),
with escalation and accepted risks, and the notifications sent about them.

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("finding_id", sa.String(length=32), nullable=False),
        sa.Column("round", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("recipient", sa.String(length=320), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("notifications_pkey")),
    )
    with op.batch_alter_table("notifications", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_notifications_finding_id"), ["finding_id"], unique=False
        )
        batch_op.create_index(
            "ix_notifications_once",
            ["finding_id", "round", "level", "channel", "recipient"],
            unique=True,
        )
        batch_op.create_index(batch_op.f("ix_notifications_status"), ["status"], unique=False)

    op.create_table(
        "teams",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("members", sa.JSON(), nullable=False),
        sa.Column("emails", sa.JSON(), nullable=False),
        sa.Column("destinations", sa.JSON(), nullable=False),
        sa.Column("is_default", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("teams_pkey")),
    )
    with op.batch_alter_table("teams", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_teams_name"), ["name"], unique=True)

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("team", sa.String(length=128), nullable=True))

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.add_column(sa.Column("team", sa.String(length=128), nullable=True))

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("level", sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column("assignees", sa.JSON(), server_default="[]", nullable=False))
        batch_op.add_column(sa.Column("escalate_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("acknowledged_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("acknowledged_by", sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column("accepted_until", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("accepted_reason", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("clean_checks", sa.Integer(), server_default="0", nullable=False)
        )
        batch_op.add_column(sa.Column("verified", sa.Boolean(), server_default="1", nullable=False))
        batch_op.add_column(sa.Column("round", sa.Integer(), server_default="0", nullable=False))


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_column("round")
        batch_op.drop_column("verified")
        batch_op.drop_column("clean_checks")
        batch_op.drop_column("accepted_reason")
        batch_op.drop_column("accepted_until")
        batch_op.drop_column("acknowledged_by")
        batch_op.drop_column("acknowledged_at")
        batch_op.drop_column("escalate_at")
        batch_op.drop_column("assignees")
        batch_op.drop_column("level")

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.drop_column("team")

    with op.batch_alter_table("agents", schema=None) as batch_op:
        batch_op.drop_column("team")

    with op.batch_alter_table("teams", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_teams_name"))

    op.drop_table("teams")
    with op.batch_alter_table("notifications", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_notifications_status"))
        batch_op.drop_index("ix_notifications_once")
        batch_op.drop_index(batch_op.f("ix_notifications_finding_id"))

    op.drop_table("notifications")

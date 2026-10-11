"""Access packages: grants agents hold for a while once approved, and the assignments of
them to agents.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "access_assignments",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("package_id", sa.String(length=32), nullable=False),
        sa.Column("agent_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("days", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False),
        sa.Column("decided_by", sa.String(length=200), nullable=True),
        sa.Column("decided_at", sa.DateTime(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("starts_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("access_assignments_pkey")),
    )
    with op.batch_alter_table("access_assignments", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_access_assignments_agent_id"), ["agent_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_access_assignments_expires_at"), ["expires_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_access_assignments_package_id"), ["package_id"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_access_assignments_status"), ["status"], unique=False)

    op.create_table(
        "access_packages",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("model_access", sa.JSON(), nullable=False),
        sa.Column("agent_access", sa.JSON(), nullable=False),
        sa.Column("blueprints", sa.JSON(), nullable=False),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("approval", sa.Boolean(), nullable=False),
        sa.Column("review_days", sa.Integer(), nullable=True),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("access_packages_pkey")),
    )
    with op.batch_alter_table("access_packages", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_access_packages_name"), ["name"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("access_packages", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_access_packages_name"))

    op.drop_table("access_packages")
    with op.batch_alter_table("access_assignments", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_access_assignments_status"))
        batch_op.drop_index(batch_op.f("ix_access_assignments_package_id"))
        batch_op.drop_index(batch_op.f("ix_access_assignments_expires_at"))
        batch_op.drop_index(batch_op.f("ix_access_assignments_agent_id"))

    op.drop_table("access_assignments")

"""Microsoft sign-ins: signed-in administrators' refresh tokens, sealed, in the database
rather than in one replica's memory, so that every replica can act as them.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "microsoft_grants",
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("sealed", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("session_id", name=op.f("microsoft_grants_pkey")),
    )
    with op.batch_alter_table("microsoft_grants", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_microsoft_grants_expires_at"), ["expires_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("microsoft_grants", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_microsoft_grants_expires_at"))
    op.drop_table("microsoft_grants")

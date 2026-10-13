"""People: whom platforms name as agents' makers and owners, by Microsoft Entra object ID
(docs/platforms.md#who-made-each-agent).

Revision ID: 0024
Revises: 0023
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "people",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=True),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("found", sa.Boolean(), nullable=False),
        sa.Column("gone_at", sa.DateTime(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("people_pkey")),
    )


def downgrade() -> None:
    op.drop_table("people")

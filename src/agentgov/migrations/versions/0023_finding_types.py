"""Finding types: which kinds of findings are raised here, and how severe each is
(docs/issues.md#kinds-of-findings).

Revision ID: 0023
Revises: 0022
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_types",
        sa.Column("type", sa.String(length=128), nullable=False),
        sa.Column("mode", sa.String(length=8), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("changed_by", sa.String(length=200), nullable=False),
        sa.Column("changed_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("type", name=op.f("finding_types_pkey")),
    )


def downgrade() -> None:
    op.drop_table("finding_types")

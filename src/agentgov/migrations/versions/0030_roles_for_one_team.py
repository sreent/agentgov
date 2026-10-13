"""Roles for one team

Revision ID: 0030
Revises: 0029
Created: 2026-10-13 16:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


TABLES = ("role_grants", "api_keys")


def _resize(old: int, new: int) -> None:
    context = op.get_context()
    for table in TABLES:
        if context.dialect.name != "sqlite":
            op.alter_column(
                table, "role", existing_type=sa.String(length=old), type_=sa.String(length=new)
            )
        elif not context.as_sql:
            # SQLite rebuilds the table, which it reads first; SQL written for review leaves
            # it be (SQLite holds no text column to its length).
            with op.batch_alter_table(table, schema=None) as batch_op:
                batch_op.alter_column(
                    "role", existing_type=sa.String(length=old), type_=sa.String(length=new)
                )


def upgrade() -> None:
    # A role given in AgentGov, or an API key's, may be for one team: approver@sales.
    _resize(32, 200)


def downgrade() -> None:
    _resize(200, 32)

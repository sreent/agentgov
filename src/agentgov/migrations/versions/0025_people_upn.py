"""People by user principal name as well as email address: owners and sponsors are named
by either (docs/issues.md#people-who-leave).

Revision ID: 0025
Revises: 0024
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("people", schema=None) as batch_op:
        batch_op.add_column(sa.Column("upn", sa.String(length=320), nullable=True))
        batch_op.create_index(batch_op.f("ix_people_email"), ["email"], unique=False)
        batch_op.create_index(batch_op.f("ix_people_upn"), ["upn"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("people", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_people_upn"))
        batch_op.drop_index(batch_op.f("ix_people_email"))
        batch_op.drop_column("upn")

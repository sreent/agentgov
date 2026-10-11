"""Who agents act for: blueprints say whether their agents act for people, for which
people, and who decides approvals made for them; the ledger and approval requests
record the person.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("approval_requests", schema=None) as batch_op:
        batch_op.add_column(sa.Column("on_behalf_of", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("on_behalf_of_id", sa.String(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("deciders", sa.String(length=16), server_default="approvers", nullable=False)
        )
        batch_op.create_index(
            batch_op.f("ix_approval_requests_on_behalf_of_id"), ["on_behalf_of_id"], unique=False
        )

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("acts_for", sa.String(length=16), server_default="either", nullable=False)
        )
        batch_op.add_column(
            sa.Column("people_groups", sa.JSON(), server_default="[]", nullable=False)
        )
        batch_op.add_column(
            sa.Column(
                "approvals_by", sa.String(length=16), server_default="approvers", nullable=False
            )
        )

    with op.batch_alter_table("ledger", schema=None) as batch_op:
        batch_op.add_column(sa.Column("on_behalf_of", sa.String(length=255), nullable=True))
        batch_op.create_index(batch_op.f("ix_ledger_on_behalf_of"), ["on_behalf_of"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("ledger", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_ledger_on_behalf_of"))
        batch_op.drop_column("on_behalf_of")

    with op.batch_alter_table("blueprints", schema=None) as batch_op:
        batch_op.drop_column("approvals_by")
        batch_op.drop_column("people_groups")
        batch_op.drop_column("acts_for")

    with op.batch_alter_table("approval_requests", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_approval_requests_on_behalf_of_id"))
        batch_op.drop_column("deciders")
        batch_op.drop_column("on_behalf_of_id")
        batch_op.drop_column("on_behalf_of")

"""Versions of the objects people edit, which their edits raise, so that an edit made from
an older copy is refused rather than silently undoing a newer one (registry/versions).

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Policies have had a version from the start.
TABLES = [
    "access_packages",
    "agents",
    "blueprints",
    "destinations",
    "identity_issuers",
    "management_rules",
    "model_providers",
    "teams",
    "tool_servers",
]


def upgrade() -> None:
    for table in TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(
                sa.Column("version", sa.Integer(), server_default="1", nullable=False)
            )


def downgrade() -> None:
    for table in reversed(TABLES):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_column("version")

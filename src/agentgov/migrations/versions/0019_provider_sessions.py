"""Back-channel logout: the identity provider's session each administrator session came
from (the ID token's sid), which the provider's logout tokens name (identity/sso).

Revision ID: 0019
Revises: 0018
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("admin_sessions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("provider_session", sa.String(length=255), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_admin_sessions_provider_session"), ["provider_session"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("admin_sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_admin_sessions_provider_session"))
        batch_op.drop_column("provider_session")

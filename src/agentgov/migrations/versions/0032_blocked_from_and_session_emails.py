"""What blocking found, and the email address a session's provider vouches for

Revision ID: 0032
Revises: 0031
Created: 2026-10-13 18:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("agents", "tool_servers")
# What each can have been before it was blocked.
BEFORE = {"agents": ("pending", "active", "discovered"), "tool_servers": ("pending", "approved")}

ledger = sa.table(
    "ledger",
    sa.column("seq", sa.Integer),
    sa.column("type", sa.String),
    sa.column("agent_id", sa.String),
    sa.column("resource", sa.Text),
    sa.column("details", sa.JSON),
)


def _before(bind: Any, table: str, *where: Any) -> str | None:
    """What the latest block the ledger keeps says it was before (a block of something
    blocked already says nothing)."""
    rows = bind.execute(sa.select(ledger.c.details).where(*where).order_by(ledger.c.seq.desc()))
    for (details,) in rows:
        was = (details or {}).get("from") if isinstance(details, dict) else None
        if was in BEFORE[table]:
            return str(was)
    return None


def _backfill(bind: Any) -> None:
    """What the agents and tool servers blocked now were before, as their blocks' ledger
    entries say."""
    for table, entry in (("agents", "agent.block"), ("tool_servers", "toolserver.block")):
        rows = sa.table(
            table,
            sa.column("id", sa.String),
            sa.column("name", sa.String),
            sa.column("status", sa.String),
            sa.column("blocked_from", sa.String),
        )
        blocked = bind.execute(sa.select(rows.c.id, rows.c.name).where(rows.c.status == "blocked"))
        for row_id, name in list(blocked):
            # An agent's entries name it by its ID; a tool server's, as a resource.
            about = (
                ledger.c.agent_id == row_id
                if table == "agents"
                else ledger.c.resource == f"toolserver/{name}"
            )
            was = _before(bind, table, ledger.c.type == entry, about)
            if was:
                bind.execute(sa.update(rows).where(rows.c.id == row_id).values(blocked_from=was))


def upgrade() -> None:
    # Unblocking gives back what blocking found: a pending agent or tool server waits for
    # approval again, rather than becoming active.
    for table in TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column("blocked_from", sa.String(length=16), nullable=True))
    # Who a person is as owners, sponsors and teams name people.
    with op.batch_alter_table("admin_sessions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("email", sa.String(length=255), nullable=True))
    # Those blocked now, as the ledger says. SQL written for review adds the columns only:
    # what was blocked before is unblocked as it was until now, to active or approved.
    if not op.get_context().as_sql:
        _backfill(op.get_bind())


def downgrade() -> None:
    with op.batch_alter_table("admin_sessions", schema=None) as batch_op:
        batch_op.drop_column("email")
    for table in reversed(TABLES):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_column("blocked_from")

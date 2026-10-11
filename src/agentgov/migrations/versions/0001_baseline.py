"""Baseline: the schema when AgentGov introduced migrations.

A database created before then, by SQLAlchemy's create_all, has some or all of
these tables already: the upgrade creates only the ones it lacks, as they were
at this revision, and later migrations then apply to it like any other.

Revision ID: 0001
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = (
    "admin_sessions",
    "agent_activity",
    "agent_instructions",
    "api_keys",
    "approval_requests",
    "approved_connectors",
    "blueprints",
    "cli_logins",
    "findings",
    "integration_state",
    "ledger",
    "ledger_head",
    "login_states",
    "platform_agents",
    "platform_syncs",
    "policies",
    "risk_signals",
    "tool_servers",
    "agents",
)


def _missing() -> set[str]:
    if op.get_context().as_sql:  # SQL written for review: an empty database
        return set(TABLES)
    return set(TABLES) - set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    missing = _missing()
    if "admin_sessions" in missing:
        op.create_table(
            "admin_sessions",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("subject", sa.String(length=255), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("roles", sa.JSON(), nullable=False),
            sa.Column("id_token", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("admin_sessions_pkey")),
        )
        op.create_index(
            op.f("ix_admin_sessions_expires_at"), "admin_sessions", ["expires_at"], unique=False
        )
        op.create_index(
            op.f("ix_admin_sessions_token_hash"), "admin_sessions", ["token_hash"], unique=True
        )
    if "agent_activity" in missing:
        op.create_table(
            "agent_activity",
            sa.Column("agent_id", sa.String(length=32), nullable=False),
            sa.Column("day", sa.String(length=10), nullable=False),
            sa.Column("tool_calls", sa.Integer(), nullable=False),
            sa.Column("denied", sa.Integer(), nullable=False),
            sa.Column("model_calls", sa.Integer(), nullable=False),
            sa.Column("input_tokens", sa.Integer(), nullable=False),
            sa.Column("output_tokens", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint("agent_id", "day", name=op.f("agent_activity_pkey")),
        )
    if "agent_instructions" in missing:
        op.create_table(
            "agent_instructions",
            sa.Column("id", sa.String(length=100), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("text", sa.Text(), nullable=False),
            sa.Column("truncated", sa.Boolean(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("reported_by", sa.String(length=200), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("reported_at", sa.DateTime(), nullable=False),
            sa.Column("issues", sa.JSON(), nullable=False),
            sa.Column("classifier_state", sa.String(length=16), nullable=False),
            sa.Column("classifier", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("agent_instructions_pkey")),
        )
        op.create_index(
            op.f("ix_agent_instructions_agent_id"), "agent_instructions", ["agent_id"], unique=False
        )
        op.create_index(
            op.f("ix_agent_instructions_classifier_state"),
            "agent_instructions",
            ["classifier_state"],
            unique=False,
        )
    if "api_keys" in missing:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False),
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("prefix", sa.String(length=16), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id", name=op.f("api_keys_pkey")),
        )
        op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)
    if "approval_requests" in missing:
        op.create_table(
            "approval_requests",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=False),
            sa.Column("agent_name", sa.String(length=200), nullable=False),
            sa.Column("action", sa.String(length=128), nullable=False),
            sa.Column("resource", sa.Text(), nullable=False),
            sa.Column("arguments", sa.JSON(), nullable=True),
            sa.Column("arguments_hash", sa.String(length=64), nullable=False),
            sa.Column("reasons", sa.JSON(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("requested_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("decided_by", sa.String(length=200), nullable=True),
            sa.Column("decided_at", sa.DateTime(), nullable=True),
            sa.Column("decision_note", sa.Text(), nullable=True),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("id", name=op.f("approval_requests_pkey")),
        )
        op.create_index(
            op.f("ix_approval_requests_agent_id"), "approval_requests", ["agent_id"], unique=False
        )
        op.create_index(
            op.f("ix_approval_requests_arguments_hash"),
            "approval_requests",
            ["arguments_hash"],
            unique=False,
        )
        op.create_index(
            op.f("ix_approval_requests_status"), "approval_requests", ["status"], unique=False
        )
    if "approved_connectors" in missing:
        op.create_table(
            "approved_connectors",
            sa.Column("connector_id", sa.String(length=200), nullable=False),
            sa.Column("note", sa.Text(), nullable=False),
            sa.Column("added_by", sa.String(length=200), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("connector_id", name=op.f("approved_connectors_pkey")),
        )
    if "blueprints" in missing:
        op.create_table(
            "blueprints",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("risk_tier", sa.String(length=16), nullable=False),
            sa.Column("permissions", sa.JSON(), nullable=False),
            sa.Column("require_sponsor", sa.Boolean(), nullable=False),
            sa.Column("attestation_days", sa.Integer(), nullable=True),
            sa.Column("labels", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("blueprints_pkey")),
        )
        op.create_index(op.f("ix_blueprints_name"), "blueprints", ["name"], unique=True)
    if "cli_logins" in missing:
        op.create_table(
            "cli_logins",
            sa.Column("state", sa.String(length=64), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("challenge", sa.String(length=64), nullable=False),
            sa.Column("code_hash", sa.String(length=64), nullable=True),
            sa.Column("identity", sa.JSON(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("state", name=op.f("cli_logins_pkey")),
            sa.UniqueConstraint("code_hash", name=op.f("cli_logins_code_hash_key")),
        )
        op.create_index(
            op.f("ix_cli_logins_expires_at"), "cli_logins", ["expires_at"], unique=False
        )
    if "findings" in missing:
        op.create_table(
            "findings",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("key", sa.String(length=300), nullable=False),
            sa.Column("type", sa.String(length=64), nullable=False),
            sa.Column("category", sa.String(length=16), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=True),
            sa.Column("subject", sa.String(length=200), nullable=False),
            sa.Column("title", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("remediation", sa.Text(), nullable=False),
            sa.Column("details", sa.JSON(), nullable=False),
            sa.Column("occurrences", sa.Integer(), nullable=False),
            sa.Column("first_seen", sa.DateTime(), nullable=False),
            sa.Column("last_seen", sa.DateTime(), nullable=False),
            sa.Column("resolved_at", sa.DateTime(), nullable=True),
            sa.Column("resolved_by", sa.String(length=200), nullable=True),
            sa.PrimaryKeyConstraint("id", name=op.f("findings_pkey")),
            sa.UniqueConstraint("key", name=op.f("findings_key_key")),
        )
        op.create_index(op.f("ix_findings_agent_id"), "findings", ["agent_id"], unique=False)
        op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
        op.create_index(op.f("ix_findings_type"), "findings", ["type"], unique=False)
    if "integration_state" in missing:
        op.create_table(
            "integration_state",
            sa.Column("key", sa.String(length=64), nullable=False),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("key", name=op.f("integration_state_pkey")),
        )
    if "ledger" in missing:
        op.create_table(
            "ledger",
            sa.Column("seq", sa.Integer(), autoincrement=False, nullable=False),
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("ts", sa.DateTime(), nullable=False),
            sa.Column("type", sa.String(length=64), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("actor", sa.String(length=200), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=True),
            sa.Column("agent_name", sa.String(length=200), nullable=True),
            sa.Column("action", sa.String(length=128), nullable=True),
            sa.Column("resource", sa.Text(), nullable=True),
            sa.Column("decision", sa.String(length=32), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("details", sa.JSON(), nullable=False),
            sa.Column("trace_id", sa.String(length=64), nullable=True),
            sa.Column("prev_hash", sa.String(length=64), nullable=False),
            sa.Column("hash", sa.String(length=64), nullable=False),
            sa.PrimaryKeyConstraint("seq", name=op.f("ledger_pkey")),
            sa.UniqueConstraint("id", name=op.f("ledger_id_key")),
        )
        op.create_index(op.f("ix_ledger_agent_id"), "ledger", ["agent_id"], unique=False)
        op.create_index(op.f("ix_ledger_decision"), "ledger", ["decision"], unique=False)
        op.create_index(op.f("ix_ledger_ts"), "ledger", ["ts"], unique=False)
        op.create_index(op.f("ix_ledger_type"), "ledger", ["type"], unique=False)
    if "ledger_head" in missing:
        op.create_table(
            "ledger_head",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("last_seq", sa.Integer(), nullable=False),
            sa.Column("last_hash", sa.String(length=64), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("ledger_head_pkey")),
        )
    if "login_states" in missing:
        op.create_table(
            "login_states",
            sa.Column("state", sa.String(length=64), nullable=False),
            sa.Column("nonce", sa.String(length=64), nullable=False),
            sa.Column("code_verifier", sa.String(length=128), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("state", name=op.f("login_states_pkey")),
        )
        op.create_index(
            op.f("ix_login_states_expires_at"), "login_states", ["expires_at"], unique=False
        )
    if "platform_agents" in missing:
        op.create_table(
            "platform_agents",
            sa.Column("id", sa.String(length=320), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("external_id", sa.String(length=255), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.Column("synced_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("platform_agents_pkey")),
        )
        op.create_index(
            op.f("ix_platform_agents_agent_id"), "platform_agents", ["agent_id"], unique=False
        )
        op.create_index(
            op.f("ix_platform_agents_source"), "platform_agents", ["source"], unique=False
        )
    if "platform_syncs" in missing:
        op.create_table(
            "platform_syncs",
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("synced_at", sa.DateTime(), nullable=False),
            sa.Column("ok", sa.Boolean(), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("counts", sa.JSON(), nullable=False),
            sa.PrimaryKeyConstraint("source", name=op.f("platform_syncs_pkey")),
        )
    if "policies" in missing:
        op.create_table(
            "policies",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("rego", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("policies_pkey")),
        )
        op.create_index(op.f("ix_policies_name"), "policies", ["name"], unique=True)
    if "risk_signals" in missing:
        op.create_table(
            "risk_signals",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=False),
            sa.Column("kind", sa.String(length=64), nullable=False),
            sa.Column("detail", sa.Text(), nullable=True),
            sa.Column("ts", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("risk_signals_pkey")),
        )
        op.create_index(
            "ix_risk_signals_agent_ts", "risk_signals", ["agent_id", "ts"], unique=False
        )
    if "tool_servers" in missing:
        op.create_table(
            "tool_servers",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("owner", sa.String(length=200), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("trust_level", sa.String(length=16), nullable=False),
            sa.Column("data_classification", sa.String(length=16), nullable=False),
            sa.Column("labels", sa.JSON(), nullable=False),
            sa.Column("tools", sa.JSON(), nullable=False),
            sa.Column("tools_synced_at", sa.DateTime(), nullable=True),
            sa.Column("created_by", sa.String(length=200), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("tool_servers_pkey")),
        )
        op.create_index(op.f("ix_tool_servers_name"), "tool_servers", ["name"], unique=True)
    if "agents" in missing:
        op.create_table(
            "agents",
            sa.Column("id", sa.String(length=32), nullable=False),
            sa.Column("name", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("status_reason", sa.Text(), nullable=True),
            sa.Column("blueprint_id", sa.String(length=32), nullable=True),
            sa.Column("owner", sa.String(length=200), nullable=True),
            sa.Column("sponsors", sa.JSON(), nullable=False),
            sa.Column("labels", sa.JSON(), nullable=False),
            sa.Column("framework", sa.String(length=100), nullable=True),
            sa.Column("platform", sa.String(length=100), nullable=True),
            sa.Column("models", sa.JSON(), nullable=False),
            sa.Column("environment", sa.String(length=50), nullable=True),
            sa.Column("risk_tier", sa.String(length=16), nullable=False),
            sa.Column("risk_score", sa.Integer(), nullable=False),
            sa.Column("risk_level", sa.String(length=16), nullable=False),
            sa.Column("risk_factors", sa.JSON(), nullable=False),
            sa.Column("permissions", sa.JSON(), nullable=False),
            sa.Column("agent_card", sa.JSON(), nullable=True),
            sa.Column("external_ids", sa.JSON(), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("client_id", sa.String(length=200), nullable=True),
            sa.Column("idp_client_uuid", sa.String(length=64), nullable=True),
            sa.Column("identity_synced_at", sa.DateTime(), nullable=True),
            sa.Column("identity_error", sa.Text(), nullable=True),
            sa.Column("attested_at", sa.DateTime(), nullable=True),
            sa.Column("attested_by", sa.String(length=200), nullable=True),
            sa.Column("attestation_expires_at", sa.DateTime(), nullable=True),
            sa.Column("created_by", sa.String(length=200), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=True),
            sa.Column("deleted_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(
                ["blueprint_id"],
                ["blueprints.id"],
                name=op.f("agents_blueprint_id_fkey"),
                ondelete="SET NULL",
            ),
            sa.PrimaryKeyConstraint("id", name=op.f("agents_pkey")),
            sa.UniqueConstraint("client_id", name=op.f("agents_client_id_key")),
        )
        op.create_index(op.f("ix_agents_blueprint_id"), "agents", ["blueprint_id"], unique=False)
        op.create_index(op.f("ix_agents_name"), "agents", ["name"], unique=True)
        op.create_index(op.f("ix_agents_status"), "agents", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_agents_status"), table_name="agents")
    op.drop_index(op.f("ix_agents_name"), table_name="agents")
    op.drop_index(op.f("ix_agents_blueprint_id"), table_name="agents")
    op.drop_table("agents")
    op.drop_index(op.f("ix_tool_servers_name"), table_name="tool_servers")
    op.drop_table("tool_servers")
    op.drop_index("ix_risk_signals_agent_ts", table_name="risk_signals")
    op.drop_table("risk_signals")
    op.drop_index(op.f("ix_policies_name"), table_name="policies")
    op.drop_table("policies")
    op.drop_table("platform_syncs")
    op.drop_index(op.f("ix_platform_agents_source"), table_name="platform_agents")
    op.drop_index(op.f("ix_platform_agents_agent_id"), table_name="platform_agents")
    op.drop_table("platform_agents")
    op.drop_index(op.f("ix_login_states_expires_at"), table_name="login_states")
    op.drop_table("login_states")
    op.drop_table("ledger_head")
    op.drop_index(op.f("ix_ledger_type"), table_name="ledger")
    op.drop_index(op.f("ix_ledger_ts"), table_name="ledger")
    op.drop_index(op.f("ix_ledger_decision"), table_name="ledger")
    op.drop_index(op.f("ix_ledger_agent_id"), table_name="ledger")
    op.drop_table("ledger")
    op.drop_table("integration_state")
    op.drop_index(op.f("ix_findings_type"), table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_agent_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_cli_logins_expires_at"), table_name="cli_logins")
    op.drop_table("cli_logins")
    op.drop_index(op.f("ix_blueprints_name"), table_name="blueprints")
    op.drop_table("blueprints")
    op.drop_table("approved_connectors")
    op.drop_index(op.f("ix_approval_requests_status"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_arguments_hash"), table_name="approval_requests")
    op.drop_index(op.f("ix_approval_requests_agent_id"), table_name="approval_requests")
    op.drop_table("approval_requests")
    op.drop_index(op.f("ix_api_keys_key_hash"), table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index(op.f("ix_agent_instructions_classifier_state"), table_name="agent_instructions")
    op.drop_index(op.f("ix_agent_instructions_agent_id"), table_name="agent_instructions")
    op.drop_table("agent_instructions")
    op.drop_table("agent_activity")
    op.drop_index(op.f("ix_admin_sessions_token_hash"), table_name="admin_sessions")
    op.drop_index(op.f("ix_admin_sessions_expires_at"), table_name="admin_sessions")
    op.drop_table("admin_sessions")

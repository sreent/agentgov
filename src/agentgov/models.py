"""Registry data model.

The vocabulary mirrors Microsoft Agent 365 / Entra Agent ID so the parity
matrix in docs/baseline-agent365.md maps one-to-one:

* ``Blueprint``  - IT-approved template for a class of agents: the tools its
                   agents may use, risk tier, sponsor and attestation rules
                   (Entra "agent identity blueprint").
* ``Agent``      - one agent identity with owner, sponsors and lifecycle state.
                   Its credentials live in Keycloak, not here.
* ``ToolServer`` - an approved MCP server: published through agentgateway for
                   agents, listed in the MCP registry for developers' tools, or both.
* ``ModelProvider`` - a model provider agents call through agentgateway.
* ``Policy``     - an organisation Rego module distributed to OPA.
* ``FeatureSetting`` - which of AgentGov's features are used, and how strictly.
* ``Team``       - people and chat channels that own agents, and that issues about
                   agents escalate to.
* ``AccessPackage`` - grants an agent can hold for a while, once approved
                   (``AccessAssignment``).
* ``ManagementRule`` - acts on the agents that match it, after telling their people
                   (``RuleMatch``).
* ``McpSighting`` - an MCP server set up on a developer's machine, as reported.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentgov.db import Base, UTCDateTime
from agentgov.ids import utcnow

# Agent lifecycle (Agent 365 terms in brackets).
PENDING = "pending"  # registration awaiting review ("Pending review")
ACTIVE = "active"  # approved and usable ("Available")
BLOCKED = "blocked"  # blocked by an admin, the kill switch or risk ("Blocked")
DELETED = "deleted"  # soft-deleted, restorable for a retention period ("Deleted")
DISCOVERED = "discovered"  # seen at runtime but never registered ("Unmanaged")
AGENT_STATUSES = (PENDING, ACTIVE, BLOCKED, DELETED, DISCOVERED)

# Tool server review states (bring-your-own MCP server approval flow).
TOOLSERVER_STATUSES = (PENDING, "approved", BLOCKED)

RISK_TIERS = ("minimal", "low", "medium", "high", "critical")
RISK_LEVELS = ("low", "medium", "high", "critical")
TRUST_LEVELS = ("verified", "unverified")
DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
SEVERITIES = ("info", "low", "medium", "high", "critical")
# Model providers agentgateway can call with an API key. "openai-compatible" is any
# server that speaks OpenAI's API (vLLM, Ollama, LiteLLM, hosted APIs) at base_url.
MODEL_PROVIDER_KINDS = ("openai", "anthropic", "gemini", "openai-compatible")
# Who a blueprint's agents act for, and who decides approvals made for a person.
ACTS_FOR = ("people", "itself", "either")
APPROVALS_BY = ("approvers", "person")
# Identity providers whose tokens agents may authenticate with instead of a secret.
ISSUER_KINDS = ("kubernetes", "spiffe", "oidc")
# Where events and alerts go: SIEMs (OpenTelemetry logs, an HTTP input, Splunk's HTTP Event
# Collector) and chats.
DESTINATION_KINDS = ("otlp", "webhook", "splunk-hec", "slack", "teams")


def _created() -> Mapped[datetime]:
    return mapped_column(UTCDateTime, default=utcnow, nullable=False)


def _updated() -> Mapped[datetime]:
    return mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Blueprint(Base):
    __tablename__ = "blueprints"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    risk_tier: Mapped[str] = mapped_column(String(16), default="medium")
    # Grants: [{"server": "<glob>", "tools": ["<glob>", ...]}]
    permissions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    require_sponsor: Mapped[bool] = mapped_column(Boolean, default=True)
    attestation_days: Mapped[int | None] = mapped_column(Integer, nullable=True, default=90)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Models its agents may call: [{"provider": "<name>", "models": ["<glob>", ...]}].
    model_access: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    # Tokens (input and output) each of its agents may use per UTC day; None: no limit.
    daily_token_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Who its agents act for: "people" (only for a person), "itself" (only on their own)
    # or "either"; and the groups those people must be in (empty: anyone).
    acts_for: Mapped[str] = mapped_column(String(16), default="either", server_default="either")
    people_groups: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    # Who decides its agents' approval requests made for a person: "approvers" (AgentGov's
    # approvers) or "person" (the person the agent acted for).
    approvals_by: Mapped[str] = mapped_column(
        String(16), default="approvers", server_default="approvers"
    )
    # Its agents authenticate with a workload identity, never with a client secret.
    require_workload_identity: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="0"
    )
    # Other agents its agents may call over A2A, by name: ["billing-*", "kb-agent"].
    agent_access: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    # The team issues about its agents escalate to, after their owners and sponsors.
    team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class Agent(Base):
    __tablename__ = "agents"
    # One agent per workload identity: the issuer's subject names the agent.
    __table_args__ = (
        Index("ix_agents_workload_identity", "workload_issuer", "workload_subject", unique=True),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default=PENDING, index=True)
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    blueprint_id: Mapped[str | None] = mapped_column(
        ForeignKey("blueprints.id", ondelete="SET NULL"), nullable=True, index=True
    )
    blueprint: Mapped[Blueprint | None] = relationship(lazy="joined")

    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sponsors: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Its own escalation team, instead of its blueprint's.
    team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    framework: Mapped[str | None] = mapped_column(String(100), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(100), nullable=True)
    models: Mapped[list[Any]] = mapped_column(JSON, default=list)
    environment: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Declared risk tier (e.g. from an AI Act style assessment) vs computed risk.
    risk_tier: Mapped[str] = mapped_column(String(16), default="medium")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="low")
    risk_factors: Mapped[list[Any]] = mapped_column(JSON, default=list)

    # Agent-specific grants, in addition to the blueprint's.
    permissions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Models it may call, in addition to the blueprint's (same shape as Blueprint's).
    model_access: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    # Its own daily token budget, instead of the blueprint's.
    daily_token_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A2A AgentCard (v1.0) describing the agent's skills and interfaces.
    agent_card: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # Where it serves A2A (its JSON-RPC endpoint), for other agents to call through the
    # gateway at /a2a/<name>; and the agents it may call, in addition to the blueprint's.
    a2a_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_access: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    # Calls around the gateway (registry/reachability): what stops calls that don't come
    # through the gateway, as its owners say ("network" or "delegation"); and what AgentGov
    # found when it last called its A2A URL itself, without a delegation.
    a2a_protection: Mapped[str | None] = mapped_column(String(16), nullable=True)
    a2a_probe: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # Identifiers in other systems (OTel agent id, platform ids, fingerprints).
    external_ids: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(64), default="registered")

    # Its workload identity, when it authenticates with a token from an identity issuer
    # (IdentityIssuer.name) for this subject instead of a client secret.
    workload_issuer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    workload_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Identity provider binding (Keycloak clientId and internal id).
    client_id: Mapped[str | None] = mapped_column(String(200), unique=True, nullable=True)
    idp_client_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    identity_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    identity_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    attested_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    attested_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    attestation_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    @property
    def on_platform(self) -> bool:
        """Run by another platform (Microsoft 365, Copilot Studio), not through the gateway."""
        return (self.source or "").startswith("platform:")


class ToolServer(Base):
    __tablename__ = "tool_servers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # The server's own MCP endpoint. A server only for developers may have none ("")
    # when they run one of its packages on their machines instead.
    url: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="approved")
    trust_level: Mapped[str] = mapped_column(String(16), default="unverified")
    data_classification: Mapped[str] = mapped_column(String(16), default="internal")
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Published on the gateway, at /mcp/<name>, for agents.
    gateway: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    # Listed for developers, in the MCP registry their MCP clients read
    # (agentgov.registry.mcp_registry).
    developers: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    # Its name there; by default "<namespace>/<name>".
    registry_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Packages developers run on their machines: [{registry_type, identifier, version,
    # command}] ("npm", "@playwright/mcp", "0.0.41").
    packages: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    # Bumped when what the registry lists changes, so developers' clients see a new version.
    revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Catalog observed through the gateway: [{name, description, annotations,
    # fingerprint, first_seen, changed_at}]. Fingerprints detect definition drift.
    tools: Mapped[list[Any]] = mapped_column(JSON, default=list)
    tools_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class ModelProvider(Base):
    """A model provider agents call through the gateway, at ``/llm/<name>``.

    Its API key never enters AgentGov: the gateway reads it from ``key_file``, a
    file mounted into the gateway (by default ``/model-keys/<name>``).
    """

    __tablename__ = "model_providers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")
    # Where an OpenAI-compatible server listens (http(s)://host[:port][/path]).
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_file: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="approved")
    # "verified": personal data may be sent to it (by agents labelled pii-access).
    trust_level: Mapped[str] = mapped_column(String(16), default="unverified")
    # USD per million tokens, by model glob: {"gpt-4o*": {"input": 2.5, "output": 10}}.
    prices: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class IdentityIssuer(Base):
    """An identity provider whose tokens agents may authenticate with instead of a client
    secret: a Kubernetes cluster, a SPIFFE trust domain, or an OpenID Connect issuer such
    as Microsoft Entra ID, Okta, AWS or GitHub Actions.

    AgentGov makes it an identity provider in Keycloak, and the client of each agent bound
    to it one that authenticates with that issuer's token for the agent's subject
    (Keycloak's federated client authentication).
    """

    __tablename__ = "identity_issuers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    # As its tokens name it: a URL, or a SPIFFE trust domain (spiffe://example.org).
    issuer: Mapped[str] = mapped_column(String(512), unique=True)
    # Where its signing keys are: a Kubernetes issuer discovery URL, an OpenID Connect
    # JWKS URL, or a SPIFFE bundle endpoint.
    keys_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # OpenID Connect: the audience its tokens carry, when it can't be Keycloak's realm.
    audience: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # OpenID Connect: a token may authenticate more than once.
    allow_reuse: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    status: Mapped[str] = mapped_column(String(16), default="approved")
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class Destination(Base):
    """Where AgentGov hands its evidence and alerts to the security team: a SIEM, through
    OpenTelemetry logs, an HTTP input or Splunk's HTTP Event Collector, or a Teams or Slack
    channel. Its credential (a token, or the chat's webhook URL) is a file the control plane
    reads, named after the destination: never in the database.
    """

    __tablename__ = "destinations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    # The SIEM's endpoint; for Teams and Slack, the webhook URL is the credential.
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # A webhook's body: a JSON array of events, or JSON lines.
    format: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # What it gets: categories of ledger entries for a SIEM, alerts for a chat.
    events: Mapped[list[str]] = mapped_column(JSON, default=list)
    min_severity: Mapped[str] = mapped_column(String(16), default="info")
    status: Mapped[str] = mapped_column(String(16), default="active")
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Delivery: the ledger entry it has been sent up to, at least once.
    cursor: Mapped[int] = mapped_column(Integer, default=0)
    delivered: Mapped[int] = mapped_column(Integer, default=0)
    delivered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class ModelUsage(Base):
    """Model calls through the gateway, per agent, UTC day, provider and model.

    ``agent_id`` is empty for callers the gateway could not identify (only possible
    when unknown agents are monitored rather than rejected).
    """

    __tablename__ = "model_usage"

    agent_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)  # YYYY-MM-DD (UTC)
    provider: Mapped[str] = mapped_column(String(64), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), primary_key=True)
    calls: Mapped[int] = mapped_column(Integer, default=0)
    refused: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)

    __table_args__ = (Index("ix_model_usage_day", "day"),)


class Policy(Base):
    """An organisation Rego module, shipped to OPA alongside the built-in library."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    rego: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class FeatureSetting(Base):
    """The mode chosen for one of AgentGov's features (``agentgov.registry.features``).

    Features nobody chose a mode for have no row and run in their default mode.
    """

    __tablename__ = "feature_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    mode: Mapped[str] = mapped_column(String(16))
    # Chosen by the deployment (AGENTGOV_FEATURES), so not changeable in the app.
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    changed_by: Mapped[str] = mapped_column(String(200))
    changed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ApiKey(Base):
    """Scoped keys for people and automation (approvers, auditors, CI pipelines)."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(32))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = _created()
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AdminSession(Base):
    """An administrator signed in through single sign-on.

    The browser holds a random token in an HttpOnly cookie; only its hash is
    stored. The provider's ID token is kept for RP-initiated logout.
    """

    __tablename__ = "admin_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    subject: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    roles: Mapped[list[Any]] = mapped_column(JSON, default=list)
    id_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class LoginState(Base):
    """A sign-in in flight: state, nonce and PKCE verifier, used once and short-lived."""

    __tablename__ = "login_states"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class CliLogin(Base):
    """A sign-in for the command line (``agentgov login``), used once and short-lived.

    The CLI listens on a loopback port and proves with PKCE that it started the
    sign-in. Once the person has signed in, who they are waits here, under the
    hash of a one-time code, until the CLI collects its session.
    """

    __tablename__ = "cli_logins"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    port: Mapped[int] = mapped_column(Integer)
    challenge: Mapped[str] = mapped_column(String(64))
    code_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    identity: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class MicrosoftGrant(Base):
    """A signed-in administrator's Microsoft sign-in, which AgentGov acts with in Microsoft
    365 and Power Platform (agentgov.identity.delegation): the refresh token, sealed with a
    key derived from the client secret, kept for as long as the AgentGov session lasts."""

    __tablename__ = "microsoft_grants"

    # The AgentGov session it belongs to (during a CLI sign-in, the sign-in's state).
    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sealed: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class PlatformAgent(Base):
    """An agent as the platform that runs it reports it (Microsoft 365, Copilot Studio).

    These agents never call tools through AgentGov's gateway, so AgentGov
    governs what their platform reports: inventory, ownership, sharing and the
    connectors they use. ``agent_id`` is their record in the registry.
    """

    __tablename__ = "platform_agents"

    id: Mapped[str] = mapped_column(String(320), primary_key=True)  # "<source>:<external id>"
    source: Mapped[str] = mapped_column(String(64), index=True)
    external_id: Mapped[str] = mapped_column(String(255))
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class PlatformSync(Base):
    """The outcome of the latest sync or import from each platform."""

    __tablename__ = "platform_syncs"

    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    synced_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    message: Mapped[str] = mapped_column(Text, default="")
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class IntegrationState(Base):
    """Where an integration with another service got to, between runs (a cursor, a
    pending query, the permissions an app was granted)."""

    __tablename__ = "integration_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AgentInstructions(Base):
    """What an agent is instructed to do (its system prompt), from one source, and
    what scanning found in it. Credentials in the text are redacted before storing."""

    __tablename__ = "agent_instructions"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)  # "<agent id>:<source>"
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(64))
    text: Mapped[str] = mapped_column(Text)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    sha256: Mapped[str] = mapped_column(String(64))
    reported_by: Mapped[str] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    reported_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    issues: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # "off" (no classifier), "pending", "done" or "error".
    classifier_state: Mapped[str] = mapped_column(String(16), default="off", index=True)
    classifier: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class ApprovedConnector(Base):
    """A Power Platform connector the organisation allows its agents to use."""

    __tablename__ = "approved_connectors"

    connector_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    note: Mapped[str] = mapped_column(Text, default="")
    added_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = _created()


class ApprovalRequest(Base):
    """Human-in-the-loop approval for one specific tool call."""

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    agent_name: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(128))
    resource: Mapped[str] = mapped_column(Text)
    arguments: Mapped[Any] = mapped_column(JSON, nullable=True)
    arguments_hash: Mapped[str] = mapped_column(String(64), index=True)
    reasons: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    requested_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # The person the agent acted for: their name, and their ID (the token's subject),
    # which an approval must match to be used.
    on_behalf_of: Mapped[str | None] = mapped_column(String(255), nullable=True)
    on_behalf_of_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    # Who decides it: "approvers" (AgentGov's approvers) or "person" (that person).
    # Administrators can always decide.
    deciders: Mapped[str] = mapped_column(
        String(16), default="approvers", server_default="approvers"
    )


class Finding(Base):
    """A posture or threat finding, open until resolved or dismissed."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    key: Mapped[str] = mapped_column(String(300), unique=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(16), default="posture")
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    agent_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = _created()
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Who it is with (docs/issues.md): how far up its chain it has gone (owner, sponsors,
    # team), the people and teams there, and when it goes further if nobody acknowledges it.
    level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    assignees: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    escalate_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # A risk accepted until a date, and why: it opens again then, if it still holds.
    accepted_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    accepted_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Checks in a row that found it gone (findings from syncs close after two), and
    # whether the last check could run at all.
    clean_checks: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    verified: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    # How many times it was raised again after being resolved or accepted: each time, its
    # chain starts over.
    round: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


class Team(Base):
    """People and chat channels that can own agents, and that issues escalate to."""

    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    # The people in it, by email address or user name: they see its issues in AgentGov
    # and may acknowledge them.
    members: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Where its issues are emailed: a list's or a shared mailbox's address, or people's
    # own (without any, its members' addresses). And the Teams and Slack destinations,
    # by name, that they are posted to.
    emails: Mapped[list[Any]] = mapped_column(JSON, default=list)
    destinations: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Issues that have no team of their own escalate to the default team.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class AccessPackage(Base):
    """Grants an agent can hold for a while: requested, approved, and expiring
    (docs/access-packages.md)."""

    __tablename__ = "access_packages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    # What it grants, as a blueprint does: tools, models, other agents (A2A).
    permissions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    model_access: Mapped[list[Any]] = mapped_column(JSON, default=list)
    agent_access: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # The blueprints whose agents may hold it (none: any agent).
    blueprints: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # How many days an assignment lasts at most; whether an approver decides requests;
    # and how often assignments are reviewed (none: never).
    duration_days: Mapped[int] = mapped_column(Integer, default=90)
    approval: Mapped[bool] = mapped_column(Boolean, default=True)
    review_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class AccessAssignment(Base):
    """An access package for an agent: asked for, then held until it expires, is revoked
    or is renewed (each renewal is an assignment of its own)."""

    __tablename__ = "access_assignments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    package_id: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    # requested, active, denied, expired, revoked, or renewed (by a later assignment).
    status: Mapped[str] = mapped_column(String(16), index=True)
    days: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(200))
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    starts_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()


class ManagementRule(Base):
    """Conditions on agents, and what to do about the agents that meet them for long enough:
    raise an issue, give them an owner, block them, delete them or revoke their access
    packages, after telling their people (docs/management-rules.md)."""

    __tablename__ = "management_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    # off, monitor (records what it would do) or enforce; the feature's mode caps it.
    mode: Mapped[str] = mapped_column(String(16), default="monitor")
    # What an agent must meet (all of it), and which agents the rule looks at.
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # issue, assign_owner, block, delete or revoke_access, and what it needs (the owner to
    # assign); how many days an agent matches before it, how severe its issue is, and how
    # many agents it acts on at once, at most.
    action: Mapped[str] = mapped_column(String(32), default="issue")
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    after_days: Mapped[int] = mapped_column(Integer, default=14)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    max_actions: Mapped[int] = mapped_column(Integer, default=10)
    labels: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _created()
    updated_at: Mapped[datetime] = _updated()
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class RuleMatch(Base):
    """An agent a management rule matches, from when it started to match: when its people
    were told, and what the rule did or would have done. Gone once the agent no longer
    matches."""

    __tablename__ = "rule_matches"
    __table_args__ = (Index("ix_rule_matches_once", "rule_id", "agent_id", unique=True),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[str] = mapped_column(String(32), index=True)
    since: Mapped[datetime] = mapped_column(UTCDateTime)
    # When the agent's people were told what the rule will do (an enforced rule only).
    warned_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # When a monitored rule would have acted, and when an enforced one did.
    monitored_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    acted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    outcome: Mapped[str | None] = mapped_column(Text, nullable=True)


class Notification(Base):
    """A message about an issue to someone's email address or a team's chat, which the
    control plane sends and retries (docs/issues.md)."""

    __tablename__ = "notifications"
    # Once per recipient, at each level of each round of an issue.
    __table_args__ = (
        Index(
            "ix_notifications_once",
            "finding_id",
            "round",
            "level",
            "channel",
            "recipient",
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(32), index=True)
    round: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[str] = mapped_column(String(16))
    # "email" to an address, or "slack" or "teams" to a destination's channel, by name.
    channel: Mapped[str] = mapped_column(String(16))
    recipient: Mapped[str] = mapped_column(String(320))
    # pending, sent, or failed for good after retrying.
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _created()
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class RiskSignal(Base):
    """Runtime evidence feeding an agent's risk score; decays after a window."""

    __tablename__ = "risk_signals"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    __table_args__ = (Index("ix_risk_signals_agent_ts", "agent_id", "ts"),)


class AgentActivity(Base):
    """Daily usage counters per agent, from gateway decisions and telemetry."""

    __tablename__ = "agent_activity"

    agent_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)  # YYYY-MM-DD (UTC)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0)
    denied: Mapped[int] = mapped_column(Integer, default=0)
    model_calls: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)


class LedgerEntry(Base):
    """Append-only, hash-chained evidence ledger.

    ``hash = sha256(prev_hash || canonical_json(entry))``, so modifying or
    deleting any stored entry breaks verification of every later entry.
    """

    __tablename__ = "ledger"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    id: Mapped[str] = mapped_column(String(32), unique=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    actor: Mapped[str] = mapped_column(String(200))
    agent_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    agent_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    action: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The person the agent acted for, by name (agentgov.identity.people.name_of).
    on_behalf_of: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class LedgerHead(Base):
    """Single row holding the tip of the hash chain.

    Appenders update this row first, which takes a write lock (row lock on
    PostgreSQL, database lock on SQLite) and serialises chain extension.
    """

    __tablename__ = "ledger_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_seq: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str] = mapped_column(String(64))


class LedgerCheckpoint(Base):
    """A point of the ledger's hash chain kept for good (docs/evidence.md): made every so
    often, time-stamped by a time-stamping authority when one is set (RFC 3161), and,
    once the entries up to it are archived and removed, where the chain goes on from."""

    __tablename__ = "ledger_checkpoints"

    # The last entry it covers, and that entry's hash and time.
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    hash: Mapped[str] = mapped_column(String(64))
    entry_ts: Mapped[datetime] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = _created()
    # The authority's time-stamp of the checkpoint's statement: its whole response, base64,
    # the time it gives, and why there is none, if it failed.
    tsa_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamped_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    timestamp_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The archive of the entries since the previous archive, up to this one, and its
    # SHA-256; and when the entries left the database.
    archive: Mapped[str | None] = mapped_column(Text, nullable=True)
    archive_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    archived_from: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pruned_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class McpSighting(Base):
    """An MCP server set up in one client on one developer's machine, as last reported
    by ``agentgov mcp scan --report``. Credentials never arrive here: environment
    variables and headers are reported by name only."""

    __tablename__ = "mcp_sightings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    machine: Mapped[str] = mapped_column(String(200))
    os_user: Mapped[str] = mapped_column(String(200), default="")
    client: Mapped[str] = mapped_column(String(64))  # "vscode", "claude-desktop", ...
    scope: Mapped[str] = mapped_column(String(16))  # "user" or "project"
    name: Mapped[str] = mapped_column(String(200))  # as the client calls it
    # What identifies the server anywhere: "url:<url>", "npm:<package>", "command:<...>".
    identity: Mapped[str] = mapped_column(String(400), index=True)
    transport: Mapped[str] = mapped_column(String(16))  # "stdio", "http" or "sse"
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    command: Mapped[list[Any]] = mapped_column(JSON, default=list)
    env: Mapped[list[Any]] = mapped_column(JSON, default=list)
    headers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    reported_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime)

    __table_args__ = (Index("ix_mcp_sightings_machine", "machine", "os_user"),)

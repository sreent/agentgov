"""The database's tables, as Django models (docs/adr/0007-django.md).

The same tables, columns and constraints as the SQLAlchemy models in agentgov.models, which
the migrations build, for the modules to use as they move to Django's ORM one at a time
(tests/test_django_models.py compares them with the database the migrations make). Django
doesn't manage these tables yet (``managed = False``): Alembic does, until Django's
migrations take over.
"""

from __future__ import annotations

from typing import Any

from django.db.models import (
    SET_NULL,
    AutoField,
    BigIntegerField,
    BooleanField,
    CharField,
    CompositePrimaryKey,
    FloatField,
    ForeignKey,
    Index,
    IntegerField,
    Manager,
    Model,
    QuerySet,
    TextField,
    UniqueConstraint,
)

from agentgov.db.fields import JSONField, UTCDateTimeField
from agentgov.ids import utcnow


class Row(Model):
    """A row of one of the tables, written as SQLAlchemy wrote one: ``save()`` writes the
    fields that changed since it was read, and the time it was updated with them, rather
    than every field. Two transactions that change different fields of one row (a job its
    last sighting, a person its description) keep both changes; a save that changed
    nothing writes nothing. A JSON value counts as changed when another is set, not when
    the one there is changed in place."""

    class Meta:
        abstract = True

    @classmethod
    def from_db(cls, db: str | None, field_names: Any, values: Any) -> Any:
        row = super().from_db(db, field_names, values)
        row._stored = row._values()
        return row

    def _values(self) -> dict[str, Any]:
        """The fields loaded, as they are now."""
        return {
            f.attname: self.__dict__[f.attname]
            for f in self._meta.concrete_fields
            if f.attname in self.__dict__
        }

    def changed(self) -> list[str]:
        """The fields set to another value since the row was read or last saved."""
        stored: dict[str, Any] = self.__dict__.get("_stored", {})
        keys = {f.attname for f in self._meta.pk_fields}
        return [
            name
            for name, value in self._values().items()
            if name not in keys and (name not in stored or value != stored[name])
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if (
            "_stored" in self.__dict__
            and not self._state.adding
            and not args
            and kwargs.get("update_fields") is None
            and not kwargs.get("force_insert")
        ):
            fields = self.changed()
            if fields:
                fields += [
                    f.attname
                    for f in self._meta.concrete_fields
                    if getattr(f, "auto_now", False) and f.attname not in fields
                ]
            kwargs["update_fields"] = fields
        super().save(*args, **kwargs)
        self._stored = self._values()

    def refresh_from_db(self, *args: Any, **kwargs: Any) -> None:
        fields = kwargs.get("fields", args[1] if len(args) > 1 else None)
        deferred = self.get_deferred_fields()
        super().refresh_from_db(*args, **kwargs)
        read = (
            set(fields)
            if fields is not None
            else {f.attname for f in self._meta.concrete_fields} - deferred
        )
        stored = self.__dict__.setdefault("_stored", {})
        stored.update({name: value for name, value in self._values().items() if name in read})


class Blueprint(Row):
    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=128)
    description = TextField(default="")
    risk_tier = CharField(max_length=16, default="medium")
    # Grants: [{"server": "<glob>", "tools": ["<glob>", ...]}]
    permissions = JSONField(default=list)
    require_sponsor = BooleanField(default=True)
    attestation_days = IntegerField(null=True, default=90)
    labels = JSONField(default=dict)
    # Models its agents may call: [{"provider": "<name>", "models": ["<glob>", ...]}].
    model_access = JSONField(default=list, db_default=[])
    # Tokens (input and output) each of its agents may use per UTC day; None: no limit.
    daily_token_budget = IntegerField(null=True)
    # Who its agents act for: "people" (only for a person), "itself" (only on their own)
    # or "either"; and the groups those people must be in (empty: anyone).
    acts_for = CharField(max_length=16, default="either", db_default="either")
    people_groups = JSONField(default=list, db_default=[])
    # Who decides its agents' approval requests made for a person: "approvers" (AgentGov's
    # approvers) or "person" (the person the agent acted for).
    approvals_by = CharField(max_length=16, default="approvers", db_default="approvers")
    # Its agents authenticate with a workload identity, never with a client secret.
    require_workload_identity = BooleanField(default=False, db_default=False)
    # Other agents its agents may call over A2A, by name: ["billing-*", "kb-agent"].
    agent_access = JSONField(default=list, db_default=[])
    # The team issues about its agents escalate to, after their owners and sponsors.
    team = CharField(max_length=128, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "blueprints"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_blueprints_name"),
        ]


class _WithBlueprint(Manager):
    """Agents, read with their blueprints (as SQLAlchemy's relationship read them): most
    of what is worked out about an agent is its blueprint's too."""

    def get_queryset(self) -> QuerySet[Any]:
        return super().get_queryset().select_related("blueprint")


class Agent(Row):
    objects = _WithBlueprint()

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=200)
    description = TextField(default="")
    status = CharField(max_length=16, default="pending")
    status_reason = TextField(null=True)
    # Blocked, what it was before (pending, active, discovered): unblocking gives that back,
    # so that blocking then unblocking approves nothing.
    blocked_from = CharField(max_length=16, null=True)
    blueprint = ForeignKey(
        "Blueprint", on_delete=SET_NULL, db_column="blueprint_id", db_index=False, null=True
    )
    owner = CharField(max_length=200, null=True)
    sponsors = JSONField(default=list)
    # Its own escalation team, instead of its blueprint's.
    team = CharField(max_length=128, null=True)
    labels = JSONField(default=dict)
    framework = CharField(max_length=100, null=True)
    platform = CharField(max_length=100, null=True)
    models = JSONField(default=list)
    environment = CharField(max_length=50, null=True)
    # Declared risk tier (e.g. from an AI Act style assessment) vs computed risk.
    risk_tier = CharField(max_length=16, default="medium")
    # Its classification under the EU AI Act: category, role, basis, purpose, and who
    # classified it, when (agentgov.registry.classification). None: not classified yet.
    classification = JSONField(null=True)
    risk_score = IntegerField(default=0)
    risk_level = CharField(max_length=16, default="low")
    risk_factors = JSONField(default=list)
    # Agent-specific grants, in addition to the blueprint's.
    permissions = JSONField(default=list)
    # Models it may call, in addition to the blueprint's (same shape as Blueprint's).
    model_access = JSONField(default=list, db_default=[])
    # Its own daily token budget, instead of the blueprint's.
    daily_token_budget = IntegerField(null=True)
    # A2A AgentCard (v1.0) describing the agent's skills and interfaces.
    agent_card = JSONField(null=True)
    # Where it serves A2A (its JSON-RPC endpoint), for other agents to call through the
    # gateway at /a2a/<name>; and the agents it may call, in addition to the blueprint's.
    a2a_url = TextField(null=True)
    agent_access = JSONField(default=list, db_default=[])
    # Calls around the gateway (registry/reachability): what stops calls that don't come
    # through the gateway, as its owners say ("network" or "delegation"); and what AgentGov
    # found when it last called its A2A URL itself, without a delegation.
    a2a_protection = CharField(max_length=16, null=True)
    a2a_probe = JSONField(null=True)
    # Identifiers in other systems (OTel agent id, platform ids, fingerprints).
    external_ids = JSONField(default=dict)
    source = CharField(max_length=64, default="registered")
    # Its workload identity, when it authenticates with a token from an identity issuer
    # (IdentityIssuer.name) for this subject instead of a client secret.
    workload_issuer = CharField(max_length=64, null=True)
    workload_subject = CharField(max_length=512, null=True)
    # Its client in the identity provider: "service", a confidential client that gets
    # tokens for itself (and exchanges people's); or "public", one people sign in to on
    # their own machines, such as a developer's MCP client, which acts for them only. A
    # public client's redirect URIs are where the sign-in may return (none: the loopback
    # addresses, at any port).
    client_type = CharField(max_length=16, default="service", db_default="service")
    redirect_uris = JSONField(default=list, db_default=[])
    # Identity provider binding (Keycloak clientId and internal id).
    client_id = CharField(max_length=200, null=True)
    idp_client_uuid = CharField(max_length=64, null=True)
    identity_synced_at = UTCDateTimeField(null=True)
    identity_error = TextField(null=True)
    # What its Keycloak client and client scope were last synced to be, in short: a pass
    # that isn't full syncs only the agents whose digest has changed since.
    identity_digest = CharField(max_length=64, null=True)
    attested_at = UTCDateTimeField(null=True)
    attested_by = CharField(max_length=200, null=True)
    attestation_expires_at = UTCDateTimeField(null=True)
    created_by = CharField(max_length=200, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)
    last_seen_at = UTCDateTimeField(null=True)
    deleted_at = UTCDateTimeField(null=True)

    class Meta:
        managed = False
        db_table = "agents"
        indexes = [
            Index(fields=["blueprint"], name="ix_agents_blueprint_id"),
            Index(fields=["status"], name="ix_agents_status"),
        ]
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_agents_name"),
            UniqueConstraint(
                fields=["workload_issuer", "workload_subject"], name="ix_agents_workload_identity"
            ),
            UniqueConstraint(fields=["client_id"], name="agents_client_id_key"),
        ]

    @property
    def on_platform(self) -> bool:
        """Run by another platform (Microsoft 365, Copilot Studio), not through the gateway."""
        return (self.source or "").startswith("platform:")


class ToolServer(Row):
    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=64)
    # The server's own MCP endpoint. A server only for developers may have none ("")
    # when they run one of its packages on their machines instead.
    url = TextField()
    description = TextField(default="")
    owner = CharField(max_length=200, null=True)
    status = CharField(max_length=16, default="approved")
    # Blocked, what it was before (pending or approved): unblocking gives that back.
    blocked_from = CharField(max_length=16, null=True)
    trust_level = CharField(max_length=16, default="unverified")
    data_classification = CharField(max_length=16, default="internal")
    labels = JSONField(default=dict)
    # Published on the gateway, at /mcp/<name>, for agents.
    gateway = BooleanField(default=True, db_default=True)
    # Listed for developers, in the MCP registry their MCP clients read
    # (agentgov.registry.mcp_registry).
    developers = BooleanField(default=False, db_default=False)
    # Its name there; by default "<namespace>/<name>".
    registry_name = CharField(max_length=200, null=True)
    # Packages developers run on their machines: [{registry_type, identifier, version,
    # command}] ("npm", "@playwright/mcp", "0.0.41").
    packages = JSONField(default=list, db_default=[])
    # Bumped when what the registry lists changes, so developers' clients see a new version.
    revision = IntegerField(default=0, db_default=0)
    # A server outside the gateway that takes access tokens from an authorization server of
    # its own (its issuer), for which AgentGov gives agents identity assertions (ID-JAG,
    # agentgov.identity.assertions); and the client AgentGov's agents are there (none: each
    # agent's own client ID).
    authorization_server = TextField(null=True)
    oauth_client_id = CharField(max_length=200, null=True)
    # Catalog observed through the gateway: [{name, description, annotations,
    # fingerprint, first_seen, changed_at}]. Fingerprints detect definition drift.
    tools = JSONField(default=list)
    tools_synced_at = UTCDateTimeField(null=True)
    created_by = CharField(max_length=200, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "tool_servers"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_tool_servers_name"),
        ]


class ModelProvider(Row):
    """A model provider agents call through the gateway, at ``/llm/<name>``.

    Its API key never enters AgentGov: the gateway reads it from ``key_file``, a
    file mounted into the gateway (by default ``/model-keys/<name>``).
    """

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=64)
    kind = CharField(max_length=32)
    description = TextField(default="")
    # Where an OpenAI-compatible server listens (http(s)://host[:port][/path]).
    base_url = TextField(null=True)
    key_file = TextField(null=True)
    status = CharField(max_length=16, default="approved")
    # "verified": personal data may be sent to it (by agents labelled pii-access).
    trust_level = CharField(max_length=16, default="unverified")
    # USD per million tokens, by model glob: {"gpt-4o*": {"input": 2.5, "output": 10}}.
    prices = JSONField(default=dict)
    labels = JSONField(default=dict)
    created_by = CharField(max_length=200, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "model_providers"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_model_providers_name"),
        ]


class IdentityIssuer(Row):
    """An identity provider whose tokens agents may authenticate with instead of a client
    secret: a Kubernetes cluster, a SPIFFE trust domain, or an OpenID Connect issuer such
    as Microsoft Entra ID, Okta, AWS or GitHub Actions.

    AgentGov makes it an identity provider in Keycloak, and the client of each agent bound
    to it one that authenticates with that issuer's token for the agent's subject
    (Keycloak's federated client authentication). Trusted at the gateway, its tokens are
    taken there too, without Keycloak (docs/agent-identity.md#straight-to-the-gateway).
    """

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=64)
    kind = CharField(max_length=16)
    description = TextField(default="")
    # As its tokens name it: a URL, or a SPIFFE trust domain (spiffe://example.org).
    issuer = CharField(max_length=512)
    # Where its signing keys are: a Kubernetes issuer discovery URL, an OpenID Connect
    # JWKS URL, or a SPIFFE bundle endpoint.
    keys_url = TextField(null=True)
    # OpenID Connect: the audience its tokens carry, when it can't be Keycloak's realm.
    audience = CharField(max_length=512, null=True)
    # OpenID Connect: a token may authenticate more than once.
    allow_reuse = BooleanField(default=False, db_default=False)
    # The gateway takes its tokens itself, with the signing keys AgentGov last fetched from
    # it (only those with a key ID), when it did, and why it couldn't since.
    gateway = BooleanField(default=False, db_default=False)
    gateway_keys = JSONField(null=True)
    keys_at = UTCDateTimeField(null=True)
    keys_error = TextField(null=True)
    status = CharField(max_length=16, default="approved")
    labels = JSONField(default=dict)
    synced_at = UTCDateTimeField(null=True)
    sync_error = TextField(null=True)
    created_by = CharField(max_length=200, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "identity_issuers"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_identity_issuers_name"),
            UniqueConstraint(fields=["issuer"], name="identity_issuers_issuer_key"),
        ]


class Destination(Row):
    """Where AgentGov hands its evidence and alerts to the security team: a SIEM, through
    OpenTelemetry logs, an HTTP input or Splunk's HTTP Event Collector, or a Teams or Slack
    channel. Its credential (a token, or the chat's webhook URL) is a file the control plane
    reads, named after the destination: never in the database.
    """

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=64)
    kind = CharField(max_length=16)
    description = TextField(default="")
    # The SIEM's endpoint; for Teams and Slack, the webhook URL is the credential.
    url = TextField(null=True)
    # A webhook's body: a JSON array of events, or JSON lines.
    format = CharField(max_length=16, null=True)
    # What it gets: categories of ledger entries for a SIEM, alerts for a chat.
    events = JSONField(default=list)
    # A service desk's tickets: where they go and what they hold (registry/desks).
    tickets = JSONField(null=True)
    min_severity = CharField(max_length=16, default="info")
    status = CharField(max_length=16, default="active")
    labels = JSONField(default=dict)
    # Delivery: the ledger entry it has been sent up to, at least once.
    cursor = IntegerField(default=0)
    delivered = IntegerField(default=0)
    delivered_at = UTCDateTimeField(null=True)
    failures = IntegerField(default=0)
    last_error = TextField(null=True)
    retry_at = UTCDateTimeField(null=True)
    created_by = CharField(max_length=200, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "destinations"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_destinations_name"),
        ]


class ModelUsage(Row):
    """Model calls through the gateway, per agent, UTC day, provider and model.

    ``agent_id`` is empty for callers the gateway could not identify (only possible
    when unknown agents are monitored rather than rejected).
    """

    agent_id = CharField(max_length=32)
    day = CharField(max_length=10)  # YYYY-MM-DD (UTC)
    provider = CharField(max_length=64)
    model = CharField(max_length=128)
    calls = IntegerField(default=0)
    refused = IntegerField(default=0)
    input_tokens = IntegerField(default=0)
    output_tokens = IntegerField(default=0)
    cost_usd = FloatField(default=0.0)
    pk = CompositePrimaryKey("agent_id", "day", "provider", "model")

    class Meta:
        managed = False
        db_table = "model_usage"
        indexes = [
            Index(fields=["day"], name="ix_model_usage_day"),
        ]


class Policy(Row):
    """An organisation Rego module, shipped to OPA alongside the built-in library."""

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=128)
    description = TextField(default="")
    rego = TextField()
    enabled = BooleanField(default=True)
    version = IntegerField(default=1)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)

    class Meta:
        managed = False
        db_table = "policies"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_policies_name"),
        ]


class FindingType(Row):
    """How findings of one type are handled here (``agentgov.registry.finding_types``):
    raised or not, and how severe. Types nobody configured have no row."""

    type = CharField(max_length=128, primary_key=True)
    mode = CharField(max_length=8, default="on")
    # Instead of the severity its check gives it; None keeps that one.
    severity = CharField(max_length=16, null=True)
    changed_by = CharField(max_length=200)
    changed_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "finding_types"


class FeatureSetting(Row):
    """The mode chosen for one of AgentGov's features (``agentgov.registry.features``).

    Features nobody chose a mode for have no row and run in their default mode.
    """

    key = CharField(max_length=64, primary_key=True)
    mode = CharField(max_length=16)
    # Chosen by the deployment (AGENTGOV_FEATURES), so not changeable in the app.
    pinned = BooleanField(default=False)
    changed_by = CharField(max_length=200)
    changed_at = UTCDateTimeField(default=utcnow)
    # Its exceptions: another mode for the agents in a scope, the first that matches
    # ({"mode", "scope", "note"}; docs/features.md#exceptions).
    scopes = JSONField(default=list, db_default=[])

    class Meta:
        managed = False
        db_table = "feature_settings"


class ApiKey(Row):
    """Scoped keys for people and automation (approvers, auditors, CI pipelines)."""

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=200)
    # Its role, for every team (auditor) or one team's agents only (auditor@sales).
    role = CharField(max_length=200)
    key_hash = CharField(max_length=64)
    prefix = CharField(max_length=16)
    created_at = UTCDateTimeField(default=utcnow)
    last_used_at = UTCDateTimeField(null=True)
    revoked_at = UTCDateTimeField(null=True)
    # When it stops working, as its creator chose it (None: never); AGENTGOV_API_KEY_MAX_DAYS
    # may end it sooner (agentgov.registry.apikeys.expiry).
    expires_at = UTCDateTimeField(null=True)

    class Meta:
        managed = False
        db_table = "api_keys"
        constraints = [
            UniqueConstraint(fields=["key_hash"], name="ix_api_keys_key_hash"),
        ]


class AdminSession(Row):
    """An administrator signed in through single sign-on.

    The browser holds a random token in an HttpOnly cookie; only its hash is
    stored. The provider's ID token is kept for RP-initiated logout, and the
    provider's session it came from for back-channel logout.
    """

    id = CharField(max_length=32, primary_key=True)
    token_hash = CharField(max_length=64)
    subject = CharField(max_length=255)
    name = CharField(max_length=255)
    # The email address the provider vouches for, if it vouches for one: who the person is as
    # owners, sponsors and teams name people (a name it doesn't vouch for is nobody's).
    email = CharField(max_length=255, null=True)
    roles = JSONField(default=list)
    id_token = TextField(null=True)
    # The ID token's sid: the provider's logout tokens name the session they end by it.
    provider_session = CharField(max_length=255, null=True)
    created_at = UTCDateTimeField(default=utcnow)
    expires_at = UTCDateTimeField()

    class Meta:
        managed = False
        db_table = "admin_sessions"
        indexes = [
            Index(fields=["expires_at"], name="ix_admin_sessions_expires_at"),
            Index(fields=["provider_session"], name="ix_admin_sessions_provider_session"),
        ]
        constraints = [
            UniqueConstraint(fields=["token_hash"], name="ix_admin_sessions_token_hash"),
        ]


class RoleGrant(Row):
    """An AgentGov role given to a person in AgentGov rather than by the identity provider:
    for providers whose tokens carry no groups (Google's), and the first administrators.
    It applies when they sign in with this email address, which the provider vouches for.
    """

    id = CharField(max_length=32, primary_key=True)
    # Lowercase.
    email = CharField(max_length=255)
    # For every team (approver), or one team's agents only (approver@sales).
    role = CharField(max_length=200)
    granted_by = CharField(max_length=255)
    reason = TextField(null=True)
    created_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "role_grants"
        indexes = [
            Index(fields=["email"], name="ix_role_grants_email"),
        ]
        constraints = [
            UniqueConstraint(fields=["email", "role"], name="role_grants_email_key"),
        ]


class LoginState(Row):
    """A sign-in in flight: state, nonce and PKCE verifier, used once and short-lived."""

    state = CharField(max_length=64, primary_key=True)
    nonce = CharField(max_length=64)
    code_verifier = CharField(max_length=128)
    expires_at = UTCDateTimeField()

    class Meta:
        managed = False
        db_table = "login_states"
        indexes = [
            Index(fields=["expires_at"], name="ix_login_states_expires_at"),
        ]


class CliLogin(Row):
    """A sign-in for the command line (``agentgov login``), used once and short-lived.

    The CLI listens on a loopback port and proves with PKCE that it started the
    sign-in. Once the person has signed in, who they are waits here, under the
    hash of a one-time code, until the CLI collects its session.
    """

    state = CharField(max_length=64, primary_key=True)
    port = IntegerField()
    challenge = CharField(max_length=64)
    code_hash = CharField(max_length=64, null=True)
    identity = JSONField(null=True)
    expires_at = UTCDateTimeField()

    class Meta:
        managed = False
        db_table = "cli_logins"
        indexes = [
            Index(fields=["expires_at"], name="ix_cli_logins_expires_at"),
        ]
        constraints = [
            UniqueConstraint(fields=["code_hash"], name="cli_logins_code_hash_key"),
        ]


class MicrosoftGrant(Row):
    """A signed-in administrator's Microsoft sign-in, which AgentGov acts with in Microsoft
    365 and Power Platform (agentgov.identity.delegation): the refresh token, sealed with a
    key derived from the client secret, kept for as long as the AgentGov session lasts."""

    # The AgentGov session it belongs to (during a CLI sign-in, the sign-in's state).
    session_id = CharField(max_length=64, primary_key=True)
    sealed = TextField()
    expires_at = UTCDateTimeField()
    updated_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "microsoft_grants"
        indexes = [
            Index(fields=["expires_at"], name="ix_microsoft_grants_expires_at"),
        ]


class PlatformAgent(Row):
    """An agent as the platform that runs it reports it (Microsoft 365, Copilot Studio).

    These agents never call tools through AgentGov's gateway, so AgentGov
    governs what their platform reports: inventory, ownership, sharing and the
    connectors they use. ``agent_id`` is their record in the registry.
    """

    id = CharField(max_length=320, primary_key=True)  # "<source>:<external id>"
    source = CharField(max_length=64)
    external_id = CharField(max_length=255)
    agent_id = CharField(max_length=32)
    name = CharField(max_length=255)
    data = JSONField(default=dict)
    synced_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "platform_agents"
        indexes = [
            Index(fields=["agent_id"], name="ix_platform_agents_agent_id"),
            Index(fields=["source"], name="ix_platform_agents_source"),
        ]


class PlatformSync(Row):
    """The outcome of the latest sync or import from each platform."""

    source = CharField(max_length=64, primary_key=True)
    synced_at = UTCDateTimeField(default=utcnow)
    ok = BooleanField(default=True)
    message = TextField(default="")
    counts = JSONField(default=dict)

    class Meta:
        managed = False
        db_table = "platform_syncs"


class ComponentReport(Row):
    """What one instance of a component (a governance processor) last said it can reach:
    OPA, Presidio, Granite Guardian, a decision point of your own (agentgov.health)."""

    component = CharField(max_length=32)
    instance = CharField(max_length=200)
    reported_at = UTCDateTimeField(default=utcnow)
    version = CharField(max_length=32, default="")
    # Seconds between its reports: it is out of touch after a few missed ones.
    interval = IntegerField(default=60)
    # {"opa": {"configured": bool, "ok": bool, "detail": str}, ...}
    checks = JSONField(default=dict)
    # The settings that decide what a failed check does (Presidio's failure mode).
    settings = JSONField(default=dict)
    pk = CompositePrimaryKey("component", "instance")

    class Meta:
        managed = False
        db_table = "component_reports"


class Person(Row):
    """Someone in Microsoft Entra ID whom a platform names as an agent's maker or owner, by
    object ID (registry.people): as the directory last said, or a list uploaded from it."""

    id = CharField(max_length=64, primary_key=True)  # the object ID
    name = CharField(max_length=256, null=True)
    # Their email address (else their user principal name), and their user principal name:
    # AgentGov names owners and sponsors by either.
    email = CharField(max_length=320, null=True)
    upn = CharField(max_length=320, null=True)
    # Whether their account is enabled; None when what was read didn't say.
    enabled = BooleanField(null=True)
    # False when the directory has no such user: never was one (not a person), or deleted.
    found = BooleanField(default=True)
    # When a user it had found was no longer there: they left.
    gone_at = UTCDateTimeField(null=True)
    # "graph" (read by AgentGov's app or a signed-in admin) or "upload".
    source = CharField(max_length=16)
    checked_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "people"
        indexes = [
            Index(fields=["email"], name="ix_people_email"),
            Index(fields=["upn"], name="ix_people_upn"),
        ]


class IntegrationState(Row):
    """Where an integration with another service got to, between runs (a cursor, a
    pending query, the permissions an app was granted)."""

    key = CharField(max_length=64, primary_key=True)
    data = JSONField(default=dict)
    updated_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "integration_state"


class AgentInstructions(Row):
    """What an agent is instructed to do (its system prompt), from one source, and
    what scanning found in it. Credentials in the text are redacted before storing."""

    id = CharField(max_length=100, primary_key=True)  # "<agent id>:<source>"
    agent_id = CharField(max_length=32)
    source = CharField(max_length=64)
    text = TextField()
    truncated = BooleanField(default=False)
    sha256 = CharField(max_length=64)
    reported_by = CharField(max_length=200)
    updated_at = UTCDateTimeField(default=utcnow)
    reported_at = UTCDateTimeField(default=utcnow)
    issues = JSONField(default=list)
    # "off" (no classifier), "pending", "done" or "error".
    classifier_state = CharField(max_length=16, default="off")
    classifier = JSONField(default=dict)

    class Meta:
        managed = False
        db_table = "agent_instructions"
        indexes = [
            Index(fields=["agent_id"], name="ix_agent_instructions_agent_id"),
            Index(fields=["classifier_state"], name="ix_agent_instructions_classifier_state"),
        ]


class ApprovedConnector(Row):
    """A Power Platform connector the organisation allows its agents to use."""

    connector_id = CharField(max_length=200, primary_key=True)
    note = TextField(default="")
    added_by = CharField(max_length=200)
    created_at = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "approved_connectors"


class ApprovalRequest(Row):
    """Human-in-the-loop approval for one specific tool call."""

    id = CharField(max_length=32, primary_key=True)
    agent_id = CharField(max_length=32)
    agent_name = CharField(max_length=200)
    action = CharField(max_length=128)
    resource = TextField()
    arguments = JSONField(null=True)
    arguments_hash = CharField(max_length=64)
    reasons = JSONField(default=list)
    status = CharField(max_length=16, default="pending")
    requested_at = UTCDateTimeField(default=utcnow)
    expires_at = UTCDateTimeField()
    decided_by = CharField(max_length=200, null=True)
    decided_at = UTCDateTimeField(null=True)
    decision_note = TextField(null=True)
    used_at = UTCDateTimeField(null=True)
    # The person the agent acted for: their name, and their ID (the token's subject),
    # which an approval must match to be used.
    on_behalf_of = CharField(max_length=255, null=True)
    on_behalf_of_id = CharField(max_length=255, null=True)
    # Who decides it: "approvers" (AgentGov's approvers) or "person" (that person).
    # Administrators can always decide.
    deciders = CharField(max_length=16, default="approvers", db_default="approvers")

    class Meta:
        managed = False
        db_table = "approval_requests"
        indexes = [
            Index(fields=["agent_id"], name="ix_approval_requests_agent_id"),
            Index(fields=["arguments_hash"], name="ix_approval_requests_arguments_hash"),
            Index(fields=["on_behalf_of_id"], name="ix_approval_requests_on_behalf_of_id"),
            Index(fields=["status"], name="ix_approval_requests_status"),
        ]


class Finding(Row):
    """A posture or threat finding, open until resolved or dismissed."""

    id = CharField(max_length=32, primary_key=True)
    key = CharField(max_length=300)
    type = CharField(max_length=64)
    category = CharField(max_length=16, default="posture")
    severity = CharField(max_length=16)
    status = CharField(max_length=16, default="open")
    agent_id = CharField(max_length=32, null=True)
    subject = CharField(max_length=200)
    title = TextField()
    description = TextField(default="")
    remediation = TextField(default="")
    details = JSONField(default=dict)
    occurrences = IntegerField(default=1)
    first_seen = UTCDateTimeField(default=utcnow)
    last_seen = UTCDateTimeField(default=utcnow)
    resolved_at = UTCDateTimeField(null=True)
    resolved_by = CharField(max_length=200, null=True)
    # Who it is with (docs/issues.md): how far up its chain it has gone (owner, sponsors,
    # team), the people and teams there, and when it goes further if nobody acknowledges it.
    level = CharField(max_length=16, null=True)
    assignees = JSONField(default=list, db_default=[])
    escalate_at = UTCDateTimeField(null=True)
    acknowledged_at = UTCDateTimeField(null=True)
    acknowledged_by = CharField(max_length=200, null=True)
    # A risk accepted until a date, and why: it opens again then, if it still holds.
    accepted_until = UTCDateTimeField(null=True)
    accepted_reason = TextField(null=True)
    # Checks in a row that found it gone (findings from syncs close after two), and
    # whether the last check could run at all.
    clean_checks = IntegerField(default=0, db_default=0)
    verified = BooleanField(default=True, db_default=True)
    # How many times it was raised again after being resolved or accepted: each time, its
    # chain starts over.
    round = IntegerField(default=0, db_default=0)

    class Meta:
        managed = False
        db_table = "findings"
        indexes = [
            Index(fields=["agent_id"], name="ix_findings_agent_id"),
            Index(fields=["status"], name="ix_findings_status"),
            Index(fields=["type"], name="ix_findings_type"),
        ]
        constraints = [
            UniqueConstraint(fields=["key"], name="findings_key_key"),
        ]


class Team(Row):
    """People and chat channels that can own agents, and that issues escalate to."""

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=128)
    description = TextField(default="")
    # The people in it, by email address or user name: they see its issues in AgentGov
    # and may acknowledge them.
    members = JSONField(default=list)
    # Where its issues are emailed: a list's or a shared mailbox's address, or people's
    # own (without any, its members' addresses). And the Teams and Slack destinations,
    # by name, that they are posted to.
    emails = JSONField(default=list)
    destinations = JSONField(default=list)
    # Issues that have no team of their own escalate to the default team.
    is_default = BooleanField(default=False, db_default=False)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "teams"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_teams_name"),
        ]


class AccessPackage(Row):
    """Grants an agent can hold for a while: requested, approved, and expiring
    (docs/access-packages.md)."""

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=128)
    description = TextField(default="")
    # What it grants, as a blueprint does: tools, models, other agents (A2A).
    permissions = JSONField(default=list)
    model_access = JSONField(default=list)
    agent_access = JSONField(default=list)
    # The blueprints whose agents may hold it (none: any agent).
    blueprints = JSONField(default=list)
    # How many days an assignment lasts at most; whether an approver decides requests;
    # and how often assignments are reviewed (none: never).
    duration_days = IntegerField(default=90)
    approval = BooleanField(default=True)
    review_days = IntegerField(null=True)
    labels = JSONField(default=dict)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "access_packages"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_access_packages_name"),
        ]


class AccessAssignment(Row):
    """An access package for an agent: asked for, then held until it expires, is revoked
    or is renewed (each renewal is an assignment of its own)."""

    id = CharField(max_length=32, primary_key=True)
    package_id = CharField(max_length=32)
    agent_id = CharField(max_length=32)
    # requested, active, denied, expired, revoked, or renewed (by a later assignment).
    status = CharField(max_length=16)
    days = IntegerField()
    reason = TextField()
    requested_by = CharField(max_length=200)
    decided_by = CharField(max_length=200, null=True)
    decided_at = UTCDateTimeField(null=True)
    note = TextField(null=True)
    starts_at = UTCDateTimeField(null=True)
    expires_at = UTCDateTimeField(null=True)
    reviewed_at = UTCDateTimeField(null=True)
    ended_at = UTCDateTimeField(null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)

    class Meta:
        managed = False
        db_table = "access_assignments"
        indexes = [
            Index(fields=["agent_id"], name="ix_access_assignments_agent_id"),
            Index(fields=["expires_at"], name="ix_access_assignments_expires_at"),
            Index(fields=["package_id"], name="ix_access_assignments_package_id"),
            Index(fields=["status"], name="ix_access_assignments_status"),
        ]


class ManagementRule(Row):
    """Conditions on agents, and what to do about the agents that meet them for long enough:
    raise an issue, give them an owner, block them, delete them or revoke their access
    packages, after telling their people (docs/management-rules.md)."""

    id = CharField(max_length=32, primary_key=True)
    name = CharField(max_length=128)
    description = TextField(default="")
    # off, monitor (records what it would do) or enforce; the feature's mode caps it.
    mode = CharField(max_length=16, default="monitor")
    # What an agent must meet (all of it), and which agents the rule looks at.
    conditions = JSONField(default=dict)
    scope = JSONField(default=dict)
    # issue, assign_owner, block, delete or revoke_access, and what it needs (the owner to
    # assign); how many days an agent matches before it, how severe its issue is, and how
    # many agents it acts on at once, at most.
    action = CharField(max_length=32, default="issue")
    params = JSONField(default=dict)
    after_days = IntegerField(default=14)
    severity = CharField(max_length=16, default="medium")
    max_actions = IntegerField(default=10)
    labels = JSONField(default=dict)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)
    # Raised by each edit: an edit made from an older copy is refused (registry/versions).
    version = IntegerField(default=1, db_default=1)

    class Meta:
        managed = False
        db_table = "management_rules"
        constraints = [
            UniqueConstraint(fields=["name"], name="ix_management_rules_name"),
        ]


class RuleMatch(Row):
    """An agent a management rule matches, from when it started to match: when its people
    were told, and what the rule did or would have done. Gone once the agent no longer
    matches."""

    id = CharField(max_length=32, primary_key=True)
    rule_id = CharField(max_length=32)
    agent_id = CharField(max_length=32)
    since = UTCDateTimeField()
    # When the agent's people were told what the rule will do (an enforced rule only).
    warned_at = UTCDateTimeField(null=True)
    # When a monitored rule would have acted, and when an enforced one did.
    monitored_at = UTCDateTimeField(null=True)
    acted_at = UTCDateTimeField(null=True)
    outcome = TextField(null=True)

    class Meta:
        managed = False
        db_table = "rule_matches"
        indexes = [
            Index(fields=["agent_id"], name="ix_rule_matches_agent_id"),
            Index(fields=["rule_id"], name="ix_rule_matches_rule_id"),
        ]
        constraints = [
            UniqueConstraint(fields=["rule_id", "agent_id"], name="ix_rule_matches_once"),
        ]


class Notification(Row):
    """A message about an issue to someone's email address or a team's chat, which the
    control plane sends and retries (docs/issues.md)."""

    id = CharField(max_length=32, primary_key=True)
    finding_id = CharField(max_length=32)
    round = IntegerField(default=0)
    level = CharField(max_length=16)
    # "email" to an address, or "slack" or "teams" to a destination's channel, by name.
    channel = CharField(max_length=16)
    recipient = CharField(max_length=320)
    # pending, sent, or failed for good after retrying.
    status = CharField(max_length=16, default="pending")
    attempts = IntegerField(default=0)
    next_attempt_at = UTCDateTimeField(default=utcnow)
    last_error = TextField(null=True)
    created_at = UTCDateTimeField(default=utcnow)
    sent_at = UTCDateTimeField(null=True)

    class Meta:
        managed = False
        db_table = "notifications"
        indexes = [
            Index(fields=["finding_id"], name="ix_notifications_finding_id"),
            Index(fields=["status"], name="ix_notifications_status"),
        ]
        constraints = [
            UniqueConstraint(
                fields=["finding_id", "round", "level", "channel", "recipient"],
                name="ix_notifications_once",
            ),
        ]


class Ticket(Row):
    """An issue's ticket in a service desk (docs/tickets.md): AgentGov opens it, keeps it in
    step with the issue, and reads back what happens to it there."""

    id = CharField(max_length=32, primary_key=True)
    finding_id = CharField(max_length=32)
    destination_id = CharField(max_length=32)
    # The issue's round it was opened for, and the team whose group it went to.
    round = IntegerField(default=0)
    team = CharField(max_length=128, null=True)
    # pending (to open), open, closed (AgentGov is done with it), failed (gave up opening
    # it), or skipped (open before the desk was added).
    status = CharField(max_length=16, default="pending")
    # The desk's own: its number (INC0012345, OPS-12, #42), its ID, and where people open it.
    key = CharField(max_length=64, null=True)
    remote_id = CharField(max_length=64, null=True)
    url = TextField(null=True)
    # What the desk last said: its state, as it names it; new, active or done; and who has it.
    state = CharField(max_length=64, null=True)
    phase = CharField(max_length=16, default="new")
    assignee = CharField(max_length=200, null=True)
    # What the desk was last told of the issue, so only what changed is sent.
    told = JSONField(default=dict)
    # The ticket it took over from: done in the desk while AgentGov still finds the problem.
    replaces = CharField(max_length=64, null=True)
    attempts = IntegerField(default=0)
    next_attempt_at = UTCDateTimeField(default=utcnow)
    last_error = TextField(null=True)
    # When AgentGov saw it done in the desk, and when it last read it there.
    done_seen_at = UTCDateTimeField(null=True)
    synced_at = UTCDateTimeField(null=True)
    created_at = UTCDateTimeField(default=utcnow)
    updated_at = UTCDateTimeField(auto_now=True)

    class Meta:
        managed = False
        db_table = "tickets"
        indexes = [
            Index(fields=["destination_id"], name="ix_tickets_destination_id"),
            Index(fields=["finding_id"], name="ix_tickets_finding_id"),
            Index(fields=["status"], name="ix_tickets_status"),
        ]


class RiskSignal(Row):
    """Runtime evidence feeding an agent's risk score; decays after a window."""

    id = CharField(max_length=32, primary_key=True)
    agent_id = CharField(max_length=32)
    kind = CharField(max_length=64)
    detail = TextField(null=True)
    ts = UTCDateTimeField(default=utcnow)

    class Meta:
        managed = False
        db_table = "risk_signals"
        indexes = [
            Index(fields=["agent_id", "ts"], name="ix_risk_signals_agent_ts"),
        ]


class AgentActivity(Row):
    """Daily usage counters per agent, from gateway decisions and telemetry."""

    agent_id = CharField(max_length=32)
    day = CharField(max_length=10)  # YYYY-MM-DD (UTC)
    tool_calls = IntegerField(default=0)
    denied = IntegerField(default=0)
    model_calls = IntegerField(default=0)
    input_tokens = IntegerField(default=0)
    output_tokens = IntegerField(default=0)
    pk = CompositePrimaryKey("agent_id", "day")

    class Meta:
        managed = False
        db_table = "agent_activity"


class LedgerEntry(Row):
    """Append-only, hash-chained evidence ledger.

    ``hash = sha256(prev_hash || canonical_json(entry))``, so modifying or
    deleting any stored entry breaks verification of every later entry.
    """

    seq = IntegerField(primary_key=True)
    id = CharField(max_length=32)
    ts = UTCDateTimeField()
    type = CharField(max_length=64)
    severity = CharField(max_length=16, default="info")
    actor = CharField(max_length=200)
    agent_id = CharField(max_length=32, null=True)
    agent_name = CharField(max_length=200, null=True)
    action = CharField(max_length=128, null=True)
    resource = TextField(null=True)
    decision = CharField(max_length=32, null=True)
    reason = TextField(null=True)
    details = JSONField(default=dict)
    trace_id = CharField(max_length=64, null=True)
    # The person the agent acted for, by name (agentgov.identity.people.name_of).
    on_behalf_of = CharField(max_length=255, null=True)
    prev_hash = CharField(max_length=64)
    hash = CharField(max_length=64)

    class Meta:
        managed = False
        db_table = "ledger"
        indexes = [
            Index(fields=["agent_id"], name="ix_ledger_agent_id"),
            Index(fields=["decision"], name="ix_ledger_decision"),
            Index(fields=["on_behalf_of"], name="ix_ledger_on_behalf_of"),
            Index(fields=["ts"], name="ix_ledger_ts"),
            Index(fields=["type"], name="ix_ledger_type"),
        ]
        constraints = [
            UniqueConstraint(fields=["id"], name="ledger_id_key"),
        ]


class LedgerHead(Row):
    """Single row holding the tip of the hash chain.

    Appenders update this row first, which takes a write lock (row lock on
    PostgreSQL, database lock on SQLite) and serialises chain extension.
    """

    id = AutoField(primary_key=True)
    last_seq = IntegerField(default=0)
    last_hash = CharField(max_length=64)

    class Meta:
        managed = False
        db_table = "ledger_head"


class LedgerCheckpoint(Row):
    """A point of the ledger's hash chain kept for good (docs/evidence.md): made every so
    often, time-stamped by a time-stamping authority when one is set (RFC 3161), and,
    once the entries up to it are archived and removed, where the chain goes on from."""

    # The last entry it covers, and that entry's hash and time.
    seq = IntegerField(primary_key=True)
    hash = CharField(max_length=64)
    entry_ts = UTCDateTimeField()
    created_at = UTCDateTimeField(default=utcnow)
    # The authority's time-stamp of the checkpoint's statement: its whole response, base64,
    # the time it gives, and why there is none, if it failed.
    tsa_url = TextField(null=True)
    timestamp = TextField(null=True)
    timestamped_at = UTCDateTimeField(null=True)
    timestamp_error = TextField(null=True)
    # Its entry in a transparency log (agentgov.transparency): the log's answer as it came
    # (the entry, its index and the proof that the log holds it), whether that proof was
    # checked with the log's key, and why there is none, if adding it failed.
    tlog_url = TextField(null=True)
    tlog_entry = JSONField(null=True)
    tlog_index = BigIntegerField(null=True)
    tlog_logged_at = UTCDateTimeField(null=True)
    tlog_checked = BooleanField(null=True)
    tlog_error = TextField(null=True)
    # The archive of the entries since the previous archive, up to this one, and its
    # SHA-256; and when the entries left the database.
    archive = TextField(null=True)
    archive_sha256 = CharField(max_length=64, null=True)
    archived_from = IntegerField(null=True)
    pruned_at = UTCDateTimeField(null=True)

    class Meta:
        managed = False
        db_table = "ledger_checkpoints"


class McpSighting(Row):
    """An MCP server set up in one client on one developer's machine, as last reported
    by ``agentgov mcp scan --report``. Credentials never arrive here: environment
    variables and headers are reported by name only."""

    id = CharField(max_length=32, primary_key=True)
    machine = CharField(max_length=200)
    os_user = CharField(max_length=200, default="")
    client = CharField(max_length=64)  # "vscode", "claude-desktop", ...
    scope = CharField(max_length=16)  # "user" or "project"
    name = CharField(max_length=200)  # as the client calls it
    # What identifies the server anywhere: "url:<url>", "npm:<package>", "command:<...>".
    identity = CharField(max_length=400)
    transport = CharField(max_length=16)  # "stdio", "http" or "sse"
    url = TextField(null=True)
    command = JSONField(default=list)
    env = JSONField(default=list)
    headers = JSONField(default=list)
    reported_by = CharField(max_length=200, null=True)
    first_seen_at = UTCDateTimeField()
    last_seen_at = UTCDateTimeField()

    class Meta:
        managed = False
        db_table = "mcp_sightings"
        indexes = [
            Index(fields=["identity"], name="ix_mcp_sightings_identity"),
            Index(fields=["machine", "os_user"], name="ix_mcp_sightings_machine"),
        ]

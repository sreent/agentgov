"""Runtime configuration.

Every setting can be supplied through an ``AGENTGOV_<NAME>`` environment variable,
e.g. ``AGENTGOV_DATABASE_URL`` or ``AGENTGOV_KEYCLOAK_URL``. Integrations whose
settings are left empty are disabled, which keeps unit tests and local
development free of external dependencies.
"""

from __future__ import annotations

import dataclasses
import functools
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
# The secrets AgentGov's own stacks, .env.example and docs come with: anybody who reaches a
# control plane that holds one is in.
WELL_KNOWN_SECRETS = frozenset(
    {
        "change-me",
        "dev",
        "dev-admin-token",
        "dev-service-token",
        "dev-signing-secret",
        "dev-keycloak-secret",
        "dev-oidc-secret",
    }
)
SECRET_SETTINGS = (
    "admin_token",
    "service_token",
    "signing_secret",
    "keycloak_client_secret",
    "oidc_client_secret",
)
M365_PACKAGE_TYPES = ("custom", "shared", "external", "microsoft")
# The least the ledger keeps its entries for, when it doesn't keep them all: six months, as
# the EU AI Act asks of providers' and deployers' logs (Articles 19 and 26(6)).
LEDGER_MIN_DAYS = 183
# The least operational records are kept: risk windows and budgets look back that far.
DATA_MIN_DAYS = 30
# Starting points for the features' modes (agentgov.registry.features.PRESETS).
FEATURE_PRESETS = ("monitor", "inventory")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# What the governance processor does when what it depends on fails, which it tells the
# control plane (docs/features.md#when-something-is-down).
FAILURE_SETTINGS = (
    "gateway_failure_mode",
    "presidio_failure_mode",
    "guardian_failure_mode",
    "authzen_failure_mode",
)
# Settings that became features (docs/features.md), and the feature that replaced each.
RETIRED = {
    "AGENTGOV_UNKNOWN_AGENT_MODE": "unknown-callers",
    "AGENTGOV_REGISTRATION_REQUIRES_APPROVAL": "registration-approval",
    "AGENTGOV_COPILOT_STUDIO_THREAT_DETECTION": "copilot-studio-threat-detection",
}
# Settings that something else replaced, and what to use instead.
REPLACED = {
    "AGENTGOV_ALERT_WEBHOOK_URL": "alerts go to Teams and Slack destinations now: add a "
    "destination of kind slack or teams with its webhook URL in its secret file, and turn on "
    "the security-operations feature (see docs/secops.md)",
}
# What Kubernetes sets in each pod for every Service in its namespace (service links), such
# as AGENTGOV_GATEWAY_PORT=tcp://10.96.0.12:8080 for a Service named agentgov-gateway: never
# one of these settings.
_SERVICE_LINK = re.compile(r"^(?:tcp|udp|sctp)://[^/\s]+:\d+$")
# An AWS region (us-east-1, us-gov-west-1) and an IAM role's ARN.
AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}$")
AWS_ROLE = re.compile(r"^arn:aws(?:-[a-z]+)*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
AWS_KINDS = ("bedrock-agents", "agentcore", "agentcore-gateways", "quick", "agent-registry")
# A Google Cloud project ID (6-30 characters; a domain-scoped one has a prefix), and a region
# (us-central1) or multi-region (us, eu).
GOOGLE_PROJECT = re.compile(r"^(?:[a-z0-9.-]+:)?[a-z][a-z0-9-]{4,28}[a-z0-9]$")
GOOGLE_REGION = re.compile(r"^(?:[a-z]+-[a-z]+\d{1,2}|us|eu)$")
# A Salesforce org's My Domain URL (https://contoso.my.salesforce.com), with nothing after it.
SALESFORCE_URL = re.compile(r"^https://[A-Za-z0-9.-]+/?$")
# A Databricks workspace's URL (https://dbc-1234.cloud.databricks.com), and what to read there.
DATABRICKS_URL = SALESFORCE_URL
DATABRICKS_KINDS = ("serving", "apps", "genie", "mcp-services")
# A Microsoft Foundry project's endpoint:
# https://contoso.services.ai.azure.com/api/projects/support
FOUNDRY_PROJECT = re.compile(r"^https://[A-Za-z0-9.-]+/api/projects/[A-Za-z0-9_.-]+/?$")
# Microsoft Entra ID's issuer: https://login.microsoftonline.com/<tenant>/v2.0
ENTRA_ISSUER = re.compile(
    r"^(?P<base>https://login\.microsoftonline\.(?:com|us)|https://login\.chinacloudapi\.cn)"
    r"/(?P<tenant>[^/]+)/v2\.0$"
)
# Google's issuer, which every Google account shares.
GOOGLE_ISSUER = "https://accounts.google.com"
# A Keycloak realm's issuer: https://sso.example.com/realms/<realm>
KEYCLOAK_REALM = re.compile(r"/realms/[^/]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# A host name (a service's short name too, such as splunk), or *. and a domain.
_HOST_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def _ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _coerce(raw: str, target: str) -> Any:
    if target == "bool":
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if target == "int":
        return int(raw)
    if target == "float":
        return float(raw)
    return raw


@dataclass(frozen=True)
class Settings:
    # --- Control plane -------------------------------------------------------
    # SQLite is fine for development; use PostgreSQL (postgresql+psycopg://...)
    # for anything shared.
    database_url: str = "sqlite:///./agentgov.db"
    # Bring the database's schema up to date when the control plane starts. Turn it
    # off where a deployment job runs `agentgov db upgrade` before new versions start.
    database_auto_migrate: bool = True
    # Externally reachable URL of the control plane (UI, API, OPA bundles).
    public_url: str = "http://localhost:8000"
    # Seconds the control plane keeps an idle HTTP connection open. Behind a load
    # balancer, keep it longer than the load balancer's own (600 on Google Cloud), or the
    # load balancer may send a request on a connection the control plane just closed.
    http_keepalive_seconds: int = 620
    # Bootstrap administrator bearer token for the admin API and UI.
    admin_token: str | None = None
    # Development only: without an admin token, the control plane makes one up and logs it.
    dev_mode: bool = False
    # Shared token for internal components (OPA, governance processor, OTel
    # collector) calling the control plane.
    service_token: str | None = None
    # The secret the keys AgentGov signs delegations and ID-JAGs with derive from. Only the
    # control plane and the processor hold it; without it, the keys derive from the service
    # token, which OPA and the OTel Collector hold too.
    signing_secret: str | None = None
    # Features pinned by the deployment, e.g. "least-privilege=monitor,discovery=off"
    # (docs/features.md). Administrators choose the others in the app.
    features: str = ""
    # A starting point for the features' modes, applied once, when the control plane starts
    # with one it hasn't applied yet: "monitor" (every control records what it would do and
    # stops nothing) or "inventory" (no gateway: AgentGov finds agents and checks them).
    # Administrators change the modes from there; pinned features keep their pins.
    feature_preset: str = ""
    # How long an approval request waits for a decision before it expires.
    approval_ttl_seconds: int = 86400
    # Deleted agents can be restored for this many days, then they are purged (Agent 365
    # parity). 0 keeps them.
    soft_delete_retention_days: int = 30
    # When > 0, agents whose risk score reaches this value are blocked.
    auto_block_risk_score: int = 0
    # How long risk signals (denied calls, credentials, prompt injections) count towards
    # an agent's risk score.
    risk_window_hours: int = 24
    # Agents not seen for this many days raise a stale-agent issue.
    stale_agent_days: int = 30
    # Seconds between posture scans (owners, sponsors, attestations, stale agents); 0
    # turns the scheduled scan off.
    posture_interval_seconds: int = 300

    # --- Security operations (docs/secops.md) -------------------------------------
    # Where destinations' credentials are: a file per destination, named after it (a
    # mounted secret). Never in the database.
    destination_secrets_dir: str = "/destination-secrets"
    # The hosts credentials may go to, comma-separated: destinations' (SIEMs, chats and
    # service desks, with what AgentGov sends them) and openai-compatible model providers'
    # (the gateway sends those). `*.example.com` is any host under example.com. Empty: any
    # host, so an administrator can send these credentials anywhere by changing a URL.
    credential_hosts: str = ""
    # How often destinations are sent what is new in the ledger (also as soon as it is
    # written, on the replica that wrote it). 0 turns delivery off.
    delivery_interval_seconds: int = 10

    # --- Issues (docs/issues.md) ---------------------------------------------------

    # Hours an issue waits at each step of its chain (owner, sponsors, team) for someone
    # to acknowledge it, before it goes to the next, by severity.
    issue_escalation_hours: str = "critical:4,high:24,medium:72,low:168,info:168"
    # Seconds between rounds of routing issues, escalating them and sending what is due.
    issues_interval_seconds: int = 60
    # Issues below this severity reach people in AgentGov only, without an email or a chat
    # message: by default, low and info ones wait there. info: every issue is sent.
    issues_notify_severity: str = "medium"
    # What a platform's first sync finds reaches people in AgentGov only, without an email
    # or a chat message: what was there before AgentGov looked doesn't flood inboxes. Found
    # again after it is resolved, it is sent as any other.
    issues_quiet_first_sync: bool = True
    # Days a threat issue stays open without happening again before it is resolved (it
    # opens again if it happens again). 0 keeps threats open until someone closes them.
    threat_finding_days: int = 30
    # The time of day, HH:MM, a digest of their open issues goes to each address and team
    # chat that has some: one message a day, those issues below
    # AGENTGOV_ISSUES_NOTIFY_SEVERITY included (docs/issues.md#a-daily-digest). Empty: none.
    issues_digest_at: str | None = None
    # The time zone of AGENTGOV_ISSUES_DIGEST_AT, such as Europe/London.
    issues_digest_timezone: str = "UTC"
    # The days the digest goes out: mon to sun, separated by commas.
    issues_digest_days: str = "mon,tue,wed,thu,fri"
    # The mail server for issues' emails: smtp://host:587 (STARTTLS) or smtps://host:465
    # (TLS). Without it, issues reach people in AgentGov and in their teams' chats only.
    smtp_url: str | None = None
    # The sender of issues' emails, such as agentgov@example.com.
    smtp_from: str | None = None
    # The mail server's user and password, if it needs them.
    smtp_username: str | None = None
    smtp_password: str | None = None

    # --- Evidence and retention (docs/evidence.md) ----------------------------------
    # Days the ledger keeps its entries in the database: older ones are archived to
    # AGENTGOV_LEDGER_ARCHIVE_DIR, then removed, and the chain goes on from the checkpoint
    # at their end. 0 keeps every entry; otherwise at least 183 (six months).
    ledger_retention_days: int = 0
    # Where the ledger's archives go, as gzipped JSON Lines files (a mounted volume, or a
    # bucket mounted as one). Needed with AGENTGOV_LEDGER_RETENTION_DAYS.
    ledger_archive_dir: str | None = None
    # A file where the control plane keeps the ledger's head outside the database, to notice
    # a database restored from an older backup or rolled back (docs/backup.md): on storage
    # that restoring the database doesn't touch. By default ledger-head.json in
    # AGENTGOV_LEDGER_ARCHIVE_DIR, when that is set; "off" keeps none.
    ledger_witness_file: str | None = None
    # Hours between ledger checkpoints: the chain's head, kept, and time-stamped when a
    # time-stamping authority is set. 0 makes them only on demand.
    ledger_checkpoint_hours: int = 24
    # An RFC 3161 time-stamping authority, such as https://freetsa.org/tsr. It signs each
    # checkpoint with its own time, which proves the chain existed then, unchanged since.
    ledger_tsa_url: str | None = None
    # The authority's certificates (PEM: its root, and any intermediate ones), which each
    # time-stamp's signature is checked against, when it comes and whenever the ledger is
    # verified. Unset, a time-stamp is checked against the certificate it carries, which
    # shows it whole, not that the authority signed it.
    ledger_tsa_ca_file: str | None = None
    # A transparency log, Sigstore's Rekor v2: its public shard (such as
    # https://log2025-1.rekor.sigstore.dev) or a rekor-tiles of your own. Each checkpoint is
    # signed with AGENTGOV_LEDGER_REKOR_SIGNING_KEY_FILE and added to it, where anyone can
    # see that it was published: AgentGov can't later show another checkpoint for the same
    # entry without the log holding both. What the log publishes, for good, is the
    # statement's SHA-256, the signature and AgentGov's public key.
    ledger_rekor_url: str | None = None
    # AgentGov's key for the log: an ECDSA P-256 private key (PEM). `agentgov
    # transparency-key DIR` makes one.
    ledger_rekor_signing_key_file: str | None = None
    # The log's public key (PEM, Ed25519), to check each answer's proof that the log holds
    # the entry. Unset, entries are kept unchecked.
    ledger_rekor_log_key_file: str | None = None
    # The log's name in its checkpoints (its origin). Unset: the URL's host name.
    ledger_rekor_origin: str | None = None
    # Days AgentGov keeps the operational records whose history the ledger has: daily
    # activity and model usage, risk signals, notifications sent, decided approvals,
    # resolved issues, ended access assignments, and developers' MCP servers not
    # reported since. 0 keeps them; otherwise at least 30.
    data_retention_days: int = 0

    # --- Keycloak (agent identity) ---------------------------------------------
    # Base URL the control plane uses to reach Keycloak's admin API.
    keycloak_url: str | None = None
    # The realm agents' clients, identity issuers and people live in.
    keycloak_realm: str = "agentgov"
    # The client the control plane provisions agents' clients with.
    keycloak_client_id: str = "agentgov-control-plane"
    # Its secret. Provisioning in Keycloak is on when this and keycloak_url are set.
    keycloak_client_secret: str | None = None
    # Issuer that appears in agent tokens (Keycloak's frontend URL + realm).
    keycloak_issuer: str | None = None
    # JWKS URL the gateway uses to validate agent tokens.
    keycloak_jwks_url: str | None = None
    # Seconds between passes that sync every agent with Keycloak, which also repair what
    # was changed in Keycloak itself. The passes between, every minute and after each
    # change, sync only the agents whose clients should change. 0: every pass is full.
    identity_full_sync_seconds: int = 900
    # Audience every agent token Keycloak issues carries; the gateway requires it. The tokens
    # of the identity issuers the gateway trusts carry the gateway's address instead
    # (AGENTGOV_GATEWAY_PUBLIC_URL), unless an issuer names an audience of its own.
    gateway_audience: str = "agentgov-gateway"
    # Seconds between fetches of the signing keys of the identity issuers the gateway
    # trusts, which rotate them (docs/agent-identity.md#straight-to-the-gateway). 0: only
    # when an issuer is added or changed, or an administrator asks.
    issuer_keys_interval_seconds: int = 300
    # Keycloak clients of the apps people sign in to and use agents from (comma-separated
    # client IDs). Each agent that acts for people has a client scope named after its
    # client ID, which these apps may request: the person's token is then one the agent
    # can exchange for a token of its own, on the person's behalf.
    people_app_clients: str = ""
    # Seconds the identity assertions (ID-JAG) AgentGov gives agents for MCP servers
    # outside the gateway last, at most 300: the agent trades one for an access token
    # at once (docs/acting-for-people.md#mcp-servers-outside-the-gateway).
    assertion_lifetime_seconds: int = 300

    # --- Administrator single sign-on (OIDC) -------------------------------------
    # The control plane signs people in (administrators, and the people issues and
    # approvals are sent to) with the bundled Keycloak or your own OpenID Connect provider
    # (docs/administration.md#your-identity-provider), as a confidential client, and keeps
    # the session server-side: the browser only holds an HttpOnly cookie. Enabled when a
    # client secret is set.

    # The client AgentGov signs administrators in as.
    oidc_client_id: str = "agentgov-admin"
    # Its secret. Single sign-on is on when this is set.
    oidc_client_secret: str | None = None
    # Your identity provider's issuer, exactly as its tokens name it (Okta, Google,
    # Microsoft Entra ID, Ping, Auth0 and any other OpenID Connect provider). Defaults to
    # keycloak_issuer, the bundled Keycloak.
    oidc_issuer: str | None = None
    # The provider's endpoints: read from its discovery document
    # (<issuer>/.well-known/openid-configuration) unless set here. Keycloak's and Microsoft
    # Entra ID's are known: for the bundled Keycloak, the authorization and logout
    # endpoints are under the issuer (browser-facing), the token endpoint and JWKS under
    # keycloak_url when set (server-to-server).
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_jwks_url: str | None = None
    oidc_end_session_endpoint: str | None = None
    # How AgentGov shows its client secret at the token endpoint: client_secret_basic or
    # client_secret_post. By default basic, or post with a provider that takes only that.
    oidc_client_auth: str = ""
    # The scopes asked for at sign-in.
    oidc_scopes: str = "openid profile email"
    # Where role names are found in the tokens: dot paths, comma-separated. By default
    # realm_access.roles with the bundled Keycloak, roles (app roles) with Microsoft Entra
    # ID, and groups with other providers.
    oidc_roles_claim: str = ""
    # The prefix that marks AgentGov roles: "agentgov-approver" grants the approver role.
    oidc_role_prefix: str = "agentgov-"
    # Values of the roles claim that grant AgentGov roles, as value=role pairs,
    # comma-separated: a group's ID or name, or an app role
    # (8f0c2d1e-...=admin,Security Operations=secops,Sales approvers=approver@sales, the
    # last for team sales' agents only). When set, only these grant roles.
    oidc_role_map: str = ""
    # The email domains whose people may sign in, comma-separated (empty: anyone the
    # provider signs in to this client). Google's issuer is shared by every Google
    # account, so with Google this is required and checked against the hosted domain.
    oidc_allowed_domains: str = ""
    # Only people with a role may sign in: one the provider gives (agentgov-admin, ...,
    # or AGENTGOV_OIDC_ROLE_MAP), or one given in AgentGov. The person role (agentgov-person)
    # lets owners and sponsors in to see only what is sent to them. Off: anyone the provider
    # signs in may sign in with that view, while issues or approvals go to people.
    oidc_require_role: bool = False
    # The longest an administrator's session lasts.
    session_hours: int = 8
    # How many days a new API key works, unless whoever creates it chooses otherwise.
    api_key_days: int = 90
    # The most days an API key may work, keys made before included (0: no limit, and keys
    # may be made that never expire).
    api_key_max_days: int = 0
    # Act in Microsoft 365 and Power Platform as the administrator who is signed in
    # (quarantine Copilot Studio agents, read the Power Platform inventory, block
    # Microsoft 365 agents): Microsoft accepts these only from a signed-in admin.
    # Needs sign-in through Microsoft Entra ID (oidc_issuer
    # https://login.microsoftonline.com/<tenant>/v2.0) and an app registration with
    # the delegated permissions listed in docs/platforms.md.
    microsoft_admin_actions: bool = False

    # --- Microsoft 365 agent inventory --------------------------------------------
    # AgentGov's Entra app registration, for the connections to Microsoft's services
    # (docs/microsoft-connections.md), each turned on by the application permission it
    # needs: CopilotPackages.Read.All for the agent catalog (which also needs a Microsoft
    # Agent 365 licence), AgentIdentity.Read.All, AuditLogsQuery.Read.All,
    # SecurityAlert.Read.All and EntitlementManagement.Read.All. The connections are on
    # when all three are set.

    # The Microsoft Entra tenant (directory) ID.
    m365_tenant_id: str | None = None
    # The app registration's application (client) ID, and its client secret.
    m365_client_id: str | None = None
    m365_client_secret: str | None = None
    # 0 turns the scheduled sync off; admins can still sync on demand.
    m365_sync_interval_seconds: int = 3600
    # Package types to import: custom (built in your organisation), shared (shared
    # by its users), external (from partners) and microsoft (Microsoft's own).
    m365_package_types: str = "custom,shared,external"
    # Microsoft's endpoints: change them for a national cloud (such as
    # https://graph.microsoft.us and https://login.microsoftonline.us).
    graph_url: str = "https://graph.microsoft.com"
    entra_login_url: str = "https://login.microsoftonline.com"
    power_platform_url: str = "https://api.powerplatform.com"

    # --- Copilot Studio threat detection (optional) -------------------------------
    # Copilot Studio asks AgentGov before each tool call its agents make, once a
    # Power Platform admin connects AgentGov to an environment
    # (docs/microsoft-connections.md). Turned on with the feature
    # copilot-studio-threat-detection (monitor or enforce) once these are set.

    # The app registrations that may call (the one connected to Copilot Studio),
    # comma-separated application (client) IDs.
    copilot_studio_caller_app_ids: str = ""
    # Accepted token audiences, comma-separated: AgentGov's API's application ID URI
    # (by default the origin of AGENTGOV_PUBLIC_URL) and, for v2.0 tokens, its client ID.
    copilot_studio_audiences: str = ""
    # The tenant ID (a GUID) whose apps may call. By default the tenant of
    # AGENTGOV_M365_TENANT_ID or of sign-in through Entra ID, when that is a GUID.
    copilot_studio_tenant_id: str | None = None
    # The answer when AgentGov cannot decide in time (enforce mode): "block" or "allow".
    copilot_studio_on_error: str = "block"

    # --- Agents on other platforms --------------------------------------------------
    # AgentGov reads the agents on AWS, Google Cloud, Salesforce, Databricks and Microsoft
    # Foundry into the inventory, each where its settings below are set
    # (docs/other-platforms.md).

    # Seconds between reads of each platform; 0 reads them only on demand.
    platform_sync_interval_seconds: int = 3600
    # AWS: the regions to read Amazon Bedrock agents, AgentCore's harnesses, agent runtimes
    # and gateways, Amazon Quick's agents and AWS Agent Registry's in, comma-separated, such
    # as us-east-1,eu-west-1 (empty: AWS isn't read).
    # AgentGov signs its requests with AWS credentials from the usual places:
    # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, IAM roles for service accounts or Pod
    # Identity on EKS, or the instance's role.
    aws_regions: str = ""
    # Roles to assume, comma-separated ARNs, to read other AWS accounts too (in the same
    # regions), with the credentials above.
    aws_role_arns: str = ""
    # The external ID those roles' trust policies ask for, if any.
    aws_external_id: str | None = None
    # What to read in each account's regions, comma-separated: bedrock-agents (Amazon
    # Bedrock agents), agentcore (AgentCore's harnesses and agent runtimes),
    # agentcore-gateways (its gateways), quick (Amazon Quick's agents) and agent-registry
    # (AWS Agent Registry's agents and MCP servers; with auto-detection, an organisation's
    # registry has the AgentCore runtimes and gateways of all its accounts).
    aws_read: str = "bedrock-agents,agentcore,agentcore-gateways,quick,agent-registry"
    # Google Cloud: the projects to read Agent Runtime (formerly Vertex AI Agent Engine)
    # agents in, comma-separated project IDs (empty: Google Cloud isn't read). AgentGov gets
    # its tokens where Google's libraries do: the file GOOGLE_APPLICATION_CREDENTIALS names (a
    # workload identity federation configuration, or a service account key), gcloud's
    # application default credentials, or the metadata server (Workload Identity on GKE).
    google_cloud_projects: str = ""
    # The regions to read them in, comma-separated (us and eu for the multi-regions).
    google_cloud_regions: str = "us-central1"
    # What to read in each project, comma-separated: agent-runtime (its agents, in each
    # region) and agent-registry (Agent Registry's agents and MCP servers, in each region
    # and global: agents on Cloud Run and GKE, Gemini Enterprise's, and those registered
    # by hand).
    google_cloud_read: str = "agent-runtime,agent-registry"
    # Salesforce: the org to read Agentforce agents in, by its My Domain URL, such as
    # https://contoso.my.salesforce.com (empty: Salesforce isn't read).
    salesforce_url: str | None = None
    # The External Client App AgentGov signs in with: its consumer key, and its consumer
    # secret, for the client credentials flow (as the app's Run As user).
    salesforce_client_id: str | None = None
    salesforce_client_secret: str | None = None
    # Instead of the secret, the JWT bearer flow: the user AgentGov signs in as, and the
    # private key (PEM) of the certificate uploaded to the app.
    salesforce_username: str | None = None
    salesforce_private_key_file: str | None = None
    # Databricks: the workspaces to read agents in, comma-separated URLs, such as
    # https://dbc-1234.cloud.databricks.com (empty: Databricks isn't read).
    databricks_hosts: str = ""
    # The service principal AgentGov reads as (OAuth machine-to-machine): its application
    # ID and an OAuth secret of its own.
    databricks_client_id: str | None = None
    databricks_client_secret: str | None = None
    # Instead, a personal access token, valid in the workspaces named.
    databricks_token: str | None = None
    # What to read in each, comma-separated: serving (agents on Model Serving), apps (Agent
    # Bricks agents), genie (Genie agents) and mcp-services (the MCP services registered in
    # Unity Catalog, read catalog by catalog).
    databricks_read: str = "serving,apps,genie,mcp-services"
    # Microsoft Foundry: the projects to read agents in, comma-separated project endpoints,
    # such as https://contoso.services.ai.azure.com/api/projects/support. AgentGov reads them
    # as its Microsoft app registration (AGENTGOV_M365_*), which needs a role on each project
    # that may read agents.
    foundry_projects: str = ""
    # Azure subscriptions to find Foundry projects in, comma-separated IDs: every project of
    # every Foundry resource the app may see there (Reader on the subscription).
    foundry_subscriptions: str = ""
    # Foundry's token audience and Azure Resource Manager: change them for a national cloud.
    foundry_audience: str = "https://ai.azure.com"
    azure_management_url: str = "https://management.azure.com"

    # --- Classifier, optional (docs/detection.md) ---------------------------------
    # IBM Granite Guardian behind an OpenAI-compatible API (vLLM, llama.cpp,
    # Ollama), e.g. http://guardian:8000/v1. The control plane asks it about agent
    # instructions, and the processor about tool results, agents' answers and people's
    # prompts (the traffic-classifier feature). Without it, AgentGov's rules decide alone.
    guardian_url: str | None = None
    # The name the server serves the model under, and its API key if it needs one.
    guardian_model: str = "ibm-granite/granite-guardian-4.1-8b"
    guardian_api_key: str | None = None
    # Criteria to judge agent instructions by (one classifier call each): harm, jailbreak,
    # social_bias, violence, profanity, unethical_behavior, exfiltration, deception.
    guardian_criteria: str = (
        "harm,jailbreak,social_bias,violence,unethical_behavior,exfiltration,deception"
    )
    # The longest one classifier call may take.
    guardian_timeout_seconds: float = 60.0
    # How long the processor waits for the classifier's verdict on a call where it is
    # enforced; past that, AGENTGOV_GUARDIAN_FAILURE_MODE says what happens, and the ledger
    # says so.
    classifier_timeout_seconds: float = 3.0
    # Where the processor waits for the classifier and gets no verdict (it is down, or too
    # slow): "open" lets the rules decide alone; "closed" counts the text as flagged, so
    # the call is refused.
    guardian_failure_mode: str = "open"
    # Classifier calls one processor makes at a time. In the background, what waits
    # beyond a few hundred goes unclassified rather than piling up.
    classifier_concurrency: int = 4

    # --- OPA (policy decisions) --------------------------------------------------
    # Where the processor asks OPA for decisions, and the control plane for What if, such
    # as http://opa:8181.
    opa_url: str | None = None
    # An AuthZEN decision point of your own (OpenID AuthZEN Authorization API 1.0), which
    # the processor also asks about the calls AgentGov's policies let through, as the
    # external-decision-point feature says: its base URL, such as https://pdp.example.com
    # (docs/policies.md#authzen).
    authzen_url: str | None = None
    # The bearer token it asks for, if it asks for one.
    authzen_token: str | None = None
    # Seconds to wait for its answer.
    authzen_timeout_seconds: float = 2.0
    # When it can't be asked while the external-decision-point feature is enforced:
    # "closed" refuses the call; "open" lets AgentGov's own decision stand. Monitored, it
    # never stops a call.
    authzen_failure_mode: str = "closed"
    # Longest a bundle long-poll request is held open.
    bundle_long_poll_seconds: int = 30
    # A PEM private key (RSA, or EC P-256 or P-384) the control plane signs OPA's bundles
    # with; OPA verifies each with the matching certificate or public key, and refuses one
    # that doesn't verify (docs/production.md). `agentgov bundle-signing-key DIR` makes a
    # pair. Unset, bundles go unsigned.
    bundle_signing_key_file: str | None = None
    # The key's name: OPA's configuration names the same one (bundles.<name>.signing.keyid).
    bundle_signing_key_id: str = "agentgov"

    # --- agentgateway (enforcement) ---------------------------------------------
    # Where the generated agentgateway config is written (shared volume).
    gateway_config_path: str | None = None
    # The gateway's address as agents reach it, which the app and the API show; also the
    # audience of the tokens of the identity issuers the gateway trusts (unless an issuer
    # names one), so that one install's are no good at another's.
    gateway_public_url: str = "http://localhost:8080"
    # The namespace of tool servers' names in the MCP registry ("<namespace>/<name>"); by
    # default the control plane's host name reversed, such as com.contoso.agentgov.
    mcp_registry_namespace: str = ""
    # The port agentgateway listens on, in the configuration generated for it.
    gateway_port: int = 8080
    # Where agentgateway reaches the governance processor for tool calls (gRPC).
    processor_address: str = "processor:50051"
    # ...and for model calls and calls between agents (HTTP).
    processor_webhook_address: str = "processor:8091"
    # When a call through the gateway can't be checked (OPA can't decide, or the governance
    # processor can't be reached or fails): "closed" refuses it; "open" lets it through
    # unchecked, and recorded where the processor can; "modes" refuses it only while a
    # control at the gateway is enforced, so that controls in monitor mode never stop a
    # call. Set it alike where the control plane (which configures the gateway) and the
    # processor run.
    gateway_failure_mode: str = "modes"
    # OTLP/gRPC endpoint for gateway traces, e.g. http://otel-collector:4317.
    gateway_otlp_endpoint: str | None = None
    # OTLP/gRPC endpoint for the gateway's access logs of model calls, which meter tokens and
    # cost: a receiver of the collector's own, which takes them from the gateway alone (with
    # AGENTGOV_TLS_DIR, the gateway shows its certificate), e.g. otel-collector:4319. Unset,
    # they go with the traces to AGENTGOV_GATEWAY_OTLP_ENDPOINT, where whatever can send
    # traces (agents do) can report model usage too.
    gateway_usage_endpoint: str | None = None
    # agentgateway binds IPv6 sockets by default, which fails on IPv4-only hosts.
    gateway_ipv6: bool = False
    # Link to a trace in your trace viewer, with {trace_id} where the W3C trace ID
    # goes, such as http://localhost:16686/trace/{trace_id} for Jaeger. Ledger entries
    # recorded at the gateway then link to their trace.
    trace_url: str | None = None

    # --- Mutual TLS between components (docs/production.md) -----------------------
    # Where this component finds its certificate (tls.crt), its key (tls.key) and the
    # certificate of the authority that issued every component's (ca.crt), as
    # cert-manager writes them. Set, AgentGov's components talk over mutual TLS: each
    # serves TLS on its internal ports and asks callers for a certificate from the same
    # authority, and the control plane gives the service role only on its internal port.
    # `agentgov internal-certs DIR` makes an authority and the certificates.
    tls_dir: str | None = None
    # Seconds between looks at those files for a renewed certificate (cert-manager's, or an
    # X.509-SVID spiffe-helper writes from SPIRE): a new one serves the next connections,
    # with no restart. 0 reads them once, at start.
    tls_reload_seconds: float = 60.0
    # The callers this component's TLS listeners take, comma-separated: their SPIFFE IDs
    # (the chart's: spiffe://example.org/ns/agentgov/agentgov/agentgov-gateway) or DNS
    # names, exact or with a trailing * for a prefix. Empty: any certificate from the
    # authority, which then must issue AgentGov's components' only; with SPIRE, which gives
    # every workload one, list them.
    tls_peers: str = ""
    # The control plane's port for AgentGov's other components, over mutual TLS.
    internal_port: int = 8443
    # Where agentgateway finds its tls.crt, tls.key and ca.crt, to call the processor
    # over mutual TLS (the control plane writes it into the gateway's configuration).
    gateway_tls_dir: str = "/tls"

    # --- Governance processor ----------------------------------------------------
    # Where it answers agentgateway about tool calls (gRPC).
    processor_listen: str = "0.0.0.0:50051"
    # Where it answers agentgateway's guardrail webhook for model calls, and its external
    # authorization of calls between agents.
    processor_webhook_listen: str = "0.0.0.0:8091"
    # Control plane URL as seen from the processor.
    control_plane_url: str = "http://localhost:8000"
    # Seconds between the processor's reports to the control plane of what it can reach
    # (OPA, Presidio, Granite Guardian, your decision point), which say on the Features page
    # whether each control can do what its mode says; 0 sends none.
    component_report_seconds: int = 60
    # Presidio's analyzer, such as http://presidio-analyzer:3000. Without it, personal
    # data isn't looked for.
    presidio_url: str | None = None
    # Presidio entities treated as personal data, with per-entity minimum scores.
    # Noisy recognisers (DATE_TIME, URL, LOCATION, ...) are deliberately absent;
    # add PERSON:0.85 to also mask names (it has false positives).
    pii_entities: str = (
        "EMAIL_ADDRESS:0.5,PHONE_NUMBER:0.4,US_SSN:0.5,CREDIT_CARD:0.5,IBAN_CODE:0.5,CRYPTO:0.5"
    )
    # Presidio costs ~40 ms per KB; text beyond this budget is not sent to it.
    presidio_max_chars: int = 16000
    # When Presidio is unreachable: "closed" denies the call, "open" skips PII scanning.
    presidio_failure_mode: str = "closed"
    # The score (0 to 1) from which text counts as a prompt injection or a jailbreak (also
    # for the control plane's Copilot Studio checks).
    prompt_injection_threshold: float = 0.7

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None, **overrides: Any) -> Settings:
        env = os.environ if environ is None else environ
        for name, feature in RETIRED.items():
            if env.get(name):
                raise ValueError(
                    f"{name} is now the {feature} feature: choose its mode in the app, or pin "
                    f"it with AGENTGOV_FEATURES={feature}=<mode> (see docs/features.md)"
                )
        for name, instead in REPLACED.items():
            if env.get(name):
                raise ValueError(f"{name} is no longer used: {instead}")
        values: dict[str, Any] = {}
        for field in dataclasses.fields(cls):
            name = f"AGENTGOV_{field.name.upper()}"
            raw = env.get(name)
            if raw is None or raw == "":
                continue
            target = str(field.type).replace(" | None", "")
            if target == "int" and _SERVICE_LINK.match(raw):
                continue
            try:
                values[field.name] = _coerce(raw, target)
            except ValueError:
                kind = "an integer" if target == "int" else "a number"
                raise ValueError(f"{name} must be {kind} (got {raw!r})") from None
        values.update({k: v for k, v in overrides.items() if v is not None})
        settings = cls(**values)
        settings.validate()
        return settings

    def validate(self) -> None:
        if not 0 < self.prompt_injection_threshold <= 1:
            raise ValueError("AGENTGOV_PROMPT_INJECTION_THRESHOLD must be in (0, 1]")
        for name in ("presidio", "authzen", "guardian"):
            if getattr(self, f"{name}_failure_mode") not in ("open", "closed"):
                raise ValueError(f"AGENTGOV_{name.upper()}_FAILURE_MODE must be 'open' or 'closed'")
        if self.feature_preset not in ("", *FEATURE_PRESETS):
            raise ValueError(
                f"AGENTGOV_FEATURE_PRESET is one of {', '.join(FEATURE_PRESETS)} (or empty)"
            )
        if self.gateway_failure_mode not in ("modes", "open", "closed"):
            raise ValueError("AGENTGOV_GATEWAY_FAILURE_MODE must be 'modes', 'open' or 'closed'")
        if self.delivery_interval_seconds < 0:
            raise ValueError("AGENTGOV_DELIVERY_INTERVAL_SECONDS must be 0 (off) or more")
        self.credential_host_list()
        if self.issues_interval_seconds < 0:
            raise ValueError("AGENTGOV_ISSUES_INTERVAL_SECONDS must be 0 (off) or more")
        if self.issues_notify_severity not in ("info", "low", "medium", "high", "critical"):
            raise ValueError(
                "AGENTGOV_ISSUES_NOTIFY_SEVERITY is one of info, low, medium, high, critical"
            )
        if self.threat_finding_days < 0:
            raise ValueError("AGENTGOV_THREAT_FINDING_DAYS must be 0 (never) or more")
        if self.issues_digest_at:
            self.digest_time()
            self.digest_zone()
            self.digest_days()
        if self.component_report_seconds < 0:
            raise ValueError("AGENTGOV_COMPONENT_REPORT_SECONDS must be 0 (none) or more")
        if self.platform_sync_interval_seconds < 0:
            raise ValueError(
                "AGENTGOV_PLATFORM_SYNC_INTERVAL_SECONDS must be 0 (on demand only) or more"
            )
        if self.issuer_keys_interval_seconds < 0:
            raise ValueError(
                "AGENTGOV_ISSUER_KEYS_INTERVAL_SECONDS must be 0 (on changes only) or more"
            )
        for region in self.aws_region_list():
            if not AWS_REGION.match(region):
                raise ValueError(f"AGENTGOV_AWS_REGIONS: {region!r} is not an AWS region")
        for arn in self.aws_role_arn_list():
            if not AWS_ROLE.match(arn):
                raise ValueError(f"AGENTGOV_AWS_ROLE_ARNS: {arn!r} is not an IAM role's ARN")
        if self.aws_role_arn_list() and not self.aws_region_list():
            raise ValueError("AGENTGOV_AWS_ROLE_ARNS needs AGENTGOV_AWS_REGIONS")
        for kind in self.aws_kind_list():
            if kind not in AWS_KINDS:
                raise ValueError(
                    f"AGENTGOV_AWS_READ: {kind!r} is not bedrock-agents, agentcore, "
                    "agentcore-gateways, quick or agent-registry"
                )
        for project in self.google_cloud_project_list():
            if not GOOGLE_PROJECT.match(project):
                raise ValueError(f"AGENTGOV_GOOGLE_CLOUD_PROJECTS: {project!r} is not a project ID")
        for region in self.google_cloud_region_list():
            if not GOOGLE_REGION.match(region):
                raise ValueError(
                    f"AGENTGOV_GOOGLE_CLOUD_REGIONS: {region!r} is not a Google Cloud region"
                )
        for kind in self.google_cloud_kind_list():
            if kind not in ("agent-runtime", "agent-registry"):
                raise ValueError(
                    f"AGENTGOV_GOOGLE_CLOUD_READ: {kind!r} is not agent-runtime or agent-registry"
                )
        if self.salesforce_url:
            if not SALESFORCE_URL.match(self.salesforce_url):
                raise ValueError(
                    "AGENTGOV_SALESFORCE_URL must be the org's My Domain URL, such as "
                    "https://contoso.my.salesforce.com"
                )
            if not self.salesforce_client_id:
                raise ValueError("AGENTGOV_SALESFORCE_URL needs AGENTGOV_SALESFORCE_CLIENT_ID")
            if not self.salesforce_client_secret and not (
                self.salesforce_username and self.salesforce_private_key_file
            ):
                raise ValueError(
                    "AGENTGOV_SALESFORCE_CLIENT_ID needs AGENTGOV_SALESFORCE_CLIENT_SECRET, or "
                    "AGENTGOV_SALESFORCE_USERNAME and AGENTGOV_SALESFORCE_PRIVATE_KEY_FILE"
                )
        for host in self.databricks_host_list():
            if not DATABRICKS_URL.match(host):
                raise ValueError(
                    f"AGENTGOV_DATABRICKS_HOSTS: {host!r} is not a workspace's URL, such as "
                    "https://dbc-1234.cloud.databricks.com"
                )
        signs_in = bool(self.databricks_client_id and self.databricks_client_secret)
        if self.databricks_host_list() and not (signs_in or self.databricks_token):
            raise ValueError(
                "AGENTGOV_DATABRICKS_HOSTS needs AGENTGOV_DATABRICKS_CLIENT_ID and "
                "AGENTGOV_DATABRICKS_CLIENT_SECRET, or AGENTGOV_DATABRICKS_TOKEN"
            )
        for endpoint in self.foundry_project_list():
            if not FOUNDRY_PROJECT.match(endpoint):
                raise ValueError(
                    f"AGENTGOV_FOUNDRY_PROJECTS: {endpoint!r} is not a project's endpoint, such as "
                    "https://contoso.services.ai.azure.com/api/projects/support"
                )
        for subscription in self.foundry_subscription_list():
            if not _GUID.match(subscription):
                raise ValueError(
                    f"AGENTGOV_FOUNDRY_SUBSCRIPTIONS: {subscription!r} is not a subscription ID"
                )
        if (self.foundry_project_list() or self.foundry_subscription_list()) and not (
            self.m365_tenant_id and self.m365_client_id and self.m365_client_secret
        ):
            raise ValueError(
                "Microsoft Foundry is read as AgentGov's Microsoft app: set "
                "AGENTGOV_M365_TENANT_ID, AGENTGOV_M365_CLIENT_ID and AGENTGOV_M365_CLIENT_SECRET"
            )
        for kind in self.databricks_kind_list():
            if kind not in DATABRICKS_KINDS:
                raise ValueError(
                    f"AGENTGOV_DATABRICKS_READ: {kind!r} is not serving, apps, genie or "
                    "mcp-services"
                )
        if self.classifier_timeout_seconds <= 0 or self.classifier_concurrency < 1:
            raise ValueError(
                "AGENTGOV_CLASSIFIER_TIMEOUT_SECONDS must be positive and "
                "AGENTGOV_CLASSIFIER_CONCURRENCY at least 1"
            )
        if self.smtp_url:
            scheme = self.smtp_url.partition("://")[0]
            if scheme not in ("smtp", "smtps") or "@" in self.smtp_url:
                raise ValueError(
                    "AGENTGOV_SMTP_URL is smtp://host:port or smtps://host:port, without "
                    "credentials (AGENTGOV_SMTP_USERNAME and AGENTGOV_SMTP_PASSWORD hold them)"
                )
            if not self.smtp_from:
                raise ValueError("AGENTGOV_SMTP_URL needs AGENTGOV_SMTP_FROM, the sender")
        self.escalation_delays()  # raises on malformed entries
        if self.ledger_retention_days < 0 or 0 < self.ledger_retention_days < LEDGER_MIN_DAYS:
            raise ValueError(
                f"AGENTGOV_LEDGER_RETENTION_DAYS is 0 (keep every entry) or at least "
                f"{LEDGER_MIN_DAYS}: six months, the least the EU AI Act asks of AI systems' logs"
            )
        if self.ledger_retention_days and not self.ledger_archive_dir:
            raise ValueError(
                "AGENTGOV_LEDGER_RETENTION_DAYS needs AGENTGOV_LEDGER_ARCHIVE_DIR: entries are "
                "archived there before they leave the database"
            )
        if self.ledger_checkpoint_hours < 0:
            raise ValueError("AGENTGOV_LEDGER_CHECKPOINT_HOURS must be 0 (on demand) or more")
        if self.authzen_url and not self.authzen_url.startswith(("https://", "http://")):
            raise ValueError("AGENTGOV_AUTHZEN_URL is the decision point's http(s) URL")
        if self.identity_full_sync_seconds < 0:
            raise ValueError("AGENTGOV_IDENTITY_FULL_SYNC_SECONDS is 0 (every pass) or more")
        if self.tls_reload_seconds < 0:
            raise ValueError("AGENTGOV_TLS_RELOAD_SECONDS is 0 (read once) or more")
        if self.authzen_timeout_seconds <= 0:
            raise ValueError("AGENTGOV_AUTHZEN_TIMEOUT_SECONDS must be more than 0")
        if not 30 <= self.assertion_lifetime_seconds <= 300:
            raise ValueError("AGENTGOV_ASSERTION_LIFETIME_SECONDS is between 30 and 300")
        if self.ledger_tsa_url and not self.ledger_tsa_url.startswith(("https://", "http://")):
            raise ValueError("AGENTGOV_LEDGER_TSA_URL is the authority's http(s) URL")
        if self.ledger_rekor_url:
            if not self.ledger_rekor_url.startswith(("https://", "http://")):
                raise ValueError("AGENTGOV_LEDGER_REKOR_URL is the log's http(s) URL")
            if not self.ledger_rekor_signing_key_file:
                raise ValueError(
                    "AGENTGOV_LEDGER_REKOR_URL needs AGENTGOV_LEDGER_REKOR_SIGNING_KEY_FILE: the "
                    "key AgentGov signs checkpoints with for the log (agentgov transparency-key)"
                )
        if self.data_retention_days < 0 or 0 < self.data_retention_days < DATA_MIN_DAYS:
            raise ValueError(
                f"AGENTGOV_DATA_RETENTION_DAYS is 0 (keep everything) or at least {DATA_MIN_DAYS}"
            )
        if self.api_key_days < 1 or self.api_key_max_days < 0:
            raise ValueError(
                "AGENTGOV_API_KEY_DAYS is 1 or more, and AGENTGOV_API_KEY_MAX_DAYS 0 or more"
            )
        if self.api_key_max_days and self.api_key_days > self.api_key_max_days:
            raise ValueError("AGENTGOV_API_KEY_DAYS can't be more than AGENTGOV_API_KEY_MAX_DAYS")
        if self.session_hours <= 0:
            raise ValueError("AGENTGOV_SESSION_HOURS must be positive")
        if self.trace_url and "{trace_id}" not in self.trace_url:
            raise ValueError("AGENTGOV_TRACE_URL must contain {trace_id}")
        m365 = (self.m365_tenant_id, self.m365_client_id, self.m365_client_secret)
        if any(m365) and not all(m365):
            raise ValueError(
                "set AGENTGOV_M365_TENANT_ID, AGENTGOV_M365_CLIENT_ID and "
                "AGENTGOV_M365_CLIENT_SECRET together"
            )
        if self.oidc_client_auth not in ("", "client_secret_basic", "client_secret_post"):
            raise ValueError(
                "AGENTGOV_OIDC_CLIENT_AUTH must be client_secret_basic or client_secret_post"
            )
        self.oidc_role_pairs()  # raises on malformed pairs and unknown roles
        domains = self.oidc_domains()  # raises on malformed domains
        if self.sso_enabled and self.oidc_provider == "google" and not domains:
            raise ValueError(
                "signing in with Google needs AGENTGOV_OIDC_ALLOWED_DOMAINS: every Google "
                "account shares Google's issuer, so name your organisation's domains"
            )
        if self.microsoft_admin_actions and not (self.sso_enabled and self.oidc_issuer):
            raise ValueError(
                "AGENTGOV_MICROSOFT_ADMIN_ACTIONS needs single sign-on through Microsoft Entra "
                "ID: set AGENTGOV_OIDC_ISSUER and AGENTGOV_OIDC_CLIENT_SECRET"
            )
        if self.copilot_studio_on_error not in ("block", "allow"):
            raise ValueError("AGENTGOV_COPILOT_STUDIO_ON_ERROR must be 'block' or 'allow'")
        if self.copilot_studio_tenant_id and not _GUID.match(self.copilot_studio_tenant_id):
            raise ValueError("AGENTGOV_COPILOT_STUDIO_TENANT_ID must be the tenant ID (a GUID)")
        self.feature_pins()  # raises on unknown features and modes
        self.m365_types()  # raises on unknown package types
        self.guardian_criteria_list()  # raises on unknown criteria
        self.pii_thresholds()  # raises on malformed entries

    def tls(self) -> Any:
        """This component's certificate for mutual TLS (agentgov.tls), or None without: one
        for each directory, which looks after its renewals."""
        if not self.tls_dir:
            return None
        return _tls_identity(self.tls_dir, self.tls_peers, self.tls_reload_seconds)

    def feature_pins(self) -> dict[str, str]:
        from agentgov.registry.features import parse_pins, unmet

        pins = parse_pins(self.features)
        for key, mode in pins.items():
            reason = unmet(key, mode, self)
            if reason:
                raise ValueError(f"AGENTGOV_FEATURES: {reason}")
        return pins

    @property
    def copilot_studio_configured(self) -> bool:
        """Whether Copilot Studio's calls can be authenticated."""
        return bool(self.copilot_studio_callers() and self.copilot_studio_tenant())

    def people_apps(self) -> list[str]:
        return [c.strip() for c in self.people_app_clients.split(",") if c.strip()]

    def copilot_studio_callers(self) -> list[str]:
        return [a.strip() for a in self.copilot_studio_caller_app_ids.split(",") if a.strip()]

    def copilot_studio_tenant(self) -> str | None:
        """The tenant whose apps may call threat detection (a GUID), if known."""
        entra = ENTRA_ISSUER.match((self.oidc_issuer or "").rstrip("/"))
        for candidate in (
            self.copilot_studio_tenant_id,
            self.m365_tenant_id,
            entra["tenant"] if entra else None,
        ):
            if candidate and _GUID.match(candidate):
                return candidate.lower()
        return None

    def copilot_studio_token_audiences(self) -> list[str]:
        configured = [a.strip() for a in self.copilot_studio_audiences.split(",") if a.strip()]
        if configured:
            return configured
        scheme, _, rest = self.public_url.partition("://")
        return [f"{scheme}://{rest.split('/', 1)[0]}"]

    def aws_region_list(self) -> list[str]:
        return [r.strip() for r in self.aws_regions.split(",") if r.strip()]

    def aws_role_arn_list(self) -> list[str]:
        return [r.strip() for r in self.aws_role_arns.split(",") if r.strip()]

    def aws_kind_list(self) -> list[str]:
        return [k.strip() for k in self.aws_read.split(",") if k.strip()]

    def google_cloud_project_list(self) -> list[str]:
        return [p.strip() for p in self.google_cloud_projects.split(",") if p.strip()]

    def google_cloud_region_list(self) -> list[str]:
        return [r.strip() for r in self.google_cloud_regions.split(",") if r.strip()]

    def google_cloud_kind_list(self) -> list[str]:
        return [k.strip() for k in self.google_cloud_read.split(",") if k.strip()]

    def databricks_host_list(self) -> list[str]:
        return [h.strip().rstrip("/") for h in self.databricks_hosts.split(",") if h.strip()]

    def databricks_kind_list(self) -> list[str]:
        return [k.strip() for k in self.databricks_read.split(",") if k.strip()]

    def foundry_project_list(self) -> list[str]:
        return [p.strip().rstrip("/") for p in self.foundry_projects.split(",") if p.strip()]

    def foundry_subscription_list(self) -> list[str]:
        return [s.strip() for s in self.foundry_subscriptions.split(",") if s.strip()]

    def m365_types(self) -> set[str]:
        types = {t.strip().lower() for t in self.m365_package_types.split(",") if t.strip()}
        unknown = types - set(M365_PACKAGE_TYPES)
        if unknown or not types:
            raise ValueError(
                f"AGENTGOV_M365_PACKAGE_TYPES takes {', '.join(M365_PACKAGE_TYPES)}; "
                f"got {self.m365_package_types!r}"
            )
        return types

    def pii_thresholds(self) -> dict[str, float]:
        thresholds = {}
        for item in filter(None, (p.strip() for p in self.pii_entities.split(","))):
            entity, _, score = item.partition(":")
            try:
                thresholds[entity.strip().upper()] = float(score) if score else 0.5
            except ValueError as exc:
                raise ValueError(f"bad AGENTGOV_PII_ENTITIES entry {item!r}") from exc
        return thresholds

    def digest_time(self) -> tuple[int, int] | None:
        """When the daily digest of open issues goes out: (hour, minute), or None."""
        if not self.issues_digest_at:
            return None
        match = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", self.issues_digest_at.strip())
        if match is None:
            raise ValueError("AGENTGOV_ISSUES_DIGEST_AT is a time of day, HH:MM, such as 08:30")
        return int(match[1]), int(match[2])

    def digest_zone(self) -> Any:
        """The time zone of the daily digest (a ZoneInfo)."""
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

        try:
            return ZoneInfo(self.issues_digest_timezone.strip() or "UTC")
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError(
                "AGENTGOV_ISSUES_DIGEST_TIMEZONE is a time zone's name, such as Europe/London "
                f"(not {self.issues_digest_timezone!r})"
            ) from None

    def digest_days(self) -> set[int]:
        """The days of the week the digest goes out, Monday 0."""
        days = [d.strip().lower()[:3] for d in self.issues_digest_days.split(",") if d.strip()]
        unknown = sorted(set(days) - set(WEEKDAYS))
        if unknown or not days:
            raise ValueError(
                "AGENTGOV_ISSUES_DIGEST_DAYS lists days of the week: mon, tue, wed, thu, fri, "
                "sat, sun"
            )
        return {WEEKDAYS.index(d) for d in days}

    def well_known_secrets(self) -> list[str]:
        """The settings holding a secret AgentGov's stacks and examples come with."""
        return [
            f"AGENTGOV_{name.upper()}"
            for name in SECRET_SETTINGS
            if getattr(self, name) in WELL_KNOWN_SECRETS
        ]

    def only_this_machine(self) -> bool:
        """Whether people reach the control plane on this machine only (AGENTGOV_PUBLIC_URL)."""
        host = urlsplit(self.public_url).hostname or ""
        return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")

    def witness_file(self) -> str | None:
        """Where the ledger's head is kept outside the database, if anywhere."""
        if self.ledger_witness_file:
            return None if self.ledger_witness_file == "off" else self.ledger_witness_file
        if self.ledger_archive_dir:
            return str(Path(self.ledger_archive_dir) / "ledger-head.json")
        return None

    def escalation_delays(self) -> dict[str, float]:
        """Hours an issue of each severity waits at a step of its chain."""
        from agentgov.models import SEVERITIES

        delays: dict[str, float] = {}
        for item in filter(None, (p.strip() for p in self.issue_escalation_hours.split(","))):
            severity, _, hours = item.partition(":")
            try:
                delays[severity.strip().lower()] = float(hours)
            except ValueError as exc:
                raise ValueError(f"bad AGENTGOV_ISSUE_ESCALATION_HOURS entry {item!r}") from exc
        unknown = sorted(set(delays) - set(SEVERITIES))
        if unknown or any(h <= 0 for h in delays.values()):
            raise ValueError(
                "AGENTGOV_ISSUE_ESCALATION_HOURS takes severity:hours pairs, hours above 0, for "
                f"{', '.join(SEVERITIES)}"
            )
        return {s: delays.get(s, 72.0) for s in SEVERITIES}

    def guardian_criteria_list(self) -> list[str]:
        from agentgov.scanners.guardian import CRITERIA

        names = [c.strip().lower() for c in self.guardian_criteria.split(",") if c.strip()]
        unknown = sorted(set(names) - set(CRITERIA))
        if unknown or not names:
            raise ValueError(
                f"AGENTGOV_GUARDIAN_CRITERIA takes {', '.join(CRITERIA)}; got {unknown or 'none'}"
            )
        return list(dict.fromkeys(names))

    @property
    def m365_enabled(self) -> bool:
        return bool(self.m365_tenant_id and self.m365_client_id and self.m365_client_secret)

    @property
    def keycloak_enabled(self) -> bool:
        return bool(self.keycloak_url and self.keycloak_client_secret)

    @property
    def key_secret(self) -> str | None:
        """What AgentGov's signing keys derive from: the signing secret, or else the
        service token."""
        return self.signing_secret or self.service_token

    @property
    def sso_enabled(self) -> bool:
        return bool(self.oidc_client_secret and (self.oidc_issuer or self.keycloak_issuer))

    @property
    def oidc_provider(self) -> str:
        """Which identity provider signs people in: ``keycloak`` (the bundled realm, or
        another Keycloak realm), ``entra`` (Microsoft Entra ID), ``google``, or ``oidc``
        (any other)."""
        if not self.oidc_issuer:
            return "keycloak"
        issuer = self.oidc_issuer.rstrip("/")
        if ENTRA_ISSUER.match(issuer):
            return "entra"
        if issuer == GOOGLE_ISSUER:
            return "google"
        if KEYCLOAK_REALM.search(issuer):
            return "keycloak"
        return "oidc"

    def oidc_roles_claims(self) -> list[str]:
        """The claims role names are read from, by default the provider's usual one."""
        configured = [c.strip() for c in self.oidc_roles_claim.split(",") if c.strip()]
        if configured:
            return configured
        return [
            {"keycloak": "realm_access.roles", "entra": "roles"}.get(self.oidc_provider, "groups")
        ]

    def oidc_role_pairs(self) -> dict[str, set[str]]:
        """AGENTGOV_OIDC_ROLE_MAP: each claim value and the AgentGov roles it grants."""
        if not self.oidc_role_map.strip():
            return {}
        from agentgov.identity.sso import GIVABLE, known_role

        pairs: dict[str, set[str]] = {}
        for item in self.oidc_role_map.split(","):
            if not item.strip():
                continue
            value, sep, role = item.rpartition("=")
            value, role = value.strip(), role.strip()
            if not sep or not value or not known_role(role):
                raise ValueError(
                    f"AGENTGOV_OIDC_ROLE_MAP takes value=role pairs, the roles one of "
                    f"{', '.join(GIVABLE)}, or one of them for a team, such as approver@sales "
                    f"(got {item.strip()!r})"
                )
            pairs.setdefault(value, set()).add(role)
        return pairs

    def credential_host_list(self) -> list[str]:
        """AGENTGOV_CREDENTIAL_HOSTS, lowercase: hosts, IP addresses, and *.domain."""
        hosts = [h.strip().lower().rstrip(".") for h in self.credential_hosts.split(",")]
        for host in hosts:
            if host and not (_HOST_PATTERN.match(host) or _ip_address(host)):
                raise ValueError(
                    f"AGENTGOV_CREDENTIAL_HOSTS: {host!r} is not a host, an IP address or *.domain"
                )
        return [h for h in hosts if h]

    def credentials_may_go_to(self, url: str | None) -> bool:
        """Whether a credential may go to ``url``'s host: any while AGENTGOV_CREDENTIAL_HOSTS
        is empty, else only those it lists."""
        listed = self.credential_host_list()
        if not listed:
            return True
        try:
            host = (urlsplit(url or "").hostname or "").rstrip(".")
        except ValueError:
            return False
        return bool(host) and any(
            host.endswith(entry[1:]) if entry.startswith("*.") else host == entry
            for entry in listed
        )

    def oidc_domains(self) -> list[str]:
        """AGENTGOV_OIDC_ALLOWED_DOMAINS, lowercase."""
        domains = [d.strip().lower().lstrip("@") for d in self.oidc_allowed_domains.split(",")]
        for domain in domains:
            if domain and not _DOMAIN.match(domain):
                raise ValueError(f"AGENTGOV_OIDC_ALLOWED_DOMAINS: {domain!r} is not a domain")
        return [d for d in domains if d]

    def oidc_endpoints(self) -> dict[str, str | None]:
        """Issuer and endpoints for administrator sign-in: Keycloak's paths for a Keycloak
        realm, Microsoft Entra ID's for an Entra tenant, and for other providers the
        endpoints set here, if any (agentgov.identity.sso reads the rest from the
        provider's discovery document)."""
        if self.oidc_provider in ("google", "oidc"):
            return {
                "issuer": self.oidc_issuer,
                "authorization_endpoint": self.oidc_authorization_endpoint,
                "token_endpoint": self.oidc_token_endpoint,
                "jwks_uri": self.oidc_jwks_url,
                "end_session_endpoint": self.oidc_end_session_endpoint,
            }
        issuer = (self.oidc_issuer or self.keycloak_issuer or "").rstrip("/")
        entra = ENTRA_ISSUER.match(issuer)
        if entra:
            tenant = f"{entra['base']}/{entra['tenant']}"
            return {
                "issuer": issuer,
                "authorization_endpoint": self.oidc_authorization_endpoint
                or f"{tenant}/oauth2/v2.0/authorize",
                "token_endpoint": self.oidc_token_endpoint or f"{tenant}/oauth2/v2.0/token",
                "jwks_uri": self.oidc_jwks_url or f"{tenant}/discovery/v2.0/keys",
                "end_session_endpoint": self.oidc_end_session_endpoint
                or f"{tenant}/oauth2/v2.0/logout",
            }
        backchannel = issuer
        if self.keycloak_url and not self.oidc_issuer:
            backchannel = f"{self.keycloak_url.rstrip('/')}/realms/{self.keycloak_realm}"
        return {
            "issuer": issuer,
            "authorization_endpoint": self.oidc_authorization_endpoint
            or f"{issuer}/protocol/openid-connect/auth",
            "token_endpoint": self.oidc_token_endpoint
            or f"{backchannel}/protocol/openid-connect/token",
            "jwks_uri": self.oidc_jwks_url
            or (self.keycloak_jwks_url if not self.oidc_issuer else None)
            or f"{backchannel}/protocol/openid-connect/certs",
            "end_session_endpoint": self.oidc_end_session_endpoint
            or f"{issuer}/protocol/openid-connect/logout",
        }

    def with_overrides(self, **overrides: Any) -> Settings:
        return dataclasses.replace(self, **overrides)


@functools.lru_cache(maxsize=8)
def _tls_identity(directory: str, peers: str, reload_seconds: float) -> Any:
    from agentgov.tls import Identity, Peers

    return Identity.from_dir(directory, peers=Peers.parse(peers), reload_seconds=reload_seconds)

"""Runtime configuration.

Every setting can be supplied through an ``AGENTGOV_<NAME>`` environment variable,
e.g. ``AGENTGOV_DATABASE_URL`` or ``AGENTGOV_KEYCLOAK_URL``. Integrations whose
settings are left empty are disabled, which keeps unit tests and local
development free of external dependencies.
"""

from __future__ import annotations

import dataclasses
import os
import re
from dataclasses import dataclass
from typing import Any

_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
M365_PACKAGE_TYPES = ("custom", "shared", "external", "microsoft")
# The least the ledger keeps its entries for, when it doesn't keep them all: six months, as
# the EU AI Act asks of providers' and deployers' logs (Articles 19 and 26(6)).
LEDGER_MIN_DAYS = 183
# The least operational records are kept: risk windows and budgets look back that far.
DATA_MIN_DAYS = 30
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
# Microsoft Entra ID's issuer: https://login.microsoftonline.com/<tenant>/v2.0
ENTRA_ISSUER = re.compile(
    r"^(?P<base>https://login\.microsoftonline\.(?:com|us)|https://login\.chinacloudapi\.cn)"
    r"/(?P<tenant>[^/]+)/v2\.0$"
)


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
    # Features pinned by the deployment, e.g. "least-privilege=monitor,discovery=off"
    # (docs/features.md). Administrators choose the others in the app.
    features: str = ""
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
    # Agents not seen for this many days raise a stale-agent finding.
    stale_agent_days: int = 30
    # Seconds between posture scans (owners, sponsors, attestations, stale agents); 0
    # turns the scheduled scan off.
    posture_interval_seconds: int = 300

    # --- Security operations (docs/secops.md) -------------------------------------
    # Where destinations' credentials are: a file per destination, named after it (a
    # mounted secret). Never in the database.
    destination_secrets_dir: str = "/destination-secrets"
    # How often destinations are sent what is new in the ledger (also as soon as it is
    # written, on the replica that wrote it). 0 turns delivery off.
    delivery_interval_seconds: int = 10

    # --- Issues (docs/issues.md) ---------------------------------------------------

    # Hours an issue waits at each step of its chain (owner, sponsors, team) for someone
    # to acknowledge it, before it goes to the next, by severity.
    issue_escalation_hours: str = "critical:4,high:24,medium:72,low:168,info:168"
    # Seconds between rounds of routing issues, escalating them and sending what is due.
    issues_interval_seconds: int = 60
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
    # Hours between ledger checkpoints: the chain's head, kept, and time-stamped when a
    # time-stamping authority is set. 0 makes them only on demand.
    ledger_checkpoint_hours: int = 24
    # An RFC 3161 time-stamping authority, such as https://freetsa.org/tsr. It signs each
    # checkpoint with its own time, which proves the chain existed then, unchanged since.
    ledger_tsa_url: str | None = None
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
    # resolved findings, ended access assignments, and developers' MCP servers not
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
    # Audience every agent token carries; the gateway requires it.
    gateway_audience: str = "agentgov-gateway"
    # Keycloak clients of the apps people sign in to and use agents from (comma-separated
    # client IDs). Each agent that acts for people has a client scope named after its
    # client ID, which these apps may request: the person's token is then one the agent
    # can exchange for a token of its own, on the person's behalf.
    people_app_clients: str = ""

    # --- Administrator single sign-on (OIDC) -------------------------------------
    # The control plane signs administrators in with an OIDC provider (Keycloak by
    # default) as a confidential client and keeps the session server-side: the
    # browser only holds an HttpOnly cookie. Enabled when a client secret is set.

    # The client AgentGov signs administrators in as.
    oidc_client_id: str = "agentgov-admin"
    # Its secret. Single sign-on is on when this is set.
    oidc_client_secret: str | None = None
    # Defaults to keycloak_issuer. Endpoints default to Keycloak's paths: the
    # authorization and logout endpoints under the issuer (browser-facing), the
    # token endpoint and JWKS under keycloak_url when set (server-to-server).
    oidc_issuer: str | None = None
    # The provider's endpoints, where they aren't Keycloak's or Microsoft Entra ID's.
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_jwks_url: str | None = None
    oidc_end_session_endpoint: str | None = None
    # The scopes asked for at sign-in.
    oidc_scopes: str = "openid profile email"
    # Where role names are found in the tokens (a dot path).
    oidc_roles_claim: str = "realm_access.roles"
    # The prefix that marks AgentGov roles: "agentgov-approver" grants the approver role.
    oidc_role_prefix: str = "agentgov-"
    # The longest an administrator's session lasts.
    session_hours: int = 8
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
    # enforced; past that, the rules alone decide, and the ledger says so.
    classifier_timeout_seconds: float = 3.0
    # Classifier calls one processor makes at a time. In the background, what waits
    # beyond a few hundred goes unclassified rather than piling up.
    classifier_concurrency: int = 4

    # --- OPA (policy decisions) --------------------------------------------------
    # Where the processor asks OPA for decisions, and the control plane for What if, such
    # as http://opa:8181.
    opa_url: str | None = None
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
    # The gateway's address as agents reach it, which the app and the API show.
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
    # OTLP/gRPC endpoint for gateway traces, e.g. http://otel-collector:4317.
    gateway_otlp_endpoint: str | None = None
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
        if self.presidio_failure_mode not in ("open", "closed"):
            raise ValueError("AGENTGOV_PRESIDIO_FAILURE_MODE must be 'open' or 'closed'")
        if self.delivery_interval_seconds < 0:
            raise ValueError("AGENTGOV_DELIVERY_INTERVAL_SECONDS must be 0 (off) or more")
        if self.issues_interval_seconds < 0:
            raise ValueError("AGENTGOV_ISSUES_INTERVAL_SECONDS must be 0 (off) or more")
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
        """This component's certificate for mutual TLS (agentgov.tls), or None without."""
        from agentgov.tls import Identity

        return Identity.from_dir(self.tls_dir) if self.tls_dir else None

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
    def sso_enabled(self) -> bool:
        return bool(self.oidc_client_secret and (self.oidc_issuer or self.keycloak_issuer))

    def oidc_endpoints(self) -> dict[str, str]:
        """Issuer and endpoints for administrator sign-in (Keycloak paths by default,
        Microsoft Entra ID's when the issuer is an Entra tenant)."""
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

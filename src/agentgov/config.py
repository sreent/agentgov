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

UNKNOWN_AGENT_MODES = ("reject", "monitor")
M365_PACKAGE_TYPES = ("custom", "shared", "external", "microsoft")
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
    # Externally reachable URL of the control plane (UI, API, OPA bundles).
    public_url: str = "http://localhost:8000"
    # Bootstrap administrator bearer token for the admin API and UI.
    admin_token: str | None = None
    # Shared token for internal components (OPA, governance processor, OTel
    # collector) calling the control plane.
    service_token: str | None = None
    # Agents registered by non-admins start "pending" until approved.
    registration_requires_approval: bool = True
    approval_ttl_seconds: int = 86400
    # Soft-deleted agents can be restored for this many days (Agent 365 parity).
    soft_delete_retention_days: int = 30
    # When > 0, agents whose risk score reaches this value are blocked.
    auto_block_risk_score: int = 0
    risk_window_hours: int = 24
    stale_agent_days: int = 30
    posture_interval_seconds: int = 300
    alert_webhook_url: str | None = None

    # --- Keycloak (agent identity) ---------------------------------------------
    # Base URL the control plane uses to reach Keycloak's admin API.
    keycloak_url: str | None = None
    keycloak_realm: str = "agentgov"
    keycloak_client_id: str = "agentgov-control-plane"
    keycloak_client_secret: str | None = None
    # Issuer that appears in agent tokens (Keycloak's frontend URL + realm).
    keycloak_issuer: str | None = None
    # JWKS URL the gateway uses to validate agent tokens.
    keycloak_jwks_url: str | None = None
    # Audience every agent token carries; the gateway requires it.
    gateway_audience: str = "agentgov-gateway"

    # --- Administrator single sign-on (OIDC) -------------------------------------
    # The control plane signs administrators in with an OIDC provider (Keycloak by
    # default) as a confidential client and keeps the session server-side: the
    # browser only holds an HttpOnly cookie. Enabled when a client secret is set.
    oidc_client_id: str = "agentgov-admin"
    oidc_client_secret: str | None = None
    # Defaults to keycloak_issuer. Endpoints default to Keycloak's paths: the
    # authorization and logout endpoints under the issuer (browser-facing), the
    # token endpoint and JWKS under keycloak_url when set (server-to-server).
    oidc_issuer: str | None = None
    oidc_authorization_endpoint: str | None = None
    oidc_token_endpoint: str | None = None
    oidc_jwks_url: str | None = None
    oidc_end_session_endpoint: str | None = None
    oidc_scopes: str = "openid profile email"
    # Where role names are found in the tokens (a dot path), and the prefix that
    # marks AgentGov roles: "agentgov-approver" grants the approver role.
    oidc_roles_claim: str = "realm_access.roles"
    oidc_role_prefix: str = "agentgov-"
    session_hours: int = 8
    # Act in Microsoft 365 and Power Platform as the administrator who is signed in
    # (quarantine Copilot Studio agents, read the Power Platform inventory, block
    # Microsoft 365 agents): Microsoft accepts these only from a signed-in admin.
    # Needs sign-in through Microsoft Entra ID (oidc_issuer
    # https://login.microsoftonline.com/<tenant>/v2.0) and an app registration with
    # the delegated permissions listed in docs/platforms.md.
    microsoft_admin_actions: bool = False

    # --- Microsoft 365 agent inventory --------------------------------------------
    # An Entra app registration with the Microsoft Graph application permission
    # CopilotPackages.Read.All (admin-consented). Microsoft's Package Management
    # API needs a Microsoft Agent 365 licence. Sync is enabled when all three are set.
    m365_tenant_id: str | None = None
    m365_client_id: str | None = None
    m365_client_secret: str | None = None
    # 0 turns the scheduled sync off; admins can still sync on demand.
    m365_sync_interval_seconds: int = 3600
    # Package types to import: custom (built in your organisation), shared (shared
    # by its users), external (from partners) and microsoft (Microsoft's own).
    m365_package_types: str = "custom,shared,external"
    graph_url: str = "https://graph.microsoft.com"
    entra_login_url: str = "https://login.microsoftonline.com"
    power_platform_url: str = "https://api.powerplatform.com"

    # --- Instruction classifier (optional) ----------------------------------------
    # IBM Granite Guardian behind an OpenAI-compatible API (vLLM, llama.cpp,
    # Ollama), e.g. http://guardian:8000/v1. Without it, agent instructions are
    # checked by AgentGov's rules only.
    guardian_url: str | None = None
    guardian_model: str = "ibm-granite/granite-guardian-4.1-8b"
    guardian_api_key: str | None = None
    # Criteria to judge (one classifier call each): harm, jailbreak, social_bias,
    # violence, profanity, unethical_behavior, exfiltration, deception.
    guardian_criteria: str = (
        "harm,jailbreak,social_bias,violence,unethical_behavior,exfiltration,deception"
    )
    guardian_timeout_seconds: float = 60.0

    # --- OPA (policy decisions) --------------------------------------------------
    opa_url: str | None = None
    # Longest a bundle long-poll request is held open.
    bundle_long_poll_seconds: int = 30

    # --- agentgateway (enforcement) ---------------------------------------------
    # Where the generated agentgateway config is written (shared volume).
    gateway_config_path: str | None = None
    gateway_public_url: str = "http://localhost:8080"
    gateway_port: int = 8080
    # Address agentgateway uses to reach the governance processor.
    processor_address: str = "processor:50051"
    # OTLP/gRPC endpoint for gateway traces, e.g. http://otel-collector:4317.
    gateway_otlp_endpoint: str | None = None
    # agentgateway binds IPv6 sockets by default, which fails on IPv4-only hosts.
    gateway_ipv6: bool = False
    # Link to a trace in your trace viewer, with {trace_id} where the W3C trace ID
    # goes. Ledger entries recorded at the gateway then link to their trace, e.g.
    # Langfuse: http://localhost:3000/project/<project>/traces/{trace_id}
    # Jaeger:   http://localhost:16686/trace/{trace_id}
    trace_url: str | None = None

    # --- Governance processor ----------------------------------------------------
    processor_listen: str = "0.0.0.0:50051"
    # Control plane URL as seen from the processor.
    control_plane_url: str = "http://localhost:8000"
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
    prompt_injection_threshold: float = 0.7
    # How calls without a recognised agent identity are handled:
    #   reject  - deny (default)
    #   monitor - allow, record, and register the caller as a discovered agent
    unknown_agent_mode: str = "reject"

    dev_mode: bool = False

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None, **overrides: Any) -> Settings:
        env = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        for field in dataclasses.fields(cls):
            raw = env.get(f"AGENTGOV_{field.name.upper()}")
            if raw is None or raw == "":
                continue
            values[field.name] = _coerce(raw, str(field.type).replace(" | None", ""))
        values.update({k: v for k, v in overrides.items() if v is not None})
        settings = cls(**values)
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.unknown_agent_mode not in UNKNOWN_AGENT_MODES:
            raise ValueError(f"AGENTGOV_UNKNOWN_AGENT_MODE must be one of {UNKNOWN_AGENT_MODES}")
        if not 0 < self.prompt_injection_threshold <= 1:
            raise ValueError("AGENTGOV_PROMPT_INJECTION_THRESHOLD must be in (0, 1]")
        if self.presidio_failure_mode not in ("open", "closed"):
            raise ValueError("AGENTGOV_PRESIDIO_FAILURE_MODE must be 'open' or 'closed'")
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
        self.m365_types()  # raises on unknown package types
        self.guardian_criteria_list()  # raises on unknown criteria
        self.pii_thresholds()  # raises on malformed entries

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

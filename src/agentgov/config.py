"""Runtime configuration.

Every setting can be supplied through an ``AGENTGOV_<NAME>`` environment variable,
e.g. ``AGENTGOV_DATABASE_URL`` or ``AGENTGOV_KEYCLOAK_URL``. Integrations whose
settings are left empty are disabled, which keeps unit tests and local
development free of external dependencies.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass
from typing import Any

UNKNOWN_AGENT_MODES = ("reject", "monitor")


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
    # OTLP endpoint for gateway traces.
    gateway_otlp_endpoint: str | None = None
    # agentgateway binds IPv6 sockets by default, which fails on IPv4-only hosts.
    gateway_ipv6: bool = False

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
        self.pii_thresholds()  # raises on malformed entries

    def pii_thresholds(self) -> dict[str, float]:
        thresholds = {}
        for item in filter(None, (p.strip() for p in self.pii_entities.split(","))):
            entity, _, score = item.partition(":")
            try:
                thresholds[entity.strip().upper()] = float(score) if score else 0.5
            except ValueError as exc:
                raise ValueError(f"bad AGENTGOV_PII_ENTITIES entry {item!r}") from exc
        return thresholds

    @property
    def keycloak_enabled(self) -> bool:
        return bool(self.keycloak_url and self.keycloak_client_secret)

    def with_overrides(self, **overrides: Any) -> Settings:
        return dataclasses.replace(self, **overrides)

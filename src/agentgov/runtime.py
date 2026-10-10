"""Wires the control plane's components together and runs its background loops."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

import httpx

from agentgov import ledger
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.gateway import GatewayConfigWriter
from agentgov.identity.delegation import Delegations
from agentgov.identity.keycloak import IdentityReconciler, KeycloakAdmin
from agentgov.identity.sso import OIDCClient
from agentgov.opa.bundle import BundleServer
from agentgov.platforms.microsoft import (
    Microsoft365Catalog,
    MicrosoftAdmin,
    PlatformError,
    declarative_instructions,
    is_declarative,
)
from agentgov.registry import agents as agents_svc
from agentgov.registry import instructions, platforms, posture
from agentgov.scanners.guardian import Guardian, GuardianError, GuardianUnavailable

log = logging.getLogger(__name__)
# Package details (for declarative agents' instructions) read per Microsoft 365 sync.
MAX_PACKAGE_DETAILS = 100


class _Worker:
    """A daemon thread that runs ``fn`` when triggered and every ``interval`` seconds."""

    def __init__(self, name: str, fn: Any, interval: float) -> None:
        self.name = name
        self.fn = fn
        self.interval = interval
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def trigger(self) -> None:
        self._wake.set()

    def start(self) -> None:
        def run() -> None:
            while not self._stop.is_set():
                try:
                    self.fn()
                except Exception:
                    log.exception("%s failed", self.name)
                self._wake.wait(timeout=self.interval)
                self._wake.clear()

        self._thread = threading.Thread(target=run, name=self.name, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


class AlertSink:
    """Posts short alerts to a Slack/Teams-compatible webhook, best effort."""

    def __init__(self, url: str | None) -> None:
        self.url = url

    def send(self, text: str) -> None:
        if not self.url:
            return
        url = self.url

        def post() -> None:
            try:
                httpx.post(
                    url,
                    content=json.dumps({"text": text}),
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
            except httpx.HTTPError as exc:
                log.warning("alert webhook failed: %s", exc)

        threading.Thread(target=post, daemon=True).start()


class Runtime:
    def __init__(
        self,
        settings: Settings,
        *,
        keycloak_http: httpx.Client | None = None,
        oidc_http: httpx.Client | None = None,
        m365_http: httpx.Client | None = None,
        guardian_http: httpx.Client | None = None,
        microsoft_http: httpx.Client | None = None,
    ) -> None:
        self.settings = settings
        self.db = Database(settings.database_url, on_commit=self._on_commit)
        self.bundles = BundleServer(self.db)
        self.gateway = GatewayConfigWriter(self.db, settings)
        self.alerts = AlertSink(settings.alert_webhook_url)
        self.ledger_integrity = ledger.IntegrityMonitor()
        # Administrator single sign-on (OIDC), when a client secret is configured.
        self.sso = OIDCClient(settings, http=oidc_http) if settings.sso_enabled else None
        # Acting as the signed-in administrator in Microsoft 365 and Power Platform.
        self.delegations: Delegations | None = None
        self.microsoft_admin: MicrosoftAdmin | None = None
        if settings.microsoft_admin_actions:
            self.delegations = Delegations(settings, http=oidc_http)
            self.microsoft_admin = MicrosoftAdmin(settings, http=microsoft_http)
        self.identity: IdentityReconciler | None = None
        if settings.keycloak_enabled:
            admin = KeycloakAdmin(
                settings.keycloak_url or "",
                settings.keycloak_realm,
                settings.keycloak_client_id,
                settings.keycloak_client_secret or "",
                http=keycloak_http,
            )
            self.identity = IdentityReconciler(self.db, settings, admin)
        # The Microsoft 365 agent catalog, read with Microsoft Graph (app-only).
        self.m365 = Microsoft365Catalog(settings, http=m365_http) if settings.m365_enabled else None
        self._m365_lock = threading.Lock()
        # Optional classifier for agent instructions (IBM Granite Guardian).
        self.guardian = Guardian(settings, http=guardian_http) if settings.guardian_url else None
        self._gateway_worker = _Worker("gateway-config", self.gateway.sync, 300)
        self._posture_worker = (
            _Worker("posture-scan", self.run_posture_scan, settings.posture_interval_seconds)
            if settings.posture_interval_seconds > 0
            else None
        )
        self._classifier_worker = (
            _Worker("instruction-classifier", self.classify_pending_instructions, 120)
            if self.guardian is not None
            else None
        )
        self._m365_worker = (
            _Worker(
                "microsoft-365-sync", self._scheduled_m365_sync, settings.m365_sync_interval_seconds
            )
            if self.m365 is not None and settings.m365_sync_interval_seconds > 0
            else None
        )
        self._started = False

    # -- lifecycle -----------------------------------------------------------
    def init_db(self) -> None:
        self.db.create_all()
        with self.db.session() as session:
            ledger.ensure_head(session)

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self.init_db()
        if loop is not None:
            self.bundles.bind_loop(loop)
        if self.identity is not None:
            self.identity.start()
        if self.settings.gateway_config_path:
            self._gateway_worker.start()
        if self._posture_worker is not None:
            self._posture_worker.start()
        if self._m365_worker is not None:
            self._m365_worker.start()
        if self._classifier_worker is not None:
            with self.db.session() as session:
                instructions.queue_unclassified(session)
            self._classifier_worker.start()
        self._started = True

    def stop(self) -> None:
        if self.identity is not None:
            self.identity.stop()
        self._gateway_worker.stop()
        if self._posture_worker is not None:
            self._posture_worker.stop()
        if self._m365_worker is not None:
            self._m365_worker.stop()
        if self._classifier_worker is not None:
            self._classifier_worker.stop()
        self.db.dispose()

    # -- reconciliation triggers -----------------------------------------------
    def _on_commit(self, topics: set[str]) -> None:
        self.bundles.notify()
        if self.identity is not None and topics & {"agents", "blueprints"}:
            self.identity.trigger()
        if "toolservers" in topics and self.settings.gateway_config_path:
            self._gateway_worker.trigger()
        if "instructions" in topics and self._classifier_worker is not None:
            self._classifier_worker.trigger()

    def run_posture_scan(self) -> dict[str, Any]:
        with self.db.session() as session:
            return posture.scan(session, self.settings)

    def sync_microsoft_365(self, *, actor: str | None = None) -> dict[str, int]:
        """Read the Microsoft 365 agent catalog into the registry; returns the counts."""
        if self.m365 is None:
            raise PlatformError("Microsoft 365 sync is not configured")
        include = self.settings.m365_types()
        with self._m365_lock:
            try:
                packages = self.m365.agents()  # before the transaction: paging can be slow
            except PlatformError as exc:
                with self.db.session() as session:
                    platforms.set_sync(
                        session, "microsoft-365", ok=False, counts={}, message=str(exc), actor=actor
                    )
                raise
            # Declarative agents' instructions are in their package details: read those
            # of packages that changed since they were last read, a batch per sync.
            with self.db.session() as session:
                checked = platforms.instructions_checked(session)
            found: dict[str, str | None] = {}
            for pkg in packages:
                package_id = pkg.get("id")
                if (
                    len(found) >= MAX_PACKAGE_DETAILS
                    or not isinstance(package_id, str)
                    or pkg.get("type") not in include
                    or not is_declarative(pkg)
                    or checked.get(package_id) == pkg.get("lastModifiedDateTime")
                ):
                    continue
                try:
                    found[package_id] = declarative_instructions(self.m365.package(package_id))
                except PlatformError as exc:
                    log.warning("could not read package %s: %s", package_id, exc)
            with self.db.session() as session:
                counts = platforms.record_microsoft_365(
                    session,
                    packages,
                    include_types=include,
                    actor=actor,
                    agent_instructions=found,
                    classify=self.guardian is not None,
                )
                platforms.refresh_risk(session, self.settings)
                return counts

    def _scheduled_m365_sync(self) -> None:
        try:
            self.sync_microsoft_365()
        except PlatformError as exc:
            log.warning("Microsoft 365 sync failed: %s", exc)

    def classify_pending_instructions(self, limit: int = 100) -> int:
        """Run the classifier over instructions waiting for it; returns how many."""
        if self.guardian is None:
            return 0
        done = 0
        while done < limit:
            with self.db.session() as session:
                batch = instructions.pending(session, limit=5)
            if not batch:
                break
            for row_id, text, digest in batch:
                # Outside any transaction: on a CPU each criterion takes seconds.
                try:
                    result, error = self.guardian.classify(text), None
                except GuardianUnavailable as exc:
                    # Still queued: the next round (or the next change) tries again.
                    log.warning("instruction classifier unavailable: %s", exc)
                    return done
                except GuardianError as exc:
                    result, error = {"model": self.guardian.model, "verdicts": {}}, str(exc)
                    log.warning("instruction classifier failed: %s", exc)
                with self.db.session() as session:
                    agent = instructions.record_classification(
                        session, row_id, digest, result, error=error
                    )
                    if agent is not None:
                        agents_svc.refresh_risk(session, self.settings, agent)
                done += 1
        return done

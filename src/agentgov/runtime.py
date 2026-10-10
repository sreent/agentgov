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
from agentgov.identity.keycloak import IdentityReconciler, KeycloakAdmin
from agentgov.identity.sso import OIDCClient
from agentgov.opa.bundle import BundleServer
from agentgov.registry import posture

log = logging.getLogger(__name__)


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
    ) -> None:
        self.settings = settings
        self.db = Database(settings.database_url, on_commit=self._on_commit)
        self.bundles = BundleServer(self.db)
        self.gateway = GatewayConfigWriter(self.db, settings)
        self.alerts = AlertSink(settings.alert_webhook_url)
        self.ledger_integrity = ledger.IntegrityMonitor()
        # Administrator single sign-on (OIDC), when a client secret is configured.
        self.sso = OIDCClient(settings, http=oidc_http) if settings.sso_enabled else None
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
        self._gateway_worker = _Worker("gateway-config", self.gateway.sync, 300)
        self._posture_worker = (
            _Worker("posture-scan", self.run_posture_scan, settings.posture_interval_seconds)
            if settings.posture_interval_seconds > 0
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
        self._started = True

    def stop(self) -> None:
        if self.identity is not None:
            self.identity.stop()
        self._gateway_worker.stop()
        if self._posture_worker is not None:
            self._posture_worker.stop()
        self.db.dispose()

    # -- reconciliation triggers -----------------------------------------------
    def _on_commit(self, topics: set[str]) -> None:
        self.bundles.notify()
        if self.identity is not None and topics & {"agents", "blueprints"}:
            self.identity.trigger()
        if "toolservers" in topics and self.settings.gateway_config_path:
            self._gateway_worker.trigger()

    def run_posture_scan(self) -> dict[str, Any]:
        with self.db.session() as session:
            return posture.scan(session, self.settings)

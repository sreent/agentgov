"""Wires the control plane's components together and runs its background loops."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from datetime import datetime, timedelta
from typing import Any

import httpx

from agentgov import ids, ledger, migrations
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.gateway import GatewayConfigWriter
from agentgov.identity.delegation import Delegations
from agentgov.identity.keycloak import IdentityReconciler, KeycloakAdmin
from agentgov.identity.sso import OIDCClient
from agentgov.opa.bundle import BundleServer
from agentgov.platforms import connections
from agentgov.platforms.microsoft import (
    MicrosoftAdmin,
    MicrosoftApp,
    PlatformError,
    declarative_instructions,
    is_declarative,
)
from agentgov.platforms.threat_detection import ThreatDetection
from agentgov.registry import agents as agents_svc
from agentgov.registry import (
    features,
    instructions,
    mcp_sightings,
    microsoft_signals,
    platforms,
    posture,
)
from agentgov.scanners.guardian import Guardian, GuardianError, GuardianUnavailable

log = logging.getLogger(__name__)
# Package details (for declarative agents' instructions) read per Microsoft 365 sync.
MAX_PACKAGE_DETAILS = 100
# The Purview audit searches: agents' use, and Copilot Studio makers' changes.
# Both by operation name: Microsoft documents the record type enum's casing two ways.
AUDIT_SEARCHES: dict[str, dict[str, Any]] = {
    "usage": {"operations": ["CopilotInteraction"]},
    "makers": {"operations": list(microsoft_signals.MAKER_EVENTS)},
}
AUDIT_LAG = timedelta(hours=1)
AUDIT_MIN_WINDOW = timedelta(minutes=15)
AUDIT_FIRST_WINDOW = timedelta(days=1)
AUDIT_GIVE_UP = timedelta(hours=6)
DEFENDER_FIRST_WINDOW = timedelta(days=7)


def _graph_time(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


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
        copilot_studio_http: httpx.Client | None = None,
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
        self.m365 = MicrosoftApp(settings, http=m365_http) if settings.m365_enabled else None
        self._m365_lock = threading.Lock()
        # Copilot Studio asks AgentGov about each tool call its agents make, while the
        # copilot-studio-threat-detection feature is on.
        self.threat_detection: ThreatDetection | None = None
        if settings.copilot_studio_configured:
            self.threat_detection = ThreatDetection(
                settings, opa_http=copilot_studio_http, keys_http=copilot_studio_http
            )
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
        # Checks what arrived while instruction checks were off, once they are on again.
        self._recheck_worker = _Worker(
            "instruction-recheck", self.check_unchecked_instructions, 3600
        )
        # Developers' MCP servers against the approved ones, again when tool servers change.
        self._mcp_worker = _Worker("developer-mcp", self.refresh_developer_mcp, 3600)
        self._m365_worker = (
            _Worker(
                "microsoft-sync",
                self._scheduled_microsoft_sync,
                settings.m365_sync_interval_seconds,
            )
            if self.m365 is not None and settings.m365_sync_interval_seconds > 0
            else None
        )
        self._started = False

    # -- lifecycle -----------------------------------------------------------
    def init_db(self) -> None:
        if self.settings.database_auto_migrate:
            migrations.upgrade(self.db.engine)
        else:
            migrations.check(self.db.engine)
        with self.db.session() as session:
            ledger.ensure_head(session)
        with self.db.session() as session:
            features.apply_pins(session, self.settings)

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
        self._recheck_worker.start()
        self._mcp_worker.start()
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
        self._recheck_worker.stop()
        self._mcp_worker.stop()
        self.db.dispose()

    # -- reconciliation triggers -----------------------------------------------
    def _on_commit(self, topics: set[str]) -> None:
        self.bundles.notify()
        if self.identity is not None and topics & {"agents", "blueprints"}:
            self.identity.trigger()
        if topics & {"toolservers", "features"} and self.settings.gateway_config_path:
            self._gateway_worker.trigger()
        if "feature:instruction-checks" in topics:
            self._recheck_worker.trigger()
        if topics & {"toolservers", "feature:mcp-discovery"}:
            self._mcp_worker.trigger()
        if "instructions" in topics and self._classifier_worker is not None:
            self._classifier_worker.trigger()

    def run_posture_scan(self) -> dict[str, Any] | None:
        """Scan, unless posture checks are off (then None)."""
        with self.db.session() as session:
            if not features.is_on(session, "posture-checks"):
                return None
            return posture.scan(session, self.settings)

    def refresh_developer_mcp(self) -> int:
        """Re-check the MCP servers developers reported against the approved tool servers;
        returns how many findings resolved."""
        with self.db.session() as session:
            if not features.is_on(session, "mcp-discovery"):
                return 0
            return mcp_sightings.refresh(session, self.settings)

    def check_unchecked_instructions(self) -> int:
        """Check instructions that arrived while instruction checks were off."""
        with self.db.session() as session:
            if not features.is_on(session, "instruction-checks"):
                return 0
            checked = instructions.check_unchecked(session, classify=self.guardian is not None)
            for agent in checked:
                agents_svc.refresh_risk(session, self.settings, agent)
            return len(checked)

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

    # -- AgentGov's app connections to Microsoft -------------------------------------

    def sync_microsoft(
        self, keys: list[str] | None = None, *, actor: str | None = None
    ) -> dict[str, Any]:
        """Run the app connections the app registration may use; returns each outcome.

        A connection whose permission the app lacks is skipped (and shown as such);
        one that fails doesn't stop the others.
        """
        if self.m365 is None:
            raise PlatformError("AgentGov's Microsoft app registration is not configured")
        with self.db.session() as session:
            turned_on = {k for k in connections.APP_CONNECTIONS if features.is_on(session, k)}
        results: dict[str, Any] = {k: {"off": True} for k in keys or () if k not in turned_on}
        wanted = [k for k in keys or connections.APP_CONNECTIONS if k in turned_on]
        if not wanted:
            return results

        def lacking(roles: frozenset[str] | None) -> bool:
            return any(not connections.runnable(connections.BY_KEY[k], roles) for k in wanted)

        try:
            roles = self.m365.granted()
            if actor is not None and lacking(roles):
                # Someone asked: pick up permissions granted since the token was issued.
                roles = self.m365.granted(refresh=True)
        except PlatformError as exc:
            with self.db.session() as session:
                for key in wanted:
                    platforms.set_sync(
                        session, key, ok=False, counts={}, message=str(exc), actor=actor
                    )
            raise
        with self.db.session() as session:
            connections.remember_grants(session, roles)
        runs = {
            "microsoft-365": self.sync_microsoft_365,
            "entra-agent-id": self.sync_agent_identities,
            "purview-audit": self.sync_audit,
            "defender": self.sync_defender,
        }
        for key in wanted:
            connection = connections.BY_KEY[key]
            if not connections.runnable(connection, roles):
                results[key] = {"lacks_permission": connection.permission}
                continue
            try:
                results[key] = runs[key](actor=actor)
            except PlatformError as exc:
                results[key] = {"error": str(exc)}
        return results

    def _scheduled_microsoft_sync(self) -> None:
        try:
            for key, outcome in self.sync_microsoft().items():
                if "error" in outcome:
                    log.warning("Microsoft sync of %s failed: %s", key, outcome["error"])
        except PlatformError as exc:
            log.warning("Microsoft sync failed: %s", exc)

    def _failed(self, key: str, exc: PlatformError, actor: str | None) -> None:
        with self.db.session() as session:
            platforms.set_sync(session, key, ok=False, counts={}, message=str(exc), actor=actor)

    def sync_agent_identities(self, *, actor: str | None = None) -> dict[str, int]:
        """Read the tenant's Entra agent identities and link them to agents."""
        assert self.m365 is not None
        try:
            identities = self.m365.agent_identities()
        except PlatformError as exc:
            self._failed("entra-agent-id", exc, actor)
            raise
        with self.db.session() as session:
            counts = platforms.record_agent_identities(session, identities, actor=actor)
            platforms.refresh_risk(session, self.settings)
            return counts

    def sync_audit(self, *, actor: str | None = None) -> dict[str, Any]:
        """Read agents' use and makers' changes from the Purview audit log.

        Audit searches run for minutes, so each run collects the searches the
        previous one started, then starts the next ones; nothing waits.
        """
        assert self.m365 is not None
        counts: dict[str, Any] = {"interactions": 0, "maker_events": 0, "searching": 0}
        try:
            for kind, search in AUDIT_SEARCHES.items():
                self._audit_step(kind, search, counts)
        except PlatformError as exc:
            self._failed("purview-audit", exc, actor)
            raise
        with self.db.session() as session:
            platforms.set_sync(session, "purview-audit", ok=True, counts=counts, actor=actor)
        return counts

    def _audit_step(self, kind: str, search: dict[str, Any], counts: dict[str, Any]) -> None:
        assert self.m365 is not None
        with self.db.session() as session:
            state = connections.load_state(session, "purview-audit")
        pending = state.get(kind)
        if pending:
            status = self.m365.audit_query_status(pending["id"])
            started = datetime.fromisoformat(pending["started"])
            if status == "succeeded":
                records = self.m365.audit_records(pending["id"])
                with self.db.session() as session:
                    if kind == "usage":
                        got = microsoft_signals.record_usage(session, self.settings, records)
                        counts["interactions"] += got["interactions"]
                    else:
                        got = microsoft_signals.record_maker_events(session, records)
                        counts["maker_events"] += got["events"]
                    state = connections.load_state(session, "purview-audit")
                    state[kind], state[f"{kind}_until"] = None, pending["end"]
                    connections.save_state(session, "purview-audit", state)
            elif status in ("failed", "cancelled") or ids.utcnow() - started > AUDIT_GIVE_UP:
                # Search the same window again: from where the failed search started, which
                # for the first search isn't a day before now any more.
                with self.db.session() as session:
                    state = connections.load_state(session, "purview-audit")
                    state[kind], state[f"{kind}_until"] = None, pending["start"]
                    connections.save_state(session, "purview-audit", state)
            else:
                counts["searching"] += 1
                return
        now = ids.utcnow()
        until = state.get(f"{kind}_until")
        start = datetime.fromisoformat(until.replace("Z", "+00:00")) if until else None
        start = start or now - AUDIT_FIRST_WINDOW
        end = now - AUDIT_LAG  # records reach the audit log late
        if end - start < AUDIT_MIN_WINDOW:
            return  # Purview takes about 200 searches a day: don't spend them on slivers
        start_at, end_at = _graph_time(start), _graph_time(end)
        query_id = self.m365.start_audit_query(
            f"AgentGov {kind} {start_at}", start_at, end_at, **search
        )
        with self.db.session() as session:
            state = connections.load_state(session, "purview-audit")
            state[kind] = {
                "id": query_id,
                "start": start_at,
                "end": end_at,
                "started": now.isoformat(),
            }
            connections.save_state(session, "purview-audit", state)
        counts["searching"] += 1

    def sync_defender(self, *, actor: str | None = None) -> dict[str, int]:
        """Read Defender's alerts about agents since the last run, as findings."""
        assert self.m365 is not None
        with self.db.session() as session:
            state = connections.load_state(session, "defender")
        since = state.get("since") or _graph_time(ids.utcnow() - DEFENDER_FIRST_WINDOW)
        try:
            alerts = self.m365.alerts_since(since)
        except PlatformError as exc:
            self._failed("defender", exc, actor)
            raise
        latest = max([str(a.get("lastUpdateDateTime") or "") for a in alerts] + [since])
        with self.db.session() as session:
            counts = microsoft_signals.record_alerts(session, self.settings, alerts)
            connections.save_state(session, "defender", {"since": latest})
            platforms.set_sync(session, "defender", ok=True, counts=counts, actor=actor)
            return counts

    def classify_pending_instructions(self, limit: int = 100) -> int:
        """Run the classifier over instructions waiting for it; returns how many."""
        if self.guardian is None:
            return 0
        with self.db.session() as session:
            if not features.is_on(session, "instruction-checks"):
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

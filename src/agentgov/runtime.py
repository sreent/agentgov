"""Wires the control plane's components together and runs its background loops."""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta
from typing import Any

import httpx

from agentgov import (
    health,
    ids,
    ledger,
    migrations,
    retention,
    timestamping,
    transparency,
    witness,
)
from agentgov.config import Settings
from agentgov.coordination import Coordinator
from agentgov.db import Database
from agentgov.db.models import Agent, LedgerCheckpoint
from agentgov.gateway import GatewayConfigWriter
from agentgov.identity import issuer_keys
from agentgov.identity.delegation import Delegations
from agentgov.identity.keycloak import IdentityReconciler, KeycloakAdmin
from agentgov.identity.sso import OIDCClient
from agentgov.notify import Notifier
from agentgov.opa.bundle import BundleServer
from agentgov.opa.signing import Signer
from agentgov.platforms import connections, inventories
from agentgov.platforms.microsoft import (
    MicrosoftAdmin,
    MicrosoftApp,
    PlatformError,
    declarative_instructions,
    is_declarative,
)
from agentgov.platforms.threat_detection import ThreatDetection
from agentgov.registry import (
    access_packages,
    entra_access,
    features,
    findings,
    instructions,
    issues,
    mcp_sightings,
    microsoft_signals,
    people,
    platforms,
    posture,
    reachability,
    rules,
)
from agentgov.registry import agents as agents_svc
from agentgov.registry.errors import Conflict, InvalidTransition
from agentgov.scanners.guardian import Guardian, GuardianError, GuardianUnavailable
from agentgov.secops.delivery import Delivery
from agentgov.ticketing import Ticketing

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
# How long a job an administrator starts waits for a run of it already going (on this
# replica or another) before answering that it is busy.
JOB_WAIT_SECONDS = 15.0


def _graph_time(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Worker:
    """A daemon thread that runs ``fn`` when triggered and every ``interval`` seconds; with
    ``leading``, only while it says this replica leads (the scheduled work runs on one)."""

    def __init__(self, name: str, fn: Any, interval: float, *, leading: Any = None) -> None:
        self.name = name
        self.fn = fn
        self.interval = interval
        self.leading = leading
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def trigger(self) -> None:
        self._wake.set()

    def start(self) -> None:
        def run() -> None:
            while not self._stop.is_set():
                if self.leading is None or self.leading():
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
        destinations_http: httpx.Client | None = None,
        tsa_http: httpx.Client | None = None,
        tlog_http: httpx.Client | None = None,
        platforms_http: httpx.Client | None = None,
        issuer_http: httpx.Client | None = None,
    ) -> None:
        self.settings = settings
        # This component's certificate, for mutual TLS with the others (agentgov.tls).
        self.tls = settings.tls()
        # What the control plane reaches itself, for whether features can do their work.
        self.health = health.Cached(
            settings, verify=lambda: self.tls.client_context() if self.tls else True
        )
        self.db = Database(settings.database_url, on_commit=self._on_commit)
        # OPA's bundles, signed when a key is set (agentgov.opa.signing).
        signer = (
            Signer.from_file(settings.bundle_signing_key_file, settings.bundle_signing_key_id)
            if settings.bundle_signing_key_file
            else None
        )
        # The other replicas: their changes, which one runs the scheduled work, and jobs
        # that run on one at a time (agentgov.coordination).
        self.coordination = Coordinator(
            self.db, on_remote=self._on_remote, on_leader=self._on_leader
        )
        self.bundles = BundleServer(self.db, signer=signer)
        self.gateway = GatewayConfigWriter(self.db, settings)
        # The security team's SIEMs and chats (the security-operations feature).
        self.delivery = Delivery(self.db, settings, http=destinations_http)
        # Issues to the people responsible for them, by email and in their teams' chats.
        self.notifier = Notifier(self.db, settings, self.delivery)
        # And as tickets in service desks, kept in step with them (docs/tickets.md).
        self.ticketing = Ticketing(self.db, settings, self.delivery)
        self.ledger_integrity = ledger.IntegrityMonitor(settings=settings)
        # Administrator single sign-on (OIDC), when a client secret is configured.
        self.sso = OIDCClient(settings, http=oidc_http) if settings.sso_enabled else None
        # Acting as the signed-in administrator in Microsoft 365 and Power Platform.
        self.delegations: Delegations | None = None
        self.microsoft_admin: MicrosoftAdmin | None = None
        if settings.microsoft_admin_actions:
            self.delegations = Delegations(settings, self.db, http=oidc_http)
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
        # Copilot Studio asks AgentGov about each tool call its agents make, while the
        # copilot-studio-threat-detection feature is on.
        self.threat_detection: ThreatDetection | None = None
        if settings.copilot_studio_configured:
            self.threat_detection = ThreatDetection(
                settings, opa_http=copilot_studio_http, keys_http=copilot_studio_http
            )
        # Optional classifier for agent instructions (IBM Granite Guardian).
        self.guardian = Guardian(settings, http=guardian_http) if settings.guardian_url else None
        # Agents on AWS, Google Cloud, Salesforce and Databricks, each read by a connector
        # of AgentGov's own where it is configured (agentgov.platforms.inventories).
        self.platforms = inventories.connectors(settings, http=platforms_http)
        # Each replica writes the gateway's configuration file (Compose), and sends
        # destinations what it wrote to the ledger (each claims a destination first).
        self._gateway_worker = _Worker("gateway-config", self.gateway.sync, 300)
        self._delivery_worker = (
            _Worker("secops-delivery", self.delivery.run, settings.delivery_interval_seconds)
            if settings.delivery_interval_seconds > 0
            else None
        )
        # The rest runs on the leader.
        leading = lambda: self.coordination.leading  # noqa: E731
        self._posture_worker = (
            _Worker(
                "posture-scan",
                self.run_posture_scan,
                settings.posture_interval_seconds,
                leading=leading,
            )
            if settings.posture_interval_seconds > 0
            else None
        )
        self._classifier_worker = (
            _Worker(
                "instruction-classifier",
                self.classify_pending_instructions,
                120,
                leading=leading,
            )
            if self.guardian is not None
            else None
        )
        # Checks what arrived while instruction checks were off, once they are on again.
        self._recheck_worker = _Worker(
            "instruction-recheck", self.check_unchecked_instructions, 3600, leading=leading
        )
        # Developers' MCP servers against the approved ones, again when tool servers change.
        self._mcp_worker = _Worker(
            "developer-mcp", self.refresh_developer_mcp, 3600, leading=leading
        )
        # Deleted agents are purged once they can no longer be restored; the ledger gets its
        # checkpoints, their time-stamps and its archives; old operational records go.
        self._retention_worker = _Worker("retention", self.run_retention, 3600, leading=leading)
        self._tsa_http = tsa_http
        self._tlog_http = tlog_http
        self._m365_worker = (
            _Worker(
                "microsoft-sync",
                self._scheduled_microsoft_sync,
                settings.m365_sync_interval_seconds,
                leading=leading,
            )
            if self.m365 is not None and settings.m365_sync_interval_seconds > 0
            else None
        )
        self._issues_worker = (
            _Worker("issues", self.run_issues, settings.issues_interval_seconds, leading=leading)
            if settings.issues_interval_seconds > 0
            else None
        )
        self._tickets_worker = (
            _Worker("tickets", self.run_tickets, settings.issues_interval_seconds, leading=leading)
            if settings.issues_interval_seconds > 0
            else None
        )
        # The signing keys of the identity issuers the gateway trusts, which rotate them.
        self.issuer_http = issuer_http or httpx.Client(timeout=10)
        self._issuer_keys_worker = _Worker(
            "issuer-keys",
            self._scheduled_issuer_keys,
            settings.issuer_keys_interval_seconds or 365 * 24 * 3600,
            leading=leading,
        )
        # Whatever connectors there are when it runs: one may be added after this.
        self._platforms_worker = (
            _Worker(
                "platform-sync",
                self._scheduled_platform_sync,
                settings.platform_sync_interval_seconds,
                leading=leading,
            )
            if settings.platform_sync_interval_seconds > 0
            else None
        )
        self._started = False

    def _leader_workers(self) -> list[_Worker]:
        workers = [
            self._posture_worker,
            self._classifier_worker,
            self._recheck_worker,
            self._mcp_worker,
            self._retention_worker,
            self._m365_worker,
            self._issues_worker,
            self._tickets_worker,
            self._platforms_worker,
            self._issuer_keys_worker,
        ]
        return [w for w in workers if w is not None]

    # -- lifecycle -----------------------------------------------------------
    def init_db(self) -> None:
        if self.settings.database_auto_migrate:
            migrations.upgrade(self.db)
        else:
            migrations.check(self.db)
        # Replicas starting together: one at a time.
        with self.coordination.job("startup"):
            with self.db.transaction() as tx:
                ledger.ensure_head(tx)
            with self.db.transaction() as tx:
                features.apply_deployment_preset(tx, self.settings)
                features.apply_pins(tx, self.settings)
        # A database restored from an older backup shows before anything is written to it.
        self.check_witness()

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self.init_db()
        if loop is not None:
            self.bundles.bind_loop(loop)
        self.coordination.start()
        if self.identity is not None:
            self.identity.start(
                full_every=self.settings.identity_full_sync_seconds,
                leading=lambda: self.coordination.leading,
                exclusive=lambda: self.coordination.job("identity"),
            )
        if self._classifier_worker is not None:
            with self.db.transaction() as tx:
                instructions.queue_unclassified(tx)
        # Every scheduled job, so that none is built and left idle.
        for worker in self._workers():
            worker.start()
        self._started = True

    def _workers(self) -> list[_Worker]:
        gateway = [self._gateway_worker] if self.settings.gateway_config_path else []
        delivery = [self._delivery_worker] if self._delivery_worker is not None else []
        return gateway + delivery + self._leader_workers()

    def stop(self) -> None:
        if self.identity is not None:
            self.identity.stop()
        for worker in self._workers():
            worker.stop()
        # Last: another replica takes the lead once this one lets go.
        self.coordination.stop()
        self.db.dispose()

    # -- reconciliation triggers -----------------------------------------------
    def _on_remote(self, topics: set[str] | None) -> None:
        """Another replica committed changes to ``topics`` (None: anything may have changed,
        while this replica wasn't listening)."""
        if topics is not None:
            self._on_commit(topics)
            return
        self.bundles.notify()
        for worker in [self._gateway_worker, self._delivery_worker, *self._leader_workers()]:
            if worker is not None:
                worker.trigger()
        if self.identity is not None:
            self.identity.trigger()

    def _on_leader(self, leading: bool) -> None:
        """This replica took the lead: run the scheduled work now rather than at its next
        interval."""
        if not leading:
            return
        for worker in self._leader_workers():
            worker.trigger()
        if self.identity is not None:
            self.identity.trigger()

    def _on_commit(self, topics: set[str]) -> None:
        if topics - {"ledger"}:  # OPA's data changed, not only the ledger
            self.bundles.notify()
        secops = {"ledger", "destinations", "feature:security-operations"}
        if self._delivery_worker is not None and topics & secops:
            self._delivery_worker.trigger()
        identity = {"agents", "blueprints", "issuers", "feature:workload-identity"}
        if self.identity is not None and topics & identity:
            self.identity.trigger()
        # Agents publish A2A routes, so their changes reach the gateway's configuration too;
        # and the issuers it trusts, with their keys.
        gateway = {"toolservers", "features", "agents", "issuers", "issuer-keys"}
        if topics & gateway and self.settings.gateway_config_path:
            self._gateway_worker.trigger()
        if "issuers" in topics:
            self._issuer_keys_worker.trigger()
        if "feature:instruction-checks" in topics:
            self._recheck_worker.trigger()
        if topics & {"toolservers", "feature:mcp-discovery"}:
            self._mcp_worker.trigger()
        if "instructions" in topics and self._classifier_worker is not None:
            self._classifier_worker.trigger()

    def run_posture_scan(self, *, wait: float | None = None) -> dict[str, Any] | None:
        """Scan, unless posture checks are off (then None); then the management rules.

        ``wait``, for this and the other jobs an administrator can start: how long to wait
        for a run already going, on this replica or another, before JobBusy (None: as long
        as it takes, as the scheduled runs do)."""
        with self.coordination.job("posture-scan", wait=wait):
            with self.db.transaction() as tx:
                scanning = features.is_on(tx, "posture-checks")
                urls = reachability.targets(tx) if scanning else None
            # Calls around the gateway, when the feature says "test": over the network, so
            # outside any transaction (None: not tested this time). Agents on this machine
            # are called only where people reach the control plane on it alone.
            tested = (
                reachability.call_all(urls, loopback=self.settings.only_this_machine())
                if urls is not None
                else None
            )
            with self.db.transaction() as tx:
                scanned = posture.scan(tx, self.settings, tested=tested) if scanning else None
            ruled = self.run_rules(wait=wait)
        return None if scanned is None else {**scanned, "rules": ruled}

    # -- someone says they fixed what an issue is about ---------------------------------

    def _how_checked(self, type_: str, source: str | None) -> tuple[str | None, str | None]:
        """How AgentGov checks a finding of ``type_`` again on demand, about an agent on
        ``source`` (None: AgentGov's own): the check, or None and why it can't."""
        if source == "copilot-studio" and type_ in platforms.FINDING_TYPES:
            return "posture", (
                "AgentGov checks what the last Copilot Studio import or sync says: import or "
                "sync again to see a fix made in Copilot Studio."
            )
        if type_ in posture.POSTURE_TYPES or type_ == platforms.TO_REVIEW:
            return "posture", None
        if type_ == "agent.high_risk":
            return "risk", None
        if type_ == instructions.FINDING:
            return "instructions", None
        if type_ in platforms.INVENTORY_FINDINGS and source in self.platforms:
            return "platform", None
        for key, types in platforms.SYNCED_FINDINGS.items():
            if type_ in types and key != "copilot-studio" and self.m365 is not None:
                return f"microsoft:{key}", None
        return None, (
            "AgentGov can't check this kind of finding again on demand: it resolves itself "
            "when what raised it is gone, or an approver resolves it."
        )

    def recheck(self, finding_id: str, *, actor: str) -> dict[str, Any]:
        """Check an open finding again now, as far as AgentGov can, because someone says
        they fixed it: whether it is gone, how it was checked, and what else to know."""
        with self.db.transaction() as tx:
            finding = findings.get(tx, finding_id)
            if finding.status != "open":
                raise InvalidTransition(
                    f"finding is {finding.status}: only open findings are checked again"
                )
            agent_id = finding.agent_id
            agent = Agent.objects.filter(pk=agent_id).first() if agent_id else None
            source = (agent.source or "").removeprefix("platform:") if agent else None
            source = source if agent is not None and agent.on_platform else None
            how, note = self._how_checked(finding.type, source)
        if how is None:
            raise Conflict(note or "")
        if how == "posture":
            if self.run_posture_scan(wait=JOB_WAIT_SECONDS) is None:
                raise Conflict("posture checks are off: turn them on in Features first")
        elif how == "platform":
            assert source is not None
            self.sync_platform(source, actor=actor, wait=JOB_WAIT_SECONDS, clean=1)
        elif how.startswith("microsoft:"):
            key = how.split(":", 1)[1]
            outcome = self.sync_microsoft([key], actor=actor, wait=JOB_WAIT_SECONDS)[key]
            if outcome.get("off") or "lacks_permission" in outcome:
                raise Conflict(f"AgentGov can't read {key} now: it is off, or lacks a permission")
            if "error" in outcome:
                raise PlatformError(outcome["error"])
        else:
            with self.db.transaction() as tx:
                agent = Agent.objects.filter(pk=agent_id).first()
                if how == "risk":
                    agents_svc.refresh_risk(tx, self.settings, agent)
                else:
                    instructions.rescan(tx, agent, actor=actor, classify=self.guardian is not None)
        with self.db.transaction() as tx:
            finding = findings.get(tx, finding_id)
            fixed = finding.status != "open"
            findings.record(
                tx, finding, "fix_claimed", actor, severity="info", checked=how, fixed=fixed
            )
            return {
                "fixed": fixed,
                "checked": how,
                "note": note,
                "finding": findings.to_dict(finding),
            }

    def run_rules(self, *, wait: float | None = None) -> dict[str, Any]:
        """A round of the management rules (docs/management-rules.md)."""
        with self.coordination.job("rules", wait=wait), self.db.transaction() as tx:
            return rules.evaluate(tx, self.settings)

    def run_retention(self, *, wait: float | None = None) -> dict[str, Any]:
        """Purge deleted agents past their retention, keep a ledger checkpoint when one is
        due, time-stamp checkpoints, archive the ledger past its retention, and remove old
        operational records (docs/evidence.md)."""
        with self.coordination.job("retention", wait=wait):
            out: dict[str, Any] = {"purged": self.purge_deleted_agents()}
            with self.db.transaction() as tx:
                point = retention.checkpoint_if_due(tx, self.settings)
                out["checkpoint"] = point.seq if point is not None else None
            out["timestamped"] = self.stamp_checkpoints()
            out["logged"] = self.log_checkpoints()
            with self.db.transaction() as tx:
                out["archived"] = retention.archive(tx, self.settings)
            checked = self.check_witness()
            out["witness"] = checked.state if checked is not None else None
            with self.db.transaction() as tx:
                out["pruned"] = retention.prune_records(tx, self.settings)
            return out

    def check_witness(self) -> witness.Status | None:
        """Compare the database's ledger with its head kept outside it (docs/backup.md), and
        keep that head up to date while they agree. A ledger behind it, or with another
        history, is a critical finding until an administrator accepts it."""
        path = self.settings.witness_file()
        if path is None:
            return None
        with self.coordination.job("witness"):
            with self.db.transaction() as tx:
                status = witness.compare(tx, path)
                if status.rewound:
                    if status.restored_at is None:
                        # Noticed now: where the database's ledger ended stays the start of
                        # the gap, whatever is written after.
                        status.restored_at = status.head_seq
                    findings.raise_finding(
                        tx,
                        type=witness.FINDING,
                        severity="critical",
                        subject="ledger",
                        title="The ledger lost entries: the database was restored or changed",
                        description=status.message(),
                        details={
                            "restored_at": status.restored_at,
                            "witness": witness.kept_head(status),
                        },
                        remediation="If the database was restored on purpose (after a failed "
                        "upgrade, say), accept the restore under Ledger: AgentGov writes what is "
                        "missing into the ledger. If nobody restored it, find out who changed "
                        "the database.",
                    )
            if not status.rewound and status.error is None:
                try:
                    witness.write(path, status.head_seq, status.head_hash, status.head_ts)
                except witness.WitnessError as exc:
                    status.error = str(exc)
            if status.error:
                log.warning("ledger witness: %s", status.error)
        return status

    def accept_rewind(self, *, actor: str) -> witness.Status:
        """An administrator accepts that the ledger lost entries (a restore): what is missing
        goes into the ledger itself, and it goes on from the head it has."""
        path = self.settings.witness_file()
        if path is None:
            raise Conflict("no file keeps the ledger's head (AGENTGOV_LEDGER_WITNESS_FILE)")
        with self.coordination.job("witness"):
            with self.db.transaction() as tx:
                status = witness.compare(tx, path)
                if not status.rewound:
                    raise Conflict("the ledger has every entry AgentGov wrote: nothing to accept")
                ledger.append(
                    tx,
                    type="ledger.rewound",
                    actor=actor,
                    severity="critical",
                    resource="ledger",
                    reason=status.message(),
                    details={
                        "state": status.state,
                        "head": {"seq": status.head_seq, "hash": status.head_hash},
                        "witness": {**witness.kept_head(status), "at": status.witness_at},
                        **({"missing": status.missing()} if status.missing() else {}),
                        **(
                            {"restored_at": status.restored_at}
                            if status.restored_at is not None
                            else {}
                        ),
                    },
                )
            with self.db.transaction() as tx:
                findings.resolve_key(tx, f"{witness.FINDING}:ledger", actor=actor)
                seq, hash_ = witness.head(tx)
                ts = witness.written(tx, seq)
            witness.write(path, seq, hash_, ts)
            with self.db.transaction() as tx:
                return witness.compare(tx, path)

    def make_checkpoint(self, *, wait: float | None = None) -> dict[str, Any] | None:
        """A checkpoint at the chain's head now (None for an empty ledger), time-stamped
        when an authority is set."""
        with self.coordination.job("retention", wait=wait):
            with self.db.transaction() as tx:
                point = ledger.checkpoint(tx)
                if point is None:
                    return None
                seq = point.seq
            self.stamp_checkpoints()
            self.log_checkpoints()
            with self.db.transaction() as tx:
                return ledger.checkpoint_dict(LedgerCheckpoint.objects.get(pk=seq))

    def stamp_checkpoints(self) -> int:
        """Have the time-stamping authority sign the checkpoints it hasn't yet; returns how
        many it did. Its failures are kept on the checkpoints, and tried again; so is an
        answer whose signature doesn't check out (against the authority's certificates,
        AGENTGOV_LEDGER_TSA_CA_FILE, when set), which isn't kept."""
        url = self.settings.ledger_tsa_url
        if not url:
            return 0
        trust = timestamping.trust(self.settings.ledger_tsa_ca_file)
        with self.coordination.job("retention"):
            with self.db.transaction() as tx:
                todo = retention.unstamped(tx)
                if trust.error:
                    for seq, _ in todo:
                        error = f"AGENTGOV_LEDGER_TSA_CA_FILE: {trust.error}"
                        retention.save_stamp(tx, seq, url, error=error)
                    return 0
            done = 0
            for seq, hash_ in todo:  # the network calls happen outside any transaction
                try:
                    got = timestamping.stamp(
                        url, ledger.statement(seq, hash_), http=self._tsa_http, roots=trust.roots
                    )
                except timestamping.TimestampError as exc:
                    with self.db.transaction() as tx:
                        retention.save_stamp(tx, seq, url, error=str(exc))
                    continue
                with self.db.transaction() as tx:
                    retention.save_stamp(tx, seq, url, stamp=got)
                done += 1
            return done

    def log_checkpoints(self) -> int:
        """Add the checkpoints the transparency log doesn't hold yet; returns how many it
        took. Each answer's proof is checked with the log's key, when it is set, before it
        is kept; failures are kept on the checkpoints, and tried again."""
        url = self.settings.ledger_rekor_url
        if not url:
            return 0
        with self.coordination.job("retention"):
            with self.db.transaction() as tx:
                todo = retention.unlogged(tx)
            if not todo:
                return 0
            try:
                key = transparency.load_signing_key(
                    self.settings.ledger_rekor_signing_key_file or ""
                )
                log_key = (
                    transparency.load_log_key(self.settings.ledger_rekor_log_key_file)
                    if self.settings.ledger_rekor_log_key_file
                    else None
                )
            except transparency.TransparencyError as exc:
                with self.db.transaction() as tx:
                    for seq, _ in todo:
                        retention.save_log_entry(tx, seq, url, error=str(exc))
                return 0
            origin = self.settings.ledger_rekor_origin or transparency.origin_of(url)
            done = 0
            for seq, hash_ in todo:  # the network calls happen outside any transaction
                statement = ledger.statement(seq, hash_)
                try:
                    entry = transparency.add(url, statement, key, http=self._tlog_http)
                except transparency.TransparencyError as exc:
                    with self.db.transaction() as tx:
                        retention.save_log_entry(tx, seq, url, error=str(exc))
                    continue
                checked, error = None, None
                if log_key is not None:
                    try:
                        transparency.check(
                            entry,
                            statement,
                            log_key=log_key,
                            origin=origin,
                            signer=key.public_key(),
                        )
                        checked = True
                    except transparency.TransparencyError as exc:
                        # The log has the entry: kept, with why its proof doesn't hold.
                        checked, error = False, f"the log's proof doesn't check out: {exc}"
                with self.db.transaction() as tx:
                    retention.save_log_entry(
                        tx, seq, url, entry=entry, checked=checked, error=error
                    )
                done += 1
            return done

    def purge_deleted_agents(self) -> list[str]:
        """Purge the agents deleted longer ago than AGENTGOV_SOFT_DELETE_RETENTION_DAYS."""
        with self.db.transaction() as tx:
            purged = agents_svc.purge_expired(tx, self.settings)
        if purged:
            log.info("purged %d agent(s) deleted over the retention period", len(purged))
        return purged

    def run_issues(self) -> dict[str, Any]:
        """Expire access packages and raise their reminders and reviews; route findings to
        the people responsible, escalate those nobody acknowledged, open accepted risks
        whose time ran out, resolve threats that haven't happened for a while, and send
        what is due, the day's digests included."""
        with self.coordination.job("issues"):
            with self.db.transaction() as tx:
                access = access_packages.check(tx, self.settings)
            with self.db.transaction() as tx:
                reopened = issues.reopen_accepted(tx)
                stale = findings.close_stale_threats(tx, self.settings.threat_finding_days)
                if not features.is_on(tx, "issues"):
                    return {"reopened": reopened, "stale_threats": stale, **access}
                routed = issues.route(tx, self.settings)
            return {
                "reopened": reopened,
                "stale_threats": stale,
                **access,
                **routed,
                **self.notifier.run(),
                **self.notifier.digest(),
            }

    def run_tickets(self) -> dict[str, Any]:
        """Open issues' tickets in the service desks, read back what happened to them there,
        and tell the desks what changed (docs/tickets.md)."""
        with self.coordination.job("tickets"):
            return self.ticketing.run()

    def refresh_issuer_keys(self, names: list[str] | None = None) -> dict[str, list[str]]:
        """Fetch the signing keys of the identity issuers the gateway trusts (all, or those
        ``names``), outside any transaction, and keep them (agentgov.identity.issuer_keys)."""
        with self.db.transaction() as tx:
            wanted = issuer_keys.targets(tx, names)
        found = issuer_keys.fetch_all(wanted, self.issuer_http)
        with self.db.transaction() as tx:
            return issuer_keys.store(tx, found)

    def _scheduled_issuer_keys(self) -> None:
        with self.coordination.job("issuer-keys"):
            self.refresh_issuer_keys()

    def refresh_developer_mcp(self) -> int:
        """Re-check the MCP servers developers reported against the approved tool servers;
        returns how many findings resolved."""
        with self.coordination.job("developer-mcp"), self.db.transaction() as tx:
            if not features.is_on(tx, "mcp-discovery"):
                return 0
            return mcp_sightings.refresh(tx, self.settings)

    def check_unchecked_instructions(self) -> int:
        """Check instructions that arrived while instruction checks were off."""
        with self.coordination.job("instruction-checks"), self.db.transaction() as tx:
            if not features.is_on(tx, "instruction-checks"):
                return 0
            checked = instructions.check_unchecked(tx, classify=self.guardian is not None)
            for agent in checked:
                agents_svc.refresh_risk(tx, self.settings, agent)
            return len(checked)

    def sync_microsoft_365(self, *, actor: str | None = None) -> dict[str, int]:
        """Read the Microsoft 365 agent catalog into the registry; returns the counts."""
        if self.m365 is None:
            raise PlatformError("Microsoft 365 sync is not configured")
        include = self.settings.m365_types()
        with self.coordination.job("microsoft-sync"):
            try:
                packages = self.m365.agents()  # before the transaction: paging can be slow
            except PlatformError as exc:
                with self.db.transaction() as tx:
                    platforms.set_sync(
                        tx, "microsoft-365", ok=False, counts={}, message=str(exc), actor=actor
                    )
                raise
            # Declarative agents' instructions are in their package details: read those
            # of packages that changed since they were last read, a batch per sync.
            with self.db.transaction() as tx:
                checked = platforms.instructions_checked(tx)
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
            with self.db.transaction() as tx, platforms.first_sync(tx, "microsoft-365"):
                counts = platforms.record_microsoft_365(
                    tx,
                    packages,
                    include_types=include,
                    actor=actor,
                    agent_instructions=found,
                    classify=self.guardian is not None,
                )
                platforms.refresh_risk(tx, self.settings)
                return counts

    # -- AgentGov's app connections to Microsoft -------------------------------------

    def sync_microsoft(
        self,
        keys: list[str] | None = None,
        *,
        actor: str | None = None,
        wait: float | None = None,
    ) -> dict[str, Any]:
        """Run the app connections the app registration may use; returns each outcome.

        A connection whose permission the app lacks is skipped (and shown as such);
        one that fails doesn't stop the others. One run at a time, on one replica.
        """
        if self.m365 is None:
            raise PlatformError("AgentGov's Microsoft app registration is not configured")
        with self.coordination.job("microsoft-sync", wait=wait):
            return self._sync_microsoft(keys, actor=actor)

    def _sync_microsoft(self, keys: list[str] | None, *, actor: str | None) -> dict[str, Any]:
        assert self.m365 is not None
        with self.db.transaction() as tx:
            turned_on = {k for k in connections.APP_CONNECTIONS if features.is_on(tx, k)}
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
            with self.db.transaction() as tx:
                for key in wanted:
                    platforms.set_sync(tx, key, ok=False, counts={}, message=str(exc), actor=actor)
            raise
        with self.db.transaction() as tx:
            connections.remember_grants(tx, roles)
        runs = {
            "microsoft-365": self.sync_microsoft_365,
            "entra-agent-id": self.sync_agent_identities,
            "entra-users": self.sync_people,
            "purview-audit": self.sync_audit,
            "defender": self.sync_defender,
            "entra-access-packages": self.sync_entra_access_packages,
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

    # -- AgentGov's connectors to other platforms -------------------------------------

    def sync_platform(
        self, source: str, *, actor: str | None = None, wait: float | None = None, clean: int = 2
    ) -> dict[str, int]:
        """Read one platform's agents into the registry; returns the counts. One run per
        platform at a time, on one replica. ``clean``: syncs in a row that must find a
        finding gone before it resolves (one, when someone says they fixed it)."""
        connector = self.platforms.get(source)
        if connector is None:
            raise PlatformError(f"{platforms.SOURCES.get(source, source)} is not configured")
        with self.coordination.job(f"platform-sync:{source}", wait=wait):
            try:
                inventory = connector.inventory()  # before the transaction: it can be slow
            except PlatformError as exc:
                with self.db.transaction() as tx:
                    platforms.sync_failed(tx, source, str(exc), actor=actor)
                raise
            with self.db.transaction() as tx, platforms.first_sync(tx, source):
                counts = platforms.record_inventory(
                    tx,
                    source,
                    inventory,
                    actor=actor,
                    classify=self.guardian is not None,
                    clean=clean,
                )
                platforms.refresh_risk(tx, self.settings)
                return counts

    def _scheduled_platform_sync(self) -> None:
        with self.db.transaction() as tx:
            turned_on = [source for source in self.platforms if features.is_on(tx, source)]
        for source in turned_on:
            try:
                self.sync_platform(source)
            except PlatformError as exc:
                log.warning("sync of %s failed: %s", source, exc)

    def _failed(self, key: str, exc: PlatformError, actor: str | None) -> None:
        with self.db.transaction() as tx:
            platforms.set_sync(tx, key, ok=False, counts={}, message=str(exc), actor=actor)

    def sync_agent_identities(self, *, actor: str | None = None) -> dict[str, int]:
        """Read the tenant's Entra agent identities and link them to agents."""
        assert self.m365 is not None
        try:
            identities = self.m365.agent_identities()
        except PlatformError as exc:
            self._failed("entra-agent-id", exc, actor)
            raise
        with self.db.transaction() as tx, platforms.first_sync(tx, "entra-agent-id"):
            counts = platforms.record_agent_identities(tx, identities, actor=actor)
            platforms.refresh_risk(tx, self.settings)
            return counts

    def sync_people(
        self,
        *,
        actor: str | None = None,
        token: str | None = None,
        limit: int = people.MAX_LOOKUP,
    ) -> dict[str, int]:
        """Look up the people platforms name as agents' owners and makers: with AgentGov's
        app, or as the signed-in administrator whose access ``token`` is given. One lookup
        at a time, on one replica."""
        with self.coordination.job("people-lookup", wait=JOB_WAIT_SECONDS if actor else None):
            with self.db.transaction() as tx:
                wanted = people.wanted(tx, limit=limit)
                emails = people.wanted_emails(tx, limit=limit)
            found: list[dict[str, Any]] = []
            missing: list[str] = []
            missing_emails: list[str] = []
            try:
                if token is not None:
                    assert self.microsoft_admin is not None
                    if wanted:
                        found, missing = self.microsoft_admin.users(token, wanted)
                    if emails:
                        more, missing_emails = self.microsoft_admin.users_by_email(token, emails)
                        found += more
                else:
                    assert self.m365 is not None
                    # Whether it may ask whose account is enabled: what its token holds.
                    roles = self.m365.granted() if wanted or emails else None
                    if wanted:
                        found, missing = self.m365.users(wanted, roles=roles)
                    if emails:
                        more, missing_emails = self.m365.users_by_email(emails, roles=roles)
                        found += more
            except PlatformError as exc:
                self._failed("entra-users", exc, actor)
                raise
            with self.db.transaction() as tx:
                counts = people.record_lookup(
                    tx, found, missing, missing_emails=missing_emails, actor=actor
                )
                platforms.set_sync(tx, "entra-users", ok=True, counts=counts, actor=actor)
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
        with self.db.transaction() as tx:
            platforms.set_sync(tx, "purview-audit", ok=True, counts=counts, actor=actor)
        return counts

    def _audit_step(self, kind: str, search: dict[str, Any], counts: dict[str, Any]) -> None:
        assert self.m365 is not None
        with self.db.transaction() as tx:
            state = connections.load_state(tx, "purview-audit")
        pending = state.get(kind)
        if pending:
            status = self.m365.audit_query_status(pending["id"])
            started = datetime.fromisoformat(pending["started"])
            if status == "succeeded":
                records = self.m365.audit_records(pending["id"])
                with self.db.transaction() as tx:
                    if kind == "usage":
                        got = microsoft_signals.record_usage(tx, self.settings, records)
                        counts["interactions"] += got["interactions"]
                    else:
                        got = microsoft_signals.record_maker_events(tx, records)
                        counts["maker_events"] += got["events"]
                    state = connections.load_state(tx, "purview-audit")
                    state[kind], state[f"{kind}_until"] = None, pending["end"]
                    # From when AgentGov knows what happened (management rules about
                    # inactive agents count no further back).
                    state.setdefault(f"{kind}_from", pending["start"])
                    connections.save_state(tx, "purview-audit", state)
            elif status in ("failed", "cancelled") or ids.utcnow() - started > AUDIT_GIVE_UP:
                # Search the same window again: from where the failed search started, which
                # for the first search isn't a day before now any more.
                with self.db.transaction() as tx:
                    state = connections.load_state(tx, "purview-audit")
                    state[kind], state[f"{kind}_until"] = None, pending["start"]
                    connections.save_state(tx, "purview-audit", state)
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
        with self.db.transaction() as tx:
            state = connections.load_state(tx, "purview-audit")
            state[kind] = {
                "id": query_id,
                "start": start_at,
                "end": end_at,
                "started": now.isoformat(),
            }
            connections.save_state(tx, "purview-audit", state)
        counts["searching"] += 1

    def sync_defender(self, *, actor: str | None = None) -> dict[str, int]:
        """Read Defender's alerts about agents since the last run, as findings."""
        assert self.m365 is not None
        with self.db.transaction() as tx:
            state = connections.load_state(tx, "defender")
        since = state.get("since") or _graph_time(ids.utcnow() - DEFENDER_FIRST_WINDOW)
        try:
            alerts = self.m365.alerts_since(since)
        except PlatformError as exc:
            self._failed("defender", exc, actor)
            raise
        latest = max([str(a.get("lastUpdateDateTime") or "") for a in alerts] + [since])
        with self.db.transaction() as tx:
            counts = microsoft_signals.record_alerts(tx, self.settings, alerts)
            connections.save_state(tx, "defender", {"since": latest})
            platforms.set_sync(tx, "defender", ok=True, counts=counts, actor=actor)
            return counts

    def sync_entra_access_packages(self, *, actor: str | None = None) -> dict[str, int]:
        """Read the access packages agents can hold in Microsoft Entra, and what their
        identities hold, raising issues for those about to expire."""
        assert self.m365 is not None
        try:
            # Network calls before the transaction: a package's assignments page by page.
            packages = [p for p in self.m365.access_packages() if entra_access.agent_policies(p)][
                : entra_access.MAX_PACKAGES
            ]
            assignments = {p["id"]: self.m365.package_assignments(p["id"]) for p in packages}
        except PlatformError as exc:
            self._failed("entra-access-packages", exc, actor)
            raise
        with self.db.transaction() as tx:
            counts = entra_access.record(tx, packages, assignments)
            platforms.set_sync(tx, "entra-access-packages", ok=True, counts=counts, actor=actor)
            return counts

    def classify_pending_instructions(self, limit: int = 100) -> int:
        """Run the classifier over instructions waiting for it; returns how many."""
        if self.guardian is None:
            return 0
        with self.coordination.job("instruction-classifier"):
            return self._classify_pending(limit)

    def _classify_pending(self, limit: int) -> int:
        assert self.guardian is not None
        with self.db.transaction() as tx:
            if not features.is_on(tx, "instruction-checks"):
                return 0
        done = 0
        while done < limit:
            with self.db.transaction() as tx:
                batch = instructions.pending(tx, limit=5)
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
                with self.db.transaction() as tx:
                    agent = instructions.record_classification(
                        tx, row_id, digest, result, error=error
                    )
                    if agent is not None:
                        agents_svc.refresh_risk(tx, self.settings, agent)
                done += 1
        return done

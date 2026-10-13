"""Builds and serves the OPA bundle: the policy library plus registry data.

OPA polls ``GET /v1/opa/bundles/agentgov.tar.gz``. Responses carry an ETag
derived from the bundle contents; OPA sends it back in ``If-None-Match``. When
OPA asks for long polling (``Prefer: wait=N``) and nothing has changed, the
request is held until the registry changes or the wait elapses, so blocking an
agent reaches every OPA instance in well under a second.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
import logging
import tarfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.db import Database
from agentgov.models import (
    DELETED,
    DISCOVERED,
    Agent,
    ApprovedConnector,
    Blueprint,
    IntegrationState,
    Policy,
    ToolServer,
)
from agentgov.opa import WHAT_IF
from agentgov.opa.signing import SIGNATURES, Signer
from agentgov.registry import (
    access_packages,
    features,
    identity_issuers,
    model_providers,
    model_usage,
    scopes,
)
from agentgov.registry import agents as agents_svc

log = logging.getLogger(__name__)

BUNDLE_CONTENT_TYPE = "application/vnd.openpolicyagent.bundles"
# What the bundle owns: OPA erases the policies under these as it activates one. system.log
# and not all of system, where OPA can have an authorization policy of its own, from a file
# (system.authz: the chart's, with SPIRE).
ROOTS = ["agentgov", "agentos", "registry", "system/log"]
# How long a bundle built is served without being built again, even with no change heard
# of: a change a replica didn't hear about (it lost the database for a while) reaches the
# OPA instances it serves within this.
MAX_AGE_SECONDS = 60.0
# The OPA instances' last status reports, for every replica to show.
OPA_STATUS = "opa-status"
# An instance not heard from for this long drops off the list.
OPA_FORGET = timedelta(days=1)

# Decision-log hygiene, evaluated by OPA itself: never log raw tool arguments, and log
# only the decisions of agents that ask OPA themselves (agentos, the Agent Governance
# Toolkit). The processor and the control plane record the decisions they ask for in the
# ledger with richer context, and their reads of the registry and the feature modes aren't
# decisions. Nor are what-if questions from the policies page (WHAT_IF in their input).
SYSTEM_LOG_REGO = f"""package system.log

mask contains "/input/arguments"

mask contains "/input/tool_args"

drop if not startswith(input.path, "agentos")

drop if input.input.{WHAT_IF} == true
"""


def library_dir() -> Path:
    return Path(str(resources.files("agentgov") / "policies"))


def library_files() -> dict[str, str]:
    """Built-in Rego modules keyed by bundle path (tests excluded)."""
    root = library_dir()
    files = {}
    for path in sorted(root.rglob("*.rego")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith("tests/") or rel.endswith("_test.rego"):
            continue
        files[rel] = path.read_text()
    return files


def custom_package(name: str) -> str:
    return "agentgov.custom." + name.replace("-", "_")


def registry_snapshot(session: Session) -> dict[str, Any]:
    agents: dict[str, Any] = {}
    clients: dict[str, str] = {}
    names: dict[str, str] = {}
    # Who calls with a token of an identity issuer the gateway takes tokens from: the agent
    # whose workload identity it names, by the issuer as tokens name it and the subject
    # (docs/agent-identity.md#straight-to-the-gateway). A blocked issuer's agents, and
    # agents not adopted yet, are callers AgentGov can't tell.
    takers = {i.name: i.issuer for i in identity_issuers.at_the_gateway(session)}
    workloads: dict[str, dict[str, str]] = {}
    used = model_usage.tokens_used(session)
    held = access_packages.held(session)
    current = features.modes(session)
    exceptions = features.all_scopes(session)
    scoped = False
    for agent in session.scalars(select(Agent).where(Agent.status != DELETED)).unique():
        bp = agent.blueprint
        budget = model_providers.effective_budget(agent)
        # The controls whose mode differs for this agent (docs/features.md#exceptions).
        own = {k: v["mode"] for k, v in features.exceptions_for(agent, current, exceptions).items()}
        scoped = scoped or bool(own)
        agents[agent.id] = {
            "id": agent.id,
            "name": agent.name,
            "status": agent.status,
            "client_id": agent.client_id,
            "blueprint": bp.name if bp else None,
            "team": scopes.team(agent),
            "platform": scopes.platform(agent),
            "modes": own,
            "owner": agent.owner,
            "sponsors": agent.sponsors or [],
            "labels": {**((bp.labels or {}) if bp else {}), **(agent.labels or {})},
            "environment": agent.environment,
            "risk_tier": agent.risk_tier,
            "risk_level": agent.risk_level,
            "risk_score": agent.risk_score,
            "grants": agents_svc.effective_grants(agent),
            "model_access": model_providers.effective_model_access(agent),
            "daily_token_budget": budget,
            "over_budget": model_usage.over_budget(budget, used.get(agent.id, 0)),
            "acts_for": bp.acts_for if bp else "either",
            "people_groups": (bp.people_groups or []) if bp else [],
            # How it authenticates: its workload identity, or (null) a client secret.
            "workload_identity": agents_svc.workload_identity(agent),
            # Agent to agent: whether it serves A2A, and the agents it may call.
            "a2a": bool(agent.a2a_url),
            "agent_access": agents_svc.effective_agent_access(agent),
            # Access packages it holds: their grants, and when each expires.
            "packages": held.get(agent.id, []),
        }
        names[agent.name] = agent.id
        if agent.client_id:
            clients[agent.client_id] = agent.id
        taker = takers.get(agent.workload_issuer or "")
        if taker and agent.workload_subject and agent.status != DISCOVERED:
            workloads.setdefault(taker, {})[agent.workload_subject] = agent.id
    servers: dict[str, Any] = {}
    # Servers only for developers never reach the gateway, so OPA never decides on them;
    # it does on those agents get identity assertions for (agentgov.idjag).
    reached = or_(ToolServer.gateway.is_(True), ToolServer.authorization_server.is_not(None))
    for ts in session.scalars(select(ToolServer).where(reached)):
        servers[ts.name] = {
            "name": ts.name,
            "status": ts.status,
            "gateway": bool(ts.gateway),
            "trust_level": ts.trust_level,
            "data_classification": ts.data_classification,
            "labels": ts.labels or {},
            "tools": {
                t["name"]: {
                    "annotations": t.get("annotations") or {},
                    "changed": bool(t.get("changed_at")),
                    "poisoned": bool(t.get("poisoned")),
                }
                for t in ts.tools or []
            },
        }
    blueprints = {
        bp.name: {
            "risk_tier": bp.risk_tier,
            "permissions": bp.permissions or [],
            "labels": bp.labels or {},
        }
        for bp in session.scalars(select(Blueprint))
    }
    # The connector allowlist for Copilot Studio agents (enforced through threat detection).
    approved = {c.connector_id: True for c in session.scalars(select(ApprovedConnector))}
    providers = {
        p.name: {
            "name": p.name,
            "kind": p.kind,
            "status": p.status,
            "trust_level": p.trust_level,
            "labels": p.labels or {},
        }
        for p in model_providers.list_all(session)
    }
    return {
        "agents": agents,
        "clients": clients,
        "workloads": workloads,
        "agent_names": names,
        "toolservers": servers,
        "model_providers": providers,
        "blueprints": blueprints,
        "connector_allowlist": {"active": bool(approved), "approved": approved},
        # The mode of each feature: the policies apply each control as its mode says, but
        # for the agents with a mode of their own (agents.<id>.modes).
        "features": current,
        "scoped_modes": scoped,
    }


def custom_modules(session: Session) -> dict[str, str]:
    return {
        f"agentgov/custom/{p.name}.rego": p.rego
        for p in session.scalars(
            select(Policy).where(Policy.enabled.is_(True)).order_by(Policy.name)
        )
    }


@dataclass(frozen=True)
class Bundle:
    etag: str
    body: bytes
    revision: str


def build(session: Session, signer: Signer | None = None) -> Bundle:
    """The bundle as the registry has it now; signed (.signatures.json) with ``signer``."""
    files = {**library_files(), "system/log.rego": SYSTEM_LOG_REGO, **custom_modules(session)}
    data = registry_snapshot(session)
    data_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(data_json.encode())
    for path in sorted(files):
        digest.update(path.encode())
        digest.update(files[path].encode())
    revision = digest.hexdigest()[:24]
    manifest = {"revision": revision, "roots": ROOTS}
    entries = {
        ".manifest": json.dumps(manifest, sort_keys=True),
        "registry/data.json": data_json,
        **files,
    }
    if signer is not None:
        entries[SIGNATURES] = signer.signatures(entries)
    buf = io.BytesIO()
    # Fixed mtimes keep the archive (and therefore the ETag) deterministic.
    with (
        gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w") as tar,
    ):
        for name in sorted(entries):
            payload = entries[name].encode()
            info = tarfile.TarInfo(name="/" + name)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            tar.addfile(info, io.BytesIO(payload))
    return Bundle(etag=f'"{revision}"', body=buf.getvalue(), revision=revision)


class BundleServer:
    """Caches the current bundle and wakes long-polling OPA instances on change."""

    def __init__(
        self, db: Database, *, max_age: float = MAX_AGE_SECONDS, signer: Signer | None = None
    ) -> None:
        self._db = db
        self.max_age = max_age
        self._signer = signer
        self._lock = threading.Lock()
        self._generation = 0
        # Keyed by generation and UTC day (budgets start again when the day does), and
        # built at (monotonic seconds).
        self._cached: tuple[tuple[int, str], Bundle, float] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._changed: asyncio.Condition | None = None
        self._wakeups: set[asyncio.Future[None]] = set()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._changed = asyncio.Condition()

    def notify(self) -> None:
        """Mark the bundle stale. Safe to call from any thread."""
        with self._lock:
            self._generation += 1
        if self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._wake)

    def _wake(self) -> None:
        async def notify_all() -> None:
            assert self._changed is not None
            async with self._changed:
                self._changed.notify_all()

        task = asyncio.ensure_future(notify_all())
        self._wakeups.add(task)
        task.add_done_callback(self._wakeups.discard)

    def current(self) -> Bundle:
        with self._lock:
            key = (self._generation, model_usage.today())
            cached = self._cached
        if cached is not None and cached[0] == key and time.monotonic() - cached[2] < self.max_age:
            return cached[1]
        built_at = time.monotonic()
        with self._db.session() as session:
            bundle = build(session, self._signer)
        with self._lock:
            self._cached = (key, bundle, built_at)
        return bundle

    async def wait_for_change(self, etag: str | None, timeout: float) -> Bundle | None:
        """Return a bundle whose ETag differs from ``etag``, or None on timeout."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            with self._lock:
                seen = self._generation
            bundle = await asyncio.to_thread(self.current)
            if bundle.etag != etag:
                return bundle
            remaining = deadline - loop.time()
            if remaining <= 0 or self._changed is None:
                return None
            async with self._changed:
                with self._lock:
                    changed_meanwhile = self._generation != seen
                if changed_meanwhile:
                    continue  # a change landed while we were building; re-check
                try:
                    await asyncio.wait_for(
                        self._changed.wait(), timeout=min(remaining, self.max_age)
                    )
                except TimeoutError:
                    if loop.time() >= deadline:
                        return None
                    # Nothing heard of: look again all the same (see MAX_AGE_SECONDS).


def record_status(session: Session, status: dict[str, Any]) -> None:
    """Keep an OPA instance's status report: when it reported, and the bundle it runs."""
    labels = status.get("labels") or {}
    instance = str(labels.get("id") or "opa")[:100]
    bundle = (status.get("bundles") or {}).get("agentgov") or {}
    row = session.get(IntegrationState, OPA_STATUS, with_for_update=True)
    if row is None:
        try:
            with session.begin_nested():
                session.add(IntegrationState(key=OPA_STATUS, data={}))
        except IntegrityError:
            pass  # another replica added it meanwhile
        row = session.get(
            IntegrationState, OPA_STATUS, with_for_update=True, populate_existing=True
        )
        assert row is not None
    now = ids.utcnow()
    instances = {
        key: value
        for key, value in ((row.data or {}).get("instances") or {}).items()
        if datetime.fromisoformat(value["at"]) > now - OPA_FORGET
    }
    instances[instance] = {
        "at": ids.isoformat(now),
        "revision": bundle.get("active_revision"),
        "version": labels.get("version"),
    }
    row.data = {"instances": instances}
    row.updated_at = now


def opa_status(session: Session) -> dict[str, Any]:
    """The OPA instances heard from in the last day: when each reported and its bundle."""
    row = session.get(IntegrationState, OPA_STATUS)
    instances = ((row.data or {}).get("instances") or {}) if row is not None else {}
    listed = sorted(
        ({"id": key, **value} for key, value in instances.items()),
        key=lambda i: i["at"],
        reverse=True,
    )
    return {"last_status_at": listed[0]["at"] if listed else None, "instances": listed}


def parse_prefer_wait(header: str | None) -> float | None:
    """Extract ``wait=N`` from OPA's ``Prefer`` header."""
    if not header:
        return None
    for part in header.replace(",", ";").split(";"):
        key, _, value = part.strip().partition("=")
        if key == "wait":
            try:
                return max(0.0, float(value))
            except ValueError:
                return None
    return None

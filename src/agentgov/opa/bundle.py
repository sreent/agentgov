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
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids
from agentgov.db import Database
from agentgov.models import DELETED, Agent, ApprovedConnector, Blueprint, Policy, ToolServer
from agentgov.registry import agents as agents_svc
from agentgov.registry import features, model_providers, model_usage

log = logging.getLogger(__name__)

BUNDLE_CONTENT_TYPE = "application/vnd.openpolicyagent.bundles"
ROOTS = ["agentgov", "agentos", "registry", "system"]

# Decision-log hygiene, evaluated by OPA itself: never log raw tool arguments,
# and skip gateway decisions on tool and model calls (the governance processor
# records those in the ledger with richer context) and reads of registry data
# (the processor reads the feature modes). In-process (agentos) decisions are logged.
SYSTEM_LOG_REGO = """package system.log

mask contains "/input/arguments"

mask contains "/input/tool_args"

drop if startswith(input.path, "agentgov/mcp")

drop if startswith(input.path, "agentgov/models")

drop if startswith(input.path, "registry")
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
    used = model_usage.tokens_used(session)
    for agent in session.scalars(select(Agent).where(Agent.status != DELETED)).unique():
        bp = agent.blueprint
        budget = model_providers.effective_budget(agent)
        agents[agent.id] = {
            "id": agent.id,
            "name": agent.name,
            "status": agent.status,
            "client_id": agent.client_id,
            "blueprint": bp.name if bp else None,
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
        }
        if agent.client_id:
            clients[agent.client_id] = agent.id
    servers: dict[str, Any] = {}
    # Servers only for developers never reach the gateway, so OPA never decides on them.
    for ts in session.scalars(select(ToolServer).where(ToolServer.gateway.is_(True))):
        servers[ts.name] = {
            "name": ts.name,
            "status": ts.status,
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
        "toolservers": servers,
        "model_providers": providers,
        "blueprints": blueprints,
        "connector_allowlist": {"active": bool(approved), "approved": approved},
        # The mode of each feature: the policies apply each control as its mode says.
        "features": features.modes(session),
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


def build(session: Session) -> Bundle:
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

    def __init__(self, db: Database) -> None:
        self._db = db
        self._lock = threading.Lock()
        self._generation = 0
        # Keyed by generation and UTC day: budgets start again when the day does.
        self._cached: tuple[tuple[int, str], Bundle] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._changed: asyncio.Condition | None = None
        self._wakeups: set[asyncio.Future[None]] = set()
        self.last_status: dict[str, Any] | None = None
        self.last_status_at: str | None = None

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
        if cached is not None and cached[0] == key:
            return cached[1]
        with self._db.session() as session:
            bundle = build(session)
        with self._lock:
            self._cached = (key, bundle)
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
                    await asyncio.wait_for(self._changed.wait(), timeout=remaining)
                except TimeoutError:
                    return None

    def record_status(self, status: dict[str, Any]) -> None:
        self.last_status = status
        self.last_status_at = ids.isoformat(ids.utcnow())


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

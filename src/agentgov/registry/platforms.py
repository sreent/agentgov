"""Agents that run on other platforms: Microsoft 365 Copilot and Copilot Studio.

These agents never call tools through AgentGov's gateway, so AgentGov governs
what their platform reports about them: the inventory, ownership, sharing and,
for Copilot Studio agents, the Power Platform connectors they use. Each one is
a registry agent (``discovered`` until someone adopts it, with source
``platform:<source>``) plus a :class:`PlatformAgent` record of the platform's
view, refreshed on every sync.

Two sources feed it:

* ``microsoft-365``: the Microsoft 365 agent catalog, synced from Microsoft
  Graph with an app-only token (``agentgov.platforms.microsoft``).
* ``copilot-studio``: the Power Platform inventory of Copilot Studio agents.
  Microsoft only lets a signed-in user query it, so an admin exports it
  (``pac resource-query`` or the Power Platform API) and imports the JSON.

Copilot Studio agents are checked against the connector allowlist and for
risky settings; each check is a finding that resolves itself once fixed.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections import defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import mark_changed
from agentgov.models import (
    DELETED,
    DISCOVERED,
    Agent,
    ApprovedConnector,
    PlatformAgent,
    PlatformSync,
)
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, findings
from agentgov.registry import instructions as instructions_svc
from agentgov.registry.errors import Conflict, NotFound, ValidationError

SOURCES = {"microsoft-365": "Microsoft 365", "copilot-studio": "Copilot Studio"}
FINDING_TYPES = {
    "platform.unapproved_connector",
    "platform.no_authentication",
    "platform.maker_credentials",
    "platform.shared_with_everyone",
}
SYSTEM_ACTOR = "system:platforms"
INVENTORY_TYPE = "microsoft.copilotstudio/agents"
_CONNECTOR_ID = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")


def connector_key(value: Any) -> str | None:
    """The connector's short ID (``shared_office365``), also given its full API path."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().rstrip("/").rsplit("/", 1)[-1]


def _entra_index(session: Session) -> dict[str, str]:
    """Registry agent ids by Entra agent ID, to match an agent both sources report."""
    index = {}
    for record in session.scalars(select(PlatformAgent)):
        entra_id = (record.data or {}).get("entra_agent_id")
        if entra_id:
            index[str(entra_id)] = record.agent_id
    return index


def upsert(
    session: Session,
    *,
    source: str,
    external_id: str,
    name: str,
    platform: str,
    details: dict[str, Any],
    external_ids: dict[str, str],
    entra_index: dict[str, str],
    description: str | None = None,
) -> tuple[Agent, bool]:
    """Record one agent as the platform reports it; returns ``(agent, created)``."""
    key = f"{source}:{external_id}"
    record = session.get(PlatformAgent, key)
    agent = session.get(Agent, record.agent_id) if record is not None else None
    entra_id = external_ids.get("entra_agent_id")
    if agent is None and entra_id and entra_id in entra_index:
        # A Copilot Studio agent published to Microsoft 365 is in both sources.
        agent = session.get(Agent, entra_index[entra_id])
    created = agent is None
    if agent is None:
        agent = Agent(
            id=ids.new_id(ids.AGENT),
            name=discovery.unique_name(session, discovery.slugify(name)),
            description=description or "",
            status=DISCOVERED,
            source=f"platform:{source}",
            platform=platform,
            sponsors=[],
            labels={},
            models=[],
            permissions=[],
            external_ids=external_ids,
            created_by=f"system:{source}",
        )
        session.add(agent)
        session.flush()
        ledger.append(
            session,
            type="agent.discovered",
            actor=f"system:{source}",
            agent=agent,
            details={"platform": SOURCES[source], "external_id": external_id, "name": name},
        )
        findings.raise_finding(
            session,
            type="agent.unmanaged",
            severity="medium",
            subject=agent.id,
            agent_id=agent.id,
            title=f"{SOURCES[source]} agent to review: {name}",
            description=f"This agent exists in {SOURCES[source]} but has no owner, sponsors or "
            "periodic review in AgentGov.",
            remediation="Adopt it to give it an owner, sponsors and attestation, or dismiss this "
            f"finding. To stop it from being used, block it in {SOURCES[source]}'s admin center.",
            details={"platform": SOURCES[source]},
        )
        mark_changed(session, "agents")
    else:
        agent.external_ids = {**(agent.external_ids or {}), **external_ids}
        agent.platform = agent.platform or platform
        if description and not agent.description:
            agent.description = description
    if entra_id:
        entra_index[entra_id] = agent.id
    if record is None:
        record = PlatformAgent(id=key, source=source, external_id=external_id, agent_id=agent.id)
        session.add(record)
    elif details.get("quarantined") is None and (record.data or {}).get("quarantined") is not None:
        # The inventory may not report quarantines: keep the one AgentGov made.
        details = {**details, "quarantined": record.data["quarantined"]}
    record.agent_id, record.name, record.data = agent.id, name, details
    record.synced_at = ids.utcnow()
    return agent, created


def _scope(value: Any) -> str | None:
    """Microsoft's availability enums ('allowedForAll', 'acquiredForSome', or 'all')."""
    if not isinstance(value, str):
        return None
    lowered = value.lower()
    for scope in ("all", "some", "none"):
        if lowered == scope or lowered.endswith(f"for{scope}"):
            return scope
    return lowered


def instructions_checked(session: Session) -> dict[str, Any]:
    """For each catalog package, the version (last change) whose instructions were read."""
    return {
        record.external_id: (record.data or {}).get("instructions_checked")
        for record in session.scalars(
            select(PlatformAgent).where(PlatformAgent.source == "microsoft-365")
        )
    }


def record_microsoft_365(
    session: Session,
    packages: list[dict[str, Any]],
    *,
    include_types: set[str],
    actor: str | None = None,
    agent_instructions: dict[str, str | None] | None = None,
    classify: bool = False,
) -> dict[str, int]:
    """Store the Microsoft 365 agent catalog (Graph ``copilotPackage`` objects).

    ``agent_instructions`` maps the packages whose details were read to their
    declarative agents' instructions (None when there are none)."""
    agent_instructions = agent_instructions or {}
    counts = {"created": 0, "updated": 0, "skipped": 0}
    index = _entra_index(session)
    seen: set[str] = set()
    for pkg in packages:
        package_id = pkg.get("id")
        if not isinstance(package_id, str) or not package_id:
            counts["skipped"] += 1
            continue
        seen.add(f"microsoft-365:{package_id}")
        if pkg.get("type") not in include_types:
            counts["skipped"] += 1
            continue
        details = {
            "publisher": pkg.get("publisher"),
            "type": pkg.get("type"),
            "built_with": pkg.get("platform"),
            "classification": pkg.get("governanceMetadata"),
            "hosts": pkg.get("supportedHosts") or [],
            "element_types": pkg.get("elementTypes") or [],
            "available_to": _scope(pkg.get("availableTo")),
            "deployed_to": _scope(pkg.get("deployedTo")),
            "blocked": bool(pkg.get("isBlocked")),
            "request": {"type": pkg.get("requestType"), "status": pkg.get("requestStatus")}
            if pkg.get("requestType")
            else None,
            "entra_agent_id": pkg.get("agentIdentityId"),
            "app_id": pkg.get("appId"),
            "version": pkg.get("version"),
            "created_at": pkg.get("createdDateTime"),
            "last_modified": pkg.get("lastModifiedDateTime"),
            "in_catalog": True,
        }
        previous = session.get(PlatformAgent, f"microsoft-365:{package_id}")
        details["instructions_checked"] = (
            pkg.get("lastModifiedDateTime")
            if package_id in agent_instructions
            else ((previous.data or {}).get("instructions_checked") if previous else None)
        )
        external_ids = {"m365_package_id": package_id}
        if pkg.get("agentIdentityId"):
            external_ids["entra_agent_id"] = str(pkg["agentIdentityId"])
        agent, created = upsert(
            session,
            source="microsoft-365",
            external_id=package_id,
            name=str(pkg.get("displayName") or package_id),
            platform="Microsoft 365 Copilot",
            details=details,
            external_ids=external_ids,
            entra_index=index,
            description=pkg.get("shortDescription"),
        )
        counts["created" if created else "updated"] += 1
        text = agent_instructions.get(package_id)
        if text:
            with contextlib.suppress(ValidationError):  # too long to keep
                instructions_svc.report(
                    session,
                    agent,
                    source="microsoft-365",
                    text=text,
                    actor="system:microsoft-365",
                    classify=classify,
                )
    # Agents that left the catalog stay in the registry, marked as gone.
    for record in session.scalars(
        select(PlatformAgent).where(PlatformAgent.source == "microsoft-365")
    ):
        if record.id not in seen and (record.data or {}).get("in_catalog", True):
            record.data = {**(record.data or {}), "in_catalog": False}
    set_sync(session, "microsoft-365", ok=True, counts=counts, actor=actor)
    return counts


def _rows(payload: Any) -> list[dict[str, Any]]:
    """Inventory rows from the Power Platform API, `pac resource-query` or Resource Graph."""
    rows = payload
    if isinstance(payload, dict):
        rows = payload.get("data", payload.get("value"))
    if not isinstance(rows, list):
        raise ValidationError(
            "expected the inventory query result: a JSON list of resources, or an object "
            'with a "data" list'
        )
    return [r for r in rows if isinstance(r, dict)]


def _connectors(props: dict[str, Any]) -> list[dict[str, Any]]:
    connectors = []
    for item in props.get("powerPlatformConnectors") or []:
        key = connector_key(item.get("connectorId")) if isinstance(item, dict) else None
        if key is None:
            continue
        operations = []
        for op in item.get("operations") or []:
            if not isinstance(op, dict):
                continue
            operations.append(
                {
                    "operation_id": op.get("operationId") or op.get("OperationId"),
                    "used_as": op.get("usedAs"),
                    "enabled": op.get("isEnabled", True) is not False,
                    "maker_connection": op.get("connectionProvider") == "Maker",
                    "requires_consent": op.get("requiresEndUserConsent"),
                }
            )
        connectors.append({"connector_id": key, "operations": operations})
    return connectors


def import_copilot_studio(session: Session, payload: Any, *, actor: str) -> dict[str, int]:
    """Store a Power Platform inventory export of Copilot Studio agents."""
    counts = {"created": 0, "updated": 0, "skipped": 0}
    index = _entra_index(session)
    for row in _rows(payload):
        if str(row.get("type", INVENTORY_TYPE)).lower() != INVENTORY_TYPE:
            counts["skipped"] += 1  # apps, flows and environments share the table
            continue
        props = row.get("properties", row)
        if isinstance(props, str):  # some Resource Graph clients return it as JSON text
            try:
                props = json.loads(props)
            except ValueError:
                props = None
        if not isinstance(props, dict):
            counts["skipped"] += 1
            continue
        agent_id = row.get("name") or props.get("botId") or props.get("name")
        if not agent_id:
            counts["skipped"] += 1
            continue
        agent_id = str(agent_id)
        viewers = props.get("sharedWithViewers") or {}
        editors = props.get("sharedWithEditors") or {}
        details = {
            "environment_id": props.get("environmentId"),
            "created_in": props.get("createdIn"),
            "harness": props.get("harness"),
            "owner_id": props.get("ownerId"),
            "created_by": props.get("createdBy"),
            "created_at": props.get("createdAt"),
            "authentication": props.get("authentication"),
            "channels": props.get("channels") or [],
            "shared_with_everyone": bool(viewers.get("entireTenant")),
            "viewers": {"users": viewers.get("userCount"), "groups": viewers.get("groupCount")},
            "editors": {"users": editors.get("userCount"), "groups": editors.get("groupCount")},
            "orchestration": props.get("orchestration"),
            "model": props.get("model"),
            "published_at": props.get("lastPublishedAt"),
            "quarantined": props.get("isQuarantined"),
            "web_search_knowledge": props.get(
                "IsWebSearchEnabledForKnowledge", props.get("isWebSearchEnabledForKnowledge")
            ),
            "entra_agent_id": props.get("entraAgentId"),
            "connectors": _connectors(props),
        }
        external_ids = {"copilot_studio_agent_id": agent_id}
        if props.get("environmentId"):
            external_ids["power_platform_environment_id"] = str(props["environmentId"])
        if props.get("entraAgentId"):
            external_ids["entra_agent_id"] = str(props["entraAgentId"])
        _, created = upsert(
            session,
            source="copilot-studio",
            external_id=agent_id,
            name=str(props.get("displayName") or agent_id),
            platform=str(props.get("createdIn") or "Copilot Studio"),
            details=details,
            external_ids=external_ids,
            entra_index=index,
        )
        counts["created" if created else "updated"] += 1
    session.flush()
    counts["findings"] = evaluate(session)
    set_sync(session, "copilot-studio", ok=True, counts=counts, actor=actor)
    return counts


# ------------------------------------------------------------------ allowlist


def approved_connectors(session: Session) -> list[ApprovedConnector]:
    return list(session.scalars(select(ApprovedConnector).order_by(ApprovedConnector.connector_id)))


def approve_connector(session: Session, connector_id: str, *, note: str, actor: str) -> None:
    key = connector_key(connector_id)
    if key is None or not _CONNECTOR_ID.match(key):
        raise ValidationError(f"{connector_id!r} is not a connector ID (e.g. shared_office365)")
    existing = session.get(ApprovedConnector, key)
    if existing is not None:
        existing.note = note or existing.note
        return
    session.add(ApprovedConnector(connector_id=key, note=note or "", added_by=actor))
    session.flush()
    ledger.append(
        session,
        type="connector.approved",
        actor=actor,
        resource=f"connector/{key}",
        reason=note or None,
    )
    evaluate(session)


def remove_approval(session: Session, connector_id: str, *, actor: str) -> None:
    key = connector_key(connector_id) or connector_id
    existing = session.get(ApprovedConnector, key)
    if existing is None:
        raise NotFound(f"connector {key!r} is not on the allowlist")
    session.delete(existing)
    session.flush()
    ledger.append(
        session,
        type="connector.approval_removed",
        actor=actor,
        severity="warning",
        resource=f"connector/{key}",
    )
    evaluate(session)


# ------------------------------------------------------------------- checks


def _records(session: Session, source: str) -> list[PlatformAgent]:
    """The source's agents that are still in the registry (not deleted)."""
    return list(
        session.scalars(
            select(PlatformAgent)
            .join(Agent, Agent.id == PlatformAgent.agent_id)
            .where(PlatformAgent.source == source, Agent.status != DELETED)
            .order_by(PlatformAgent.name)
        )
    )


def evaluate(session: Session) -> int:
    """Raise or resolve the Copilot Studio findings; returns how many are open."""
    approved = {c.connector_id for c in approved_connectors(session)}
    present: set[str] = set()

    def flag(type_: str, record: PlatformAgent, severity: str, title: str, **kw: Any) -> None:
        finding, _ = findings.raise_finding(
            session,
            type=type_,
            severity=severity,
            subject=record.agent_id,
            agent_id=record.agent_id,
            title=title,
            **kw,
        )
        present.add(finding.key)

    for record in _records(session, "copilot-studio"):
        data = record.data or {}
        connectors = data.get("connectors") or []
        used = sorted({c["connector_id"] for c in connectors})
        unapproved = [c for c in used if c not in approved]
        # With no allowlist yet, every connector would be "unapproved": stay quiet.
        if approved and unapproved:
            flag(
                "platform.unapproved_connector",
                record,
                "high",
                f"{record.name} uses connectors that are not approved",
                description="Not on the connector allowlist: " + ", ".join(unapproved) + ".",
                remediation="Approve them on the Platforms page if they are acceptable; otherwise "
                "remove them from the agent in Copilot Studio, or block the agent in the Power "
                "Platform admin center.",
                details={"connectors": unapproved},
            )
        if data.get("published_at") and str(data.get("authentication")).lower() == "none":
            flag(
                "platform.no_authentication",
                record,
                "high",
                f"{record.name} is published without user authentication",
                description="Anyone who can reach one of its channels can use it, and it cannot "
                "tell its users apart.",
                remediation="Set the agent's authentication to Microsoft Entra ID in Copilot "
                "Studio and publish it again.",
            )
        maker = [
            f"{c['connector_id']}/{op.get('operation_id')}"
            for c in connectors
            for op in c.get("operations") or []
            if op.get("maker_connection") and op.get("enabled", True)
        ]
        if maker:
            flag(
                "platform.maker_credentials",
                record,
                "medium",
                f"{record.name} uses its maker's own connections",
                description="These tools run with the maker's credentials for every user, so "
                "users reach data with the maker's access: " + ", ".join(maker) + ".",
                remediation="Switch the tools to user-provided connections in Copilot Studio, or "
                "confirm the shared access is intended and dismiss this finding.",
                details={"operations": maker},
            )
        if data.get("shared_with_everyone"):
            flag(
                "platform.shared_with_everyone",
                record,
                "medium",
                f"{record.name} is shared with the whole organisation",
                remediation="Share it with the groups that need it, or confirm that everyone "
                "should have it and dismiss this finding.",
            )
    findings.resolve_absent(session, types=FINDING_TYPES, present_keys=present, actor=SYSTEM_ACTOR)
    return len(present)


def refresh_risk(session: Session, settings: Settings) -> None:
    """Recompute platform agents' risk now rather than at the next posture scan."""
    for agent in session.scalars(
        select(Agent).where(Agent.source.like("platform:%"), Agent.status != DELETED)
    ).unique():
        agents_svc.refresh_risk(session, settings, agent)


# ------------------------------------------------- acting in Microsoft's platforms


def target(session: Session, agent: Agent) -> dict[str, str]:
    """Where to block ``agent`` in its own platform: the Copilot Studio agent (quarantine
    needs no Agent 365 licence) when there is one, otherwise the Microsoft 365 package."""
    records = {
        r.source: r
        for r in session.scalars(select(PlatformAgent).where(PlatformAgent.agent_id == agent.id))
    }
    studio = records.get("copilot-studio")
    if studio is not None:
        environment = (studio.data or {}).get("environment_id")
        if not environment:
            raise Conflict(
                f"the inventory gave no environment for {agent.name}: import it again first"
            )
        return {"source": "copilot-studio", "id": studio.external_id, "environment": environment}
    m365 = records.get("microsoft-365")
    if m365 is not None:
        return {"source": "microsoft-365", "id": m365.external_id}
    raise Conflict(f"{agent.name} is not an agent on Microsoft 365 or Copilot Studio")


def record_platform_block(
    session: Session, agent: Agent, where: dict[str, str], *, blocked: bool, actor: str
) -> None:
    """Remember that ``actor`` blocked (or unblocked) the agent in its platform."""
    record = session.get(PlatformAgent, f"{where['source']}:{where['id']}")
    if record is not None:
        flag = "quarantined" if where["source"] == "copilot-studio" else "blocked"
        record.data = {**(record.data or {}), flag: blocked}
    ledger.append(
        session,
        type="platform.agent_blocked" if blocked else "platform.agent_unblocked",
        actor=actor,
        agent=agent,
        severity="warning" if blocked else "info",
        resource=f"{where['source']}/{where['id']}",
        details={"platform": SOURCES[where["source"]], **where},
    )


# -------------------------------------------------------------------- views


def set_sync(
    session: Session,
    source: str,
    *,
    ok: bool,
    counts: dict[str, Any],
    message: str = "",
    actor: str | None = None,
) -> None:
    """Remember how the latest sync or import went; one a person started is in the ledger."""
    sync = session.get(PlatformSync, source) or PlatformSync(source=source)
    sync.synced_at, sync.ok, sync.message, sync.counts = ids.utcnow(), ok, message, counts
    session.add(sync)
    if actor:
        ledger.append(
            session,
            type="platform.synced" if source == "microsoft-365" else "platform.imported",
            actor=actor,
            severity="info" if ok else "warning",
            resource=f"platform/{source}",
            reason=message or None,
            details=counts,
        )


def overview(session: Session, *, m365_configured: bool) -> dict[str, Any]:
    agents = dict(
        session.execute(
            select(PlatformAgent.source, func.count())
            .join(Agent, Agent.id == PlatformAgent.agent_id)
            .where(Agent.status != DELETED)
            .group_by(PlatformAgent.source)
        ).all()
    )
    sources = []
    for source, name in SOURCES.items():
        sync = session.get(PlatformSync, source)
        sources.append(
            {
                "source": source,
                "name": name,
                "mode": "sync" if source == "microsoft-365" else "import",
                "configured": m365_configured if source == "microsoft-365" else True,
                "agents": agents.get(source, 0),
                "last_sync": {
                    "at": ids.isoformat(sync.synced_at),
                    "ok": sync.ok,
                    "message": sync.message,
                    "counts": sync.counts or {},
                }
                if sync
                else None,
            }
        )
    return {"sources": sources, "allowlist_active": bool(approved_connectors(session))}


def connector_usage(session: Session) -> dict[str, Any]:
    """Every connector Copilot Studio agents use, approved or not, and who uses it."""
    approved = {c.connector_id: c for c in approved_connectors(session)}

    def unused() -> dict[str, Any]:
        return {"agents": [], "operations": set(), "maker_connections": 0}

    usage: dict[str, dict[str, Any]] = defaultdict(unused)
    for record in _records(session, "copilot-studio"):
        for connector in (record.data or {}).get("connectors") or []:
            entry = usage[connector["connector_id"]]
            entry["agents"].append({"id": record.agent_id, "name": record.name})
            for op in connector.get("operations") or []:
                entry["operations"].add(op.get("operation_id"))
                entry["maker_connections"] += 1 if op.get("maker_connection") else 0
    for connector_id in approved:  # approved, but no agent uses it yet
        usage.setdefault(connector_id, unused())
    rows = []
    for connector_id, entry in usage.items():
        allowed = approved.get(connector_id)
        rows.append(
            {
                "connector_id": connector_id,
                "approved": allowed is not None,
                "note": allowed.note if allowed else None,
                "approved_by": allowed.added_by if allowed else None,
                "approved_at": ids.isoformat(allowed.created_at) if allowed else None,
                "agents": entry["agents"],
                "operations": sorted(op for op in entry["operations"] if op),
                "maker_connections": entry["maker_connections"],
            }
        )
    # Unapproved first, then the most used.
    rows.sort(key=lambda r: (r["approved"], -len(r["agents"]), r["connector_id"]))
    return {"allowlist_active": bool(approved), "connectors": rows}


def for_agent(session: Session, agent_id: str) -> list[dict[str, Any]]:
    """What each platform reports about one agent, with connectors' allowlist status."""
    approved = {c.connector_id for c in approved_connectors(session)}
    views = []
    for record in session.scalars(
        select(PlatformAgent).where(PlatformAgent.agent_id == agent_id).order_by(PlatformAgent.id)
    ):
        data = dict(record.data or {})
        if "connectors" in data:
            data["connectors"] = [
                {**c, "approved": c["connector_id"] in approved} for c in data["connectors"]
            ]
        views.append(
            {
                **data,
                "source": record.source,
                "source_name": SOURCES.get(record.source, record.source),
                "external_id": record.external_id,
                "display_name": record.name,
                "synced_at": ids.isoformat(record.synced_at),
                "allowlist_active": bool(approved),
            }
        )
    return views

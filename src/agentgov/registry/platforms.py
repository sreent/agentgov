"""Agents that run on other platforms: Microsoft 365 Copilot and Copilot Studio.

These agents never call tools through AgentGov's gateway, so AgentGov governs
what their platform reports about them: the inventory, ownership, sharing and,
for Copilot Studio agents, the Power Platform connectors they use. Each one is
a registry agent (``discovered`` until someone adopts it, with source
``platform:<source>``) plus a :class:`PlatformAgent` record of the platform's
view, refreshed on every sync.

Three sources feed it:

* ``microsoft-365``: the Microsoft 365 agent catalog, synced from Microsoft
  Graph with an app-only token (``agentgov.platforms.microsoft``).
* ``copilot-studio``: the Power Platform inventory of Copilot Studio agents.
  Microsoft only lets a signed-in user query it, so it is synced as the
  signed-in admin, or an admin exports it and imports the JSON.
* ``entra-agent-id``: the tenant's Microsoft Entra agent identities, linked to
  the agents the other sources report (by Entra agent ID); identities no other
  source reports are discovered agents of their own.

Copilot Studio agents are checked against the connector allowlist and for
risky settings; each check is a finding that resolves itself once fixed.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import mark_changed
from agentgov.db.models import Finding
from agentgov.models import (
    BLOCKED,
    DELETED,
    DISCOVERED,
    Agent,
    ApprovedConnector,
    PlatformAgent,
    PlatformSync,
)
from agentgov.platforms.base import Inventory
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, features, findings
from agentgov.registry import instructions as instructions_svc
from agentgov.registry.errors import Conflict, NotFound, ValidationError

SOURCES = {
    "microsoft-365": "Microsoft 365",
    "copilot-studio": "Copilot Studio",
    "entra-agent-id": "Microsoft Entra Agent ID",
    "aws": "AWS",
    "google-cloud": "Google Cloud",
    "salesforce": "Salesforce",
    "databricks": "Databricks",
    "microsoft-foundry": "Microsoft Foundry",
}
# The platforms read by a connector of AgentGov's own (agentgov.platforms.base): each
# reports its agents and their risky settings the same way.
INVENTORY_SOURCES = ("aws", "google-cloud", "salesforce", "databricks", "microsoft-foundry")
# What an agent known only by its Entra identity is, until a source reports what it is.
ENTRA_PLATFORM = "Microsoft Entra Agent ID"
# The agent identity blueprint Copilot Studio creates its agents' identities from.
COPILOT_STUDIO_BLUEPRINT = "25664c89-cea5-4ab6-b924-a54fd8a19ae0"
FINDING_TYPES = {
    "platform.unapproved_connector",
    "platform.no_authentication",
    "platform.maker_credentials",
    "platform.shared_with_everyone",
}
# What the connectors of INVENTORY_SOURCES may find, on their own agents.
INVENTORY_FINDINGS = {
    "platform.no_authentication",
    "platform.weak_authentication",
    "platform.shared_with_everyone",
    "platform.maker_credentials",
    "platform.no_guardrail",
    "platform.plain_secret",
    "platform.broad_identity",
    "platform.risky_tool",
}
# The findings each sync's data raises: while its latest sync failed, they are
# unverified (docs/issues.md), and verified again when one succeeds.
SYNCED_FINDINGS = {
    "copilot-studio": FINDING_TYPES,
    "entra-agent-id": {"entra.disabled_by_microsoft"},
    "defender": {"defender.alert"},
    "entra-access-packages": {"entra.access_expiring", "entra.access_failed"},
}
SYSTEM_ACTOR = "system:platforms"
SYNC_NAMES = {
    **SOURCES,
    "defender": "Microsoft Defender",
    "entra-access-packages": "Microsoft Entra access packages",
}
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
        # Not a finding of its own: one per platform says how many are left to review
        # (review_summary), so that an import of 300 agents raises one issue, not 300.
        mark_changed(session, "agents")
    else:
        agent.external_ids = {**(agent.external_ids or {}), **external_ids}
        if not agent.platform or agent.platform == ENTRA_PLATFORM:
            agent.platform = platform
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


def import_copilot_studio(
    session: Session, payload: Any, *, actor: str, complete: bool = False
) -> dict[str, int]:
    """Store a Power Platform inventory export of Copilot Studio agents. ``complete``: it is
    the whole inventory (as a sync reads it), so the agents missing from it are gone from
    Copilot Studio: they stay in the registry, marked gone, and their findings close. An
    export may cover only some environments, so without it they are left as they were."""
    counts = {"created": 0, "updated": 0, "skipped": 0}
    index = _entra_index(session)
    seen: set[str] = set()
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
        seen.add(f"copilot-studio:{agent_id}")
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
            "entra_app_id": props.get("entraAppId"),
            "schema_name": props.get("schemaName"),
            "connectors": _connectors(props),
            "in_inventory": True,
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
    # An export with no agents at all is more likely the wrong file than an empty tenant.
    if complete and seen:
        gone = 0
        for record in session.scalars(
            select(PlatformAgent).where(PlatformAgent.source == "copilot-studio")
        ):
            if record.id not in seen and (record.data or {}).get("in_inventory", True):
                record.data = {**(record.data or {}), "in_inventory": False}
                gone += 1
        if gone:
            counts["gone"] = gone
    session.flush()
    counts["findings"] = evaluate(session)
    set_sync(session, "copilot-studio", ok=True, counts=counts, actor=actor)
    return counts


def gone_agents(session: Session) -> set[str]:
    """The agents that no platform reporting them reports any more."""
    there: set[str] = set()
    gone: set[str] = set()
    for agent_id, data in session.execute(select(PlatformAgent.agent_id, PlatformAgent.data)):
        data = data or {}
        missing = data.get("in_inventory", True) is False or data.get("in_catalog", True) is False
        (gone if missing else there).add(agent_id)
    return gone - there


# ------------------------------------------------------------------ allowlist


def record_agent_identities(
    session: Session, identities: list[dict[str, Any]], *, actor: str | None = None
) -> dict[str, int]:
    """Store the tenant's Entra agent identities (Graph ``agentIdentity`` objects)."""
    counts = {"created": 0, "updated": 0, "skipped": 0, "linked": 0}
    index = _entra_index(session)
    seen: set[str] = set()
    present: set[str] = set()
    for identity in identities:
        identity_id = identity.get("id")
        if not isinstance(identity_id, str) or not identity_id:
            counts["skipped"] += 1
            continue
        key = f"entra-agent-id:{identity_id}"
        seen.add(key)
        blueprint = identity.get("agentIdentityBlueprintId")
        from_studio = str(blueprint).lower() == COPILOT_STUDIO_BLUEPRINT
        disabled_by_microsoft = identity.get("disabledByMicrosoftStatus") not in (
            None,
            "",
            "NotDisabled",
        )
        details = {
            # An agent identity's object ID and app ID are the same.
            "entra_agent_id": identity_id,
            "enabled": identity.get("accountEnabled"),
            "blueprint_id": blueprint,
            "blueprint": "Copilot Studio" if from_studio else None,
            "created_by_app_id": identity.get("createdByAppId"),
            "created_at": identity.get("createdDateTime"),
            "disabled_by_microsoft": identity.get("disabledByMicrosoftStatus")
            if disabled_by_microsoft
            else None,
            "tags": identity.get("tags") or [],
            "in_directory": True,
        }
        agent, created = upsert(
            session,
            source="entra-agent-id",
            external_id=identity_id,
            name=str(identity.get("displayName") or identity_id),
            platform="Copilot Studio" if from_studio else ENTRA_PLATFORM,
            details=details,
            external_ids={"entra_agent_id": identity_id},
            entra_index=index,
        )
        counts["created" if created else "updated"] += 1
        if disabled_by_microsoft:
            finding, _ = findings.raise_finding(
                session,
                type="entra.disabled_by_microsoft",
                severity="high",
                subject=agent.id,
                agent_id=agent.id,
                category=findings.THREAT,
                title=f"Microsoft disabled {agent.name}'s Entra agent identity",
                description="Microsoft Entra ID reports the identity as "
                f"{identity.get('disabledByMicrosoftStatus')}, so the agent cannot sign in.",
                remediation="Find out from Microsoft why the agent was disabled, and block it "
                "here until that is resolved.",
            )
            present.add(finding.key)
    # Gone from two syncs in a row: one odd page from Microsoft Graph doesn't close it.
    findings.resolve_absent(
        session,
        types={"entra.disabled_by_microsoft"},
        present_keys=present,
        actor=SYSTEM_ACTOR,
        clean=2,
    )
    # Identities deleted from Entra stay in the registry, marked as gone.
    others = set(
        session.scalars(
            select(PlatformAgent.agent_id).where(PlatformAgent.source != "entra-agent-id")
        )
    )
    for record in session.scalars(
        select(PlatformAgent).where(PlatformAgent.source == "entra-agent-id")
    ):
        if record.id not in seen and (record.data or {}).get("in_directory", True):
            record.data = {**(record.data or {}), "in_directory": False}
        # Linked: the identity of an agent that another source reports too.
        counts["linked"] += 1 if record.id in seen and record.agent_id in others else 0
    set_sync(session, "entra-agent-id", ok=True, counts=counts, actor=actor)
    return counts


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
    mark_changed(session, "connectors")  # OPA enforces the allowlist through threat detection
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
    mark_changed(session, "connectors")
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


def subjects(session: Session, source: str) -> set[str]:
    """The agents a source reports, deleted or not: its findings are about them, and other
    sources raise findings of the same types about theirs."""
    return set(
        session.scalars(select(PlatformAgent.agent_id).where(PlatformAgent.source == source))
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
        if data.get("in_inventory", True) is False:
            continue  # gone from Copilot Studio: its findings close
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
                "confirm the shared access is intended and ask an approver to accept its risk.",
                details={"operations": maker},
            )
        if data.get("shared_with_everyone"):
            flag(
                "platform.shared_with_everyone",
                record,
                "medium",
                f"{record.name} is shared with the whole organisation",
                remediation="Share it with the groups that need it, or confirm that everyone "
                "should have it and ask an approver to accept its risk.",
            )
    findings.resolve_absent(
        session,
        types=FINDING_TYPES,
        present_keys=present,
        actor=SYSTEM_ACTOR,
        subjects=subjects(session, "copilot-studio"),
    )
    sync = session.get(PlatformSync, "copilot-studio")
    if sync is not None and not sync.ok:
        # Raised again from what an earlier sync stored, which may no longer hold: they stay
        # unverified until a sync succeeds.
        findings.mark_unverified(
            session,
            types=FINDING_TYPES,
            subjects=subjects(session, "copilot-studio"),
            reason=failed_sync("copilot-studio", sync.message),
        )
    return len(present)


@contextlib.contextmanager
def first_sync(session: Session, source: str) -> Iterator[None]:
    """Around a sync of ``source``: if it is its first, what it finds about its agents
    (theirs, and AgentGov's own, such as unmanaged or high risk) was there before AgentGov
    looked, so it is marked as such (findings.BASELINE) and reaches people in AgentGov
    rather than in their inboxes (AGENTGOV_ISSUES_QUIET_FIRST_SYNC)."""
    last = session.get(PlatformSync, source)
    # None read anything before (a sync that failed reads nothing).
    first = last is None or (
        not last.ok
        and session.scalar(select(PlatformAgent.id).where(PlatformAgent.source == source).limit(1))
        is None
    )
    since = ids.utcnow()
    yield
    if not first:
        return
    theirs = set(
        session.scalars(select(PlatformAgent.agent_id).where(PlatformAgent.source == source))
    )
    found = Finding.objects.filter(status="open", level__isnull=True, first_seen__gte=since)
    for finding in found:
        if finding.agent_id in theirs:
            finding.details = {**(finding.details or {}), findings.BASELINE: True}
            finding.save()


def failed_sync(source: str, message: str | None) -> str:
    """Why the findings a failed sync checks are unverified."""
    return f"the last {SYNC_NAMES.get(source, source)} sync failed" + (
        f": {message}" if message else ""
    )


def record_inventory(
    session: Session,
    source: str,
    inventory: Inventory,
    *,
    actor: str | None = None,
    classify: bool = False,
    clean: int = 2,
) -> dict[str, int]:
    """Store what a connector read from ``source``: each agent, with its risky settings
    as findings. Agents gone from a part read in full are marked gone; a part that
    couldn't be read leaves its agents and their findings as they were, unverified.
    ``clean``: syncs in a row that must find a finding gone before it resolves."""
    counts = {"created": 0, "updated": 0, "skipped": 0}
    seen: set[str] = set()
    present: set[str] = set()
    partial: dict[str, str] = {}  # agents read in part: their findings can't be resolved
    # An agent with an Entra agent identity (Foundry's) is the agent Entra Agent ID reports.
    index = _entra_index(session)
    for item in inventory.found:
        key = f"{source}:{item.external_id}"
        if key in seen:
            counts["skipped"] += 1
            continue
        seen.add(key)
        details = {**item.details, "kind": item.kind, "part": item.part, "in_inventory": True}
        if item.maker and "@" in item.maker:  # a person, not a service principal
            details["maker"] = item.maker
        if item.stopped is not None:
            details["stopped"] = item.stopped
        agent, created = upsert(
            session,
            source=source,
            external_id=item.external_id,
            name=item.name,
            platform=item.kind,
            details=details,
            external_ids=item.external_ids,
            entra_index=index,
            description=item.description,
        )
        counts["created" if created else "updated"] += 1
        if not item.complete:
            partial[agent.id] = f"the last {SOURCES[source]} sync read it in part: " + (
                "; ".join(item.missing) or "some of it couldn't be read"
            )
        if agent.status == DELETED:
            continue
        if item.instructions and item.instructions.strip():
            with contextlib.suppress(ValidationError):  # too long to keep
                instructions_svc.report(
                    session,
                    agent,
                    source=source,
                    text=item.instructions,
                    actor=f"system:{source}",
                    classify=classify,
                )
        for risk in item.risks:
            finding, _ = findings.raise_finding(
                session,
                type=risk.type,
                severity=risk.severity,
                subject=agent.id,
                agent_id=agent.id,
                title=risk.title,
                description=risk.description,
                remediation=risk.remediation,
                details={"platform": SOURCES[source], **risk.details},
            )
            present.add(finding.key)
    # Agents gone from what was read stay in the registry, marked as gone.
    unread: dict[str, str] = dict(partial)  # agent: why its findings can't be checked
    name = SOURCES[source]
    for record in session.scalars(select(PlatformAgent).where(PlatformAgent.source == source)):
        part = (record.data or {}).get("part")
        if part in inventory.failed:
            unread[record.agent_id] = (
                f"the last {name} sync couldn't read {part}: {inventory.failed[part]}"
            )
        elif part not in inventory.read and record.id not in seen:
            unread.setdefault(
                record.agent_id, f"the last {name} sync didn't read {part or 'the part it is in'}"
            )
        elif record.id not in seen and (record.data or {}).get("in_inventory", True):
            record.data = {**(record.data or {}), "in_inventory": False}
    checked = subjects(session, source) - set(unread)
    findings.resolve_absent(
        session,
        types=INVENTORY_FINDINGS,
        present_keys=present,
        actor=SYSTEM_ACTOR,
        subjects=checked,
        clean=clean,  # by default, one odd answer from the platform doesn't close and reopen them
    )
    by_reason: dict[str, set[str]] = {}
    for agent_id, why in unread.items():
        by_reason.setdefault(why, set()).add(agent_id)
    for why, agent_ids in by_reason.items():
        findings.mark_unverified(
            session, types=INVENTORY_FINDINGS, subjects=agent_ids, present_keys=present, reason=why
        )
    counts["findings"] = len(present)
    if inventory.failed:
        counts["failed"] = len(inventory.failed)
    message = inventory.failures()
    set_sync(session, source, ok=not inventory.failed, counts=counts, message=message, actor=actor)
    return counts


def sync_failed(session: Session, source: str, message: str, *, actor: str | None) -> None:
    """A connector couldn't read its platform at all: its agents' findings stay open,
    unverified, until a sync succeeds."""
    set_sync(session, source, ok=False, counts={}, message=message, actor=actor)
    findings.mark_unverified(
        session,
        types=INVENTORY_FINDINGS,
        subjects=subjects(session, source),
        reason=failed_sync(source, message),
    )


def refresh_risk(session: Session, settings: Settings) -> None:
    """After a sync: recompute platform agents' risk now rather than at the next posture
    scan, how many of them are left to review, and which of those blocked in AgentGov their
    platform still runs."""
    for agent in session.scalars(
        select(Agent)
        .where(Agent.source.like("platform:%"), Agent.status != DELETED)
        .order_by(Agent.id)  # in the posture scan's order (registry/posture)
    ).unique():
        agents_svc.refresh_risk(session, settings, agent)
    review_summary(session)
    check_stops(session, settings)


TO_REVIEW = "platform.agents_to_review"
# Agents named in the summary's description, at most.
NAMED = 5


def review_summary(session: Session) -> None:
    """One issue per platform with agents found there and not reviewed yet: how many, and
    a few of their names. It goes to the catch-all team, and resolves once none is left.
    (Agents found on platforms each had a finding of their own before: those resolve.)"""
    left: dict[str, list[str]] = defaultdict(list)
    platform_agents = []
    # Gone from their platforms: there is nothing left to adopt.
    gone = gone_agents(session)
    for agent in session.scalars(
        select(Agent).where(Agent.source.like("platform:%"), Agent.status != DELETED)
    ).unique():
        platform_agents.append(agent.id)
        source = (agent.source or "").removeprefix("platform:")
        if agent.status == DISCOVERED and source in SOURCES and agent.id not in gone:
            left[source].append(agent.name)
    for agent_id in platform_agents:
        findings.resolve_key(session, f"agent.unmanaged:{agent_id}", actor="system:platforms")
    for source, label in SOURCES.items():
        names = sorted(left.get(source, []), key=str.lower)
        key = f"{TO_REVIEW}:platform:{source}"
        if not names:
            findings.resolve_key(session, key, actor="system:platforms")
            continue
        shown = ", ".join(names[:NAMED])
        if len(names) > NAMED:
            shown += f" and {len(names) - NAMED} more"
        findings.raise_finding(
            session,
            type=TO_REVIEW,
            severity="medium",
            subject=f"platform:{source}",
            title=f"{len(names)} {label} agent{'' if len(names) == 1 else 's'} to review",
            description=f"Found in {label}, with no owner, sponsors or review in AgentGov yet: "
            f"{shown}.",
            remediation="Adopt the agents you keep, giving each an owner and sponsors: on the "
            "Agents page, those not reviewed yet, Adopt them at once, each with its maker as "
            f"owner where AgentGov knows them. Block or delete the others in {label}.",
            details={"platform": label, "count": len(names)},
        )


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
    session: Session,
    settings: Settings,
    agent: Agent,
    where: dict[str, str],
    *,
    blocked: bool,
    actor: str,
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
    check_stop(session, settings, agent, actor=actor)


# ----------------------------------- agents blocked in AgentGov that their platform still runs

STILL_RUNNING = "platform.still_running"
# Which platform runs an agent that several report: Copilot Studio runs the agents it
# publishes to Microsoft 365, and an Entra agent identity is how an agent signs in.
RUNS_ON = ("copilot-studio", "microsoft-365", *INVENTORY_SOURCES, "entra-agent-id")
# For each platform: what it reports an agent it stopped as (None: only that it is gone),
# and who can stop one there, and how.
STOPPING: dict[str, tuple[str | None, str]] = {
    "copilot-studio": (
        "quarantined",
        "A Power Platform administrator (or an AI or Global administrator) can quarantine it, "
        "in the Power Platform admin center (Manage > Inventory) or through the Power "
        "Platform API: it then works in no channel, though its makers can still open it. Its "
        "owner can also unpublish or delete it in Copilot Studio.",
    ),
    "microsoft-365": (
        "blocked",
        "An AI administrator or Global administrator can block it for the organisation in the "
        "Microsoft 365 admin center (Agents).",
    ),
    "entra-agent-id": (
        "disabled",
        "An administrator of its agent identity can disable it in the Microsoft Entra admin "
        "center, so that it can't sign in.",
    ),
    "aws": (
        None,
        "Someone with rights over it in its AWS account can delete it there, or take away the "
        "permissions that let people and applications call it.",
    ),
    "google-cloud": (
        None,
        "Someone with rights over it in its Google Cloud project can delete it there, or take "
        "away the roles that let people and applications call it.",
    ),
    "salesforce": (
        "deactivated",
        "A Salesforce administrator can deactivate it in Agentforce Builder.",
    ),
    "databricks": (
        "stopped",
        "Someone who can manage it in its Databricks workspace can stop it, if it is an app, "
        "or delete it.",
    ),
    "microsoft-foundry": (
        "disabled",
        "Someone with rights over its Foundry project can disable it, so that its endpoint "
        "takes no calls, or delete it.",
    ),
}
# Copilot Studio asks AgentGov before each tool call while this is enforced.
THREAT_DETECTION = "copilot-studio-threat-detection"
# What AgentGov does itself, as an administrator signed in through Microsoft Entra ID.
_ADMIN_ACTION = {"copilot-studio": "Quarantine", "microsoft-365": "Block in Microsoft 365"}


def _gone(record: PlatformAgent) -> bool:
    data = record.data or {}
    return any(data.get(f, True) is False for f in ("in_inventory", "in_catalog", "in_directory"))


def _stopped(record: PlatformAgent) -> bool:
    """Whether its platform reports the agent stopped there."""
    data = record.data or {}
    if record.source == "copilot-studio":
        return data.get("quarantined") is True
    if record.source == "microsoft-365":
        return data.get("blocked") is True
    if record.source == "entra-agent-id":
        return data.get("enabled") is False or bool(data.get("disabled_by_microsoft"))
    return data.get("stopped") is True


def _by_source(session: Session, agent: Agent) -> dict[str, PlatformAgent]:
    query = select(PlatformAgent).where(PlatformAgent.agent_id == agent.id)
    return {r.source: r for r in session.scalars(query)}


def runs_on(session: Session, agent: Agent) -> PlatformAgent | None:
    """The record of the platform that still runs ``agent``: None once the platform that
    runs it reports it stopped, or none that reported it has it any more."""
    records = _by_source(session, agent)
    for source in RUNS_ON:
        record = records.get(source)
        if record is not None and not _gone(record):
            return None if _stopped(record) else record
    return None


def still_runs_in(session: Session, agent: Agent) -> str | None:
    """The platform that still runs ``agent`` while it is blocked in AgentGov."""
    record = runs_on(session, agent) if agent.status == BLOCKED else None
    return SOURCES[record.source] if record is not None else None


def check_stop(
    session: Session, settings: Settings, agent: Agent, *, actor: str = SYSTEM_ACTOR
) -> None:
    """Blocking an agent in AgentGov doesn't stop it in its platform, and AgentGov can stop it
    there only as an administrator who signs in (Copilot Studio, Microsoft 365), if at all.
    So while the platform still runs it, an issue asks its people to stop it there, saying
    who can and how. It closes once a sync shows the platform stopped it or no longer has it,
    or once the agent isn't blocked in AgentGov any more."""
    key = f"{STILL_RUNNING}:{agent.id}"
    record = runs_on(session, agent) if agent.status == BLOCKED else None
    if record is None:
        # Over, whatever became of it (dismissed, or its risk accepted): blocked again, it
        # is raised afresh.
        finding = findings.by_key(session, key)
        if finding is not None and finding.status != "resolved":
            finding = findings.set_status(session, finding.id, "resolved", actor)
            finding.accepted_until = None
            finding.save()
        return
    name = SOURCES[record.source]
    done, how = STOPPING[record.source]
    data = record.data or {}
    # Its IDs there, for whoever stops it: the email or ticket they read has no more.
    where = f"{name} knows it as {record.external_id}" + (
        f", in environment {data['environment_id']}" if data.get("environment_id") else ""
    )
    description = f"Blocking it in AgentGov doesn't stop it in {name}. {where}."
    if (
        record.source == "copilot-studio"
        and features.mode_for(session, agent, THREAT_DETECTION) == features.ENFORCE
    ):
        description += (
            " Copilot Studio asks AgentGov before each of its tool calls, so it makes none, "
            "but it still answers people."
        )
    others = _by_source(session, agent)
    for other in others.values():
        if other.source != record.source and not _gone(other) and _stopped(other):
            description += (
                f" {SOURCES[other.source]} has it {STOPPING[other.source][0]}, but {name} "
                "still runs it."
            )
    remediation = how
    if record.source == "copilot-studio" and "microsoft-365" in others:
        remediation += (
            " Blocking it in the Microsoft 365 admin center stops it in Microsoft 365 Copilot "
            "and Teams only."
        )
    if record.source in _ADMIN_ACTION and settings.microsoft_admin_actions:
        remediation += (
            f" Such an administrator can also do it from its page in AgentGov "
            f"({_ADMIN_ACTION[record.source]}), signed in through Microsoft Entra ID."
        )
    told = f"reports it {done} or no longer has it" if done else "no longer has it"
    remediation += (
        f" AgentGov closes this issue once {name} {told}, at its next sync"
        + (" or import of its inventory" if record.source == "copilot-studio" else "")
        + f". If you stop it in a way {name} doesn't report, dismiss this issue saying how."
    )
    findings.raise_finding(
        session,
        type=STILL_RUNNING,
        severity="high",
        subject=agent.id,
        agent_id=agent.id,
        title=f"{agent.name} is blocked in AgentGov but still runs in {name}",
        description=description,
        remediation=remediation,
        details={
            "platform": name,
            "source": record.source,
            "external_id": record.external_id,
            **({"environment_id": data["environment_id"]} if data.get("environment_id") else {}),
            "synced_at": ids.isoformat(record.synced_at),
        },
    )


def check_stops(session: Session, settings: Settings) -> None:
    """:func:`check_stop` for the agents blocked in AgentGov that platforms report, and for
    those with the issue open."""
    blocked = select(PlatformAgent.agent_id).join(Agent, Agent.id == PlatformAgent.agent_id)
    agent_ids = set(session.scalars(blocked.where(Agent.status == BLOCKED)))
    agent_ids |= set(
        Finding.objects.filter(type=STILL_RUNNING, status="open").values_list("agent_id", flat=True)
    )
    for agent_id in sorted(a for a in agent_ids if a):
        agent = session.get(Agent, agent_id)
        if agent is not None:
            check_stop(session, settings, agent)


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
    """Remember how the latest sync or import went; one a person started is in the ledger.
    The findings a failed sync would have checked are unverified until one succeeds."""
    sync = session.get(PlatformSync, source) or PlatformSync(source=source)
    sync.synced_at, sync.ok, sync.message, sync.counts = ids.utcnow(), ok, message, counts
    session.add(sync)
    if source in SYNCED_FINDINGS:
        findings.mark_unverified(
            session,
            types=SYNCED_FINDINGS[source],
            verified=ok,
            # Defender's and Entra's findings come from those sources alone.
            subjects=subjects(session, source) if source == "copilot-studio" else None,
            reason=failed_sync(source, message),
        )
    if actor:
        ledger.append(
            session,
            type="platform.imported" if source == "copilot-studio" else "platform.synced",
            actor=actor,
            severity="info" if ok else "warning",
            resource=f"platform/{source}",
            reason=message or None,
            details=counts,
        )


def overview(
    session: Session, *, m365_configured: bool, connected: set[str] | None = None
) -> dict[str, Any]:
    """Each source, how many agents it reports and how its last sync went. ``connected``:
    the INVENTORY_SOURCES whose connector is configured."""
    connected = connected or set()
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
        extra: dict[str, Any] = {}
        if source in INVENTORY_SOURCES:
            configured = source in connected
            feature = features.BY_KEY.get(source)
            if feature is None:
                continue  # no connector for it yet
            extra = {
                "turned_on": feature is not None and features.is_on(session, source),
                "needs": feature.needs if feature else None,
            }
        else:
            configured = True if source == "copilot-studio" else m365_configured
        sources.append(
            {
                **extra,
                "source": source,
                "name": name,
                "mode": "import" if source == "copilot-studio" else "sync",
                "configured": configured,
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

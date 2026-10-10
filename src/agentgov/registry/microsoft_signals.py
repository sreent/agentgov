"""What Microsoft's services report about agents' use and the threats to them.

* Microsoft Purview's audit log: ``CopilotInteraction`` records (someone used an
  agent: who, when, through which app, and whether Microsoft detected a
  jailbreak or a cross-prompt injection attempt), and Copilot Studio's maker
  events (an agent created, published, shared, deleted).
* Microsoft Defender's alerts that concern agents (``aiAgentEvidence``).

Microsoft identifies an agent in several ways (the Copilot Studio bot ID, its
Entra agent ID, an app registration, a Microsoft 365 package ID, or strings
such as ``CopilotStudio.Declarative.<guid>``), so records are matched against
every identifier the platform sources reported.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import DELETED, Agent, PlatformAgent
from agentgov.registry import agents as agents_svc
from agentgov.registry import discovery, findings, risk

GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
ACTOR = "system:microsoft"
RECENT_USERS = 10

# Copilot Studio's maker events in the audit log, and the ledger entries they become.
MAKER_EVENTS = {
    "BotCreate": "platform.agent_created",
    "BotDelete": "platform.agent_deleted",
    "BotUpdateOperation-BotPublish": "platform.agent_published",
    "BotUpdateOperation-BotShare": "platform.agent_shared",
    "BotUpdateOperation-BotAuthUpdate": "platform.agent_authentication_changed",
}
DEFENDER_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def agent_index(session: Session) -> dict[str, str]:
    """Registry agent ids by every identifier the platform sources reported (lowercase)."""
    index: dict[str, str] = {}
    for record in session.scalars(
        select(PlatformAgent)
        .join(Agent, Agent.id == PlatformAgent.agent_id)
        .where(Agent.status != DELETED)
    ):
        data = record.data or {}
        names = [record.external_id] + [
            data.get(k) for k in ("entra_agent_id", "entra_app_id", "app_id", "schema_name")
        ]
        for name in names:
            if name:
                index.setdefault(str(name).lower(), record.agent_id)
    return index


def match_agent(index: dict[str, str], *values: Any) -> str | None:
    """The agent one of ``values`` names: whole, by its last dotted part (as in
    ``CopilotStudio.Declarative.<id>``), or by a GUID inside it."""
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        text = value.lower()
        for candidate in (text, text.rsplit(".", 1)[-1], *GUID.findall(text)):
            if candidate in index:
                return index[candidate]
    return None


def _when(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=ids.utcnow().tzinfo)
        except ValueError:
            pass
    return ids.utcnow()


def _audit_data(record: dict[str, Any]) -> dict[str, Any]:
    """The workload's own fields: auditData, with Copilot's CopilotEventData merged in."""
    data = record.get("auditData")
    data = dict(data) if isinstance(data, dict) else {}
    nested = data.get("CopilotEventData")
    if isinstance(nested, dict):
        data = {**nested, **{k: v for k, v in data.items() if k != "CopilotEventData"}}
    return data


def _flagged(items: Any, flag: str) -> int:
    return sum(1 for item in items or [] if isinstance(item, dict) and item.get(flag) is True)


# ------------------------------------------------------------------- Purview


def record_usage(session: Session, settings: Settings, records: list[dict[str, Any]]) -> dict:
    """Agents' use, from ``CopilotInteraction`` audit records."""
    index = agent_index(session)
    usage: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"days": Counter(), "users": [], "hosts": Counter(), "jailbreaks": 0, "xpia": 0}
    )
    last_used: dict[str, datetime] = {}
    unmatched = 0
    for record in sorted(records, key=lambda r: str(r.get("createdDateTime") or "")):
        data = _audit_data(record)
        agent_id = match_agent(index, data.get("AgentId"), data.get("AppIdentity"))
        if agent_id is None:
            unmatched += 1
            continue
        when = _when(record.get("createdDateTime"))
        entry = usage[agent_id]
        entry["days"][when.date()] += 1
        user = record.get("userPrincipalName") or record.get("userId")
        if user:
            if user in entry["users"]:
                entry["users"].remove(user)
            entry["users"].insert(0, str(user))  # the latest first
        if data.get("AppHost"):
            entry["hosts"][str(data["AppHost"])] += 1
        entry["jailbreaks"] += _flagged(data.get("Messages"), "JailbreakDetected")
        entry["xpia"] += _flagged(data.get("AccessedResources"), "XPIADetected")
        last_used[agent_id] = max(last_used.get(agent_id, when), when)
    for agent_id, entry in usage.items():
        agent = session.get(Agent, agent_id)
        if agent is None:
            continue
        when = last_used[agent_id]
        agent.last_seen_at = max(agent.last_seen_at or when, when)
        for day, count in entry["days"].items():
            # Each interaction is a model call by the agent on someone's behalf.
            discovery.record_activity(
                session, agent_id, when=datetime(day.year, day.month, day.day), model_calls=count
            )
        _remember_usage(session, agent_id, entry, when)
        if entry["jailbreaks"]:
            for _ in range(min(entry["jailbreaks"], 10)):
                risk.add_signal(session, agent_id, "jailbreak_attempt", "Microsoft Purview")
            findings.raise_finding(
                session,
                type="agent.jailbreak_attempts",
                severity="medium",
                subject=agent_id,
                agent_id=agent_id,
                category=findings.THREAT,
                title=f"People tried to jailbreak {agent.name}",
                description=f"Microsoft detected {entry['jailbreaks']} jailbreak attempt(s) in "
                "conversations with the agent (Microsoft Purview audit log).",
                remediation="Review who tried it in the audit log, and check that the agent's "
                "instructions and knowledge hold up against such prompts.",
                details={"jailbreaks": entry["jailbreaks"]},
            )
        if entry["xpia"]:
            for _ in range(min(entry["xpia"], 10)):
                risk.add_signal(session, agent_id, "prompt_injection", "Microsoft Purview")
            findings.raise_finding(
                session,
                type="agent.cross_prompt_injection",
                severity="high",
                subject=agent_id,
                agent_id=agent_id,
                category=findings.THREAT,
                title=f"Content {agent.name} read tried to give it instructions",
                description=f"Microsoft detected {entry['xpia']} cross-prompt injection "
                "attempt(s) in files or messages the agent accessed (Microsoft Purview audit "
                "log).",
                remediation="Find the content in the audit log: untrusted documents or emails "
                "may be targeting your agents.",
                details={"attempts": entry["xpia"]},
            )
        agents_svc.refresh_risk(session, settings, agent)
    interactions = sum(sum(e["days"].values()) for e in usage.values())
    return {"interactions": interactions, "agents": len(usage), "unmatched": unmatched}


def _remember_usage(
    session: Session, agent_id: str, entry: dict[str, Any], last_used: datetime
) -> None:
    """Keep who used the agent lately, and where, on its platform records."""
    for record in session.scalars(select(PlatformAgent).where(PlatformAgent.agent_id == agent_id)):
        data = dict(record.data or {})
        previous = data.get("usage") or {}
        users = list(entry["users"])
        users += [u for u in previous.get("recent_users") or [] if u not in users]
        hosts = Counter(previous.get("hosts") or {})
        hosts.update(entry["hosts"])
        data["usage"] = {
            "last_used_at": ids.isoformat(
                max(_when(previous["last_used_at"]), last_used)
                if previous.get("last_used_at")
                else last_used
            ),
            "recent_users": users[:RECENT_USERS],
            "hosts": dict(hosts.most_common(10)),
        }
        record.data = data


def record_maker_events(session: Session, records: list[dict[str, Any]]) -> dict[str, int]:
    """Copilot Studio agents created, published, shared or deleted, into the ledger."""
    index = agent_index(session)
    counts = {"events": 0, "skipped": 0}
    for record in sorted(records, key=lambda r: str(r.get("createdDateTime") or "")):
        data = _audit_data(record)
        operation = record.get("operation") or data.get("Operation")
        type_ = MAKER_EVENTS.get(str(operation))
        if type_ is None:
            counts["skipped"] += 1
            continue
        bot_id = data.get("BotId") or record.get("objectId")
        agent_id = match_agent(index, bot_id, data.get("BotSchemaName"))
        agent = session.get(Agent, agent_id) if agent_id else None
        who = record.get("userPrincipalName") or record.get("userId") or "unknown"
        ledger.append(
            session,
            type=type_,
            actor=f"maker:{who}",
            agent=agent,
            agent_name=None if agent else str(data.get("BotSchemaName") or bot_id or "unknown"),
            severity="info",
            action=str(operation),
            resource=f"copilot-studio/{bot_id}" if bot_id else None,
            details={
                "platform": "Copilot Studio",
                "bot_id": bot_id,
                "schema_name": data.get("BotSchemaName"),
                "environment": data.get("EnvironmentName") or data.get("EnvironmentId"),
                "audit_record_id": record.get("id"),
            },
            ts=_when(record.get("createdDateTime")),
        )
        counts["events"] += 1
    return counts


# ------------------------------------------------------------------- Defender


def _agent_evidence(alert: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        e
        for e in alert.get("evidence") or []
        if isinstance(e, dict) and str(e.get("@odata.type", "")).endswith("aiAgentEvidence")
    ]


def is_about_agents(alert: dict[str, Any]) -> bool:
    return bool(_agent_evidence(alert)) or (
        alert.get("serviceSource") == "microsoftSecurityForAI"
        or alert.get("detectionSource") == "microsoftDefenderForAIServices"
    )


def record_alerts(session: Session, settings: Settings, alerts: list[dict[str, Any]]) -> dict:
    """Defender alerts about agents, as findings (resolved when Defender resolves them)."""
    index = agent_index(session)
    counts = {"alerts": 0, "matched": 0, "resolved": 0}
    touched: set[str] = set()
    for alert in alerts:
        alert_id = alert.get("id")
        if not alert_id or not is_about_agents(alert):
            continue
        counts["alerts"] += 1
        evidence = _agent_evidence(alert)
        agent_id = None
        for item in evidence:
            agent_id = match_agent(index, item.get("agentId"))
            if agent_id:
                break
        key = f"defender.alert:{alert_id}"
        if alert.get("status") == "resolved":
            findings.resolve_key(session, key, actor=ACTOR)
            counts["resolved"] += 1
            if agent_id:
                touched.add(agent_id)
            continue
        named = ", ".join(sorted({str(e.get("agentName")) for e in evidence if e.get("agentName")}))
        findings.raise_finding(
            session,
            type="defender.alert",
            severity=DEFENDER_SEVERITY.get(str(alert.get("severity")), "medium"),
            subject=str(alert_id),
            agent_id=agent_id,
            category=findings.THREAT,
            title=f"Microsoft Defender: {alert.get('title') or 'alert'}"
            + (f" ({named})" if named and not agent_id else ""),
            description=str(alert.get("description") or ""),
            remediation=str(alert.get("recommendedActions") or "Investigate it in Defender."),
            details={
                "alert_url": alert.get("alertWebUrl"),
                "incident_url": alert.get("incidentWebUrl"),
                "service_source": alert.get("serviceSource"),
                "detection_source": alert.get("detectionSource"),
                "status": alert.get("status"),
                "agents": [
                    {
                        "id": e.get("agentId"),
                        "name": e.get("agentName"),
                        "platform": e.get("hostingPlatformType"),
                    }
                    for e in evidence
                ],
            },
        )
        if agent_id:
            counts["matched"] += 1
            touched.add(agent_id)
    for agent_id in touched:
        agent = session.get(Agent, agent_id)
        if agent is not None:
            agents_svc.refresh_risk(session, settings, agent)
    return counts

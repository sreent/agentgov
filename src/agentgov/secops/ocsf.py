"""The evidence ledger as OCSF events (Open Cybersecurity Schema Framework 1.9.0), the
schema SIEMs read: one event per ledger entry.

| Ledger entries | OCSF class |
|---|---|
| ``decision.*`` (tool and model calls), ``approval.*``, ungranted tool use | API Activity (6003) |
| ``admin.*`` (sign-ins and sessions) | Authentication (3002) |
| ``finding.*`` | Compliance Finding (2003) for posture, Detection Finding (2004) for threats |
| everything else: what AgentGov governs, and who changed it | Entity Management (3004) |

Events carry the agent as an ``ai_agent`` (and the model as an ``ai_model``) from OCSF's
AI Operation profile, and what a control decided as ``action_id`` and ``disposition_id``
from its Security Control profile. ``metadata.uid`` is the ledger entry's ID, so a SIEM can
drop an event it got twice, and ``unmapped.agentgov`` keeps the entry itself, with its
hash in the ledger's chain.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentgov import __version__, ids
from agentgov.models import Agent, LedgerEntry

OCSF_VERSION = "1.9.0"
PRODUCT = {"name": "AgentGov", "vendor_name": "AgentGov", "version": __version__}

API_ACTIVITY = 6003
AUTHENTICATION = 3002
ENTITY_MANAGEMENT = 3004
COMPLIANCE_FINDING = 2003
DETECTION_FINDING = 2004
_IAM = "Identity & Access Management"
CLASSES = {
    API_ACTIVITY: ("api_activity", "API Activity", 6, "Application Activity"),
    AUTHENTICATION: ("authentication", "Authentication", 3, _IAM),
    ENTITY_MANAGEMENT: ("entity_management", "Entity Management", 3, _IAM),
    COMPLIANCE_FINDING: ("compliance_finding", "Compliance Finding", 2, "Findings"),
    DETECTION_FINDING: ("detection_finding", "Detection Finding", 2, "Findings"),
}

# OCSF severity_id.
INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL = 1, 2, 3, 4, 5
SEVERITY_IDS = {"info": INFORMATIONAL, "low": LOW, "medium": MEDIUM, "high": HIGH}
SEVERITY_IDS |= {"critical": CRITICAL, "warning": MEDIUM}
SEVERITY_NAMES = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

# Security Control profile: what the control did (action) and the outcome (disposition).
ALLOWED, DENIED = 1, 2
DISPOSITIONS = {
    1: "Allowed",
    2: "Blocked",
    8: "Approved",
    14: "Delayed",
    15: "Detected",
    16: "No Action",
    25: "Rejected",
}

# Entity Management activities, by the verb ending a ledger type.
ENTITY_ACTIVITIES = {
    1: "Create",
    2: "Read",
    3: "Update",
    4: "Delete",
    6: "Enroll",
    8: "Enable",
    9: "Disable",
    10: "Activate",
    99: "Other",
}
_VERBS = {
    "registered": 1,
    "created": 1,
    "discovered": 1,
    "imported": 1,
    "updated": 3,
    "changed": 3,
    "attested": 3,
    "rotated": 3,
    "pushed": 3,
    "approved": 3,
    "deleted": 4,
    "purged": 4,
    "removed": 4,
    "read": 2,
    "delete": 4,
    "adopt": 6,
    "unblock": 8,
    "unblocked": 8,
    "restore": 8,
    "block": 9,
    "blocked": 9,
    "revoked": 9,
    "pause": 9,
    "resume": 8,
    "approve": 10,
}
# What each kind of ledger resource is, for the managed entity.
_ENTITIES = {
    "agent": "AI Agent",
    "toolserver": "Tool Server",
    "model_provider": "Model Provider",
    "identity_issuer": "Identity Issuer",
    "blueprint": "Blueprint",
    "policy": "Policy",
    "feature": "Feature",
    "apikey": "API Key",
    "connector": "Connector",
    "connector_policy": "Connector Policy",
    "platform": "Platform Agent",
    "mcp": "Developer MCP Servers",
    "model": "Model Budget",
    "destination": "Destination",
}
# Agent frameworks OCSF names (ai_agent.type_id), and their captions.
_FRAMEWORKS = {"langchain": 2, "langgraph": 2, "autogen": 3, "crewai": 4}
_FRAMEWORK_NAMES = {2: "LangChain", 3: "AutoGen", 4: "CrewAI"}
# Each class's activities as OCSF names them, for type_name.
_ACTIVITY_CAPTIONS = {
    API_ACTIVITY: {1: "Create", 2: "Read", 3: "Update", 4: "Delete"},
    AUTHENTICATION: {1: "Logon", 2: "Logoff"},
    ENTITY_MANAGEMENT: ENTITY_ACTIVITIES,
    COMPLIANCE_FINDING: {1: "Create", 2: "Update", 3: "Close"},
    DETECTION_FINDING: {1: "Create", 2: "Update", 3: "Close"},
}
POSTURE_FINDINGS = "posture"


def _class(entry: LedgerEntry) -> int:
    prefix = entry.type.split(".", 1)[0]
    if prefix in ("decision", "approval") or entry.type == "telemetry.ungranted_tool_use":
        return API_ACTIVITY
    if prefix == "admin":
        return AUTHENTICATION
    if prefix == "finding":
        category = (entry.details or {}).get("category")
        if category is None:
            from agentgov.registry.posture import POSTURE_TYPES

            posture = (entry.details or {}).get("type") in POSTURE_TYPES
            category = POSTURE_FINDINGS if posture else ""
        return COMPLIANCE_FINDING if category == POSTURE_FINDINGS else DETECTION_FINDING
    return ENTITY_MANAGEMENT


_USER_TYPES = {1: "User", 2: "Admin", 3: "System", 4: "Service"}


def _who(actor: str | None) -> dict[str, Any]:
    """An OCSF user from a ledger actor (``<kind>:<name>``)."""
    kind, _, name = (actor or "").partition(":")
    if not name:
        kind, name = "", actor or "unknown"
    type_id = {"admin": 2, "system": 3, "service": 4, "agent": 4, "client": 4}.get(kind, 1)
    return {"name": name, "uid": actor or name, "type_id": type_id, "type": _USER_TYPES[type_id]}


def _ai_agent(entry: LedgerEntry, agent: Agent | None) -> dict[str, Any] | None:
    if not entry.agent_id and not entry.agent_name:
        return None
    out: dict[str, Any] = {"uid": entry.agent_id or entry.agent_name, "name": entry.agent_name}
    framework = (agent.framework or "") if agent is not None else ""
    if framework:
        type_id = next((v for k, v in _FRAMEWORKS.items() if k in framework.lower()), 99)
        out["type_id"] = type_id
        out["type"] = _FRAMEWORK_NAMES.get(type_id, framework)
    if agent is not None and agent.client_id:
        out["instance_uid"] = agent.client_id
    return {k: v for k, v in out.items() if v is not None}


def _base(
    entry: LedgerEntry, class_uid: int, activity_id: int, activity_name: str
) -> dict[str, Any]:
    name, caption, category_uid, category_name = CLASSES[class_uid]
    metadata: dict[str, Any] = {
        "version": OCSF_VERSION,
        "product": PRODUCT,
        "uid": entry.id,
        "sequence": entry.seq,
        "log_name": "agentgov-ledger",
        "profiles": [],
    }
    if entry.trace_id:
        metadata["correlation_uid"] = entry.trace_id
    return {
        "class_uid": class_uid,
        "class_name": caption,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": class_uid * 100 + activity_id,
        "type_name": f"{caption}: {_ACTIVITY_CAPTIONS[class_uid].get(activity_id, 'Other')}",
        "time": int(entry.ts.timestamp() * 1000),
        "severity_id": SEVERITY_IDS.get(entry.severity, INFORMATIONAL),
        "metadata": metadata,
        "unmapped": {
            "agentgov": {
                "type": entry.type,
                "seq": entry.seq,
                "actor": entry.actor,
                "action": entry.action,
                "resource": entry.resource,
                "decision": entry.decision,
                "details": entry.details or {},
                "hash": entry.hash,
            }
        },
        "_name": name,
    }


def _with_profile(event: dict[str, Any], profile: str) -> None:
    if profile not in event["metadata"]["profiles"]:
        event["metadata"]["profiles"].append(profile)


def _control(event: dict[str, Any], action_id: int, disposition_id: int, alert: bool) -> None:
    """The Security Control profile's outcome."""
    _with_profile(event, "security_control")
    event["action_id"] = action_id
    event["action"] = "Allowed" if action_id == ALLOWED else "Denied"
    event["disposition_id"] = disposition_id
    event["disposition"] = DISPOSITIONS[disposition_id]
    event["is_alert"] = alert


def _api_activity(entry: LedgerEntry, agent: Agent | None) -> dict[str, Any]:
    details = entry.details or {}
    kind = entry.type.split(".", 1)[0]
    model_call = entry.type.startswith("decision.model.")
    method = entry.action or ("chat" if model_call else "tools/call")
    # server/tool, or provider/model; a tool alone for in-process agents.
    resource = entry.resource or ""
    service, target = resource.split("/", 1) if "/" in resource else ("", resource)
    if kind == "approval":
        verb = entry.type.split(".", 1)[1]
        activity_id, activity = 99, f"Approval {verb}"
    elif method.endswith("/list") or method.endswith("/read"):
        activity_id, activity = 2, "Read"
    else:
        activity_id, activity = 99, "Model call" if model_call else "Tool call"
    event = _base(entry, API_ACTIVITY, activity_id, activity)
    api: dict[str, Any] = {"operation": method, "service": {"name": service or "unknown"}}
    request_uid = details.get("approval_id") or details.get("opa_decision_id")
    if request_uid:
        api["request"] = {"uid": str(request_uid)}
    event["api"] = api
    caller = {"name": entry.agent_name or entry.actor or "unknown"}
    if entry.agent_id:
        caller["uid"] = entry.agent_id
    event["src_endpoint"] = dict(caller)
    event["dst_endpoint"] = {"svc_name": service or "unknown"}
    actor: dict[str, Any] = {"application": caller}
    if entry.on_behalf_of:
        actor["user"] = {"name": entry.on_behalf_of, "type_id": 1, "type": "User"}
    if kind == "approval" and not entry.actor.startswith("agent:"):
        # An approver's decision: the person who decided.
        actor["user"] = _who(entry.actor)
    event["actor"] = actor
    if target:
        event["resources"] = [{"name": target, "type": "AI Model" if model_call else "Tool"}]
    if model_call and target:
        event["ai_model"] = {"name": target, "ai_provider": service}
    monitored = bool(details.get("monitored"))
    decision = entry.decision
    if entry.type == "telemetry.ungranted_tool_use":
        # Seen in the agent's own telemetry: it called the tool without the gateway.
        _control(event, ALLOWED, 15, alert=True)
        event["severity_id"] = MEDIUM
    elif kind == "approval":
        verb = entry.type.split(".", 1)[1]
        action_id, disposition_id = {
            "requested": (DENIED, 14),
            "approved": (ALLOWED, 8),
            "denied": (DENIED, 25),
            "used": (ALLOWED, 1),
            "cancelled": (DENIED, 16),
        }.get(verb, (ALLOWED, 16))
        _control(event, action_id, disposition_id, alert=verb == "requested")
        event["severity_id"] = LOW if verb in ("requested", "denied") else INFORMATIONAL
    elif decision == "deny":
        _control(event, DENIED, 2, alert=True)
        event["severity_id"] = MEDIUM
    elif decision == "require_approval":
        _control(event, DENIED, 14, alert=False)
        event["severity_id"] = LOW
    elif decision == "allow" or monitored:
        _control(event, ALLOWED, 15 if monitored else 1, alert=monitored)
        event["severity_id"] = LOW if monitored else INFORMATIONAL
    if decision in ("allow", "deny", "require_approval"):
        event["status_id"] = 1 if decision == "allow" else 2
        event["status"] = "Success" if decision == "allow" else "Failure"
    if entry.reason:
        event["status_detail"] = entry.reason
    event["message"] = _message(entry)
    return event


def _authentication(entry: LedgerEntry) -> dict[str, Any]:
    logon = entry.type in ("admin.login", "admin.login_denied")
    event = _base(entry, AUTHENTICATION, 1 if logon else 2, "Logon" if logon else "Logoff")
    details = entry.details or {}
    if entry.type == "admin.session_ended":
        # An administrator ended someone else's session.
        event["actor"] = {"user": _who(entry.actor)}
        person = details.get("name") or details.get("subject") or "unknown"
        event["user"] = {"name": str(person), "type_id": 1, "type": "User"}
    else:
        user = _who(entry.actor)
        if details.get("subject"):
            user["uid"] = str(details["subject"])
        event["user"] = user
    event["service"] = {"name": "AgentGov"}
    event["auth_protocol_id"] = 4
    event["auth_protocol"] = "OpenID"
    denied = entry.type == "admin.login_denied"
    event["status_id"] = 2 if denied else 1
    event["status"] = "Failure" if denied else "Success"
    if entry.reason:
        event["status_detail"] = entry.reason
    event["message"] = _message(entry)
    return event


def _finding(entry: LedgerEntry, class_uid: int, agent: Agent | None) -> dict[str, Any]:
    details = entry.details or {}
    verb = entry.type.split(".", 1)[1]
    activity_id, activity = {"raised": (1, "Create"), "reopened": (2, "Update")}.get(
        verb, (3, "Close")
    )
    event = _base(entry, class_uid, activity_id, activity)
    status_id, status = {
        "raised": (1, "New"),
        "reopened": (1, "New"),
        "resolved": (4, "Resolved"),
        "dismissed": (3, "Suppressed"),
    }.get(verb, (99, "Other"))
    event["status_id"], event["status"] = status_id, status
    severity = SEVERITY_IDS.get(str(details.get("severity")), INFORMATIONAL)
    event["severity_id"] = severity
    info: dict[str, Any] = {
        "uid": str(details.get("finding_id") or entry.id),
        "title": entry.reason or str(details.get("type") or "Finding"),
        "types": [str(details.get("type") or "finding")],
    }
    if details.get("description"):
        info["desc"] = str(details["description"])
    event["finding_info"] = info
    resources = []
    if entry.agent_id:
        resources.append(
            {"uid": entry.agent_id, "name": entry.agent_name or entry.agent_id, "type": "AI Agent"}
        )
    if entry.resource and entry.resource != entry.agent_id:
        resources.append({"uid": entry.resource, "name": entry.resource})
    if resources:
        event["resources"] = resources
    open_now = verb in ("raised", "reopened")
    if class_uid == DETECTION_FINDING:
        event["is_alert"] = open_now and severity >= MEDIUM
    else:
        event["compliance"] = {
            "standards": ["AgentGov posture checks"],
            "control": str(details.get("type") or "posture"),
            "status_id": 3 if open_now else 1 if verb == "resolved" else 99,
            "status": "Fail" if open_now else "Pass" if verb == "resolved" else "Other",
        }
        if details.get("remediation"):
            event["remediation"] = {"desc": str(details["remediation"])}
    event["message"] = _message(entry)
    return event


def _entity(entry: LedgerEntry) -> dict[str, Any]:
    prefix, _, verb = entry.type.partition(".")
    verb = verb.rsplit("_", 1)[-1] if verb not in _VERBS else verb
    activity_id = _VERBS.get(verb, 99)
    event = _base(entry, ENTITY_MANAGEMENT, activity_id, ENTITY_ACTIVITIES[activity_id])
    if activity_id == 99:
        event["activity_name"] = entry.type.partition(".")[2].replace("_", " ").capitalize()
    kind = _ENTITIES.get(prefix, prefix.replace("_", " ").title())
    resource = entry.resource or ""
    name = resource.split("/", 1)[1] if "/" in resource else resource
    # Blueprints and policies are policies; OCSF has no type for the rest.
    type_id = 5 if prefix in ("policy", "blueprint") else 99
    entity: dict[str, Any] = {"type": kind, "type_id": type_id}
    if prefix == "agent" or (entry.agent_id and not name):
        entity |= {"name": entry.agent_name or entry.agent_id, "uid": entry.agent_id}
    else:
        entity |= {"name": name or entry.type, "uid": resource or entry.type}
    event["entity"] = {k: v for k, v in entity.items() if v is not None}
    event["actor"] = {"user": _who(entry.actor)}
    event["status_id"], event["status"] = 1, "Success"
    if entry.reason:
        event["comment"] = entry.reason
    event["message"] = _message(entry)
    return event


def _message(entry: LedgerEntry) -> str:
    who = entry.agent_name or entry.actor or "AgentGov"
    what = entry.type.replace("_", " ")
    text = f"{who}: {what}"
    if entry.resource:
        text += f" {entry.resource}"
    if entry.decision:
        text += f" ({entry.decision})"
    if entry.reason:
        text += f": {entry.reason}"
    return text[:1000]


def event(entry: LedgerEntry, agent: Agent | None = None) -> dict[str, Any]:
    """The OCSF event for a ledger entry (``agent``: the entry's agent, for its framework)."""
    class_uid = _class(entry)
    if class_uid == API_ACTIVITY:
        out = _api_activity(entry, agent)
    elif class_uid == AUTHENTICATION:
        out = _authentication(entry)
    elif class_uid in (COMPLIANCE_FINDING, DETECTION_FINDING):
        out = _finding(entry, class_uid, agent)
    else:
        out = _entity(entry)
    ai_agent = _ai_agent(entry, agent)
    if ai_agent and class_uid not in (COMPLIANCE_FINDING, DETECTION_FINDING):
        # Findings name the agent among their resources instead.
        _with_profile(out, "ai_operation")
        out["ai_agent"] = ai_agent
    out.pop("_name", None)
    return out


def events(
    entries: list[LedgerEntry], agent_of: Callable[[str], Agent | None] | None = None
) -> list[dict[str, Any]]:
    cache: dict[str, Agent | None] = {}

    def lookup(agent_id: str | None) -> Agent | None:
        if not agent_id or agent_of is None:
            return None
        if agent_id not in cache:
            cache[agent_id] = agent_of(agent_id)
        return cache[agent_id]

    return [event(e, lookup(e.agent_id)) for e in entries]


def severity_name(severity_id: int) -> str:
    return SEVERITY_NAMES.get(severity_id, "Unknown")


def now_ms() -> int:
    return int(ids.utcnow().timestamp() * 1000)

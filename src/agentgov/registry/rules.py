"""Management rules: what to do about the agents that meet some conditions for long enough
(docs/management-rules.md).

A rule names conditions an agent must meet, all of them (no activity for so many days, no
owner, an attestation long overdue, an open finding, a risk level, a status), which agents
it looks at (its scope), and an action: raise an issue, give the agent an owner, block it,
delete it, or revoke its access packages. Rules run after each posture scan.

Rules tell before they act. An enforced rule that changes something raises an issue about
the agent as soon as it matches, which goes to the agent's owner, then its sponsors, then
its team (agentgov.registry.issues), and acts ``after_days`` later, if the agent still
matches. Its people can make it stop matching, or an approver accepts the risk until a
date, which keeps the rule off the agent until then (the days of notice start again once
the date has passed). A monitored rule, the default, tells nobody and changes nothing: it
records what it would have done. And a rule acts on ``max_actions`` agents at once at
most: past that, it acts on none of them and raises an issue about itself, so that a rule
that matches more agents than its author meant doesn't block them all.

A rule doesn't argue with people: once it acted on an agent, it leaves the agent be for as
long as the agent still matches, even if someone undid what it did. Nor does it guess: an
agent whose activity AgentGov can't see (one on another platform, while AgentGov doesn't
read that platform's usage) is never inactive.
"""

from __future__ import annotations

import fnmatch
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.models import (
    ACTIVE,
    BLOCKED,
    DELETED,
    DISCOVERED,
    PENDING,
    RISK_LEVELS,
    SEVERITIES,
    AccessAssignment,
    Agent,
    Finding,
    ManagementRule,
    RuleMatch,
)
from agentgov.platforms import connections
from agentgov.registry import access_packages, features, findings, scopes, teams, validation
from agentgov.registry import agents as agents_svc
from agentgov.registry.errors import Conflict, NotFound, RegistryError, ValidationError
from agentgov.registry.versions import changes, edited, start_edit

FEATURE = "management-rules"
POSTURE = "posture-checks"
# Copilot Studio asks AgentGov before each tool call while this is enforced
# (agentgov.platforms.threat_detection), so an agent blocked here makes none.
THREAT_DETECTION = "copilot-studio-threat-detection"
COPILOT_STUDIO_ID = "copilot_studio_agent_id"
ISSUE, ASSIGN_OWNER, BLOCK, DELETE, REVOKE = (
    "issue",
    "assign_owner",
    "block",
    "delete",
    "revoke_access",
)
ACTIONS = (ISSUE, ASSIGN_OWNER, BLOCK, DELETE, REVOKE)
MODES = (features.OFF, features.MONITOR, features.ENFORCE)
FIELDS = (
    "description",
    "mode",
    "conditions",
    "scope",
    "action",
    "params",
    "after_days",
    "severity",
    "max_actions",
    "labels",
)
MISSING = ("owner", "sponsors", "team", "blueprint", "workload_identity")
CONDITIONS = (
    "inactive_days",
    "missing",
    "attestation_overdue_days",
    "findings",
    "finding_severity",
    "risk_level",
    "status",
)
SCOPES = scopes.KEYS
# The statuses a rule can look for (deleted agents are no rule's business).
STATUSES = (PENDING, ACTIVE, BLOCKED, DISCOVERED)
ISSUE_SEVERITIES = ("low", "medium", "high", "critical")
MATCHED, TOO_MANY = "rule.matched", "rule.too_many"
FINDING_TYPES = {MATCHED, TOO_MANY}
# An agent label that keeps rules off it: "*", or the rules' names, separated by commas.
EXEMPT_LABEL = "agentgov/exempt-rules"
SYSTEM = "system:management-rules"
MAX_DAYS = 3650
MAX_AFTER_DAYS = 365
MAX_ACTIONS = 1000
# Usage read from another platform counts while its latest read is this recent.
USAGE_FRESH = timedelta(days=2)
# The agents each action can act on, and the status it leaves them in.
ACTS_ON = {BLOCK: (PENDING, ACTIVE, DISCOVERED), DELETE: (PENDING, ACTIVE, BLOCKED, DISCOVERED)}
LEAVES = {BLOCK: BLOCKED, DELETE: DELETED}
# What a rule doing each action does, in messages.
DOES = {
    ISSUE: "raises issues",
    ASSIGN_OWNER: "gives agents an owner",
    BLOCK: "blocks agents",
    DELETE: "deletes agents",
    REVOKE: "revokes access packages",
}
VERBS = {
    ISSUE: ("raise an issue about", "raised an issue about"),
    ASSIGN_OWNER: ("give an owner to", "gave an owner to"),
    BLOCK: ("block", "blocked"),
    DELETE: ("delete", "deleted"),
    REVOKE: ("revoke the access packages of", "revoked the access packages of"),
}
PLATFORMS = {
    "microsoft-365": "Microsoft 365",
    "copilot-studio": "Copilot Studio",
    "aws": "AWS",
    "google-cloud": "Google Cloud",
    "salesforce": "Salesforce",
    "databricks": "Databricks",
    "microsoft-foundry": "Microsoft Foundry",
}
# Entries listed per preview, at most.
PREVIEW_LIMIT = 200


def _actor(rule: ManagementRule) -> str:
    return f"system:rule:{rule.name}"


def _verb(rule: ManagementRule, past: bool = False) -> str:
    verb = VERBS[rule.action][1 if past else 0]
    if rule.action == ASSIGN_OWNER:
        owner = (rule.params or {}).get("owner")
        return f"make {owner} the owner of" if not past else f"made {owner} the owner of"
    return verb


def effective(rule_mode: str, feature_mode: str) -> str:
    """The weaker of the rule's mode and the feature's."""
    return min(rule_mode, feature_mode, key=MODES.index)


# ----------------------------------------------------------------------- rules


def get(session: Session, ref: str) -> ManagementRule:
    rule = session.scalar(
        select(ManagementRule).where((ManagementRule.name == ref) | (ManagementRule.id == ref))
    )
    if rule is None:
        raise NotFound(f"management rule {ref!r} not found")
    return rule


def list_all(session: Session) -> list[ManagementRule]:
    return list(session.scalars(select(ManagementRule).order_by(ManagementRule.name)))


def _int(value: Any, field: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValidationError(f"{field} is a whole number from {low} to {high}")
    return value


def _one_list(value: Any, allowed: tuple[str, ...], field: str) -> list[str]:
    items = validation.string_list(value, field)
    unknown = [v for v in items if v not in allowed]
    if unknown or not items:
        raise ValidationError(f"{field} is a list of {', '.join(allowed)}")
    return items


def _conditions(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"conditions is a mapping of {', '.join(CONDITIONS)}")
    unknown = sorted(set(value) - set(CONDITIONS))
    if unknown:
        raise ValidationError(
            f"unknown condition(s) {', '.join(unknown)}; a rule's conditions are "
            f"{', '.join(CONDITIONS)}"
        )
    out: dict[str, Any] = {}
    for key, raw in value.items():
        if key == "inactive_days":
            out[key] = _int(raw, "inactive_days", 1, MAX_DAYS)
        elif key == "attestation_overdue_days":
            out[key] = _int(raw, "attestation_overdue_days", 0, MAX_DAYS)
        elif key == "missing":
            out[key] = _one_list(raw, MISSING, "missing")
        elif key == "status":
            out[key] = _one_list(raw, STATUSES, "status")
        elif key == "findings":
            patterns = validation.string_list(raw, "findings")
            if not patterns:
                raise ValidationError("findings is a list of finding types, such as agent.stale")
            # A rule acting on rules' own issues would go round in circles.
            if any(fnmatch.fnmatchcase(t, p) for p in patterns for t in FINDING_TYPES):
                raise ValidationError("findings can't name rules' own issues (rule.*)")
            out[key] = patterns
        elif key == "finding_severity":
            out[key] = validation.one_of(raw, SEVERITIES, "finding_severity")
        elif key == "risk_level":
            out[key] = validation.one_of(raw, RISK_LEVELS, "risk_level")
    if "finding_severity" in out and "findings" not in out:
        raise ValidationError("finding_severity goes with findings: which findings, how severe")
    if not set(out) - {"finding_severity"}:
        raise ValidationError(
            "a rule needs at least one condition: inactive_days, missing, "
            "attestation_overdue_days, findings, risk_level or status"
        )
    return out


def _scope(value: Any) -> dict[str, Any]:
    return scopes.parse(value)


def _params(session: Session, action: str, value: Any) -> dict[str, Any]:
    value = value or {}
    if not isinstance(value, dict):
        raise ValidationError("params is a mapping")
    if action != ASSIGN_OWNER:
        if value:
            raise ValidationError(f"a rule that {DOES.get(action, action)} takes no params")
        return {}
    unknown = sorted(set(value) - {"owner"})
    owner = value.get("owner")
    if unknown or not isinstance(owner, str) or not owner.strip():
        raise ValidationError("assign_owner needs params.owner: a team, or a person's email")
    owner = owner.strip()
    if not teams.is_email(owner) and teams.find(session, owner) is None:
        raise ValidationError(
            f"params.owner {owner!r} is neither a team (add it first) nor an email address"
        )
    return {"owner": owner}


def _apply(session: Session, rule: ManagementRule, data: dict[str, Any]) -> list[str]:
    changed = []
    action = data.get("action", rule.action)
    for key in FIELDS:
        if key not in data and not (key == "params" and "action" in data):
            continue
        value = data.get(key)
        if key == "description":
            value = str(value or "")
        elif key == "mode":
            value = validation.one_of(value, MODES, "mode")
        elif key == "conditions":
            value = _conditions(value)
        elif key == "scope":
            value = _scope(value)
            scopes.check_names(session, value, had=[rule.scope or {}])
        elif key == "action":
            value = validation.one_of(value, ACTIONS, "action")
        elif key == "params":
            value = _params(session, action, value if "params" in data else rule.params)
        elif key == "after_days":
            value = _int(value, "after_days", 0, MAX_AFTER_DAYS)
        elif key == "severity":
            value = validation.one_of(value, ISSUE_SEVERITIES, "severity")
        elif key == "max_actions":
            value = _int(value, "max_actions", 1, MAX_ACTIONS)
        elif key == "labels":
            value = validation.labels(value)
        if getattr(rule, key) != value:
            setattr(rule, key, value)
            changed.append(key)
    if not rule.conditions:
        raise ValidationError("a rule needs conditions")
    if rule.action != ISSUE and rule.after_days < 1:
        raise ValidationError(
            f"a rule that {DOES[rule.action]} gives a day's notice at least: after_days >= 1"
        )
    return changed


def _known(data: dict[str, Any]) -> None:
    unknown = sorted(set(data) - set(FIELDS) - {"name"})
    if unknown:
        raise ValidationError(
            f"unknown field(s) {', '.join(unknown)}; a management rule takes name, "
            f"{', '.join(FIELDS)}"
        )


# What a rule is unless it says otherwise.
DEFAULTS: dict[str, Any] = {
    "description": "",
    "mode": features.MONITOR,
    "scope": {},
    "action": ISSUE,
    "params": {},
    "after_days": 14,
    "severity": "medium",
    "max_actions": 10,
    "labels": {},
}


def _new(name: str) -> ManagementRule:
    return ManagementRule(
        id=ids.new_id(ids.MANAGEMENT_RULE),
        name=name,
        conditions={},
        **{k: v.copy() if isinstance(v, dict) else v for k, v in DEFAULTS.items()},
    )


def draft(session: Session, data: dict[str, Any]) -> ManagementRule:
    """A rule that isn't saved: to preview it before creating it."""
    _known(data)
    rule = _new(str(data.get("name") or "draft"))
    _apply(session, rule, data)
    return rule


def create(session: Session, data: dict[str, Any], *, actor: str) -> ManagementRule:
    _known(data)
    name = validation.slug(data.get("name"), "name")
    if session.scalar(select(ManagementRule).where(ManagementRule.name == name)):
        raise Conflict(f"management rule {name!r} already exists")
    rule = _new(name)
    _apply(session, rule, data)
    session.add(rule)
    session.flush()
    ledger.append(
        session, type="rule.created", actor=actor, resource=f"rule/{name}", details=_details(rule)
    )
    return rule


def update(
    session: Session,
    rule: ManagementRule,
    data: dict[str, Any],
    *,
    actor: str,
    version: int | None = None,
) -> list[str]:
    start_edit(session, rule, version, f"management rule {rule.name}")
    _known(data)
    if "name" in data and data["name"] != rule.name:
        raise ValidationError("a management rule's name can't change: the ledger names it")
    changed = _apply(session, rule, data)
    if changed:
        edited(rule)
        ledger.append(
            session,
            type="rule.updated",
            actor=actor,
            resource=f"rule/{rule.name}",
            details={**{k: _details(rule)[k] for k in changed}, "changes": changes(rule)},
        )
    return changed


def delete(session: Session, rule: ManagementRule, *, actor: str) -> None:
    """Delete a rule: its issues are resolved; what it did stays done."""
    for finding in session.scalars(
        select(Finding).where(
            Finding.status == "open",
            (Finding.key.like(f"{MATCHED}:{rule.id}:%")) | (Finding.key == f"{TOO_MANY}:{rule.id}"),
        )
    ):
        findings.set_status(session, finding.id, "resolved", actor)
    session.execute(sql_delete(RuleMatch).where(RuleMatch.rule_id == rule.id))
    ledger.append(
        session, type="rule.deleted", actor=actor, resource=f"rule/{rule.name}", severity="warning"
    )
    session.delete(rule)


def _details(rule: ManagementRule) -> dict[str, Any]:
    return {
        "description": rule.description or "",
        "mode": rule.mode,
        "conditions": dict(rule.conditions or {}),
        "scope": dict(rule.scope or {}),
        "action": rule.action,
        "params": dict(rule.params or {}),
        "after_days": rule.after_days,
        "severity": rule.severity,
        "max_actions": rule.max_actions,
        "labels": dict(rule.labels or {}),
    }


def to_dict(session: Session, rule: ManagementRule) -> dict[str, Any]:
    rows = list(session.scalars(select(RuleMatch).where(RuleMatch.rule_id == rule.id)))
    return {
        "id": rule.id,
        "name": rule.name,
        "version": rule.version,
        **_details(rule),
        "effective_mode": effective(rule.mode, features.mode(session, FEATURE)),
        "matches": {
            "matching": len(rows),
            "acted": sum(1 for r in rows if r.acted_at is not None),
            "would_have_acted": sum(1 for r in rows if r.monitored_at is not None),
        },
        "created_at": ids.isoformat(rule.created_at),
        "updated_at": ids.isoformat(rule.updated_at),
    }


# ---------------------------------------------------------------------- matching


@dataclass
class _Context:
    """What a round needs to know, read once."""

    now: datetime
    feature: str
    agents: dict[str, Agent]
    # Open findings each agent has, other than rules' own (and those a failed sync left
    # unverified: whether they still hold is anyone's guess).
    findings: dict[str, list[Finding]]
    holding: set[str]
    # Since when, and until when, AgentGov has read other platforms' usage of agents.
    usage: tuple[datetime, datetime] | None
    # The features' modes: whether blocking a Copilot Studio agent here stops it.
    modes: dict[str, str] = field(default_factory=dict)


@dataclass
class Assessment:
    """Whether an agent matches a rule's conditions, and why."""

    matched: bool
    reasons: list[str] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    # Why it can't tell, when it can't.
    unknown: str | None = None


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _usage(session: Session, now: datetime) -> tuple[datetime, datetime] | None:
    """The stretch of time AgentGov read Microsoft 365 and Copilot Studio agents' usage for,
    from the Purview audit log, while it keeps reading it."""
    if not features.is_on(session, "purview-audit"):
        return None
    state = connections.load_state(session, "purview-audit")
    start, until = _parse(state.get("usage_from")), _parse(state.get("usage_until"))
    if start is None or until is None or now - until > USAGE_FRESH:
        return None
    return start, until


def _context(session: Session, now: datetime, feature: str) -> _Context:
    # In the posture scan's order (registry/posture), as the rules act on them.
    agents = {
        a.id: a
        for a in session.scalars(
            select(Agent).where(Agent.status != DELETED).order_by(Agent.id)
        ).unique()
    }
    open_findings: dict[str, list[Finding]] = defaultdict(list)
    for finding in session.scalars(
        select(Finding).where(Finding.status == "open", Finding.agent_id.is_not(None))
    ):
        if finding.type not in FINDING_TYPES and finding.verified is not False:
            open_findings[str(finding.agent_id)].append(finding)
    holding = set(
        session.scalars(
            select(AccessAssignment.agent_id).where(
                AccessAssignment.status.in_(access_packages.HELD)
            )
        )
    )
    return _Context(
        now,
        feature,
        agents,
        dict(open_findings),
        holding,
        _usage(session, now),
        features.modes(session),
    )


platform = scopes.platform


def _platform_name(agent: Agent) -> str:
    key = platform(agent)
    return PLATFORMS.get(key, key)


_team = scopes.team


def exempt(rule: ManagementRule, agent: Agent) -> bool:
    names = {n.strip() for n in str((agent.labels or {}).get(EXEMPT_LABEL, "")).split(",")}
    return "*" in names or rule.name in names


def in_scope(rule: ManagementRule, agent: Agent) -> bool:
    return not exempt(rule, agent) and scopes.matches(rule.scope or {}, agent)


def _applies(rule: ManagementRule, agent: Agent, row: RuleMatch | None, ctx: _Context) -> bool:
    """Whether the rule looks at this agent at all: in its scope, and one its action can
    do something about."""
    if agent.status == DELETED or not in_scope(rule, agent):
        return False
    acted = row is not None and row.acted_at is not None
    if rule.action in ACTS_ON:
        return agent.status in ACTS_ON[rule.action] or acted
    if rule.action == REVOKE:
        return agent.id in ctx.holding or acted
    if rule.action == ASSIGN_OWNER:
        return not agent.owner or acted
    return True


def _idle_since(agent: Agent, ctx: _Context) -> datetime | None:
    """Since when nothing was seen of the agent, as far as AgentGov can tell (None: it
    can't). Agents on the gateway are seen on every call; agents on other platforms only
    in the usage AgentGov reads from them."""
    if not agent.on_platform:
        return agent.last_seen_at or agent.created_at
    if ctx.usage is None:
        return None
    return max(agent.last_seen_at or agent.created_at, agent.created_at, ctx.usage[0])


def _lacks(agent: Agent, what: str) -> bool:
    on_gateway = not agent.on_platform
    return {
        "owner": not agent.owner,
        "sponsors": not agent.sponsors,
        "team": not _team(agent),
        # Agents on other platforms have neither: their platform governs that.
        "blueprint": on_gateway and agent.blueprint_id is None,
        "workload_identity": on_gateway and not agent.workload_issuer,
    }[what]


HINTS = {
    "owner": "give it an owner",
    "sponsors": "add a sponsor",
    "team": "give it a team",
    "blueprint": "give it a blueprint",
    "workload_identity": "give it a workload identity",
}
NO = Assessment(False)


def assess(rule: ManagementRule, agent: Agent, ctx: _Context) -> Assessment:
    """Whether the agent meets all the rule's conditions, and why."""
    c = rule.conditions or {}
    reasons: list[str] = []
    hints: list[str] = []
    if "status" in c:
        if agent.status not in c["status"]:
            return NO
        reasons.append(f"it is {agent.status}")
        hints.append("change its status")
    if "missing" in c:
        lacking = [m for m in c["missing"] if _lacks(agent, m)]
        if not lacking:
            return NO
        reasons.append("no " + ", no ".join(m.replace("_", " ") for m in lacking))
        hints += [HINTS[m] for m in lacking]
    if "attestation_overdue_days" in c:
        expires = agent.attestation_expires_at
        if expires is None or expires > ctx.now:
            return NO
        if (ctx.now - expires).days < c["attestation_overdue_days"]:
            return NO
        reasons.append(f"its attestation is overdue since {expires:%Y-%m-%d}")
        hints.append("a sponsor attests it")
    if "findings" in c:
        least = SEVERITIES.index(c.get("finding_severity", "info"))
        hits = [
            f
            for f in ctx.findings.get(agent.id, [])
            if any(fnmatch.fnmatchcase(f.type, p) for p in c["findings"])
            and SEVERITIES.index(f.severity) >= least
        ]
        if not hits:
            return NO
        more = f" (and {len(hits) - 1} more)" if len(hits) > 1 else ""
        reasons.append(f"open issue: {hits[0].title}{more}")
        hints.append("fix its issues")
    if "risk_level" in c:
        if RISK_LEVELS.index(agent.risk_level or "low") < RISK_LEVELS.index(c["risk_level"]):
            return NO
        reasons.append(f"it is {agent.risk_level} risk (score {agent.risk_score})")
        hints.append("bring its risk down")
    if "inactive_days" in c:
        since = _idle_since(agent, ctx)
        if since is None:
            return Assessment(
                False,
                unknown=f"AgentGov doesn't read how agents are used in "
                f"{_platform_name(agent)}: turn on the purview-audit feature to tell",
            )
        days = (ctx.now - since).days
        if days < c["inactive_days"]:
            return NO
        last = f"last seen {agent.last_seen_at:%Y-%m-%d}" if agent.last_seen_at else "never seen"
        reasons.insert(0, f"no activity for {days} days ({last})")
        hints.insert(0, "use it, or delete it if nobody needs it")
    return Assessment(True, reasons, hints)


def _copilot_studio(agent: Agent) -> bool:
    return COPILOT_STUDIO_ID in (agent.external_ids or {})


def _cannot(rule: ManagementRule, agent: Agent, modes: dict[str, str]) -> str | None:
    """Why the rule can't do its action to the agent, if it can't."""
    if rule.action not in (BLOCK, DELETE) or not agent.on_platform:
        return None
    if rule.action == BLOCK and _copilot_studio(agent):
        if modes.get(THREAT_DETECTION) == features.ENFORCE:
            # Copilot Studio asks AgentGov before each tool call: blocked here, it makes none.
            return None
        return (
            "it runs on Copilot Studio: quarantine it there (from its page in AgentGov, signed "
            "in through Microsoft Entra ID, or in the Power Platform admin center), or enforce "
            "Copilot Studio threat detection, so that blocking it in AgentGov stops its tool calls"
        )
    return (
        f"it runs on {_platform_name(agent)}: {VERBS[rule.action][0]} it in "
        f"{_platform_name(agent)}'s admin center"
    )


def _due_at(rule: ManagementRule, row: RuleMatch, mode: str, now: datetime) -> datetime:
    """When the rule acts: its days of notice after it told the agent's people (an enforced
    rule that changes something), or after the agent started to match."""
    after = timedelta(days=rule.after_days)
    if rule.action != ISSUE and mode == features.ENFORCE:
        return (row.warned_at or now) + after
    return row.since + after


def _exemption(finding: Finding | None, now: datetime) -> str | None:
    """Why the rule leaves the agent be for now: what someone decided about its issue."""
    if finding is None:
        return None
    if finding.status == "accepted" and finding.accepted_until and finding.accepted_until > now:
        return f"its risk is accepted until {finding.accepted_until:%Y-%m-%d}"
    if finding.status == "dismissed":
        return "its issue was dismissed"
    return None


# ------------------------------------------------------------------------ rounds


def _key(rule: ManagementRule, agent_id: str) -> str:
    return f"{MATCHED}:{rule.id}:{agent_id}"


def _finding(session: Session, key: str) -> Finding | None:
    return session.scalar(select(Finding).where(Finding.key == key))


def _remedy(rule: ManagementRule, a: Assessment) -> str:
    stop = ", ".join(dict.fromkeys(a.hints)) or "change what it matches"
    return (
        f"Make it stop matching ({stop}). Or an approver accepts the risk until a date, which "
        f"keeps the rule off it until then; an administrator keeps it out of the rule for good "
        f"with the label {EXEMPT_LABEL}: {rule.name}."
    )


def _raise(
    session: Session,
    rule: ManagementRule,
    agent: Agent,
    *,
    title: str,
    description: str,
    remediation: str,
    **details: Any,
) -> Finding:
    finding, _ = findings.raise_finding(
        session,
        type=MATCHED,
        severity=rule.severity,
        subject=f"{rule.id}:{agent.id}",
        agent_id=agent.id,
        title=title,
        description=description,
        remediation=remediation,
        details={"rule": rule.name, "action": rule.action, **details},
    )
    return finding


def _heads_up(
    session: Session,
    rule: ManagementRule,
    agent: Agent,
    row: RuleMatch,
    a: Assessment,
    due: datetime,
    cannot: str | None,
    now: datetime,
) -> Finding:
    """The issue that tells the agent's people what the rule will do, and when."""
    why = "; ".join(a.reasons)
    about = f"{agent.name} matches management rule {rule.name} since {row.since:%Y-%m-%d}: {why}."
    if rule.description:
        about += f" The rule: {rule.description.rstrip('.')}."
    existing = _finding(session, _key(rule, agent.id))
    held = _exemption(existing, now)
    if cannot:
        title = f"Rule {rule.name} can't {_verb(rule)} {agent.name}"
        description = f"{about} The rule would {_verb(rule)} it, but {cannot}."
    elif held:
        title = f"Rule {rule.name} would {_verb(rule)} {agent.name}: {held}"
        description = f"{about} The rule leaves it be while {held}."
    else:
        title = f"Rule {rule.name} will {_verb(rule)} {agent.name} on {due:%Y-%m-%d}"
        description = (
            f"{about} Unless it stops matching, the rule will {_verb(rule)} it on "
            f"{due:%Y-%m-%d %H:%M} UTC."
        )
    return _raise(
        session,
        rule,
        agent,
        title=title,
        description=description,
        remediation=_remedy(rule, a),
        due_at=ids.isoformat(due),
        since=ids.isoformat(row.since),
    )


def _drop(session: Session, rule: ManagementRule, row: RuleMatch | None, now: datetime) -> None:
    """The agent no longer matches: its match goes. Its issue is resolved by the end of the
    round; one dismissed or accepted is resolved too, so that a later match starts afresh."""
    if row is None:
        return
    finding = _finding(session, _key(rule, row.agent_id))
    if finding is not None and finding.status in ("dismissed", "accepted"):
        finding.status, finding.accepted_until = "resolved", None
        finding.resolved_at, finding.resolved_by = now, SYSTEM
        findings.record(session, finding, "resolved", SYSTEM)
    session.delete(row)


def _act(
    session: Session,
    settings: Settings,
    rule: ManagementRule,
    agent: Agent,
    row: RuleMatch,
    a: Assessment,
    now: datetime,
) -> None:
    """Do what the rule says, and tell the agent's people that it did."""
    actor, why = _actor(rule), "; ".join(a.reasons)
    reason = f"management rule {rule.name}: {why}"
    remediation = ""
    if rule.action == ASSIGN_OWNER:
        owner = rule.params["owner"]
        agents_svc.update(session, agent, {"owner": owner}, actor=actor)
        outcome = f"made {owner} its owner"
        remediation = "Give it the right owner if that isn't it."
    elif rule.action == BLOCK:
        agents_svc.transition(session, settings, agent, "block", actor=actor, reason=reason)
        outcome = "blocked it"
        remediation = (
            "If it is still needed, an administrator unblocks it: the rule then leaves it be "
            "for as long as it still matches."
        )
    elif rule.action == DELETE:
        agents_svc.transition(session, settings, agent, "delete", actor=actor, reason=reason)
        outcome = "deleted it"
        days = settings.soft_delete_retention_days
        remediation = (
            f"If it is still needed, an administrator restores it before "
            f"{now + timedelta(days=days):%Y-%m-%d}, when it is purged."
            if days > 0
            else "If it is still needed, an administrator restores it."
        )
    elif rule.action == REVOKE:
        held = session.scalars(
            select(AccessAssignment).where(
                AccessAssignment.agent_id == agent.id,
                AccessAssignment.status.in_(access_packages.HELD),
            )
        ).all()
        for assignment in held:
            access_packages.revoke(session, assignment, actor=actor, reason=reason)
        outcome = f"revoked {len(held)} access package(s)"
        remediation = "Ask for the packages again if it still needs them."
    else:
        outcome = "raised an issue"
    row.acted_at, row.outcome = now, outcome
    about = f"{agent.name} matches management rule {rule.name} since {row.since:%Y-%m-%d}: {why}."
    if rule.description:
        about += f" The rule: {rule.description.rstrip('.')}."
    if rule.action == ISSUE:
        title = f"{agent.name} matches rule {rule.name}: {a.reasons[0] if a.reasons else why}"
        finding = _raise(
            session,
            rule,
            agent,
            title=title,
            description=about,
            remediation=_remedy(rule, a),
            since=ids.isoformat(row.since),
        )
        return
    finding = _raise(
        session,
        rule,
        agent,
        title=f"Rule {rule.name} {_verb(rule, past=True)} {agent.name} on {now:%Y-%m-%d}",
        description=f"{about} The rule {outcome} on {now:%Y-%m-%d %H:%M} UTC.",
        remediation=remediation,
        acted_at=ids.isoformat(now),
        outcome=outcome,
    )
    findings.record(
        session, finding, "acted", actor, severity="warning", action=rule.action, outcome=outcome
    )
    # News for the agent's people: it goes to them again, from the start of its chain.
    if finding.status == "open":
        findings.restart_chain(finding)


def _would(
    session: Session, rule: ManagementRule, agent: Agent, row: RuleMatch, a: Assessment
) -> None:
    """A monitored rule's turn to act: what it would have done, in the ledger, once."""
    row.monitored_at = row.monitored_at or ids.utcnow()
    row.outcome = f"would {_verb(rule)} it"
    ledger.append(
        session,
        type="rule.would_act",
        actor=_actor(rule),
        severity="info",
        agent=agent,
        resource=f"rule/{rule.name}",
        reason="; ".join(a.reasons),
        details={"rule": rule.name, "action": rule.action, "since": ids.isoformat(row.since)},
    )


def _hold_back(
    session: Session,
    rule: ManagementRule,
    due: list[tuple[Agent, RuleMatch, Assessment]],
    mode: str,
    present: set[str],
) -> None:
    """More agents are due than the rule acts on at once: it acts on none, and says so."""
    count, names = len(due), [agent.name for agent, _, _ in due]
    verb = _verb(rule)
    title = (
        f"Rule {rule.name} is due to {verb} {count} agents, more than its limit of "
        f"{rule.max_actions}"
        if mode == features.ENFORCE
        else f"Rule {rule.name} would {verb} {count} agents at once, more than its limit of "
        f"{rule.max_actions}"
    )
    finding, new = findings.raise_finding(
        session,
        type=TOO_MANY,
        severity="high" if mode == features.ENFORCE else "medium",
        subject=rule.id,
        title=title,
        description=f"Rule {rule.name} acts on {rule.max_actions} agents at once at most, so "
        f"it acted on none of them. Among them: {', '.join(names[:10])}"
        + (f" and {count - 10} more." if count > 10 else "."),
        remediation="Preview the rule to check that it matches the agents you meant. If it "
        "does, raise its max_actions, or act on them yourself; if it doesn't, narrow its "
        "conditions or its scope.",
        details={"rule": rule.name, "due": count, "max_actions": rule.max_actions},
    )
    present.add(finding.key)
    held = f"held back: {count} agents due at once, more than {rule.max_actions}"
    for agent, row, a in due:
        row.outcome = held
        if mode == features.ENFORCE:
            # Its people were told a date: say why nothing happened on it.
            _raise(
                session,
                rule,
                agent,
                title=f"Rule {rule.name} would {verb} {agent.name}, but is held back",
                description=f"{agent.name} matches management rule {rule.name} since "
                f"{row.since:%Y-%m-%d}: {'; '.join(a.reasons)}. The rule's notice has passed, "
                f"but {count} agents are due at once, more than the {rule.max_actions} it acts "
                "on at once, so it acts on none of them until an administrator checks it.",
                remediation=_remedy(rule, a),
            )
    if new:
        ledger.append(
            session,
            type="rule.held_back",
            actor=_actor(rule),
            severity="warning",
            resource=f"rule/{rule.name}",
            reason=title,
            details={"rule": rule.name, "due": count, "agents": names[:50]},
        )


def _round(
    session: Session,
    settings: Settings,
    rule: ManagementRule,
    ctx: _Context,
    present: set[str],
) -> dict[str, int]:
    """One rule's round: which agents match, whom to tell, and what to do."""
    mode = effective(rule.mode, ctx.feature)
    counts = {"matching": 0, "due": 0, "acted": 0, "would_act": 0, "held_back": 0}
    rows = {
        r.agent_id: r
        for r in session.scalars(select(RuleMatch).where(RuleMatch.rule_id == rule.id))
    }
    if mode == features.OFF:
        for row in rows.values():
            _drop(session, rule, row, ctx.now)
        return counts
    due: list[tuple[Agent, RuleMatch, Assessment]] = []
    for agent_id in sorted(set(ctx.agents) | set(rows)):
        agent = ctx.agents.get(agent_id) or session.get(Agent, agent_id)
        row = rows.get(agent_id)
        if agent is None:  # purged
            _drop(session, rule, row, ctx.now)
            continue
        key = _key(rule, agent.id)
        if row is not None and row.acted_at is not None and LEAVES.get(rule.action) == agent.status:
            # Still as the rule left it: its issue stays until someone undoes it.
            present.add(key)
            continue
        if not _applies(rule, agent, row, ctx):
            _drop(session, rule, row, ctx.now)
            continue
        a = assess(rule, agent, ctx)
        if not a.matched:
            _drop(session, rule, row, ctx.now)
            continue
        counts["matching"] += 1
        if row is None:
            row = RuleMatch(
                id=ids.new_id(ids.RULE_MATCH), rule_id=rule.id, agent_id=agent.id, since=ctx.now
            )
            session.add(row)
        if row.acted_at is not None:
            # It did what it does; whatever people did since, it leaves the agent be.
            if mode == features.ENFORCE:
                present.add(key)
            continue
        cannot = _cannot(rule, agent, ctx.modes)
        if rule.action != ISSUE and mode == features.ENFORCE:
            row.warned_at = row.warned_at or ctx.now
            due_at = _due_at(rule, row, mode, ctx.now)
            finding = _heads_up(session, rule, agent, row, a, due_at, cannot, ctx.now)
            present.add(key)
            held = _exemption(finding, ctx.now)
            if cannot or held:
                # The notice starts again once nothing holds the rule back.
                row.warned_at, row.outcome = None, cannot or held
                continue
        else:
            # Monitored, a rule tells nobody: nor does a rule that only raises issues
            # until it is time to.
            row.warned_at = None
            due_at = _due_at(rule, row, mode, ctx.now)
            if cannot:
                row.outcome = cannot
                continue
        if ctx.now < due_at or (mode == features.MONITOR and row.monitored_at is not None):
            continue
        due.append((agent, row, a))
    counts["due"] = len(due)
    if len(due) > rule.max_actions:
        _hold_back(session, rule, due, mode, present)
        counts["held_back"] = len(due)
        return counts
    for agent, row, a in due:
        if mode == features.MONITOR:
            _would(session, rule, agent, row, a)
            counts["would_act"] += 1
            continue
        try:
            with session.begin_nested():
                _act(session, settings, rule, agent, row, a, ctx.now)
        except RegistryError as exc:
            row.outcome = f"failed: {exc}"
            continue
        present.add(_key(rule, agent.id))
        counts["acted"] += 1
    return counts


def _clear(session: Session, now: datetime) -> dict[str, Any]:
    """Rules are off: no rule matches anything, and their issues are resolved."""
    for rule in list_all(session):
        for row in session.scalars(select(RuleMatch).where(RuleMatch.rule_id == rule.id)):
            _drop(session, rule, row, now)
    resolved = findings.resolve_absent(
        session, types=FINDING_TYPES, present_keys=set(), actor=SYSTEM
    )
    return {"off": True, "resolved": resolved}


def evaluate(session: Session, settings: Settings, now: datetime | None = None) -> dict[str, Any]:
    """A round of every rule; returns what each did. Nothing runs while posture checks are
    off: rules are about what they find."""
    now = now or ids.utcnow()
    feature = features.mode(session, FEATURE)
    if feature == features.OFF:
        return _clear(session, now)
    if not features.is_on(session, POSTURE):
        return {"skipped": "posture checks are off: rules run after each posture scan"}
    ctx = _context(session, now, feature)
    present: set[str] = set()
    out: dict[str, Any] = {}
    known = set()
    for rule in list_all(session):
        known.add(rule.id)
        out[rule.name] = _round(session, settings, rule, ctx, present)
    # Matches of rules that are gone (deleting a rule removes its own).
    session.execute(sql_delete(RuleMatch).where(RuleMatch.rule_id.not_in(known)))
    findings.resolve_absent(session, types=FINDING_TYPES, present_keys=present, actor=SYSTEM)
    return out


# ---------------------------------------------------------------------- previews


def _state(
    rule: ManagementRule,
    agent: Agent,
    row: RuleMatch | None,
    mode: str,
    finding: Finding | None,
    now: datetime,
    modes: dict[str, str],
) -> tuple[str, str, datetime | None]:
    """Where the agent is with the rule: its state, what that means, and when it acts."""
    if row is not None and row.acted_at is not None:
        return "acted", f"{row.outcome or _verb(rule, past=True)} on {row.acted_at:%Y-%m-%d}", None
    cannot = _cannot(rule, agent, modes)
    if cannot:
        return "cannot", cannot, None
    if mode == features.ENFORCE and rule.action != ISSUE:
        held = _exemption(finding, now)
        if held:
            return "exempt", held, None
    if mode == features.OFF:
        return "off", "the rule is off", None
    probe = row or RuleMatch(since=now, warned_at=None)
    due = _due_at(rule, probe, mode, now)
    if mode == features.MONITOR and row is not None and row.monitored_at is not None:
        return "monitored", f"would have done it on {row.monitored_at:%Y-%m-%d}", due
    verb = _verb(rule)
    if now >= due:
        return "due", f"{'would ' if mode == features.MONITOR else ''}{verb} it now", due
    return (
        "waiting",
        f"{'would ' if mode == features.MONITOR else 'will '}{verb} it on {due:%Y-%m-%d}",
        due,
    )


def preview(session: Session, rule: ManagementRule, now: datetime | None = None) -> dict[str, Any]:
    """Which agents the rule matches now, since when, and what it will do to each: for a
    saved rule, or one that isn't saved yet. Changes nothing."""
    now = now or ids.utcnow()
    feature = features.mode(session, FEATURE)
    mode = effective(rule.mode, feature)
    ctx = _context(session, now, feature)
    saved = rule.id is not None and session.get(ManagementRule, rule.id) is rule
    rows = (
        {
            r.agent_id: r
            for r in session.scalars(select(RuleMatch).where(RuleMatch.rule_id == rule.id))
        }
        if saved
        else {}
    )
    entries: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for agent_id in sorted(set(ctx.agents) | set(rows)):
        agent = ctx.agents.get(agent_id) or session.get(Agent, agent_id)
        if agent is None:
            continue
        row = rows.get(agent_id)
        left = (
            row is not None and row.acted_at is not None and LEAVES.get(rule.action) == agent.status
        )
        if not left:
            if not _applies(rule, agent, row, ctx):
                continue
            a = assess(rule, agent, ctx)
            if a.unknown:
                unknown.append({"agent_id": agent.id, "agent": agent.name, "why": a.unknown})
                continue
            if not a.matched:
                continue
            reasons = a.reasons
        else:
            reasons = [row.outcome or ""]
        finding = _finding(session, _key(rule, agent.id)) if saved else None
        state, detail, due = _state(rule, agent, row, mode, finding, now, ctx.modes)
        entries.append(
            {
                "agent_id": agent.id,
                "agent": agent.name,
                "status": agent.status,
                "platform": platform(agent),
                "reasons": reasons,
                "since": ids.isoformat(row.since if row else now),
                "warned_at": ids.isoformat(row.warned_at) if row else None,
                "due_at": ids.isoformat(due),
                "state": state,
                "detail": detail,
                "finding_id": finding.id if finding else None,
            }
        )
    order = {"due": 0, "waiting": 1, "exempt": 2, "cannot": 3, "monitored": 4, "acted": 5, "off": 6}
    entries.sort(key=lambda e: (order[e["state"]], e["due_at"] or "", e["agent"]))
    due_now = sum(1 for e in entries if e["state"] == "due")
    running, why = True, ""
    if feature == features.OFF:
        running, why = False, f"the {FEATURE} feature is off"
    elif not features.is_on(session, POSTURE):
        running, why = False, "posture checks are off: rules run after each posture scan"
    elif mode == features.OFF:
        running, why = False, "the rule is off"
    return {
        "rule": rule.name if saved else None,
        "action": rule.action,
        "mode": mode,
        "running": running,
        "why_not": why,
        "matching": len(entries),
        "due": due_now,
        "held_back": due_now > rule.max_actions,
        "max_actions": rule.max_actions,
        "agents": entries[:PREVIEW_LIMIT],
        "unknown": unknown[:PREVIEW_LIMIT],
        "unknown_count": len(unknown),
    }


def for_agent(session: Session, agent: Agent) -> list[dict[str, Any]]:
    """The rules that match the agent, and what each will do or did."""
    feature = features.mode(session, FEATURE)
    modes = features.modes(session)
    out = []
    now = ids.utcnow()
    for row, rule in session.execute(
        select(RuleMatch, ManagementRule)
        .join(ManagementRule, ManagementRule.id == RuleMatch.rule_id)
        .where(RuleMatch.agent_id == agent.id)
        .order_by(ManagementRule.name)
    ):
        mode = effective(rule.mode, feature)
        state, detail, due = _state(
            rule, agent, row, mode, _finding(session, _key(rule, agent.id)), now, modes
        )
        out.append(
            {
                "rule": rule.name,
                "description": rule.description,
                "action": rule.action,
                "mode": mode,
                "since": ids.isoformat(row.since),
                "warned_at": ids.isoformat(row.warned_at),
                "due_at": ids.isoformat(due),
                "acted_at": ids.isoformat(row.acted_at),
                "outcome": row.outcome,
                "state": state,
                "detail": detail,
            }
        )
    return out

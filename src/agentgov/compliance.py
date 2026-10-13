"""Compliance reports: what AgentGov does towards the EU AI Act, ISO/IEC 42001 and the
NIST AI RMF, whether that is set up here, and the evidence it holds (docs/evidence.md).

A report doesn't say that an organisation complies: that depends on its AI systems, its
processes and its people, and on assessors. It says first how much of the agents AgentGov
saw in the period, and how (coverage): a control only works for the agents it sees. Then,
control by control, it says what the framework asks, what AgentGov does towards it, how
far that is set up in this deployment (in place, partly, configured but not observed in
the period, not set up, or outside what AgentGov does), and the evidence: counts from the
registry and the ledger over the period, and where to look. An evidence pack
bundles the reports with the ledger for the period, the checkpoints and their
time-stamps, the inventory and the registry as code, so that an assessor can check them
without access to AgentGov.
"""

from __future__ import annotations

import contextlib
import json
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from tempfile import SpooledTemporaryFile
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentgov import __version__, ids, ledger, transparency
from agentgov.config import LEDGER_MIN_DAYS, Settings
from agentgov.models import (
    ACTIVE,
    BLOCKED,
    DELETED,
    DISCOVERED,
    PENDING,
    AccessAssignment,
    Agent,
    Blueprint,
    Destination,
    Finding,
    IntegrationState,
    LedgerCheckpoint,
    LedgerEntry,
    ManagementRule,
    ModelProvider,
    PlatformAgent,
    PlatformSync,
    Team,
    ToolServer,
)
from agentgov.registry import features, posture
from agentgov.registry import scopes as scope_rules

# CONFIGURED: set up, but nothing in the period shows it working (no call through the
# gateway, no scan run, nothing delivered).
IN_PLACE, PARTLY, CONFIGURED, NOT_SET_UP, ATTENTION, OUTSIDE = (
    "in_place",
    "partly",
    "configured",
    "not_set_up",
    "attention",
    "outside",
)
STATUSES = (IN_PLACE, PARTLY, CONFIGURED, NOT_SET_UP, ATTENTION, OUTSIDE)
STATUS_NAMES = {
    IN_PLACE: "In place",
    PARTLY: "Partly",
    CONFIGURED: "Configured, not observed",
    NOT_SET_UP: "Not set up",
    ATTENTION: "Needs attention",
    OUTSIDE: "Outside AgentGov",
}
MAX_DAYS = 3650
# The controls at the gateway that make calls safe, as Article 15 and MEASURE 2.7 ask.
SAFEGUARDS = (
    "least-privilege",
    "data-protection",
    "prompt-injection",
    "jailbreak-detection",
    "tool-integrity",
    "unknown-callers",
)


@dataclass(frozen=True)
class Framework:
    key: str
    title: str
    url: str
    note: str


FRAMEWORKS = {
    f.key: f
    for f in (
        Framework(
            "eu-ai-act",
            "EU AI Act (Regulation (EU) 2024/1689)",
            "https://artificialintelligenceact.eu/",
            "As amended by Regulation (EU) 2026/1744: the obligations for high-risk AI "
            "systems apply from 2 December 2027 (Annex III) and 2 August 2028 (Annex I). "
            "Whether an agent is a high-risk AI system, and whether you are its provider or "
            "its deployer, decides which articles apply to it.",
        ),
        Framework(
            "iso-42001",
            "ISO/IEC 42001:2023, Annex A",
            "https://www.iso.org/standard/81230.html",
            "The Annex A controls an AI management system selects, as far as AgentGov's "
            "records bear on them. The management system itself (policy, objectives, "
            "competence, internal audit) is the organisation's.",
        ),
        Framework(
            "nist-ai-rmf",
            "NIST AI Risk Management Framework 1.0 (NIST AI 100-1)",
            "https://www.nist.gov/itl/ai-risk-management-framework",
            "Subcategories of the GOVERN, MAP, MEASURE and MANAGE functions that AgentGov's "
            "records and controls bear on. NIST is updating the framework; the Generative "
            "AI Profile (NIST AI 600-1) adds to it.",
        ),
    )
}


@dataclass
class Facts:
    """What the reports draw on, read once."""

    now: datetime
    since: datetime
    settings: Settings
    modes: dict[str, str]
    agents: list[Agent]
    # Controls' exceptions: their mode for some agents (docs/features.md#exceptions).
    exceptions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    entries: int = 0
    by_type: Counter[str] = field(default_factory=Counter)
    denied: int = 0
    monitored: int = 0
    chain: dict[str, Any] = field(default_factory=dict)
    checkpoints: int = 0
    stamped: int = 0
    latest_stamp: datetime | None = None
    archives: int = 0
    oldest: datetime | None = None
    findings_open: Counter[str] = field(default_factory=Counter)
    findings_raised: int = 0
    findings_resolved: int = 0
    acknowledged: int = 0
    teams: int = 0
    default_team: bool = False
    blueprints: int = 0
    servers: Counter[str] = field(default_factory=Counter)
    unverified_servers: int = 0
    providers: int = 0
    destinations: int = 0
    failing_destinations: int = 0
    rules_enforced: int = 0
    packages_active: int = 0
    # What AgentGov saw of each agent in the period: its calls checked by AgentGov's
    # policies (a decision about it), its activity (telemetry, its platform's usage logs),
    # or its platform's inventory read.
    checked: set[str] = field(default_factory=set)
    platform_seen: set[str] = field(default_factory=set)
    # The platforms read in the period, and those whose last read is older, or failed.
    platforms_read: list[str] = field(default_factory=list)
    platforms_not_read: list[str] = field(default_factory=list)
    posture_scanned_at: datetime | None = None
    # Destinations that delivered something to the security team in the period.
    delivered: int = 0

    def count(self, *prefixes: str) -> int:
        return sum(n for t, n in self.by_type.items() if t.startswith(prefixes))


def facts(session: Session, settings: Settings, days: int, now: datetime | None = None) -> Facts:
    now = now or ids.utcnow()
    since = now - timedelta(days=days)
    agents = list(session.scalars(select(Agent).where(Agent.status != DELETED)).unique())
    f = Facts(now, since, settings, features.modes(session), agents)
    f.exceptions = features.all_scopes(session)
    for type_, decision, n in session.execute(
        select(LedgerEntry.type, LedgerEntry.decision, func.count())
        .where(LedgerEntry.ts >= since)
        .group_by(LedgerEntry.type, LedgerEntry.decision)
    ):
        f.by_type[type_] += n
        f.entries += n
        if type_.startswith("decision.") and decision == "deny":
            f.denied += n
    f.monitored = session.scalar(
        select(func.count())
        .select_from(LedgerEntry)
        .where(
            LedgerEntry.ts >= since,
            LedgerEntry.type.startswith("decision."),
            LedgerEntry.reason.startswith("monitored:"),
        )
    )
    f.chain = ledger.verify(session)
    points = list(session.scalars(select(LedgerCheckpoint)))
    f.checkpoints = len(points)
    stamps = [p.timestamped_at for p in points if p.timestamp is not None and p.timestamped_at]
    f.stamped, f.latest_stamp = len(stamps), max(stamps, default=None)
    f.archives = sum(1 for p in points if p.archive)
    f.oldest = session.scalar(select(func.min(LedgerEntry.ts)))
    f.findings_open = Counter(
        dict(
            session.execute(
                select(Finding.severity, func.count())
                .where(Finding.status == "open")
                .group_by(Finding.severity)
            ).all()
        )
    )
    f.findings_raised = session.scalar(
        select(func.count()).select_from(Finding).where(Finding.first_seen >= since)
    )
    f.findings_resolved = session.scalar(
        select(func.count()).select_from(Finding).where(Finding.resolved_at >= since)
    )
    f.acknowledged = session.scalar(
        select(func.count()).select_from(Finding).where(Finding.acknowledged_at >= since)
    )
    teams = list(session.scalars(select(Team)))
    f.teams, f.default_team = len(teams), any(t.is_default for t in teams)
    f.blueprints = session.scalar(select(func.count()).select_from(Blueprint))
    servers = list(session.scalars(select(ToolServer)))
    f.servers = Counter(s.status for s in servers)
    f.unverified_servers = sum(
        1 for s in servers if s.status == "approved" and s.trust_level != "verified"
    )
    f.providers = session.scalar(select(func.count()).select_from(ModelProvider))
    destinations = list(session.scalars(select(Destination).where(Destination.status == "active")))
    f.destinations = len(destinations)
    f.failing_destinations = sum(1 for d in destinations if d.failures >= 3)
    f.rules_enforced = session.scalar(
        select(func.count()).select_from(ManagementRule).where(ManagementRule.mode == "enforce")
    )
    f.packages_active = session.scalar(
        select(func.count())
        .select_from(AccessAssignment)
        .where(AccessAssignment.status == "active")
    )
    f.checked = set(
        session.scalars(
            select(LedgerEntry.agent_id)
            .where(
                LedgerEntry.ts >= since,
                LedgerEntry.type.startswith("decision."),
                LedgerEntry.agent_id.is_not(None),
            )
            .distinct()
        )
    )
    f.platform_seen = set(
        session.scalars(
            select(PlatformAgent.agent_id).where(PlatformAgent.synced_at >= since).distinct()
        )
    )
    for sync in session.scalars(select(PlatformSync).order_by(PlatformSync.source)):
        read = sync.ok and sync.synced_at >= since
        (f.platforms_read if read else f.platforms_not_read).append(sync.source)
    scanned = session.get(IntegrationState, posture.SCANNED)
    at = (scanned.data or {}).get("at") if scanned is not None else None
    f.posture_scanned_at = datetime.fromisoformat(at) if at else None
    f.delivered = sum(
        1 for d in destinations if d.delivered_at is not None and d.delivered_at >= since
    )
    return f


def coverage(f: Facts) -> dict[str, Any]:
    """How much of the agents AgentGov saw in the period, and how. Each agent counts once,
    by the most AgentGov saw of it: its calls checked by AgentGov's policies (at the
    gateway, in the agent's own process, or by Copilot Studio's threat detection); its
    activity only (telemetry, its platform's usage logs); its platform's inventory only
    (its settings, not what it did); or nothing."""
    seen: dict[str, list[str]] = {"calls_checked": [], "activity": [], "inventory": [], "none": []}
    for a in f.agents:
        if a.id in f.checked:
            how = "calls_checked"
        elif a.last_seen_at is not None and a.last_seen_at >= f.since:
            how = "activity"
        elif a.id in f.platform_seen:
            how = "inventory"
        else:
            how = "none"
        seen[how].append(a.name)
    return {
        "agents": len(f.agents),
        "calls_checked": len(seen["calls_checked"]),
        "activity_only": len(seen["activity"]),
        "inventory_only": len(seen["inventory"]),
        "not_seen": len(seen["none"]),
        # A few of those not seen, by name, to look into.
        "not_seen_names": sorted(seen["none"], key=str.lower)[:20],
        "platforms_read": f.platforms_read,
        "platforms_not_read": f.platforms_not_read,
        "posture_scanned_at": ids.isoformat(f.posture_scanned_at),
    }


# ------------------------------------------------------------------ capabilities


@dataclass
class Assessment:
    status: str
    does: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def _row(label: str, value: Any, link: str | None = None) -> dict[str, Any]:
    return {"label": label, "value": value, "link": link}


def _on(f: Facts, key: str) -> bool:
    return f.modes.get(key, "off") != "off"


def _logging(f: Facts) -> Assessment:
    a = Assessment(
        IN_PLACE,
        "Every policy decision on a tool call, model call or call between agents, every "
        "approval, lifecycle change and administrator action is in the ledger, a hash chain "
        "anyone can verify; checkpoints keep its head, time-stamped by an authority when "
        "one is set.",
        [
            _row("Ledger entries in the period", f.entries, "#/ledger"),
            _row("Policy decisions recorded", f.count("decision."), "#/ledger?type=decision.*"),
            _row(
                "Chain",
                f"verifies ({f.chain.get('checked', 0)} entries)"
                if f.chain.get("valid")
                else f"broken at entry {f.chain.get('broken_at')}",
                "#/ledger",
            ),
            _row("Checkpoints", f.checkpoints, "#/ledger"),
            _row("Checkpoints time-stamped", f.stamped, "#/ledger"),
        ],
    )
    if not f.chain.get("valid"):
        a.status = ATTENTION
        a.gaps.append("The ledger's chain is broken: find out why before relying on it.")
    elif not f.settings.ledger_tsa_url:
        a.status = PARTLY
        a.gaps.append(
            "Set AGENTGOV_LEDGER_TSA_URL, so that a time-stamping authority vouches for the "
            "ledger's checkpoints outside AgentGov."
        )
    return a


def _retention(f: Facts) -> Assessment:
    days = f.settings.ledger_retention_days
    kept = (
        "every entry is kept in the database"
        if days == 0
        else f"entries stay {days} days in the database, then go to archives"
    )
    a = Assessment(
        IN_PLACE,
        f"The ledger keeps its records at least six months: {kept}. Archives are checked "
        "link by link as they are written, and verify offline.",
        [
            _row(
                "Oldest entry in the database",
                ids.isoformat(f.oldest) if f.oldest else "none yet",
                "#/ledger",
            ),
            _row("Archives", f.archives, "#/ledger"),
            _row("Ledger retention", f"{days} days" if days else "everything"),
        ],
    )
    if days and days < LEDGER_MIN_DAYS:  # settings refuse this; belt and braces
        a.status = ATTENTION
    return a


def _oversight(f: Facts) -> Assessment:
    approvals = f.modes.get("approvals", "off")
    a = Assessment(
        IN_PLACE,
        "People oversee agents as they run: destructive tool calls wait for an approver or "
        "the person the agent acts for, the kill switch stops an agent everywhere within a "
        "second, and controls can be watched in monitor mode before they are enforced.",
        [
            _row("Approval requests", f.by_type["approval.requested"], "#/approvals"),
            _row(
                "Decided",
                f.by_type["approval.approved"] + f.by_type["approval.denied"],
                "#/approvals/history",
            ),
            _row(
                "Agents blocked (kill switch)",
                f.by_type["agent.block"],
                "#/ledger?type=agent.block",
            ),
            _row("Human approval", approvals, "#/features"),
        ],
    )
    if approvals == "off":
        a.status = PARTLY
        a.gaps.append("Human approval is off: destructive tool calls don't wait for anyone.")
    return a


def _security(f: Facts) -> Assessment:
    modes = {k: f.modes.get(k, "off") for k in SAFEGUARDS}
    weak = [k for k, m in modes.items() if m != "enforce"]
    # Calls AgentGov's own policies decided (Copilot Studio's threat detection decides on
    # its agents' calls, but doesn't apply these safeguards).
    decided = f.count("decision.") - f.by_type["decision.copilot_studio"]
    a = Assessment(
        IN_PLACE,
        "Every call through the gateway is checked: only the tools, models and agents granted, "
        "personal data masked, credentials refused, prompt injection and jailbreaks caught, "
        "tool definitions pinned, unknown callers refused; agents' risk scores block them "
        "when they climb.",
        [
            _row("Calls checked", decided, "#/ledger?type=decision.*"),
            _row("Calls refused", f.denied, "#/ledger?decision=deny"),
            _row("Let through in monitor mode", f.monitored, "#/ledger?decision=monitored"),
            _row(
                "Agents whose calls were checked",
                f"{len(f.checked)} of {len(f.agents)}",
                "#/agents",
            ),
            *(_row(k, m, "#/features") for k, m in modes.items()),
        ],
    )
    if weak:
        a.status = PARTLY if len(weak) < len(SAFEGUARDS) else NOT_SET_UP
        a.gaps.append(f"Not enforced: {', '.join(weak)}.")
    # Enforced, but not for every agent: exceptions, and agents exempt by their label.
    partly = [
        f"{key} ("
        + "; ".join(
            f"{e['mode']} for {scope_rules.describe(e['scope'])}"
            for e in f.exceptions.get(key, [])
            if e["mode"] != "enforce"
        )
        + ")"
        for key in SAFEGUARDS
        if modes[key] == "enforce"
        and any(e["mode"] != "enforce" for e in f.exceptions.get(key, []))
    ]
    exempt = sorted(a.name for a in f.agents if features.exempted(a) & set(SAFEGUARDS))
    if partly:
        a.gaps.append(f"Enforced, but not for some agents: {', '.join(partly)}.")
    if exempt:
        a.gaps.append(
            f"Exempt from enforcement by their {features.EXEMPT_LABEL} label: "
            f"{', '.join(exempt[:10])}"
            + (f" and {len(exempt) - 10} more." if len(exempt) > 10 else ".")
        )
    if (partly or exempt) and a.status == IN_PLACE:
        a.status = PARTLY
    if not decided and a.status in (IN_PLACE, PARTLY):
        a.status = CONFIGURED
        a.gaps.append(
            "No call went through AgentGov's checks in the period: the safeguards are set, "
            "but nothing shows them working. Send agents' calls through the gateway."
        )
    return a


def _inventory(f: Facts) -> Assessment:
    by = Counter(a.status for a in f.agents)
    a = Assessment(
        IN_PLACE,
        "The registry is the inventory of agents, on the gateway and on Microsoft 365 and "
        "Copilot Studio, with blueprints, tool servers and model providers; agents nobody "
        "registered are discovered from their traffic and telemetry.",
        [
            _row("Agents", len(f.agents), "#/agents"),
            _row("Active", by[ACTIVE], "#/agents"),
            _row("Discovered, not managed", by[DISCOVERED], "#/agents"),
            _row("Blueprints", f.blueprints, "#/policies"),
            _row("Tool servers approved", f.servers["approved"], "#/toolservers"),
            _row("Model providers", f.providers, "#/models"),
        ],
    )
    if f.platforms_read or f.platforms_not_read:
        a.evidence.append(
            _row(
                "Platforms read in the period", ", ".join(f.platforms_read) or "none", "#/platforms"
            )
        )
    if by[DISCOVERED]:
        a.status = PARTLY
        a.gaps.append(f"{by[DISCOVERED]} discovered agent(s) to adopt or block.")
    if not _on(f, "discovery"):
        a.status = PARTLY
        a.gaps.append("Shadow-agent discovery is off.")
    if f.platforms_not_read:
        if not f.platforms_read and a.status == IN_PLACE:
            a.status = CONFIGURED
        elif a.status == IN_PLACE:
            a.status = PARTLY
        a.gaps.append(
            f"Not read in the period, or the last read failed: {', '.join(f.platforms_not_read)}. "
            "What AgentGov holds about their agents may be out of date."
        )
    return a


def _roles(f: Facts) -> Assessment:
    managed = [a for a in f.agents if a.status in (ACTIVE, PENDING, BLOCKED)]
    no_owner = sum(1 for a in managed if not a.owner)
    no_sponsor = sum(1 for a in managed if not a.sponsors)
    a = Assessment(
        IN_PLACE,
        "Each agent has an owner, accountable sponsors and a team, and issues about it go "
        "to them; the people who govern agents have roles (administrator, approver, "
        "security operations, auditor).",
        [
            _row("Agents managed", len(managed), "#/agents"),
            _row("Without an owner", no_owner, "#/findings"),
            _row("Without a sponsor", no_sponsor, "#/findings"),
            _row("Teams", f.teams, "#/findings/teams"),
        ],
    )
    if no_owner or no_sponsor:
        a.status = PARTLY
        a.gaps.append("Give every agent an owner and a sponsor (a management rule can help).")
    if not f.default_team:
        a.status = PARTLY
        a.gaps.append("Choose a default team, for the issues no other team owns.")
    return a


def _monitoring(f: Facts) -> Assessment:
    a = Assessment(
        IN_PLACE,
        "AgentGov watches agents in production: posture checks and risk scores, findings "
        "from the gateway and from Microsoft's services, issues sent to each agent's people "
        "until someone takes them on, and management rules for what lasts.",
        [
            _row("Findings raised in the period", f.findings_raised, "#/findings"),
            _row("Resolved in the period", f.findings_resolved, "#/findings"),
            _row("Acknowledged in the period", f.acknowledged, "#/findings"),
            _row(
                "Open, high or critical",
                f.findings_open["high"] + f.findings_open["critical"],
                "#/findings",
            ),
            _row("Management rules enforced", f.rules_enforced, "#/policies"),
            _row(
                "Last posture scan",
                ids.isoformat(f.posture_scanned_at) if f.posture_scanned_at else "none",
                "#/findings",
            ),
        ],
    )
    for key, what in (
        ("posture-checks", "Posture checks"),
        ("issues", "Issues to the people responsible"),
    ):
        if not _on(f, key):
            a.status = PARTLY
            a.gaps.append(f"{what} are off.")
    if _on(f, "posture-checks") and (
        f.posture_scanned_at is None or f.posture_scanned_at < f.since
    ):
        if a.status == IN_PLACE:
            a.status = CONFIGURED
        a.gaps.append(
            "Posture checks are on, but none ran in the period: see the scan interval "
            "(AGENTGOV_POSTURE_INTERVAL_SECONDS), or scan now from Findings."
        )
    return a


def _incidents(f: Facts) -> Assessment:
    a = Assessment(
        IN_PLACE,
        "Findings reach the people responsible as issues, and the security team's SIEMs and "
        "chats get the ledger and alerts as they happen; reporting serious incidents to "
        "authorities stays with the organisation.",
        [
            _row("Critical findings open", f.findings_open["critical"], "#/findings"),
            _row("Destinations for the security team", f.destinations, "#/secops"),
            _row("Delivered in the period", f.delivered, "#/secops"),
            _row("Failing destinations", f.failing_destinations, "#/secops"),
            _row(
                "Hand-off to security operations",
                f.modes.get("security-operations", "off"),
                "#/features",
            ),
        ],
    )
    if not _on(f, "security-operations") or not f.destinations:
        a.status = PARTLY
        a.gaps.append("Hand the ledger to the security team: a destination, and the hand-off on.")
    elif not f.delivered and a.status == IN_PLACE:
        a.status = CONFIGURED
        a.gaps.append(
            "Nothing reached the security team's destinations in the period: send a test "
            "from Security operations."
        )
    if f.failing_destinations:
        a.status = ATTENTION
        a.gaps.append("A destination is failing: the security team isn't getting everything.")
    return a


def _risk(f: Facts) -> Assessment:
    risky = sum(1 for a in f.agents if a.risk_level in ("high", "critical"))
    a = Assessment(
        IN_PLACE,
        "Agents' risk is assessed continuously: a risk tier from their blueprint, a score "
        "from what they do (refusals, credentials, injections, jailbreaks), posture "
        "findings, and the level at which they are blocked.",
        [
            _row("Agents at high or critical risk", risky, "#/agents"),
            _row("Findings raised in the period", f.findings_raised, "#/findings"),
            _row("Risk-based access", f.modes.get("risk-based-access", "off"), "#/features"),
        ],
    )
    if f.modes.get("risk-based-access", "off") != "enforce":
        a.status = PARTLY
        a.gaps.append("Risk-based access isn't enforced: risky agents aren't blocked.")
    return a


def _third_parties(f: Facts) -> Assessment:
    a = Assessment(
        IN_PLACE,
        "Agents reach only the tool servers and model providers administrators approved, "
        "reviewed and pinned; developers' MCP servers are checked against the approved "
        "ones, and Copilot Studio's connectors against an allowlist.",
        [
            _row("Tool servers approved", f.servers["approved"], "#/toolservers"),
            _row("Approved but unverified", f.unverified_servers, "#/toolservers"),
            _row("Waiting for review", f.servers[PENDING], "#/toolservers"),
            _row("Model providers", f.providers, "#/models"),
        ],
    )
    if f.unverified_servers:
        a.status = PARTLY
        a.gaps.append("Verify the approved tool servers' publishers and code.")
    return a


def _deactivation(f: Facts) -> Assessment:
    a = Assessment(
        IN_PLACE,
        "Agents can be stopped at once (block, the kill switch), quarantined on their "
        "platform, deleted and restored within the retention period, and their temporary "
        "access revoked; management rules do it for agents that meet their conditions, "
        "after telling their people.",
        [
            _row("Blocked in the period", f.by_type["agent.block"], "#/ledger?type=agent.block"),
            _row("Deleted in the period", f.by_type["agent.delete"], "#/ledger?type=agent.delete"),
            _row("Management rules enforced", f.rules_enforced, "#/policies"),
        ],
    )
    return a


def _deployment(f: Facts) -> Assessment:
    pending = sum(1 for a in f.agents if a.status == PENDING)
    a = Assessment(
        IN_PLACE,
        "Agents are registered against IT-approved blueprints and wait for an administrator "
        "before they get credentials; what they may call is what their blueprint grants.",
        [
            _row(
                "Registered in the period", f.by_type["agent.registered"], "#/ledger?type=agent.*"
            ),
            _row(
                "Approved in the period", f.by_type["agent.approve"], "#/ledger?type=agent.approve"
            ),
            _row("Waiting for approval", pending, "#/agents"),
            _row(
                "Registration approval", f.modes.get("registration-approval", "off"), "#/features"
            ),
        ],
    )
    if not _on(f, "registration-approval"):
        a.status = PARTLY
        a.gaps.append("Registration approval is off: agents are active as soon as they register.")
    return a


def _review(f: Facts) -> Assessment:
    managed = [a for a in f.agents if a.status in (ACTIVE, BLOCKED)]
    overdue = sum(
        1
        for a in managed
        if a.attestation_expires_at is not None and a.attestation_expires_at < f.now
    )
    a = Assessment(
        IN_PLACE,
        "Sponsors confirm, every so often, that each agent is still needed; access held for a "
        "while is reviewed and expires; issues and posture checks keep coming back until the "
        "cause is fixed.",
        [
            _row(
                "Attestations in the period",
                f.by_type["agent.attested"],
                "#/ledger?type=agent.attested",
            ),
            _row("Attestations overdue", overdue, "#/findings"),
            _row("Access packages held", f.packages_active, "#/policies"),
            _row(
                "Access reviews in the period",
                f.by_type["access.reviewed"],
                "#/ledger?type=access.*",
            ),
        ],
    )
    if overdue:
        a.status = PARTLY
        a.gaps.append(f"{overdue} agent(s) past their attestation.")
    return a


def _interaction(f: Facts) -> Assessment:
    a = Assessment(
        IN_PLACE,
        "Calls between agents go through the gateway over A2A, under the same controls as "
        "tool calls, with the chain of agents and the person at its head in every decision.",
        [
            _row("Calls between agents", f.count("decision.a2a."), "#/ledger?type=decision.a2a.*"),
            _row("Agent-to-agent gateway", f.modes.get("a2a-gateway", "off"), "#/features"),
        ],
    )
    if not _on(f, "a2a-gateway"):
        a.status = PARTLY
        a.gaps.append("The agent-to-agent gateway is off: calls between agents aren't governed.")
    elif not f.count("decision.a2a."):
        a.status = CONFIGURED
        a.gaps.append(
            "No call between agents went through the gateway in the period: if agents call "
            "each other, they do it around it."
        )
    return a


def _outside(what: str) -> Callable[[Facts], Assessment]:
    def assess(f: Facts) -> Assessment:
        return Assessment(OUTSIDE, what)

    return assess


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    asks: str
    assess: Callable[[Facts], Assessment]


CONTROLS: dict[str, tuple[Control, ...]] = {
    "eu-ai-act": (
        Control("Art. 4", "AI literacy", "Providers and deployers take measures to support "
                "the AI literacy of their staff.",
                _outside("Training people is the organisation's. AgentGov's issues, "
                         "approvals and previews put the people responsible in the loop.")),
        Control("Art. 9", "Risk management system", "A continuous, iterative process that "
                "identifies, evaluates and mitigates risks throughout the lifecycle.", _risk),
        Control("Art. 12", "Record-keeping", "High-risk AI systems record logs automatically "
                "over their lifetime, to trace risks, modifications and their monitoring.",
                _logging),
        Control("Art. 14", "Human oversight", "Systems are effectively overseen by natural "
                "persons, who can override or reverse their output and stop them.", _oversight),
        Control("Art. 15", "Accuracy, robustness and cybersecurity", "Systems resist errors, "
                "faults and attempts to alter their use or behaviour.", _security),
        Control("Art. 19, 26(6)", "Keeping the logs", "Providers and deployers keep the logs "
                "under their control for at least six months.", _retention),
        Control("Art. 26(2)", "Oversight by competent people", "Deployers assign human "
                "oversight to people with the competence, training and authority for it.",
                _roles),
        Control("Art. 26(5)", "Monitoring the operation", "Deployers monitor the system's "
                "operation and inform the provider of risks and serious incidents.",
                _monitoring),
        Control("Art. 72", "Post-market monitoring", "Providers monitor systems in use, "
                "including their interaction with other AI systems.", _interaction),
        Control("Art. 73", "Serious incidents", "Serious incidents are reported to market "
                "surveillance authorities, within 15 days at the latest.", _incidents),
    ),
    "iso-42001": (
        Control("A.3.2", "AI roles and responsibilities", "Roles and responsibilities for AI "
                "are defined and allocated.", _roles),
        Control("A.4.2", "Resource documentation", "The resources of AI systems are "
                "identified and documented.", _inventory),
        Control("A.4.4", "Tooling resources", "The tools AI systems use are documented.",
                _third_parties),
        Control("A.5.2", "AI system impact assessment process", "A process assesses the "
                "consequences of AI systems for individuals, groups and society.",
                _outside("Impact assessments are the organisation's. Blueprints carry each "
                         "class of agents' risk tier, and the ledger what agents did.")),
        Control("A.6.2.5", "AI system deployment", "Deployment is planned and meets its "
                "requirements before it happens.", _deployment),
        Control("A.6.2.6", "AI system operation and monitoring", "AI systems are operated "
                "and monitored as intended.", _monitoring),
        Control("A.6.2.8", "AI system recording of event logs", "Event logs are recorded "
                "while AI systems are in use.", _logging),
        Control("A.8.4", "Communication of incidents", "Incidents are communicated to the "
                "people who need to know.", _incidents),
        Control("A.9.2", "Processes for responsible use of AI systems", "Processes keep the "
                "use of AI systems responsible.", _oversight),
        Control("A.9.4", "Intended use of the AI system", "AI systems are used as intended "
                "and documented.", _security),
        Control("A.10.3", "Suppliers", "AI products and services from suppliers fit the "
                "organisation's approach to responsible AI.", _third_parties),
    ),
    "nist-ai-rmf": (
        Control("GOVERN 1.5", "Ongoing monitoring and periodic review", "The risk "
                "management process and its outcomes are monitored and reviewed periodically.",
                _review),
        Control("GOVERN 1.6", "Inventory", "Mechanisms are in place to inventory AI systems.",
                _inventory),
        Control("GOVERN 2.1", "Roles and responsibilities", "Roles, responsibilities and "
                "lines of communication for AI risks are documented.", _roles),
        Control("MAP 4.1", "Third-party risks", "Risks from third-party data, software and "
                "AI technologies are mapped and controlled.", _third_parties),
        Control("MEASURE 2.4", "Monitored in production", "The AI system's functionality "
                "and behaviour are monitored when in production.", _monitoring),
        Control("MEASURE 2.7", "Security and resilience", "Security and resilience are "
                "evaluated and documented.", _security),
        Control("MEASURE 3.1", "Emergent risks", "Existing, unanticipated and emergent AI "
                "risks are tracked.", _risk),
        Control("MANAGE 2.4", "Supersede, disengage, deactivate", "Mechanisms supersede, "
                "disengage or deactivate AI systems that perform outside their intended use.",
                _deactivation),
        Control("MANAGE 4.1", "Post-deployment monitoring", "Post-deployment monitoring "
                "plans are implemented, with override, decommissioning and incident response.",
                _oversight),
        Control("MANAGE 4.3", "Incidents communicated", "Incidents and errors are "
                "communicated to the relevant AI actors.", _incidents),
    ),
}  # fmt: skip


# ----------------------------------------------------------------------- reports


def report(f: Facts, framework: str) -> dict[str, Any]:
    if framework not in FRAMEWORKS:
        raise KeyError(framework)
    fw = FRAMEWORKS[framework]
    controls = []
    for control in CONTROLS[framework]:
        a = control.assess(f)
        controls.append(
            {
                "id": control.id,
                "title": control.title,
                "asks": control.asks,
                "agentgov": a.does,
                "status": a.status,
                "evidence": a.evidence,
                "gaps": a.gaps,
            }
        )
    return {
        "framework": {"key": fw.key, "title": fw.title, "url": fw.url, "note": fw.note},
        "period": {
            "from": ids.isoformat(f.since),
            "to": ids.isoformat(f.now),
            "days": (f.now - f.since).days,
        },
        "generated_at": ids.isoformat(f.now),
        "agentgov": __version__,
        "ledger": {
            "valid": f.chain.get("valid"),
            "checked": f.chain.get("checked"),
            "from": f.chain.get("from"),
            "head": f.chain.get("head"),
            "checkpoints": f.checkpoints,
            "timestamped": f.stamped,
            "last_timestamp": ids.isoformat(f.latest_stamp),
        },
        "coverage": coverage(f),
        "summary": {s: sum(1 for c in controls if c["status"] == s) for s in STATUSES},
        "controls": controls,
    }


def markdown(reports: list[dict[str, Any]]) -> str:
    """The reports as a document people read."""
    names = STATUS_NAMES
    out: list[str] = []
    for r in reports:
        fw, period = r["framework"], r["period"]
        out += [
            f"# {fw['title']}",
            "",
            f"From {period['from']} to {period['to']}, generated by AgentGov {r['agentgov']}.",
            "",
            fw["note"],
            "",
            "This report says what AgentGov does towards each control, how far that is set "
            "up, and the evidence it holds. It doesn't say that the organisation complies.",
            "",
            *_coverage_lines(r["coverage"]),
            "| Control | Status | Evidence |",
            "|---|---|---|",
        ]
        for c in r["controls"]:
            evidence = "; ".join(f"{e['label']}: {e['value']}" for e in c["evidence"]) or "—"
            out.append(f"| {c['id']} {c['title']} | {names[c['status']]} | {evidence} |")
        out.append("")
        for c in r["controls"]:
            out += [f"## {c['id']} {c['title']}", "", f"**Asks:** {c['asks']}", ""]
            out += [f"**AgentGov:** {c['agentgov']}", ""]
            if c["gaps"]:
                out += ["**To do:**", "", *(f"* {g}" for g in c["gaps"]), ""]
        out.append("")
    return "\n".join(out)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _coverage_lines(c: dict[str, Any]) -> list[str]:
    """What AgentGov saw in the period, for the document."""
    lines = [
        "## What AgentGov saw",
        "",
        "A control only works for the agents AgentGov sees. Of the "
        f"{_count(c['agents'], 'agent')} in the inventory, in the period:",
        "",
        f"* {c['calls_checked']} had their calls checked by AgentGov's policies;",
        f"* {c['activity_only']} were seen at work (telemetry, their platform's usage logs), "
        "their calls not checked;",
        f"* {c['inventory_only']} were seen only in their platform's inventory (their "
        "settings, not what they did);",
        f"* {c['not_seen']} weren't seen at all"
        + (f": {', '.join(c['not_seen_names'])}" if c["not_seen_names"] else "")
        + ("." if c["not_seen"] <= len(c["not_seen_names"]) else ", and more."),
        "",
    ]
    if c["platforms_not_read"]:
        lines += [
            "Platforms not read in the period, or whose last read failed: "
            f"{', '.join(c['platforms_not_read'])}.",
            "",
        ]
    return lines


# ---------------------------------------------------------------- evidence pack

README = """AgentGov evidence pack
======================

reports/*.json, report.md  What AgentGov saw of the agents in the period (coverage), what
                           it does towards the EU AI Act, ISO/IEC 42001 and the NIST AI
                           RMF, how far it is set up, and the evidence.
ledger.jsonl               The ledger's entries in the period, as AgentGov wrote them.
                           Check that they are intact, and link up, with:
                             agentgov ledger verify --file ledger.jsonl
                           (the first entry's prev_hash is the hash of the entry
                           before the period, which a checkpoint or the ledger vouches for).
checkpoints.json           The ledger's checkpoints, with their archives.
checkpoints/*.txt, *.tsr   Each time-stamped checkpoint's statement and the time-stamping
                           authority's answer. Check one with:
                             openssl ts -verify -data checkpoints/N.txt -in checkpoints/N.tsr \\
                               -CAfile the-authority's-CA.pem
checkpoints/*.sigstore.json
                           Each checkpoint's entry in the transparency log (Sigstore Rekor),
                           as a Sigstore bundle; transparency-log/ holds AgentGov's key
                           (agentgov.pub), the log's (rekor.pub) and a trusted root with the
                           log. Check one offline with:
                             cosign verify-blob --key transparency-log/agentgov.pub \\
                               --bundle checkpoints/N.sigstore.json \\
                               --trusted-root transparency-log/trusted_root.json checkpoints/N.txt
                           or: agentgov ledger verify-log-entry checkpoints/N.txt \\
                               checkpoints/N.sigstore.json --log-key transparency-log/rekor.pub \\
                               --origin <the log's name, in transparency-log/log.json> \\
                               --key transparency-log/agentgov.pub
inventory.json             The agents, with their owners, sponsors, teams, status and risk.
manifests.yaml             The registry as code: blueprints, tool servers, policies, rules...
features.json              Which of AgentGov's features are on, and how strictly.
"""


def pack(session: Session, settings: Settings, days: int) -> SpooledTemporaryFile[bytes]:
    """The evidence pack for the last ``days`` days, as a zip file."""
    import base64

    from agentgov.registry import manifests

    f = facts(session, settings, days)
    reports = [report(f, key) for key in FRAMEWORKS]
    # The caller sends it, then closes it.
    out: SpooledTemporaryFile[bytes] = SpooledTemporaryFile(max_size=64 * 1024 * 1024)  # noqa: SIM115
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", README)
        for r in reports:
            z.writestr(f"reports/{r['framework']['key']}.json", json.dumps(r, indent=2))
        z.writestr("report.md", markdown(reports))
        first = session.scalar(select(func.min(LedgerEntry.seq)).where(LedgerEntry.ts >= f.since))
        with z.open("ledger.jsonl", "w") as lines:
            if first is not None:
                for entry in ledger.iter_entries(session, after=first - 1):
                    lines.write((json.dumps(ledger.to_dict(entry), sort_keys=True) + "\n").encode())
        points = list(session.scalars(select(LedgerCheckpoint).order_by(LedgerCheckpoint.seq)))
        z.writestr(
            "checkpoints.json", json.dumps([ledger.checkpoint_dict(p) for p in points], indent=2)
        )
        for p in points:
            if p.timestamp or p.tlog_entry:
                z.writestr(f"checkpoints/{p.seq}.txt", ledger.statement(p.seq, p.hash))
            if p.timestamp:
                z.writestr(f"checkpoints/{p.seq}.tsr", base64.b64decode(p.timestamp))
            if p.tlog_entry:
                with contextlib.suppress(transparency.TransparencyError):
                    found = transparency.bundle(p.tlog_entry, ledger.statement(p.seq, p.hash))
                    z.writestr(f"checkpoints/{p.seq}.sigstore.json", json.dumps(found, indent=2))
        for name, content in _transparency_log(settings).items():
            z.writestr(f"transparency-log/{name}", content)
        z.writestr("inventory.json", json.dumps([_agent(a) for a in f.agents], indent=2))
        z.writestr("manifests.yaml", manifests.dump(manifests.export(session)))
        z.writestr("features.json", json.dumps(f.modes, indent=2, sort_keys=True))
        z.writestr("feature-exceptions.json", json.dumps(f.exceptions, indent=2, sort_keys=True))
    out.seek(0)
    return out


def _transparency_log(settings: Settings) -> dict[str, str]:
    """What checks the checkpoints' log entries offline: the log, AgentGov's public key,
    the log's, and a trusted root with the log, for cosign."""
    url = settings.ledger_rekor_url
    if not url:
        return {}
    origin = settings.ledger_rekor_origin or transparency.origin_of(url)
    out = {"log.json": json.dumps({"url": url, "origin": origin}, indent=2)}
    with contextlib.suppress(transparency.TransparencyError):
        key = transparency.load_signing_key(settings.ledger_rekor_signing_key_file or "")
        out["agentgov.pub"] = transparency.public_pem(key).decode()
    if settings.ledger_rekor_log_key_file:
        with contextlib.suppress(transparency.TransparencyError):
            log_key = transparency.load_log_key(settings.ledger_rekor_log_key_file)
            out["rekor.pub"] = transparency.public_pem(log_key).decode()
            out["trusted_root.json"] = json.dumps(
                transparency.trusted_root(url, origin, log_key), indent=2
            )
    return out


def _agent(a: Agent) -> dict[str, Any]:
    return {
        "name": a.name,
        "id": a.id,
        "status": a.status,
        "owner": a.owner,
        "sponsors": list(a.sponsors or []),
        "team": a.team or (a.blueprint.team if a.blueprint else None),
        "blueprint": a.blueprint.name if a.blueprint else None,
        "platform": a.platform,
        "source": a.source,
        "environment": a.environment,
        "risk": {"level": a.risk_level, "score": a.risk_score},
        "attested_at": ids.isoformat(a.attested_at),
        "attestation_expires_at": ids.isoformat(a.attestation_expires_at),
        "last_seen_at": ids.isoformat(a.last_seen_at),
        "created_at": ids.isoformat(a.created_at),
    }

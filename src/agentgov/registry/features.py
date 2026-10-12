"""Features: which parts of AgentGov an organisation uses, and how strictly.

Every feature can be turned off. The controls the gateway enforces can also run
in monitor mode, where AgentGov decides and records what it would have done but
lets the call through (like Conditional Access's report-only mode), so a control
can be tried on real traffic before it is enforced.

A feature's mode is, in order of precedence:

* pinned by the deployment, ``AGENTGOV_FEATURES="least-privilege=monitor,discovery=off"``:
  administrators see it but can't change it in the app;
* chosen by an administrator, in the UI, the API, the CLI or a manifest;
* its default, which is how AgentGov behaves when nobody chose.

Every change, pins included, is recorded in the ledger. Each part of AgentGov
reads the modes where it acts: OPA from its bundle (``data.registry.features``),
the governance processor from OPA, the gateway's routes and the control plane's
own jobs from the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentgov import ids, ledger
from agentgov.config import Settings
from agentgov.db import mark_changed
from agentgov.models import FeatureSetting
from agentgov.registry.errors import Conflict, NotFound, ValidationError

OFF, ON, MONITOR, ENFORCE = "off", "on", "monitor", "enforce"
# Modes from the weakest to the strongest.
SWITCH = (OFF, ON)
CONTROL = (OFF, MONITOR, ENFORCE)
# How much is handed to the security team's tools (agentgov.secops.handoff).
HANDOFF = (OFF, "inform", "triage", "contain", "decide")
# Microsoft Entra's access packages for agents' identities: read, or also changed.
INFORM, MANAGE = "inform", "manage"
READ_OR_MANAGE = (OFF, INFORM, MANAGE)
DEPLOYMENT = "deployment"  # the actor of pinned modes

GROUPS = {
    "gateway": "Gateway",
    "controls": "Controls at the gateway",
    "detection": "Detection",
    "developers": "Developer tools",
    "identity": "Identity",
    "lifecycle": "Lifecycle",
    "policy": "Policy",
    "microsoft": "Microsoft",
    "platforms": "Other platforms",
    "secops": "Security operations",
}


@dataclass(frozen=True)
class Feature:
    key: str
    title: str
    group: str
    description: str
    modes: tuple[str, ...]
    default: str
    # What each mode does.
    effects: dict[str, str] = field(default_factory=dict)
    # What it needs beyond AgentGov itself, if anything.
    needs: str | None = None


CATALOG: tuple[Feature, ...] = (
    Feature(
        "mcp-gateway",
        "MCP gateway",
        "gateway",
        "Approved MCP tool servers are published on agentgateway at /mcp/<server>, where "
        "agents call them with their AgentGov token and the controls below check every call.",
        SWITCH,
        ON,
        {
            ON: "Approved tool servers are reachable through the gateway.",
            OFF: "No tool server is published on the gateway. The registry keeps them.",
        },
    ),
    Feature(
        "model-gateway",
        "Model gateway",
        "gateway",
        "Approved model providers are published on agentgateway at /llm/<provider>, where "
        "agents call models with their AgentGov token instead of the provider's API key, and "
        "the controls below check every prompt and answer.",
        SWITCH,
        ON,
        {
            ON: "Approved model providers are reachable through the gateway.",
            OFF: "No model provider is published on the gateway. The registry keeps them.",
        },
        needs="each provider's API key in a file the gateway reads",
    ),
    Feature(
        "a2a-gateway",
        "Agent-to-agent gateway",
        "gateway",
        "Agents that serve A2A (the Agent2Agent protocol) are published on agentgateway at "
        "/a2a/<agent>, where other agents call them with their AgentGov token. The controls "
        "check every call that comes through the gateway, and the chain of agents, with the "
        "person they act for, goes with it to every agent, tool and model further down. A "
        "call straight to an agent's own URL doesn't pass the gateway: AgentGov doesn't "
        "see it (calls around the gateway, below, look for those).",
        SWITCH,
        ON,
        {
            ON: "Agents with an A2A URL are reachable through the gateway.",
            OFF: "No agent is published for A2A. The registry keeps their A2A URLs.",
        },
    ),
    Feature(
        "least-privilege",
        "Least-privilege access",
        "controls",
        "Agents call only the tools, models and other agents their blueprint and their own "
        "grants allow, and see only those tools when they list a server's.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Calls to tools, models and agents an agent wasn't granted are denied.",
            MONITOR: "Agents see and call every tool, model and agent; calls they weren't "
            "granted are recorded.",
            OFF: "Grants aren't checked.",
        },
    ),
    Feature(
        "acting-for-people",
        "Acting for people",
        "controls",
        "Agents act for the people their blueprints allow: some act only for a person, with "
        "a token they got for that person, some only on their own, and some only for people "
        "in certain groups.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Calls for people a blueprint doesn't allow, or without the person it "
            "requires, are refused.",
            MONITOR: "They go through and are recorded.",
            OFF: "Who agents act for isn't checked. The ledger still records the person.",
        },
    ),
    Feature(
        "approvals",
        "Human approval",
        "controls",
        "Calls to tools their servers mark destructive, and calls organisation policies "
        "single out, wait for a person to approve them.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Such calls wait for an approver.",
            MONITOR: "They go through and are recorded as needing approval.",
            OFF: "Nothing waits for approval.",
        },
    ),
    Feature(
        "approvals-by-person",
        "Approvals by the person",
        "controls",
        "Approval requests an agent makes while it acts for a person go to that person, where "
        "its blueprint says so. People sign in to AgentGov to decide them, people without an "
        "AgentGov role too: they see only the requests sent to them.",
        SWITCH,
        OFF,
        {
            ON: "Such requests wait for the person, who signs in to decide them. "
            "Administrators can decide them too.",
            OFF: "Approvers decide every request, and people without an AgentGov role can't "
            "sign in.",
        },
        needs="AgentGov's single sign-on through the Keycloak realm that issues agents' tokens",
    ),
    Feature(
        "data-protection",
        "Data protection",
        "controls",
        "Tool calls and model calls are inspected for credentials and personal data: "
        "credentials never reach a tool or a model provider, and personal data is masked "
        "unless policy allows it.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Credentials stop the call and personal data is masked.",
            MONITOR: "What is found is recorded; nothing is stopped or masked.",
            OFF: "Content isn't inspected.",
        },
        needs="Presidio, for personal data (credentials are found without it)",
    ),
    Feature(
        "a2a-masking",
        "Masking in calls between agents",
        "controls",
        "Personal data in the messages agents send each other through the gateway is masked, "
        "unless the agent called may have it (its pii-access label). Data protection finds "
        "it, and refuses credentials in messages whatever this says. A message sent straight "
        "to an agent's own URL doesn't pass the gateway, so nothing is masked in it.",
        CONTROL,
        MONITOR,
        {
            ENFORCE: "Personal data is masked before the agent called gets the message, unless "
            "that agent may have it.",
            MONITOR: "Messages go as they are; each call's decision records what would have "
            "been masked.",
            OFF: "Messages go as they are; the personal data in them is recorded.",
        },
        needs="data protection on, to find personal data",
    ),
    Feature(
        "prompt-injection",
        "Prompt-injection defence",
        "controls",
        "Tool results that carry instructions aimed at the agent (indirect prompt "
        "injection) are kept from it, and model calls whose conversation holds one are refused.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Such results are withheld, and a finding is raised.",
            MONITOR: "They reach the agent, are recorded and raise a finding.",
            OFF: "Results aren't checked.",
        },
    ),
    Feature(
        "jailbreak-detection",
        "Jailbreak detection",
        "controls",
        "Prompts that try to talk a model out of its instructions or its safety rules "
        "(jailbreaks) are looked for in the latest message from a person in each model call. "
        "It starts in monitor mode: people's own words vary more than tool results do.",
        CONTROL,
        MONITOR,
        {
            ENFORCE: "Such prompts are refused, and a finding is raised.",
            MONITOR: "They go through, are recorded and raise a finding.",
            OFF: "Prompts aren't checked.",
        },
    ),
    Feature(
        "traffic-classifier",
        "Classifier on traffic",
        "controls",
        "IBM Granite Guardian gives a second opinion on what the prompt-injection and "
        "jailbreak checks let through: tool results, the answers agents send each other, and "
        "people's prompts to models. It follows the check it supports.",
        CONTROL,
        MONITOR,
        {
            ENFORCE: "Where the check it supports is enforced too, calls wait for its verdict "
            "(AGENTGOV_CLASSIFIER_TIMEOUT_SECONDS at most), and what it flags is withheld or "
            "refused, and raises a finding.",
            MONITOR: "It answers in the background, after the call went on: what it flags is "
            "recorded and raises a finding.",
            OFF: "It isn't asked.",
        },
        needs="IBM Granite Guardian (AGENTGOV_GUARDIAN_URL) where the processor runs",
    ),
    Feature(
        "tool-integrity",
        "Tool integrity",
        "controls",
        "Tools whose descriptions hide instructions are quarantined, and tools that change "
        "after approval are held until an administrator reviews them.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Such tools are hidden from agents and can't be called.",
            MONITOR: "They can be called; each call is recorded.",
            OFF: "Quarantine and review don't apply.",
        },
    ),
    Feature(
        "risk-based-access",
        "Risk-based access",
        "controls",
        "Agents at critical risk are refused at the gateway, and agents whose risk score "
        "reaches AGENTGOV_AUTO_BLOCK_RISK_SCORE are blocked.",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Critical-risk agents are refused, and the automatic block applies.",
            MONITOR: "Their calls go through and are recorded; the automatic block only "
            "raises a finding.",
            OFF: "Risk is scored and shown but doesn't change what agents may do.",
        },
    ),
    Feature(
        "token-budgets",
        "Token budgets",
        "controls",
        "Agents that have used their daily token budget (their own, or their blueprint's) are "
        "refused further model calls until the next day (UTC).",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "Agents over their budget are refused.",
            MONITOR: "Their calls go through and are recorded.",
            OFF: "Budgets aren't checked. Usage is still metered.",
        },
    ),
    Feature(
        "unknown-callers",
        "Unknown callers",
        "controls",
        "Callers without a registered agent's identity are refused at the gateway.",
        (MONITOR, ENFORCE),
        ENFORCE,
        {
            ENFORCE: "They are refused.",
            MONITOR: "They are let through and recorded, and with discovery on, added to the "
            "inventory as discovered agents.",
        },
    ),
    Feature(
        "external-decision-point",
        "Your own decision point",
        "policy",
        "The processor also asks an AuthZEN decision point of yours (Cedar, Cerbos, Topaz, "
        "OpenFGA, Keycloak...) about each call to a tool, a model or another agent that "
        "AgentGov's policies let through: who, the method, the tool, model or agent, and "
        "what was found in the call, never its content.",
        CONTROL,
        OFF,
        {
            ENFORCE: "Calls it denies are refused, with its reasons; calls it says need "
            "approval wait for one; what it asks to mask is masked. Unreachable, it refuses.",
            MONITOR: "Calls go as AgentGov decides; each call's decision records what it "
            "would have done.",
            OFF: "It isn't asked.",
        },
        needs="AGENTGOV_AUTHZEN_URL where the processor runs",
    ),
    Feature(
        "authzen-decision-point",
        "AgentGov as an AuthZEN decision point",
        "policy",
        "AgentGov's policies answer AuthZEN evaluations (OpenID AuthZEN 1.0) at "
        "/access/v1/evaluation on the control plane, so that enforcement points other than "
        "AgentGov's gateway can ask whether an agent may call a tool, a model or another "
        "agent.",
        SWITCH,
        OFF,
        {
            ON: "Evaluations are answered, for callers with a role that reads AgentGov, or "
            "the service token.",
            OFF: "The endpoints answer 404.",
        },
        needs="OPA (AGENTGOV_OPA_URL) where the control plane runs",
    ),
    Feature(
        "discovery",
        "Shadow-agent discovery",
        "detection",
        "Agents seen in telemetry or at the gateway that aren't registered are added to the "
        "inventory as discovered.",
        SWITCH,
        ON,
        {
            ON: "Unregistered agents appear as discovered.",
            OFF: "They aren't added; registered agents' activity is still recorded.",
        },
    ),
    Feature(
        "calls-around-gateway",
        "Calls around the gateway",
        "detection",
        "AgentGov checks the calls between agents that come through its gateway; it doesn't "
        "own the network agents run on, so a call straight to an agent's own A2A URL skips "
        "every control. AgentGov can't stop those (the network can, or the agent, by "
        "refusing calls without the delegation the gateway gives with each one); it finds "
        "them and tells the agents' owners.",
        (OFF, "watch", "test"),
        "watch",
        {
            "test": "As watch, and each posture scan also calls each agent's A2A URL itself, "
            "without a delegation, as a call around the gateway would, and records what "
            "happened: an agent that takes the call is an issue for its owners.",
            "watch": "Telemetry that shows a call straight to an agent's A2A URL is recorded "
            "and is an issue for both agents' owners, as is an agent whose owners haven't "
            "said what stops such calls. AgentGov calls no agent itself.",
            OFF: "Nothing is looked for. What agents' owners said is kept.",
        },
        needs="posture checks on, for the test",
    ),
    Feature(
        "posture-checks",
        "Posture checks",
        "detection",
        "A regular scan raises findings for agents without owners or sponsors, attestations "
        "that are due, stale agents, broad grants and tool servers awaiting review.",
        SWITCH,
        ON,
        {
            ON: "The scan runs every AGENTGOV_POSTURE_INTERVAL_SECONDS, and on demand.",
            OFF: "No scans. Findings already raised stay until they are resolved.",
        },
    ),
    Feature(
        "instruction-checks",
        "Instruction checks",
        "detection",
        "Agents' instructions (their system prompts) are checked for unsafe content by "
        "AgentGov's rules, and by IBM Granite Guardian where it is configured.",
        SWITCH,
        ON,
        {
            ON: "Instructions are checked when they arrive or change.",
            OFF: "Instructions are kept but not checked.",
        },
    ),
    Feature(
        "mcp-registry",
        "MCP registry",
        "developers",
        "The tool servers listed for developers are served as an MCP registry at "
        "<control plane>/registry, which GitHub Copilot and VS Code read, without "
        "credentials, to offer developers only approved MCP servers.",
        SWITCH,
        OFF,
        {
            ON: "Developers' MCP clients read the registry at <control plane>/registry.",
            OFF: "The registry isn't served. Tool servers keep their listing.",
        },
        needs="the control plane reachable from developers' machines",
    ),
    Feature(
        "developer-sign-in",
        "Developers sign in at the gateway",
        "developers",
        "Developers' MCP clients (VS Code, Claude Code, Cursor...) reach the tool servers on "
        "the gateway with the developer's own token: each server's route tells them where "
        "to sign in (OAuth protected resource metadata), and they sign in to an agent "
        "registered as a public client, which acts for them. The controls check their calls "
        "as they check agents', with the developer as the person the agent acts for.",
        SWITCH,
        OFF,
        {
            ON: "Each tool server's route serves its metadata at "
            "/.well-known/oauth-protected-resource/mcp/<server>, and answers a call without "
            "a token with a pointer to it (while unknown callers are refused).",
            OFF: "The gateway takes the same tokens but doesn't say where to sign in.",
        },
        needs="Keycloak reachable from developers' machines, and an agent with client_type "
        "public for their MCP clients",
    ),
    Feature(
        "mcp-discovery",
        "Developers' MCP servers",
        "developers",
        "The MCP servers developers have set up on their machines, as agentgov mcp scan "
        "reports them, are compared with the approved tool servers, and those that aren't "
        "approved raise findings.",
        SWITCH,
        ON,
        {
            ON: "Reports are taken, and unapproved servers raise findings.",
            OFF: "Reports are refused. Findings already raised stay until resolved.",
        },
    ),
    Feature(
        "workload-identity",
        "Agents' own identities",
        "identity",
        "Agents authenticate with an identity they already have, such as a Kubernetes "
        "service account, a SPIFFE ID or a Microsoft Entra Agent ID, from identity issuers an "
        "administrator approves, instead of a client secret.",
        SWITCH,
        ON,
        {
            ON: "Agents with a workload identity authenticate with their issuer's tokens.",
            OFF: "No issuer is trusted: agents with a workload identity can't authenticate "
            "until it is on again.",
        },
        needs="Keycloak 26.6 or later, whose service account for AgentGov may manage identity "
        "providers; SPIFFE issuers need Keycloak's spiffe preview feature",
    ),
    Feature(
        "identity-assertions",
        "Identity assertions for servers outside the gateway",
        "identity",
        "Agents get identity assertions (ID-JAG, MCP's enterprise-managed authorization) for "
        "the MCP servers outside the gateway that take access tokens from an authorization "
        "server of their own, as their grants and blueprints allow, and trade them there for "
        "access tokens. AgentGov's token endpoint gives them, for the agent or the person it "
        "acts for, and the ledger records each one.",
        SWITCH,
        OFF,
        {
            ON: "Agents get assertions at <control plane>/oauth2/token for the tool servers "
            "registered with an authorization server.",
            OFF: "No assertions are given. Those given before expire within five minutes.",
        },
        needs="the service token, Keycloak's issuer and keys, and OPA, where the control plane "
        "runs; and the servers' authorization servers trusting AgentGov's",
    ),
    Feature(
        "registration-approval",
        "Registration approval",
        "lifecycle",
        "Agents registered by people who aren't administrators wait for an administrator to "
        "approve them.",
        SWITCH,
        ON,
        {
            ON: "Their agents start pending.",
            OFF: "Their agents are active at once.",
        },
    ),
    Feature(
        "access-packages",
        "Access packages",
        "lifecycle",
        "Agents hold extra tools, models and agents to call for a while: an access package, "
        "requested by their owners, sponsors or approvers, approved, reminded before it "
        "expires, renewed or reviewed.",
        CONTROL,
        MONITOR,
        {
            ENFORCE: "Expired access packages grant nothing: calls that need them are denied.",
            MONITOR: "Agents keep the access of expired packages: each call that needs it is "
            "recorded, and an issue asks for it to be renewed or revoked.",
            OFF: "Access packages grant nothing and can't be requested. Assignments are kept.",
        },
        needs="least-privilege enforced, for packages to be what grants the access",
    ),
    Feature(
        "issues",
        "Issues to the people responsible",
        "lifecycle",
        "Findings go to the people responsible for them: an agent's owner, then its sponsors, "
        "then its team, each told by email and in their team's chat, and the issue goes up "
        "the chain when nobody acknowledges it in time.",
        SWITCH,
        ON,
        {
            ON: "Findings are routed, escalated and sent to the people responsible.",
            OFF: "Findings stay in AgentGov's list only, as for administrators.",
        },
        needs="teams with email addresses or chat channels; a mail server "
        "(AGENTGOV_SMTP_URL) for email",
    ),
    Feature(
        "management-rules",
        "Management rules",
        "lifecycle",
        "Rules act on the agents that meet their conditions for long enough, such as agents "
        "nobody used for 90 days or agents without an owner: they raise an issue, give the "
        "agent an owner, block it, delete it or revoke its access packages, after telling its "
        "people, and on a few agents at once at most.",
        CONTROL,
        MONITOR,
        {
            ENFORCE: "Rules in enforce mode tell an agent's people as soon as it matches, and "
            "act after their days of notice if it still matches.",
            MONITOR: "Rules tell nobody and change nothing: they record what they would have "
            "done, for their previews and the ledger.",
            OFF: "No rule runs, and their issues are resolved. What they did stays done.",
        },
        needs="posture checks on: rules run after each posture scan",
    ),
    Feature(
        "microsoft-365",
        "Microsoft 365 agent catalog",
        "microsoft",
        "AgentGov reads the agents in Microsoft 365 Copilot into the inventory, on a schedule "
        "and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov's app registration has the permission.",
            OFF: "Not read, even where it could be.",
        },
        needs="AgentGov's Microsoft app registration, with CopilotPackages.Read.All",
    ),
    Feature(
        "entra-agent-id",
        "Microsoft Entra Agent ID",
        "microsoft",
        "AgentGov reads agents' Entra identities and links them to the agents they belong to.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov's app registration has the permission.",
            OFF: "Not read, even where it could be.",
        },
        needs="AgentGov's Microsoft app registration, with AgentIdentity.Read.All",
    ),
    Feature(
        "purview-audit",
        "Microsoft Purview audit log",
        "microsoft",
        "AgentGov reads who uses each agent, attacks on agents and makers' changes to "
        "Copilot Studio agents from the audit log.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov's app registration has the permission.",
            OFF: "Not read, even where it could be.",
        },
        needs="AgentGov's Microsoft app registration, with AuditLogsQuery.Read.All",
    ),
    Feature(
        "defender",
        "Microsoft Defender alerts",
        "microsoft",
        "AgentGov turns Defender's alerts about agents into findings on those agents.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov's app registration has the permission.",
            OFF: "Not read, even where it could be.",
        },
        needs="AgentGov's Microsoft app registration, with SecurityAlert.Read.All",
    ),
    Feature(
        "entra-access-packages",
        "Microsoft Entra access packages",
        "microsoft",
        "The access packages Microsoft Entra ID Governance assigns agents' Entra identities "
        "(groups, API permissions, Entra roles), and when each expires: an issue reminds the "
        "agent's people before one does. Managed, administrators also assign and remove them "
        "from AgentGov.",
        READ_OR_MANAGE,
        INFORM,
        {
            MANAGE: "Read, and administrators assign and remove them from AgentGov, as Entra "
            "requests made by AgentGov's app.",
            INFORM: "Read where AgentGov's app registration has the permission. Nothing is "
            "written into Entra.",
            OFF: "Not read, even where it could be.",
        },
        needs="AgentGov's Microsoft app registration, with EntitlementManagement.Read.All "
        "(EntitlementManagement.ReadWrite.All, or the Access package assignment manager role "
        "in the packages' catalogs, to manage), and a Microsoft Agent 365 licence",
    ),
    Feature(
        "copilot-studio-threat-detection",
        "Copilot Studio threat detection",
        "microsoft",
        "Copilot Studio asks AgentGov before each tool call its agents make, once a Power "
        "Platform administrator connects AgentGov to an environment.",
        CONTROL,
        OFF,
        {
            ENFORCE: "Calls that policy denies are blocked.",
            MONITOR: "Copilot Studio is told to go ahead; what AgentGov would block is recorded.",
            OFF: "AgentGov refuses Copilot Studio's calls.",
        },
        needs="AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS and the tenant ID (and OPA to enforce)",
    ),
    Feature(
        "aws",
        "AWS agents",
        "platforms",
        "AgentGov reads the agents on AWS into the inventory (Amazon Bedrock agents, "
        "AgentCore's harnesses, agent runtimes and gateways, Amazon Quick's agents, and AWS "
        "Agent Registry's agents and MCP servers), with their risky settings as findings, on a "
        "schedule and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov has AWS credentials and regions to read.",
            OFF: "Not read, even where it could be.",
        },
        needs="AGENTGOV_AWS_REGIONS, and AWS credentials allowed to read them",
    ),
    Feature(
        "google-cloud",
        "Google Cloud agents",
        "platforms",
        "AgentGov reads the agents on Google Cloud into the inventory (Agent Runtime agents, "
        "formerly Vertex AI Agent Engine, and Agent Registry's agents and MCP servers), with "
        "their risky settings as findings, on a schedule and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov has Google credentials and projects to read.",
            OFF: "Not read, even where it could be.",
        },
        needs="AGENTGOV_GOOGLE_CLOUD_PROJECTS, and Google credentials allowed to read them",
    ),
    Feature(
        "salesforce",
        "Salesforce agents",
        "platforms",
        "AgentGov reads the Agentforce agents in your Salesforce org into the inventory, with "
        "their risky settings as findings and their topics' instructions checked, on a "
        "schedule and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov has the org's URL and an app to sign in with.",
            OFF: "Not read, even where it could be.",
        },
        needs="AGENTGOV_SALESFORCE_URL, and an External Client App allowed to read the org",
    ),
    Feature(
        "databricks",
        "Databricks agents",
        "platforms",
        "AgentGov reads the agents in your Databricks workspaces into the inventory (agents on "
        "Model Serving, Agent Bricks agents, Genie agents, and the MCP services in Unity "
        "Catalog), with their risky settings as findings, on a schedule and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov has workspaces to read and a service principal there.",
            OFF: "Not read, even where it could be.",
        },
        needs="AGENTGOV_DATABRICKS_HOSTS, and a service principal in those workspaces",
    ),
    Feature(
        "security-operations",
        "Hand-off to security operations",
        "secops",
        "The security team's tools get AgentGov's evidence and alerts: SIEMs the ledger as "
        "OCSF events, Teams and Slack channels alerts. Each level up also lets the secops "
        "role, which their tools and analysts hold, do more in AgentGov; administrators "
        "can undo all of it, and the ledger names who did it.",
        HANDOFF,
        OFF,
        {
            OFF: "Nothing is sent, and the secops role only reads.",
            "inform": "SIEMs and chats get the destinations' events and alerts, and the "
            "events API serves them; the secops role reads.",
            "triage": "As inform, and the secops role resolves, dismisses and reopens findings.",
            "contain": "As triage, and the secops role blocks and unblocks agents, tool "
            "servers, model providers and identity issuers.",
            "decide": "As contain, and the secops role approves and denies approval "
            "requests sent to approvers.",
        },
        needs="destinations for the SIEM and the chats; API keys or a single sign-on role "
        "with the secops role for the security team's tools and analysts",
    ),
)
BY_KEY = {f.key: f for f in CATALOG}


def feature(key: str) -> Feature:
    try:
        return BY_KEY[key]
    except KeyError:
        raise NotFound(f"no feature {key!r}; features: {', '.join(BY_KEY)}") from None


def check_mode(f: Feature, mode: Any) -> str:
    if mode not in f.modes:
        raise ValidationError(f"{f.key} takes {', '.join(f.modes)} (got {mode!r})")
    return mode


def parse_pins(text: str) -> dict[str, str]:
    """``AGENTGOV_FEATURES``: comma-separated ``feature=mode`` pairs."""
    pins: dict[str, str] = {}
    for item in filter(None, (p.strip() for p in text.split(","))):
        key, sep, mode = (s.strip() for s in item.partition("="))
        if not sep:
            raise ValueError(f"AGENTGOV_FEATURES: {item!r} is not feature=mode")
        try:
            pins[key] = check_mode(feature(key), mode)
        except (NotFound, ValidationError) as exc:
            raise ValueError(f"AGENTGOV_FEATURES: {exc}") from None
    return pins


def unmet(key: str, mode: str, settings: Settings) -> str | None:
    """Why ``mode`` can't be used yet, or None."""
    if key == "copilot-studio-threat-detection" and mode != OFF:
        if not settings.copilot_studio_callers():
            return (
                "Copilot Studio threat detection needs AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS: "
                "the app registration connected to Copilot Studio"
            )
        if not settings.copilot_studio_tenant():
            return (
                "Copilot Studio threat detection needs the tenant ID (a GUID): set "
                "AGENTGOV_COPILOT_STUDIO_TENANT_ID"
            )
        if mode == ENFORCE and not settings.opa_url:
            return "enforcing Copilot Studio threat detection needs AGENTGOV_OPA_URL"
    if key == "external-decision-point" and mode != OFF and not settings.authzen_url:
        return (
            "your own decision point needs its URL: set AGENTGOV_AUTHZEN_URL where the "
            "processor runs"
        )
    if key == "authzen-decision-point" and mode != OFF and not settings.opa_url:
        return (
            "AgentGov answers AuthZEN with OPA's decisions: set AGENTGOV_OPA_URL where the "
            "control plane runs"
        )
    if (
        key == "developer-sign-in"
        and mode != OFF
        and not (settings.keycloak_issuer and settings.keycloak_jwks_url)
    ):
        return (
            "developers sign in to Keycloak, whose tokens the gateway checks: set "
            "AGENTGOV_KEYCLOAK_ISSUER and AGENTGOV_KEYCLOAK_JWKS_URL"
        )
    if key == "identity-assertions" and mode != OFF:
        if not settings.service_token:
            return (
                "AgentGov signs identity assertions with a key it derives from the service "
                "token: set AGENTGOV_SERVICE_TOKEN where the control plane runs"
            )
        if not (settings.keycloak_issuer and settings.keycloak_jwks_url):
            return (
                "AgentGov checks the tokens agents bring with Keycloak's keys: set "
                "AGENTGOV_KEYCLOAK_ISSUER and AGENTGOV_KEYCLOAK_JWKS_URL"
            )
        if not settings.opa_url:
            return "AgentGov's policies decide which agents get them: set AGENTGOV_OPA_URL"
    if key == "traffic-classifier" and mode != OFF and not settings.guardian_url:
        return (
            "the classifier needs IBM Granite Guardian: set AGENTGOV_GUARDIAN_URL where the "
            "control plane and the processor run"
        )
    return None


def _rows(session: Session) -> dict[str, FeatureSetting]:
    return {row.key: row for row in session.scalars(select(FeatureSetting))}


def modes(session: Session) -> dict[str, str]:
    """The mode of every feature."""
    rows = _rows(session)
    return {f.key: rows[f.key].mode if f.key in rows else f.default for f in CATALOG}


def mode(session: Session, key: str) -> str:
    row = session.get(FeatureSetting, key)
    return row.mode if row is not None else feature(key).default


def is_on(session: Session, key: str) -> bool:
    return mode(session, key) != OFF


def _weaker(f: Feature, before: str, after: str) -> bool:
    return f.modes.index(after) < f.modes.index(before)


def _set(session: Session, f: Feature, new: str, *, actor: str, pinned: bool) -> bool:
    row = session.get(FeatureSetting, f.key)
    before = row.mode if row is not None else f.default
    if row is not None and row.mode == new and row.pinned == pinned:
        return False
    if row is None:
        row = FeatureSetting(key=f.key)
        session.add(row)
    row.mode, row.pinned, row.changed_by, row.changed_at = new, pinned, actor, ids.utcnow()
    if before != new:
        ledger.append(
            session,
            type="feature.changed",
            actor=actor,
            resource=f"feature/{f.key}",
            severity="warning" if _weaker(f, before, new) else "info",
            reason=f"{f.title}: {before} to {new}",
            details={"from": before, "to": new, "pinned": pinned},
        )
        mark_changed(session, "features", f"feature:{f.key}")
    return True


def set_mode(session: Session, settings: Settings, key: str, new: Any, *, actor: str) -> bool:
    """An administrator's choice; returns whether anything changed."""
    f = feature(key)
    check_mode(f, new)
    row = session.get(FeatureSetting, key)
    if row is not None and row.pinned:
        if row.mode == new:
            return False
        raise Conflict(
            f"{key} is set to {row.mode} by the deployment (AGENTGOV_FEATURES); change it there"
        )
    reason = unmet(key, new, settings)
    if reason:
        raise ValidationError(reason)
    return _set(session, f, new, actor=actor, pinned=False)


def apply_pins(session: Session, settings: Settings) -> None:
    """Make the database match AGENTGOV_FEATURES (when the control plane starts)."""
    pins = parse_pins(settings.features)
    for key, new in pins.items():
        reason = unmet(key, new, settings)
        if reason:
            raise ValueError(f"AGENTGOV_FEATURES: {reason}")
        _set(session, BY_KEY[key], new, actor=DEPLOYMENT, pinned=True)
    for row in _rows(session).values():
        if row.pinned and row.key not in pins:
            # No longer pinned: it keeps its mode, and administrators may now change it.
            row.pinned, row.changed_by, row.changed_at = False, DEPLOYMENT, ids.utcnow()


def describe(session: Session, settings: Settings, key: str | None = None) -> list[dict[str, Any]]:
    rows = _rows(session)
    out = []
    for f in [feature(key)] if key else CATALOG:
        row = rows.get(f.key)
        current = row.mode if row is not None else f.default
        # A default that needs what isn't there, or a mode chosen before it went away: it
        # does nothing until it is there, and says so.
        missing = unmet(f.key, current, settings)
        out.append(
            {
                "key": f.key,
                "title": f.title,
                "group": f.group,
                "description": f.description,
                "modes": list(f.modes),
                "mode": current,
                "default": f.default,
                # "default", "admin" (chosen in the app) or "deployment" (pinned).
                "set_by": "default" if row is None else DEPLOYMENT if row.pinned else "admin",
                "changed_by": row.changed_by if row is not None else None,
                "changed_at": ids.isoformat(row.changed_at) if row is not None else None,
                "effect": f"{missing[:1].upper()}{missing[1:]}."
                if missing
                else f.effects.get(current, ""),
                "effects": dict(f.effects),
                "needs": f.needs,
                # Modes that can't be chosen yet, with the reason.
                "unavailable": {
                    m: reason for m in f.modes if (reason := unmet(f.key, m, settings))
                },
            }
        )
    return out


def chosen(session: Session) -> dict[str, str]:
    """Modes administrators chose (for export: pins belong to the deployment)."""
    return {row.key: row.mode for row in _rows(session).values() if not row.pinned}

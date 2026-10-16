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

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentgov import db, ids, ledger
from agentgov.config import FEATURE_PRESETS, Settings
from agentgov.db import mark_changed
from agentgov.db.models import Agent, FeatureSetting, IntegrationState
from agentgov.models import DELETED
from agentgov.registry import scopes as scope_rules
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
# Which AGENTGOV_FEATURE_PRESET was applied (integration_state).
PRESET_STATE = "feature-preset"

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
            ENFORCE: "Such results are withheld, and an issue is raised.",
            MONITOR: "They reach the agent, are recorded and raise an issue.",
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
            ENFORCE: "Such prompts are refused, and an issue is raised.",
            MONITOR: "They go through, are recorded and raise an issue.",
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
            "refused, and raises an issue.",
            MONITOR: "It answers in the background, after the call went on: what it flags is "
            "recorded and raises an issue.",
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
            "raises an issue.",
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
            "inventory as unmanaged agents. Calls to models still need a valid token: the "
            "gateway pays for them with the provider's key.",
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
        "inventory as unmanaged agents.",
        SWITCH,
        ON,
        {
            ON: "Unregistered agents appear as unmanaged.",
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
        "A regular scan raises issues for agents without owners or sponsors, attestations "
        "that are due, stale agents, broad grants and tool servers awaiting review.",
        SWITCH,
        ON,
        {
            ON: "The scan runs every AGENTGOV_POSTURE_INTERVAL_SECONDS, and on demand.",
            OFF: "No scans. Issues already raised stay until they are resolved.",
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
        "approved raise issues.",
        SWITCH,
        ON,
        {
            ON: "Reports are taken, and unapproved servers raise issues.",
            OFF: "Reports are refused. Issues already raised stay until resolved.",
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
        "Issues go to the people responsible for them: an agent's owner, then its sponsors, "
        "then its team, each told by email and in their team's chat, and the issue goes up "
        "the chain when nobody acknowledges it in time.",
        SWITCH,
        ON,
        {
            ON: "Issues are routed, escalated and sent to the people responsible.",
            OFF: "Issues stay in AgentGov's list only, as for administrators.",
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
        "entra-users",
        "Microsoft Entra users",
        "microsoft",
        "AgentGov looks up the people Copilot Studio names as its agents' owners and makers, "
        "and the owners and sponsors it names itself: to show them by name, to make them "
        "owners when adopting, and to see when one has left, so that issues go past them.",
        SWITCH,
        ON,
        {
            ON: "Looked up where AgentGov's app registration has the permission, and as the "
            "administrator who syncs Copilot Studio when they sign in with Microsoft.",
            OFF: "Not looked up: makers are known only from a list of users uploaded to "
            "AgentGov, and otherwise shown by their Entra IDs.",
        },
        needs="AgentGov's Microsoft app registration, with User.Read.All (User.ReadBasic.All "
        "doesn't say whose account is disabled), or administrators who sign in with Microsoft",
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
        "AgentGov turns Defender's alerts about agents into issues on those agents.",
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
        "connector-allowlist",
        "Connector allowlist",
        "microsoft",
        "What Copilot Studio threat detection does with a tool call through a connector that "
        "isn't on the allowlist (Platforms, Connectors), once the allowlist lists one. Agents "
        "that use such a connector are flagged in any mode (platform.unapproved_connector).",
        CONTROL,
        ENFORCE,
        {
            ENFORCE: "The call is refused.",
            MONITOR: "The call goes through; that AgentGov would have refused it is recorded.",
            OFF: "The call goes through.",
        },
        needs="Copilot Studio threat detection, to check calls as they run",
    ),
    Feature(
        "aws",
        "AWS agents",
        "platforms",
        "AgentGov reads the agents on AWS into the inventory (Amazon Bedrock agents, "
        "AgentCore's harnesses, agent runtimes and gateways, Amazon Quick's agents, and AWS "
        "Agent Registry's agents and MCP servers), with their risky settings as issues, on a "
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
        "their risky settings as issues, on a schedule and on demand.",
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
        "their risky settings as issues and their topics' instructions checked, on a "
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
        "Catalog), with their risky settings as issues, on a schedule and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov has workspaces to read and a service principal there.",
            OFF: "Not read, even where it could be.",
        },
        needs="AGENTGOV_DATABRICKS_HOSTS, and a service principal in those workspaces",
    ),
    Feature(
        "microsoft-foundry",
        "Microsoft Foundry agents",
        "platforms",
        "AgentGov reads the agents in your Microsoft Foundry projects into the inventory "
        "(prompt, hosted and workflow agents), with their risky settings as issues, linked to "
        "their Entra agent identities, on a schedule and on demand.",
        SWITCH,
        ON,
        {
            ON: "Read where AgentGov has Foundry projects to read and its Microsoft app.",
            OFF: "Not read, even where it could be.",
        },
        needs="AGENTGOV_FOUNDRY_PROJECTS or AGENTGOV_FOUNDRY_SUBSCRIPTIONS, and AgentGov's "
        "Microsoft app (AGENTGOV_M365_*) allowed to read the projects' agents and connections",
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
            "triage": "As inform, and the secops role resolves, dismisses and reopens issues.",
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
# The controls whose enforce mode refuses calls at the gateway.
GATEWAY_CONTROLS = (
    *(f.key for f in CATALOG if f.group == "controls" and ENFORCE in f.modes),
    "access-packages",
    "external-decision-point",
)
GATEWAYS = ("mcp-gateway", "model-gateway", "a2a-gateway")
# The controls whose mode can differ for some agents (docs/features.md#exceptions): every
# control at the gateway but unknown-callers, whose callers aren't agents, and the connector
# allowlist, which Copilot Studio's agents' tool calls are checked against.
SCOPABLE = (
    *(key for key in GATEWAY_CONTROLS if key != "unknown-callers"),
    "connector-allowlist",
)
# A label administrators put on an agent to exempt it from controls: "*", or the controls'
# keys, comma-separated. For that agent, an enforced control it names is monitored.
EXEMPT_LABEL = "agentgov/exempt-controls"
# Exceptions a control has at most.
MAX_SCOPES = 20
# What listing a control's exceptions adds to each: the scope in words, how many agents it
# applies to now, and what it names that there isn't. Sent back with them, they are ignored.
LISTED = ("describe", "agents", "missing")


def enforced_at_gateway(modes: dict[str, str]) -> list[str]:
    """The controls at the gateway that are enforced."""
    return [key for key in GATEWAY_CONTROLS if modes.get(key) == ENFORCE]


def fails_open(setting: str, modes: dict[str, str]) -> bool:
    """Whether a call the gateway can't check goes through unchecked, as
    AGENTGOV_GATEWAY_FAILURE_MODE says: "open" always, "closed" never, and "modes" while no
    control at the gateway is enforced, so that controls in monitor mode never stop a call."""
    if setting == "modes":
        return not enforced_at_gateway(modes)
    return setting == "open"


@dataclass(frozen=True)
class Preset:
    """A starting point that sets many modes at once (apply_preset)."""

    title: str
    description: str
    # The modes it sets, given the current ones.
    sets: Callable[[dict[str, str]], dict[str, str]]
    # The controls' exceptions it changes, given the current ones.
    sets_scopes: Callable[[dict[str, list[dict[str, Any]]]], dict[str, list[dict[str, Any]]]] = (
        lambda current: {}
    )


def _monitor(current: dict[str, str]) -> dict[str, str]:
    return {f.key: MONITOR for f in CATALOG if current[f.key] == ENFORCE and MONITOR in f.modes}


def _monitor_scopes(current: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    """Exceptions that enforce a control for some agents are monitored too."""
    return {
        key: [{**e, "mode": MONITOR} if e["mode"] == ENFORCE else e for e in entries]
        for key, entries in current.items()
        if any(e["mode"] == ENFORCE for e in entries)
    }


def _inventory(current: dict[str, str]) -> dict[str, str]:
    out = dict.fromkeys(GATEWAYS, OFF)
    out.update(
        {f.key: OFF if OFF in f.modes else MONITOR for f in CATALOG if f.group == "controls"}
    )
    out.update(dict.fromkeys(("external-decision-point", "access-packages"), OFF))
    out["calls-around-gateway"] = OFF
    return out


PRESETS = {
    "monitor": Preset(
        "Monitor everything",
        "Every control in enforce mode goes to monitor, and so do exceptions that enforce one "
        "for some agents: AgentGov records what each would have done and stops nothing. "
        "Enforce them one at a time once their records look right.",
        _monitor,
        _monitor_scopes,
    ),
    "inventory": Preset(
        "Inventory only",
        "Nothing is published on the gateway and its controls are off: AgentGov finds your "
        "agents, in its registry and on the platforms it reads, and checks how they are set "
        "up, without changing how they run.",
        _inventory,
    ),
}
assert tuple(PRESETS) == FEATURE_PRESETS


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
        if not settings.key_secret:
            return (
                "AgentGov signs identity assertions with a key it derives from the signing "
                "secret: set AGENTGOV_SIGNING_SECRET (or AGENTGOV_SERVICE_TOKEN) where the "
                "control plane runs"
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


def _rows(tx: db.Where) -> dict[str, FeatureSetting]:
    return {row.key: row for row in FeatureSetting.objects.all()}


def _row(key: str) -> FeatureSetting | None:
    return FeatureSetting.objects.filter(pk=key).first()


def modes(tx: db.Where) -> dict[str, str]:
    """The mode of every feature."""
    rows = _rows(tx)
    return {f.key: rows[f.key].mode if f.key in rows else f.default for f in CATALOG}


def mode(tx: db.Where, key: str) -> str:
    row = _row(key)
    return row.mode if row is not None else feature(key).default


def is_on(tx: db.Where, key: str) -> bool:
    return mode(tx, key) != OFF


def _weaker(f: Feature, before: str, after: str) -> bool:
    return f.modes.index(after) < f.modes.index(before)


def _set(
    tx: db.Where,
    f: Feature,
    new: str,
    *,
    actor: str,
    pinned: bool,
    preset: str | None = None,
) -> bool:
    row = _row(f.key)
    before = row.mode if row is not None else f.default
    if row is not None and row.mode == new and row.pinned == pinned:
        return False
    adding = row is None
    if row is None:
        row = FeatureSetting(key=f.key)
    row.mode, row.pinned, row.changed_by, row.changed_at = new, pinned, actor, ids.utcnow()
    row.save(force_insert=adding)
    if before != new:
        details: dict[str, Any] = {"from": before, "to": new, "pinned": pinned}
        if preset:
            details["preset"] = preset
        ledger.append(
            tx,
            type="feature.changed",
            actor=actor,
            resource=f"feature/{f.key}",
            severity="warning" if _weaker(f, before, new) else "info",
            reason=f"{f.title}: {before} to {new}" + (f" (preset {preset})" if preset else ""),
            details=details,
        )
        mark_changed(tx, "features", f"feature:{f.key}")
    return True


def set_mode(tx: db.Where, settings: Settings, key: str, new: Any, *, actor: str) -> bool:
    """An administrator's choice; returns whether anything changed."""
    f = feature(key)
    check_mode(f, new)
    row = _row(key)
    if row is not None and row.pinned:
        if row.mode == new:
            return False
        raise Conflict(
            f"{key} is set to {row.mode} by the deployment (AGENTGOV_FEATURES); change it there"
        )
    reason = unmet(key, new, settings)
    if reason:
        raise ValidationError(reason)
    return _set(tx, f, new, actor=actor, pinned=False)


def apply_pins(tx: db.Where, settings: Settings) -> None:
    """Make the database match AGENTGOV_FEATURES (when the control plane starts)."""
    pins = parse_pins(settings.features)
    for key, new in pins.items():
        reason = unmet(key, new, settings)
        if reason:
            raise ValueError(f"AGENTGOV_FEATURES: {reason}")
        _set(tx, BY_KEY[key], new, actor=DEPLOYMENT, pinned=True)
    for row in _rows(tx).values():
        if row.pinned and row.key not in pins:
            # No longer pinned: it keeps its mode, and administrators may now change it.
            row.pinned, row.changed_by, row.changed_at = False, DEPLOYMENT, ids.utcnow()
            row.save()


def preview_preset(tx: db.Where, settings: Settings, name: str) -> dict[str, Any]:
    """What applying preset ``name`` would change, and what it leaves: features the
    deployment pins, and modes that can't be used yet."""
    try:
        preset = PRESETS[name]
    except KeyError:
        raise NotFound(f"no preset {name!r}; presets: {', '.join(PRESETS)}") from None
    current = modes(tx)
    pins = parse_pins(settings.features)
    pinned = set(pins) | {row.key for row in _rows(tx).values() if row.pinned}
    changes, kept = [], []
    for key, new in preset.sets(current).items():
        if current[key] == new:
            continue
        why = (
            "pinned by the deployment (AGENTGOV_FEATURES)"
            if key in pinned
            else unmet(key, new, settings)
        )
        item = {"key": key, "title": BY_KEY[key].title, "from": current[key], "to": new}
        if why:
            kept.append({**item, "reason": why})
        else:
            changes.append(item)
    exceptions = {key: e for key, e in all_scopes(tx).items() if key not in pinned}
    for key, entries in preset.sets_scopes(exceptions).items():
        for before, after in zip(exceptions[key], entries, strict=True):
            if before["mode"] != after["mode"]:
                changes.append(
                    {
                        "key": key,
                        "title": BY_KEY[key].title,
                        "scope": scope_rules.describe(before["scope"]),
                        "from": before["mode"],
                        "to": after["mode"],
                    }
                )
    return {
        "preset": name,
        "title": preset.title,
        "description": preset.description,
        "changes": changes,
        "kept": kept,
    }


def apply_preset(tx: db.Where, settings: Settings, name: str, *, actor: str) -> dict[str, Any]:
    """Set the modes preset ``name`` sets, but for those preview_preset says it keeps;
    each change is a feature.changed entry that names the preset."""
    plan = preview_preset(tx, settings, name)
    for change in plan["changes"]:
        if "scope" not in change:
            _set(tx, BY_KEY[change["key"]], change["to"], actor=actor, pinned=False, preset=name)
    exceptions = all_scopes(tx)
    for key, entries in PRESETS[name].sets_scopes(exceptions).items():
        if any(c["key"] == key and "scope" in c for c in plan["changes"]):
            _set_scopes(tx, BY_KEY[key], entries, actor=actor, preset=name)
    return plan


def deployment_preset(tx: db.Where) -> str | None:
    """The AGENTGOV_FEATURE_PRESET last applied, if any."""
    state = IntegrationState.objects.filter(pk=PRESET_STATE).first()
    return (state.data or {}).get("applied") if state is not None else None


def apply_deployment_preset(tx: db.Where, settings: Settings) -> None:
    """AGENTGOV_FEATURE_PRESET, when the control plane starts with one it hasn't applied
    (before the pins, which then hold)."""
    name = settings.feature_preset
    if not name or deployment_preset(tx) == name:
        return
    apply_preset(tx, settings, name, actor=DEPLOYMENT)
    state = IntegrationState.objects.filter(pk=PRESET_STATE).first()
    adding = state is None
    if state is None:
        state = IntegrationState(key=PRESET_STATE)
    state.data, state.updated_at = {"applied": name}, ids.utcnow()
    state.save(force_insert=adding)


# ------------------------------------------------------------------- exceptions


def check_scopes(f: Feature, value: Any, settings: Settings) -> list[dict[str, Any]]:
    """A control's exceptions as the API takes them, checked: a list of its mode for the
    agents in a scope, the first that matches an agent applying to it."""
    if f.key not in SCOPABLE:
        raise ValidationError(f"{f.key} applies alike to every agent: it takes no exceptions")
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError("scopes is a list of {mode, scope, note}")
    if len(value) > MAX_SCOPES:
        raise ValidationError(f"a control takes {MAX_SCOPES} exceptions at most")
    out = []
    for i, item in enumerate(value):
        where = f"scopes[{i}]"
        if not isinstance(item, dict):
            raise ValidationError(f"{where} is a mapping of mode, scope and note")
        # What a listing adds to each (LISTED) may come back with it.
        unknown = sorted(set(item) - {"mode", "scope", "note", *LISTED})
        if unknown:
            raise ValidationError(f"{where}: unknown key(s) {', '.join(unknown)}")
        mode = check_mode(f, item.get("mode"))
        scope = scope_rules.parse(item.get("scope"), f"{where}.scope")
        if not scope:
            raise ValidationError(
                f"{where}.scope names no agents: an exception for every agent is the mode itself"
            )
        reason = unmet(f.key, mode, settings)
        if reason:
            raise ValidationError(reason)
        note = item.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 500):
            raise ValidationError(f"{where}.note is text of 500 characters at most")
        entry: dict[str, Any] = {"mode": mode, "scope": scope}
        if note and note.strip():
            entry["note"] = note.strip()
        out.append(entry)
    return out


def _scopes_weaken(f: Feature, mode: str, before: list[Any], after: list[Any]) -> bool:
    """Whether new exceptions are weaker than the mode, or removed ones were stronger."""
    rank = f.modes.index
    added = [e for e in after if e not in before]
    removed = [e for e in before if e not in after]
    return any(rank(e["mode"]) < rank(mode) for e in added) or any(
        rank(e["mode"]) > rank(mode) for e in removed
    )


def _set_scopes(
    tx: db.Where,
    f: Feature,
    new: list[dict[str, Any]],
    *,
    actor: str,
    preset: str | None = None,
) -> bool:
    row = _row(f.key)
    before = list(row.scopes or []) if row is not None else []
    if before == new:
        return False
    adding = row is None
    if row is None:
        row = FeatureSetting(key=f.key, mode=f.default, pinned=False)
    row.scopes, row.changed_by, row.changed_at = new, actor, ids.utcnow()
    row.save(force_insert=adding)
    words = "; ".join(f"{e['mode']} for {scope_rules.describe(e['scope'])}" for e in new)
    details: dict[str, Any] = {"scopes_from": before, "scopes_to": new}
    if preset:
        details["preset"] = preset
    ledger.append(
        tx,
        type="feature.changed",
        actor=actor,
        resource=f"feature/{f.key}",
        severity="warning" if _scopes_weaken(f, row.mode, before, new) else "info",
        reason=f"{f.title}: exceptions {words or 'none'}"
        + (f" (preset {preset})" if preset else ""),
        details=details,
    )
    mark_changed(tx, "features", f"feature:{f.key}")
    return True


def set_scopes(tx: db.Where, settings: Settings, key: str, value: Any, *, actor: str) -> bool:
    """An administrator's exceptions to a control; returns whether anything changed."""
    f = feature(key)
    new = check_scopes(f, value, settings)
    row = _row(key)
    if row is not None and row.pinned:
        raise Conflict(
            f"{key} is set by the deployment (AGENTGOV_FEATURES), for every agent: its "
            "exceptions can't be changed in the app"
        )
    had = [e["scope"] for e in (row.scopes or [])] if row is not None else []
    for i, entry in enumerate(new):
        scope_rules.check_names(tx, entry["scope"], f"scopes[{i}].scope", had=had)
    return _set_scopes(tx, f, new, actor=actor)


def all_scopes(tx: db.Where) -> dict[str, list[dict[str, Any]]]:
    """Each control's exceptions that apply: none while the deployment pins the control."""
    return {
        row.key: list(row.scopes)
        for row in _rows(tx).values()
        if row.scopes and not row.pinned and row.key in SCOPABLE
    }


def exempted(agent: Agent) -> set[str]:
    """The controls the agent's EXEMPT_LABEL names ("*": all of them)."""
    names = {n.strip() for n in str((agent.labels or {}).get(EXEMPT_LABEL, "")).split(",")}
    return set(SCOPABLE) if "*" in names else names & set(SCOPABLE)


def exceptions_for(
    agent: Agent, current: dict[str, str], exceptions: dict[str, list[dict[str, Any]]]
) -> dict[str, dict[str, str]]:
    """The controls whose mode differs for ``agent``, with why: an exception's scope it is
    in (the first), or its exemption label, which turns enforcement into monitoring."""
    out: dict[str, dict[str, str]] = {}
    for key, entries in exceptions.items():
        entry = next((e for e in entries if scope_rules.matches(e["scope"], agent)), None)
        if entry is not None and entry["mode"] != current.get(key):
            out[key] = {"mode": entry["mode"], "why": scope_rules.describe(entry["scope"])}
    for key in exempted(agent):
        if out.get(key, {}).get("mode", current.get(key)) == ENFORCE:
            out[key] = {"mode": MONITOR, "why": f"label {EXEMPT_LABEL}"}
    return out


def mode_for(tx: db.Where, agent: Agent, key: str) -> str:
    """A feature's mode for one agent: its exception's, or the feature's."""
    current = {key: mode(tx, key)}
    exceptions = {k: v for k, v in all_scopes(tx).items() if k == key}
    return exceptions_for(agent, current, exceptions).get(key, {}).get("mode", current[key])


def strictest(
    current: dict[str, str], exceptions: dict[str, list[dict[str, Any]]]
) -> dict[str, str]:
    """Each feature's strongest mode for any agent: what the gateway is set up for, and
    what counts as enforced when nothing is known of the caller."""
    out = dict(current)
    for key, entries in exceptions.items():
        rank = BY_KEY[key].modes.index
        for entry in entries:
            if rank(entry["mode"]) > rank(out[key]):
                out[key] = entry["mode"]
    return out


def strictest_modes(tx: db.Where) -> dict[str, str]:
    return strictest(modes(tx), all_scopes(tx))


def _reach(entries: list[dict[str, Any]], agents: list[Agent]) -> list[int]:
    """How many agents each exception applies to now: the first that matches an agent."""
    counts = [0] * len(entries)
    for agent in agents:
        for i, entry in enumerate(entries):
            if scope_rules.matches(entry["scope"], agent):
                counts[i] += 1
                break
    return counts


def describe(tx: db.Where, settings: Settings, key: str | None = None) -> list[dict[str, Any]]:
    rows = _rows(tx)
    agents: list[Agent] | None = None
    names: dict[str, set[str]] = {}
    out = []
    for f in [feature(key)] if key else CATALOG:
        row = rows.get(f.key)
        current = row.mode if row is not None else f.default
        entries = (row.scopes or []) if row is not None else []
        if entries and agents is None:
            # Read once: how many agents each exception applies to, and what it names that
            # there isn't.
            agents = list(Agent.objects.exclude(status=DELETED))
            names = scope_rules.known(tx)
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
                # Its mode for some agents (docs/features.md#exceptions); while the
                # deployment pins it, none apply.
                "scopable": f.key in SCOPABLE,
                # With each, in words, how many agents it applies to now, and the teams,
                # blueprints or platforms it names that there aren't.
                "scopes": [
                    {
                        **e,
                        "describe": scope_rules.describe(e["scope"]),
                        "agents": n,
                        "missing": scope_rules.missing(e["scope"], names),
                    }
                    for e, n in zip(entries, _reach(entries, agents or []), strict=True)
                ],
            }
        )
    return out


def chosen(tx: db.Where) -> dict[str, dict[str, Any]]:
    """Modes, and exceptions, administrators chose (for export: pins belong to the
    deployment)."""
    return {
        row.key: {"mode": row.mode, **({"scopes": list(row.scopes)} if row.scopes else {})}
        for row in _rows(tx).values()
        if not row.pinned
    }

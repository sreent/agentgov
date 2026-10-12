# Features

AgentGov is one application, but you don't have to use all of it. Every feature but
`unknown-callers` can be turned off, and most controls the gateway enforces can also run in
**monitor** mode. In
monitor mode AgentGov decides as usual and records what it would have done, but lets the
call through, like Conditional Access's report-only mode. Use it to try a control on real
traffic before you enforce it.

## Choosing

| | How |
|---|---|
| Admin UI | **Features** page (administrators) |
| CLI | `agentgov features list`, `agentgov features set least-privilege monitor` |
| API | `GET /v1/features`, `PUT /v1/features/{feature}` with `{"mode": "monitor"}` |
| Manifests | `kind: Feature`, `metadata.name: least-privilege`, `spec.mode: monitor` |
| Deployment | `AGENTGOV_FEATURES="least-privilege=monitor,discovery=off"` |

Every change goes into the ledger as `feature.changed`, with who made it. A change that
weakens a feature is recorded as a warning: enforce to monitor or off, or on to off.
The CLI asks before it weakens one (`--yes` skips the question).

A feature set in `AGENTGOV_FEATURES` is **pinned** by the deployment. Administrators see
it, but can only change it in the deployment: the Compose `.env` file, or the Helm value
`features`. Pins are applied, and recorded, when the control plane starts. Remove a pin
and the feature keeps its mode, which administrators may then change. `agentgov export`
includes the modes administrators chose, not the pins.

## The features

Modes run from the weakest to the strongest. The default is in bold.

### Gateway

| Feature | Modes | What it does |
|---|---|---|
| `mcp-gateway` | off, **on** | Publishes approved MCP tool servers on agentgateway at `/mcp/<server>`. Agents call them there with their AgentGov token, and the controls below check every call. Off, no tool server is published, but the registry keeps them |
| `model-gateway` | off, **on** | Publishes approved [model providers](models.md) on agentgateway at `/llm/<provider>`. Agents call models there with their AgentGov token instead of the provider's API key, and the controls below check every prompt and answer. Off, no provider is published, but the registry keeps them |
| `a2a-gateway` | off, **on** | Publishes the agents that serve A2A (an `a2a_url` in the registry) on agentgateway at `/a2a/<agent>`, where other agents call them with their AgentGov token ([agent to agent](agent-to-agent.md)). The controls below check every call that comes through the gateway, and its answer, and the chain of agents that handed the work down, with the person at its head, goes with it to every agent, tool and model further down. A call straight to an agent's own URL doesn't pass the gateway, and AgentGov doesn't see it: `calls-around-gateway` looks for those. Off, no agent is published for A2A, but the registry keeps their A2A URLs |

### Controls at the gateway

These check the calls that come through AgentGov's gateway, and only those: AgentGov doesn't
own the network agents run on. A call that goes around the gateway, straight to a tool
server, a model provider or another agent, skips them; detection finds such calls where it
can (`least-privilege`'s telemetry check below, `calls-around-gateway`, `mcp-discovery`).

| Feature | Modes | What it does |
|---|---|---|
| `least-privilege` | off, monitor, **enforce** | Agents may call only the tools, models and other agents their blueprint, their own grants and their [access packages](access-packages.md) allow, and see only those tools when they list a server's. In monitor mode, agents see and call every tool, model and agent, and calls they weren't granted are recorded. Telemetry showing a tool used without a grant raises a finding unless this control is off |
| `acting-for-people` | off, monitor, **enforce** | Agents act for the people their blueprints allow ([acting for people](acting-for-people.md)). A blueprint can say that its agents act only for a person, with a token they got for that person, or only on their own, and only for people in some groups. Monitor lets other calls through and records them. Off, who agents act for isn't checked; the ledger still records the person |
| `approvals` | off, monitor, **enforce** | Calls to tools their servers mark destructive, and calls organisation policies single out (`require_approval`), wait for a person to approve them |
| `approvals-by-person` | **off**, on | Sends the approval requests an agent makes while it acts for a person to that person, where its blueprint says so (`approvals_by: person`). People sign in to AgentGov to decide them, people without an AgentGov role too, who see only the requests sent to them. Administrators can always decide. Off, approvers decide every request, and people without an AgentGov role can't sign in unless `issues` is on. Needs AgentGov's sign-in through the Keycloak realm that issues agents' tokens ([acting for people](acting-for-people.md)) |
| `data-protection` | off, monitor, **enforce** | Inspects tool calls, model calls and calls between agents, and their answers, for credentials and personal data. Credentials stop the call (a tool's or a model's answer that contains them is withheld, and another agent's is masked), and personal data is masked unless policy allows it. Off, nothing is inspected and Presidio isn't called. Monitor records what was found. Only an enforced control stops calls when Presidio is down (`AGENTGOV_PRESIDIO_FAILURE_MODE=closed`) |
| `a2a-masking` | off, **monitor**, enforce | Masks personal data in the messages agents send each other through the gateway, unless the agent called may have it (its `pii-access` label, or its blueprint's). Monitored, messages go as they are and each call's decision records what would have been masked; off, the personal data in them is only recorded. Data protection finds it, so it needs `data-protection` on; credentials in messages are refused by `data-protection` whatever this says ([agent to agent](agent-to-agent.md#messages)) |
| `prompt-injection` | off, monitor, **enforce** | Withholds tool results and other agents' answers that carry instructions aimed at the agent (indirect prompt injection) and raises a finding, and refuses model calls whose conversation holds such a result. Monitor lets them through and still raises the finding |
| `jailbreak-detection` | off, **monitor**, enforce | Looks for jailbreaks, prompts that try to talk a model out of its instructions or its safety rules, in the latest message from a person in each [model call](models.md). Enforced, they are refused; monitored, they go through. Either way they are recorded and raise a finding. It starts in monitor mode because people's own words vary more than tool results do: see what it would refuse before you enforce it |
| `traffic-classifier` | off, **monitor**, enforce | A second opinion from IBM Granite Guardian on what `prompt-injection` and `jailbreak-detection` let through: tool results, the answers agents send each other, and people's prompts to models ([detection](detection.md)). It follows the check it supports: where both are enforced, calls wait for its verdict (`AGENTGOV_CLASSIFIER_TIMEOUT_SECONDS` at most) and what it flags is withheld or refused; otherwise it answers in the background, after the call went on, and what it flags is recorded and raises a finding. Needs Granite Guardian where the processor runs (`AGENTGOV_GUARDIAN_URL`) |
| `tool-integrity` | off, monitor, **enforce** | Quarantines tools whose descriptions hide instructions. Tools that changed since approval are held until an administrator reviews them |
| `risk-based-access` | off, monitor, **enforce** | Refuses agents at critical risk, and blocks agents whose risk score reaches `AGENTGOV_AUTO_BLOCK_RISK_SCORE`. Monitor lets them through, and the automatic block raises an `agent.would_auto_block` finding instead. Risk is always scored and shown |
| `token-budgets` | off, monitor, **enforce** | Refuses model calls from agents that have used their daily token budget, their own or their blueprint's, until the day ends (UTC). Off, budgets aren't checked; usage is still metered |
| `unknown-callers` | monitor, **enforce** | Refuses callers without a registered agent's identity. Monitor lets them through and records them; with `discovery` on, they are added to the inventory |

### Detection

| Feature | Modes | What it does |
|---|---|---|
| `discovery` | off, **on** | Adds agents seen in telemetry or at the gateway that aren't registered to the inventory, as discovered (shadow AI). Off, registered agents' activity is still recorded. Imports you start yourself are not affected |
| `calls-around-gateway` | off, **watch**, test | Looks for calls to agents that go around the gateway, straight to an agent's own A2A URL, which AgentGov can't stop: the agent's network can, or the agent, by refusing calls without the delegation the gateway gives with each one ([calls around the gateway](agent-to-agent.md#calls-around-the-gateway)). Watched, telemetry that shows such a call is recorded and raises an issue for both agents' owners, and so does an agent whose owners haven't said what stops such calls (its `a2a_protection`); AgentGov calls no agent itself. Tested, each posture scan also calls each agent's A2A URL, without a delegation, as a call around the gateway would, and an agent that takes it raises an issue (a serious one if its owners said something stops it). Off, nothing is looked for. The test runs with the posture scan, so not while `posture-checks` is off |
| `posture-checks` | off, **on** | Scans regularly and raises findings: agents without owners or sponsors, attestations that are due, stale agents, broad grants and tool servers awaiting review. Off, nothing is scanned, and findings already raised stay until resolved |
| `instruction-checks` | off, **on** | Checks agents' instructions (their system prompts) for unsafe content, with AgentGov's rules and with IBM Granite Guardian where it is configured. Off, instructions are kept but not checked; they are checked as soon as checks are on again |

### Policy

| Feature | Modes | What it does |
|---|---|---|
| `external-decision-point` | **off**, monitor, enforce | Has the processor also ask an AuthZEN decision point of yours (Cedar, Cerbos, Topaz, OpenFGA, Keycloak...) about each call to a tool, a model or another agent that AgentGov's policies let through: who, the method, the tool, model or agent, and what was found in the call, never its content ([AuthZEN](policies.md#your-own-decision-point-beside-agentgovs)). Enforced, calls it denies are refused and calls it says need approval wait for one; if it can't be asked, calls are refused. Monitored, each call's decision records what it would have done. Needs `AGENTGOV_AUTHZEN_URL` where the processor runs |
| `authzen-decision-point` | **off**, on | Answers AuthZEN evaluations with AgentGov's policies at `/access/v1/evaluation` on the control plane, for enforcement points other than AgentGov's gateway ([AuthZEN](policies.md#agentgov-as-a-decision-point)). Off, the endpoints answer 404. Needs OPA where the control plane runs |

### Developer tools

| Feature | Modes | What it does |
|---|---|---|
| `mcp-registry` | **off**, on | Serves the tool servers listed for developers as an MCP registry at `<control plane>/registry`, which GitHub Copilot and VS Code read to offer developers only approved MCP servers ([developer tools](developer-tools.md)). Its readers have no credentials, so the registry is served without them: it is off until you turn it on |
| `mcp-discovery` | off, **on** | Takes reports of the MCP servers set up on developers' machines (`agentgov mcp scan --report`), compares them with the approved tool servers, and raises findings for those that aren't approved, that skip the gateway or that are blocked. Off, reports are refused; findings already raised stay until resolved |
| `developer-sign-in` | **off**, on | Developers' MCP clients reach the tool servers on the gateway with the developer's own token: each tool server's route serves its OAuth protected resource metadata, which names Keycloak, and answers a call without a token with a pointer to it, so that the client signs the developer in to an agent registered as a public client ([developer tools](developer-tools.md#signing-in-at-the-gateway)). Off, the gateway takes the same tokens but doesn't say where to sign in. Needs `AGENTGOV_KEYCLOAK_ISSUER` and `AGENTGOV_KEYCLOAK_JWKS_URL` |

### Identity

| Feature | Modes | What it does |
|---|---|---|
| `workload-identity` | off, **on** | Agents authenticate with an identity they already have, such as a Kubernetes service account, a SPIFFE ID or a Microsoft Entra Agent ID, from the identity issuers an administrator approves, instead of a client secret ([agents' own identities](agent-identity.md)). Off, no issuer is trusted: agents with a workload identity can't authenticate until it is on again. Needs Keycloak 26.6 or later, and Keycloak's `spiffe` preview feature for SPIFFE issuers |
| `identity-assertions` | **off**, on | Agents get identity assertions (ID-JAG, MCP's enterprise-managed authorization) at `<control plane>/oauth2/token` for the MCP servers outside the gateway registered with an authorization server, as their grants and blueprints allow, and trade them there for access tokens ([acting for people](acting-for-people.md#mcp-servers-outside-the-gateway)). The ledger records each one given or refused. Off, none are given. Needs the service token, Keycloak's issuer and keys, and OPA, where the control plane runs |

### Lifecycle

| Feature | Modes | What it does |
|---|---|---|
| `registration-approval` | off, **on** | Agents registered by people who aren't administrators start pending, until an administrator approves them. Off, they are active at once |
| `access-packages` | off, **monitor**, enforce | Lets agents hold extra tools, models and agents to call for a while ([access packages](access-packages.md)): requested by their owners, sponsors or approvers, approved, and reminded, renewed or reviewed before they expire. Enforced, an expired package grants nothing. Monitored, the agent keeps its access, each call that needs it is recorded, and an issue asks for the package to be renewed or revoked. Off, packages grant nothing and can't be requested. It starts in monitor mode so that no agent loses access by surprise: enforce it once owners renew in time. Packages only matter while `least-privilege` is enforced |
| `issues` | off, **on** | Sends findings to the people responsible for them ([issues](issues.md)): an agent's owner first, then its sponsors, then its team, by email and in the team's Teams or Slack channels. An issue nobody acknowledges in time goes on to the next of them. People without an AgentGov role can sign in to see and acknowledge their own. Off, findings stay in AgentGov's list and nothing is sent; people without a role can't sign in unless `approvals-by-person` is on |
| `management-rules` | off, **monitor**, enforce | Rules act on the agents that meet their conditions for long enough ([management rules](management-rules.md)): they raise an issue, give an agent an owner, block it, delete it or revoke its access packages, after telling its people, and on a few agents at once at most. Enforced, rules in enforce mode tell, then act. Monitored, rules tell nobody and change nothing; they record what they would have done. Off, no rule runs and their issues are resolved. Rules run after each posture scan, so not while `posture-checks` is off |

### Microsoft

Each of these also needs what [microsoft-connections.md](microsoft-connections.md)
describes. Turning one off stops it even where it is configured.

| Feature | Modes | What it does |
|---|---|---|
| `microsoft-365` | off, **on** | Reads the Microsoft 365 agent catalog into the inventory |
| `entra-agent-id` | off, **on** | Reads agents' Entra identities and links them to their agents |
| `purview-audit` | off, **on** | Reads agent usage, attacks on agents and makers' changes from the audit log |
| `defender` | off, **on** | Turns Defender's alerts about agents into findings |
| `entra-access-packages` | off, **inform**, manage | Reads the access packages Microsoft Entra ID Governance assigns agents' Entra identities, and raises an [issue](issues.md) before one expires. Managed, administrators also assign and remove them from AgentGov; informed, nothing is written into Entra ([Entra access packages](microsoft-connections.md#microsoft-entra-access-packages)) |
| `copilot-studio-threat-detection` | **off**, monitor, enforce | Answers Copilot Studio before each tool call its agents make. Monitor tells Copilot Studio to go ahead and records what would have been blocked. Off, AgentGov's endpoint refuses Copilot Studio's calls. Needs `AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS` and the tenant ID, and OPA to enforce |

### Other platforms

Each of these also needs the settings [other platforms](other-platforms.md) describes.
Turning one off stops it even where it is configured.

| Feature | Modes | What it does |
|---|---|---|
| `aws` | off, **on** | Reads the agents on AWS into the inventory: Amazon Bedrock agents and AgentCore's harnesses and agent runtimes, with their risky settings as findings |
| `google-cloud` | off, **on** | Reads the agents on Google Cloud into the inventory: Agent Runtime agents (formerly Vertex AI Agent Engine), with their risky settings as findings |
| `salesforce` | off, **on** | Reads the Agentforce agents in your Salesforce org into the inventory, with their risky settings as findings and their topics' instructions checked |

### Security operations

| Feature | Modes | What it does |
|---|---|---|
| `security-operations` | **off**, inform, triage, contain, decide | Hands AgentGov's evidence and alerts to the security team's tools ([security operations](secops.md)). From inform, SIEMs get the ledger as OCSF events and Teams and Slack channels get alerts, through the destinations an administrator adds, and the events API serves the events. Each level up also lets the `secops` role, which the security team's tools and analysts hold, do more: triage resolves, dismisses and reopens findings; contain blocks and unblocks agents, tool servers, model providers and identity issuers; decide approves and denies the approval requests sent to approvers. Off, nothing is sent and the `secops` role only reads |

Some things are never switched off: an agent or tool server that is blocked stays
blocked, callers must be registered agents unless `unknown-callers` is monitored, and
organisation policies' denials always apply.

## Rolling out a control

1. Set the control to monitor: `agentgov features set least-privilege monitor`.
2. Let agents work. Each call a monitored control would have stopped is a ledger
   warning. Its reason starts with `monitored:` and its details list what each control
   would have done.
3. Fix what you find. For example, grant the tools agents legitimately need.
4. Enforce: `agentgov features set least-privilege enforce`.

## How each part applies the modes

* **OPA.** The bundle carries every mode as `data.registry.features`. The built-in
  policies apply each control as its mode says. They return what monitored controls
  would have done as `monitored` in the decision. An organisation policy can read the
  modes too, with `data.agentgov.context.enforced("approvals")`, `monitored(...)` and
  `mode(...)`. Its `deny` always applies; its `require_approval` follows `approvals`,
  and its `redact` follows `data-protection`.
* **The governance processor** reads the modes from OPA at most five seconds old. It
  doesn't inspect what an off control would look at, and it records `monitored` with
  each decision.
* **The gateway's configuration** follows `mcp-gateway`, `model-gateway`, `a2a-gateway`,
  `unknown-callers` and `developer-sign-in` when the control plane rewrites it.
* **The control plane** checks the modes when it acts: discovery, posture scans,
  instruction checks, registration, the automatic block, the Microsoft connections, and
  what it sends the security team's tools and lets their `secops` role do.
* **The Agent Governance Toolkit** (in-process) applies `least-privilege` and
  `risk-based-access` only when they are enforced. It can't record what a monitored
  control would have done.

## Settings that became features

Some environment variables became features, and AgentGov refuses them now, naming the feature
that replaced each one: [configuration](configuration.md#settings-that-changed) lists them.

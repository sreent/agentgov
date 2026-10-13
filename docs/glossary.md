# Glossary

The words AgentGov uses for each thing, the same in the admin center, the CLI, its emails,
chat messages and tickets, and these docs. Where the API, a setting or the ledger names
something differently, the last column says so.

## Agents

| Word | What it is | Elsewhere |
|---|---|---|
| Agent | Software that acts with its own identity: calls tools, models or other agents, through AgentGov's gateway or on a platform AgentGov reads | |
| Unmanaged agent | An agent nobody has adopted yet: found on one of your platforms, or seen at runtime without being registered. It has no owner until someone adopts it | Status `discovered` |
| Adopt | Bring an unmanaged agent under governance: give it an owner, sponsors and a blueprint, then approve it | `POST /v1/agents/{ref}/adopt` |
| Pending approval | Registered or adopted, and waiting for an administrator to approve it | Status `pending` |
| Active | Approved: it may do what its blueprint and grants allow | Status `active` |
| Blocked | Stopped: its calls are refused, and, where AgentGov may act on its platform, it is blocked there too | Status `blocked` |
| Deleted | Removed from the inventory, and restorable | Status `deleted` |
| Gone | No longer on the platform it was found on: a full inventory or a sync left it out. It stays in the registry, and its issues close | |
| Owner | The person or team accountable for an agent; its issues go to them first | |
| Sponsor | A person or team who vouches that the agent is still needed and its access is still right, and attests it; its issues go to them next | |
| Team | People and chat channels that own agents, and that issues reach after an agent's owner and sponsors. The default team takes what has nobody else | |
| Blueprint | What a kind of agent may use: tools, models, other agents, its risk tier, and how often its sponsors attest it | |
| Attest | A sponsor confirms that an agent is still needed and its access is still right | |

## Issues

| Word | What it is | Elsewhere |
|---|---|---|
| Issue | Something wrong with an agent, a tool server or AgentGov itself: a posture gap from a scan, a threat detected at runtime, an alert from Microsoft Defender. It goes to the people responsible ([issues](issues.md)) | *Finding* in the API (`/v1/findings`), the ledger (`finding.raised`) and the SIEM events; `agentgov findings` still works |
| Issue type | What kind of issue it is, such as `agent.no_owner`; each type can be turned off, or given a severity | *Finding type* (`/v1/finding-types`) |
| Acknowledge | Take an issue on: it goes no further up its chain | |
| Not mine | Say an issue isn't yours, and why: it goes on to the next people at once | `not-mine` |
| Accept the risk | An approver decides that an issue's risk is acceptable until a date, with a reason: it goes to nobody until then | Status `accepted` |
| Risk acceptance asked | The people an issue reached asked an approver to accept its risk; it waits on **Approvals** | `exception` in the API (`POST /v1/findings/{id}/exception`); `agentgov issues ask-to-accept` |
| Dismiss | Say an issue is wrong, and why, for good or until a date. A real risk is accepted, not dismissed | Status `dismissed` |
| Resolve | Close an issue whose cause is gone. Most close by themselves at the next check | Status `resolved` |
| Unverified | The sync that checks an issue failed, so it may no longer hold; it stays open until the check runs again | `verified: false` |

## Decisions

| Word | What it is | Elsewhere |
|---|---|---|
| Approvals | Everything waiting for a decision of yours, in one place: held calls, access requests, risks to accept, agents and tool servers to approve, changed tool definitions, and agents found on platforms ([administration](administration.md#approvals)) | `GET /v1/inbox`, `agentgov inbox` |
| Held call | A call an agent made that policy holds until a person approves or denies it | *Approval request* (`/v1/approvals`) |
| Access package | Tools, models and agents an agent holds for a while once someone approves it ([access packages](access-packages.md)) | |
| Changed tool definition | A tool whose definition changed since it was approved: with `tool-integrity` enforced, its calls are refused until an administrator approves the change | `toolserver.tool_drift` |

## Controls

| Word | What it is | Elsewhere |
|---|---|---|
| Feature | A part of AgentGov you choose to use, such as `prompt-injection` or `issues` ([features](features.md)) | |
| Off, monitor, enforce | How strictly a control works: not at all; watching and recording without stopping anything; or stopping what it finds | |
| Exception | Another mode for a control for some agents, such as enforced for one team while the rest are monitored ([features](features.md#exceptions)). Not to be confused with accepting an issue's risk | `scopes` in the API |
| Block | Stop an agent, a tool server, a model provider or an identity issuer at once | Chat alerts list blocks |
| Management rule | What to do about agents that meet some conditions for long enough, after telling their people ([management rules](management-rules.md)) | |
| Policy | Rego rules OPA evaluates for every call through the gateway ([policies](policies.md)) | |

## Evidence and the security team

| Word | What it is | Elsewhere |
|---|---|---|
| Ledger | The tamper-evident record of every decision and change ([evidence](evidence.md)) | *Evidence ledger* |
| Destination | Where AgentGov sends events, alerts and tickets: a SIEM, a Teams or Slack channel, or a service desk ([security operations](secops.md), [tickets](tickets.md)) | |
| Hand-off level | How much the security team's tools may do: inform, triage, contain or decide ([security operations](secops.md#how-much-is-handed-over)) | |
| Ticket | An issue's copy in ServiceNow, Jira Service Management or Freshservice, kept in step with it ([tickets](tickets.md)) | |

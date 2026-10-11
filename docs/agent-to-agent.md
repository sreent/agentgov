# Agent to agent

Agents hand work to other agents: a support agent asks a billing agent what a customer
owes, an orchestrator sends tasks to specialists. With A2A (the Agent2Agent protocol,
[v1.0](https://a2a-protocol.org/latest/specification/)) they do it the same way whatever
built them. AgentGov puts those calls through the gateway, as it does tool and model
calls, and:

* decides each call with policy: who may call whom, and the controls that apply to tool
  calls (least privilege, data protection, acting for people, risk, approvals);
* tells the agent called who handed it the work, and carries that on: the calls it makes
  for the work, to tools, models and other agents, carry the chain of agents that handed
  it down, with the person at its head, to policy and to the ledger.

```mermaid
sequenceDiagram
    autonumber
    participant S as support-bot (for sam)
    participant G as agentgateway
    participant Pr as Governance processor
    participant O as OPA
    participant B as billing-agent
    S->>G: SendMessage to /a2a/billing-agent, with its token
    G->>Pr: external authorization: the caller and the person (from the token), the message
    Pr->>O: data.agentgov.a2a.decision
    O-->>Pr: allow
    Pr-->>G: go ahead, with a delegation for billing-agent and who handed it the call
    G->>B: the request, with X-AgentGov-Delegation, -Caller, -On-Behalf-Of and -Chain
    B->>G: tools/call get_customer, with its own token and the delegation
    G->>Pr: the tool call and the delegation
    Pr->>O: data.agentgov.mcp.decision, with the chain sam > support-bot > billing-agent
    Pr--)Pr: both decisions → ledger, with the chain
```

## Agents that serve A2A

An agent that serves A2A has an `a2a_url` in the registry: its A2A endpoint (the JSON-RPC
binding), which only the gateway should reach. With the `a2a-gateway`
[feature](features.md) on (the default), AgentGov publishes it on agentgateway at
`/a2a/<agent>`:

| Gateway | |
|---|---|
| `GET /a2a/billing-agent/.well-known/agent-card.json` | Its agent card. The gateway gives callers its own address in the card's `supportedInterfaces`, so that their A2A clients call it through the gateway |
| `POST /a2a/billing-agent` | Its A2A methods: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask` and the others |

Callers authenticate with their AgentGov token, as for tool and model calls (while the
`unknown-callers` feature monitors, others get through, and are recorded and discovered).
Active and blocked agents are published: calls to a blocked agent are refused with a
reason. Agents waiting for review, discovered or deleted aren't, nor agents on the
platforms AgentGov inventories (Microsoft 365, Copilot Studio): the agent's page says why.
With the feature off, no agent is published, and the registry keeps their A2A endpoints.

| | How |
|---|---|
| Admin UI | **Agents** → an agent's **Edit**, *Agent to agent*, *A2A endpoint*. Its page shows where agents call it, its card, whom it may call and who may call it |
| CLI | `agentgov agents update billing-agent --a2a-url http://billing-agent:9600` (`--no-a2a` to stop); `agentgov agents a2a billing-agent` |
| API | `a2a_url` in `POST /v1/agents` and `PATCH /v1/agents/{name}`; `GET /v1/agents/{name}/a2a` |
| Manifests | `a2a_url` in an `Agent`'s spec ([example](../examples/manifests/agents.yaml)) |

## Who may call whom

`agent_access` lists the agents an agent may call, by name or pattern (`billing-*`): a
blueprint's for all its agents, and an agent's own on top of its blueprint's, as with tool
grants.

| | How |
|---|---|
| Admin UI | **Policies** → a blueprint's **Edit**, *Agent to agent*; **Agents** → an agent's **Edit**, *Extra agents it may call*. The **Agent map** draws an arc from each agent to the agents it may call, and in red to those it called without a grant |
| CLI | `agentgov blueprints update customer-support --agent-access billing-agent`; `agentgov agents update support-bot --agent-access kb-*` (`--no-agent-access` to clear) |
| API | `agent_access` in blueprints and agents; `effective_agent_access` on an agent |
| Manifests | `agent_access` in a `Blueprint`'s or an `Agent`'s spec ([example](../examples/manifests/blueprints.yaml)) |

These rules always apply:

* the agent calling and the agent called are registered and active, and the agent called
  serves A2A;
* no agent calls itself, nor an agent already in the chain (a loop);
* a chain holds at most five agents, the caller and the agent called included.

The controls apply as their features say: enforced, they refuse; monitored, the call goes
through and the ledger records what they would have done.

| Control | On a call between agents |
|---|---|
| `least-privilege` | The caller may call the agents its `agent_access` names, or an [access package](access-packages.md) it holds |
| `access-packages` | Calls only an access package that has expired allows are refused (enforced) or recorded (monitored) |
| `data-protection` | A message with credentials is refused. Personal data is found and recorded |
| `acting-for-people` | The caller acts for the person as its blueprint allows, and so must the agent called, which acts for that person from then on |
| `risk-based-access` | No agent at critical risk calls another, or is called |
| `approvals` | An organisation policy's `require_approval` holds the call for an approver (or the person, with `approvals_by: person`); the caller sends the same message again once it is approved |

## The chain of delegation

When the gateway passes a call on, AgentGov gives the agent called a **delegation**: a
token in the `X-AgentGov-Delegation` header, signed by AgentGov, for that agent only, that
lasts an hour. It names the agents that handed the work down, in order, and the person at
their head when the work is for a person.

The agent sends it back with the calls it makes for that work, to tools, models and other
agents, as a header beside its own token:

```python
headers = {
    "Authorization": f"Bearer {own_token}",  # the agent's own token, as always
    "X-AgentGov-Delegation": request.headers["X-AgentGov-Delegation"],  # what it was given
}
```

AgentGov checks it: signed by AgentGov, not expired, given to the agent that sends it, and
for the same person as the agent's token, if its token is for one. Then:

* policy sees the chain as `input.chain`, and the person at its head as `input.user`, even
  when the agent calls with a token of its own;
* the ledger records the chain with each decision, with the delegation's ID and its
  parent's.

A delegation AgentGov didn't give, an expired one, another agent's, or one for another
person gets the call refused. A call without one is the agent's own work.

The gateway also tells the agent called, in plain headers:

| Header | |
|---|---|
| `X-AgentGov-Caller` | The agent that called it |
| `X-AgentGov-On-Behalf-Of` | The person at the head of the chain, if any |
| `X-AgentGov-Chain` | The chain so far, such as `sam > support-bot` |

AgentGov sets all four on every call it passes on, over any a caller sent, so an agent
called through the gateway can rely on them. Agents carry the delegation without reading
it: it is a JWT that only AgentGov's processors sign and check, with a key derived from
`AGENTGOV_SERVICE_TOKEN`, as OAuth
[transaction tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
carry the context of a request between workloads.

## In policy

The processor asks `data.agentgov.a2a.decision`:

```json
{
  "kind": "a2a",
  "method": "SendMessage",
  "agent": {"agent_id": "agt_…", "client_id": "agent-support-bot"},
  "target": "billing-agent",
  "user": {"id": "5c0b…", "username": "sam", "groups": ["/support"], "via": "exchange"},
  "chain": [{"type": "person", "id": "5c0b…", "name": "sam"}],
  "detections": {"categories": [], "entities": []}
}
```

Organisation policies tell calls between agents by `input.kind == "a2a"`, and read
`input.chain` on tool and model calls too:

```rego
package agentgov.custom.payments

import data.agentgov.context as ctx

# Only work a person started reaches the payments agent.
deny contains "Calls to payments must come from a person's request" if {
	input.kind == "a2a"
	input.target == "payments"
	not ctx.user
}

# Refunds handed down by another agent wait for an approver.
require_approval contains "Refunds another agent asked for need an approver" if {
	input.resource.name == "refund"
	some link in input.chain
	link.type == "agent"
}
```

To try a call, choose **A call to another agent** in **What if** on the Policies page, or
`agentgov policies evaluate --agent support-bot --call-agent billing-agent --user sam`.

## In the ledger and the SIEM

| Entry | |
|---|---|
| `decision.a2a.request` | A call between agents: the caller is the agent, the agent called the resource, the A2A method the action, and the person in `on_behalf_of`. Its details hold the A2A context and task, the whole chain (ending with the agent called) and the delegation it gave (`uid`) with its parent's (`parent_uid`) |
| `decision.request`, `decision.model.request`… | A tool or model call made under a delegation holds the chain, ending with the agent calling, and the delegation's IDs |

[Security operations](secops.md) hands both to SIEMs as OCSF API Activity: the agent
called as the `api.service` and a `resources` entry of type `AI Agent`, the A2A context in
`message_context`, and OCSF's `delegation` object (`uid`, `parent_uid`, and `issuer_uid`
`agentgov`).

| | How |
|---|---|
| Admin UI | **Ledger**, each entry with its chain; **Agent map**, calls between agents in the last 30 days and how many were refused |
| CLI | `agentgov ledger tail --type 'decision.a2a.*'` |
| API | `GET /v1/ledger?type=decision.a2a.request`; `GET /v1/graph` |

## Trying it

The Compose stack runs **billing-agent** ([examples/agents/billing](../examples/agents/billing/server.py)),
an A2A agent with no secret (it authenticates with its service account token from the
demo cluster) that looks customers up in the CRM through the gateway. The
`customer-support` blueprint's agents may call it. Step 11 of
`python examples/agents/demo_agent.py`:

1. the demo agent, acting for sam, reads billing-agent's card through the gateway, and
   asks it what a customer owes, claiming to act for someone else;
2. billing-agent answers, and says who asked and for whom: the demo agent, for sam;
3. the ledger holds the call between the agents, and billing-agent's own call to the CRM,
   each with the chain `sam > demo-agent-… > billing-agent`;
4. a delegation the demo agent made up is refused;
5. without its blueprint's grant, the demo agent's call is refused.

## Limits

* AgentGov checks the requests agents send each other, not the answers: agentgateway asks
  the processor before it passes a request on. The agent called is governed in turn: its
  own tool and model calls go through the gateway with the chain.
* Personal data in a message is found and recorded, not masked: the gateway passes the
  request on as it is. Credentials are refused.
* The processor reads each request whole, up to 256 KiB: agentgateway refuses larger ones
  (HTTP 413) before they reach policy.
* The headers are only as trustworthy as the network between the gateway and the agent:
  let only the gateway reach agents' A2A endpoints (in Kubernetes, a NetworkPolicy).
  Calls that skip the gateway aren't governed.
* The gateway routes the JSON-RPC binding. Push notifications, the agent calling a
  caller's webhook back, don't go through it.
* Delegations are signed with a key derived from the service token: changing
  `AGENTGOV_SERVICE_TOKEN` ends the delegations in flight, which last an hour at most.

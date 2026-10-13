# Policies

Authorization is decided by [Open Policy Agent](https://www.openpolicyagent.org) using
the Rego library in `src/agentgov/policies/`. The control plane ships the library and
the live registry to OPA as a bundle; the governance processor asks OPA for a decision on
every governed MCP operation, on every prompt and answer of a [model call](models.md), and on
every [call between agents](agent-to-agent.md).

## How a decision is made

Every rule contributes to one of three sets, and the outcome follows a fixed precedence:

1. any entry in **`deny`** → the call is refused (or the result withheld);
2. otherwise any entry in **`require_approval`** → the call waits for a human;
3. otherwise **allow**, after masking whatever is in **`redact`** (`"secret"`, `"pii"`).

Grants are the ceiling: an agent can only call tools that its blueprint, its own
`permissions` or an [access package](access-packages.md) it holds grants. Policies can only
take permissions away or add conditions.

Most rules belong to a control that an administrator can switch
([features](features.md)): enforced, the rule applies; monitored, it only adds what it
would have done to **`monitored`**, and the call goes through; off, it doesn't apply.
The decision carries `monitored`, and the ledger records it.

## Built-in rules

| Rule | Effect | Control |
|---|---|---|
| Caller is not a registered agent | deny | `unknown-callers` |
| Agent is not `active` (pending, blocked, deleted) | deny | always |
| Tool server unknown, pending approval or blocked | deny | always |
| Tool not granted to the agent (least privilege) | deny, and hidden from `tools/list` | `least-privilege` |
| Tool granted only by an access package that has expired | deny, and hidden from `tools/list` | `access-packages` |
| Tool definition changed since it was approved (MCP rug pull) | deny until an admin approves the new definition | `tool-integrity` |
| Tool description contains hidden instructions (tool poisoning) | deny, and hidden from `tools/list` | `tool-integrity` |
| The agent acts for someone its blueprint doesn't allow (`acts_for`, `people_groups`), or for no one when it must act for a person | deny, and nothing in `tools/list` | `acting-for-people` |
| Credentials in tool arguments | deny | `data-protection` |
| Agent risk level is `critical` | deny (risk-based access) | `risk-based-access` |
| Tool result contains a prompt-injection payload | result withheld | `prompt-injection` |
| Tool annotated `destructiveHint: true` | require approval | `approvals` |
| Credentials in a tool result | redact `secret` | `data-protection` |
| Personal data in a tool result, agent lacks the `pii-access: "true"` label | redact `pii` | `data-protection` |
| Personal data sent to a server whose `trust_level` is not `verified` | redact `pii` | `data-protection` |

Every MCP call goes through these rules except those that set up and keep up the session
(`initialize`, `ping`, notifications). Reading a prompt or a resource, subscribing to one or
completing one of its arguments is checked as calling a tool is, by its name. A call about the
server as a whole, such as listing its prompts or resources or a method MCP adds later, has no
tool to grant: it gets the rules for the caller, the agent and the server, who the agent acts
for and its risk, and the lists it gets back aren't filtered as `tools/list` is.

## What a policy sees

`input` (built by the governance processor):

```json
{
  "phase": "request",                       // or "response"
  "method": "tools/call",                   // or any other MCP method but setting up the session
  "agent": {"client_id": "agent-support-bot", "agent_id": "agt_…", "subject": "…"},
  "user": {"id": "…", "username": "sam", "email": "sam@example.com",   // the person the agent
           "groups": ["/support"], "roles": [], "via": "exchange"},      // acts for, if any
  "chain": [{"type": "person", "id": "5c0b…", "name": "sam"}],          // who handed the work down
  "resource": {"server": "crm", "name": "delete_customer"},  // the tool, prompt or resource;
                                            // name is null for a call about the server as a
                                            // whole, such as listing its prompts or resources
  "arguments": {"customer_id": "c-003"},    // request phase only
  "detections": {
    "categories": ["pii"],                  // "secret", "pii"
    "entities": ["EMAIL_ADDRESS"],          // Presidio entities and secret types
    "prompt_injection": false,
    "injection_score": 0.0,
    "injection_reasons": [],
    "truncated": false                      // payload exceeded the scanning budget
  }
}
```

`data.registry` (from the control plane, refreshed on every change):

```json
{
  "agents": {"agt_…": {"name": "support-bot", "status": "active", "blueprint": "customer-support",
                        "owner": "cx-platform", "sponsors": ["alice@example.com"],
                        "labels": {"pii-access": "true"}, "environment": "prod",
                        "risk_tier": "medium", "risk_level": "low", "risk_score": 10,
                        "grants": [{"server": "crm", "tools": ["get_*"]}],
                        "acts_for": "either", "people_groups": [],
                        "a2a": false, "agent_access": ["billing-*"],
                        "workload_identity": {"issuer": "prod-cluster",
                                              "subject": "system:serviceaccount:agents:support-bot"}}},
  "clients": {"agent-support-bot": "agt_…"},
  "toolservers": {"crm": {"status": "approved", "trust_level": "verified",
                          "data_classification": "confidential", "labels": {},
                          "tools": {"delete_customer": {"annotations": {"destructiveHint": true},
                                                        "changed": false, "poisoned": false}}}},
  "blueprints": {"customer-support": {"risk_tier": "medium", "permissions": [...], "labels": {}}},
  "features": {"least-privilege": "enforce", "approvals": "monitor", "discovery": "on", ...}
}
```

`data.agentgov.context` resolves the common lookups for you: `ctx.agent`, `ctx.server`,
`ctx.tool`, `ctx.annotations`, `ctx.granted(server, tool)`, `ctx.label(name)`, the person
the agent acts for with `ctx.user`, `ctx.user_name` and `ctx.member_of(group)`
([acting for people](acting-for-people.md#in-policy)), and a feature's mode with
`ctx.mode(feature)`, `ctx.enforced(feature)` and `ctx.monitored(feature)`. An agent's
`workload_identity` is `null` while it authenticates with a client secret
([agents' own identities](agent-identity.md#in-policy)).

## Writing an organisation policy

Organisation policies are Rego modules in package `agentgov.custom.<name>` (dashes in the
name become underscores). They may define any of the three sets. Their `deny` always
applies; their `require_approval` applies as the `approvals` control does, and their
`redact` as `data-protection` does:

```rego
package agentgov.custom.payments_limits

import data.agentgov.context as ctx

# Refunds above 500 need a human; above 5,000 they are refused outright.
require_approval contains msg if {
	input.resource.name == "refund"
	input.arguments.amount > 500
	msg := sprintf("Refund of %v needs approval", [input.arguments.amount])
}

deny contains "Refunds above 5,000 are not allowed for agents" if {
	input.resource.name == "refund"
	input.arguments.amount > 5000
}

# Analysts in the EU may not see personal data from US systems.
redact contains "pii" if {
	ctx.agent.labels.region == "eu"
	ctx.server.labels.region == "us"
}
```

Apply it like any other resource:

```yaml
apiVersion: agentgov/v1alpha1
kind: Policy
metadata:
  name: payments-limits
spec:
  description: Approval and hard limits for refunds.
  regoFile: payments-limits.rego   # `agentgov apply` inlines it; the API takes `rego`
```

Before a policy is accepted, the control plane compiles it with the library
(`opa check --strict`), evaluates it against sample inputs, and checks that `deny`,
`require_approval` and `redact` are sets. A module that would break the bundle — and with
it every later registry change, including blocks — is rejected with the compiler's
message instead of being shipped.

## Model calls

Agents' calls to models through the gateway are decided by
`data.agentgov.models.decision`, for each prompt (`phase: "request"`) and for each answer
that holds something to decide on (`phase: "response"`). Its built-in rules:

| Rule | Effect | Control |
|---|---|---|
| Caller is not a registered agent | deny | `unknown-callers` |
| Agent is not `active` | deny | always |
| Model provider unknown or blocked | deny | always |
| Model not granted to the agent (`model_access`, or an access package it holds) | deny | `least-privilege` |
| Model granted only by an access package that has expired | deny | `access-packages` |
| The agent acts for someone its blueprint doesn't allow, or for no one when it must act for a person | deny | `acting-for-people` |
| Credentials in the prompt | deny | `data-protection` |
| Credentials in the answer | answer withheld | `data-protection` |
| Personal data in a prompt to a provider whose `trust_level` is not `verified` | redact `pii` (masked before the prompt leaves) | `data-protection` |
| Personal data to mask in a conversation that holds tool calls | deny (masking would break them) | `data-protection` |
| A tool result in the conversation contains a prompt-injection payload | deny | `prompt-injection` |
| The latest prompt from a person looks like a jailbreak | deny | `jailbreak-detection` |
| Agent risk level is `critical` | deny | `risk-based-access` |
| Agent has used its daily token budget | deny | `token-budgets` |

Organisation policies' `deny` applies to model calls, and their `redact` masks prompts
as `data-protection` does. A model call can't wait for an approver, so
`require_approval` doesn't apply. The input has `kind: "model"`:

```json
{
  "kind": "model",
  "phase": "request",                       // or "response"
  "agent": {"client_id": "agent-support-bot", "agent_id": "agt_…"},
  "user": {"id": "…", "username": "sam", "groups": ["/support"], "via": "exchange"},  // if any
  "provider": "openai",
  "model": "gpt-4.1-mini",
  "detections": {"categories": ["pii"], "entities": ["EMAIL_ADDRESS"],
                 "prompt_injection": false, "injection_score": 0.0,
                 "jailbreak": false, "jailbreak_score": 0.0},
  "tool_calls": false                       // the conversation holds tool calls or results
}
```

`data.registry.model_providers` holds each provider's `kind`, `status`, `trust_level`
and `labels`, and each agent in `data.registry.agents` its `model_access`,
`daily_token_budget`, whether it is `over_budget` today, and the access `packages` it
holds (each with its `grants`, `model_access`, `agent_access` and `expires_at`). For example:

```rego
package agentgov.custom.prod_models

import data.agentgov.context as ctx

deny contains "Production agents may only use self-hosted models" if {
	input.kind == "model"
	ctx.agent.environment == "prod"
	data.registry.model_providers[input.provider].labels.hosting != "self-hosted"
}
```

Rules written for tool calls look at `input.resource`, which model calls don't have, so
they don't apply to them. To ask the live OPA about a model call, use **What if** on the
Policies page, `agentgov policies evaluate --provider … --model …`, or send
`"path": "agentgov/models/decision"` with the input to `POST /v1/policies/evaluate`.

## Calls between agents

Calls between agents ask `data.agentgov.a2a.decision`, with `input.kind == "a2a"` and the
agent called in `input.target`. Its built-in rules refuse calls to agents that aren't
registered, active or serving A2A, an agent calling itself, a loop back to an agent already
in the chain, and chains of more than five agents; under `least-privilege`, a caller may call
only the agents its `agent_access`, or an [access package](access-packages.md) it holds,
names. While `a2a-masking` is enforced, the decision's `redact` names the personal data to
mask in the message, unless the agent called has the `pii-access` label (its own or its
blueprint's). Each answer the agent called sends back asks the same decision, with
`input.phase == "response"`: the built-in rules withhold an answer that carries instructions
aimed at the caller, and mask credentials, and personal data unless the caller has the
`pii-access` label (its own or its blueprint's); an organisation policy's `deny` and `redact` apply to answers
too. [Agent to agent](agent-to-agent.md#in-policy) shows
the input and an organisation policy for these calls. To ask the live OPA, use **What if**,
`agentgov policies evaluate --agent … --call-agent …`, or send
`"path": "agentgov/a2a/decision"` to `POST /v1/policies/evaluate`.

## Copilot Studio's tool calls

With [Copilot Studio threat detection](microsoft-connections.md#copilot-studio-threat-detection)
connected, the same OPA also decides the tool calls of Copilot Studio agents, through
`data.agentgov.copilotstudio.decision`. Its built-in rules deny a call when the agent is
blocked in AgentGov or critical risk, when the tool's connector isn't on the [connector
allowlist](platforms.md#connector-allowlist), when the inputs contain credentials, and
when an earlier tool result in the plan carried instructions aimed at the agent.

Organisation policies' `deny` rules apply to these calls too. Copilot Studio can't wait
for an approver or change a tool's inputs, so `require_approval` and `redact` don't. The
input is different, and `input.platform` tells the two apart:

```json
{
  "platform": "copilot-studio",
  "agent": {"id": "agt_…", "platform_id": "…", "environment_id": "…", "tenant_id": "…",
            "published": true},
  "user": {"id": "…"},                        // the Entra object ID of the agent's user
  "tool": {"id": "…", "type": "ConnectorTool", "name": "Send an email",
           "connector": "shared_office365"},  // no connector for tools that aren't one
  "arguments": {"to": "…"},
  "detections": {"categories": [], "prompt_injection": false}
}
```

`input.agent.id` is missing when AgentGov doesn't know the agent yet. `ctx.agent` and
`ctx.label(name)` work as they do for the gateway; `ctx.server` and `ctx.tool` don't apply.
A policy for these calls looks like this:

```rego
package agentgov.custom.studio_mail

import data.agentgov.context as ctx

deny contains "Only agents labelled for it may send email from Copilot Studio" if {
	input.platform == "copilot-studio"
	input.tool.connector == "shared_office365"
	ctx.label("send-email") != "true"
}
```

Rules written for the gateway look at `input.phase` and `input.resource`, which these
calls don't have, so they don't apply here. In `monitor` mode, nothing is blocked:
the ledger records what the policies would have decided.

## Testing policies

* **Unit tests**: the library's tests live in `src/agentgov/policies/tests/`; run
  `opa test src/agentgov/policies`. Write tests for your own modules the same way, using
  `with data.registry as {...}`.
* **What if?**: ask the live OPA how it would decide a hypothetical call:

  ```bash
  curl -s localhost:8000/v1/policies/evaluate -H "Authorization: Bearer $AGENTGOV_TOKEN" \
    -H 'Content-Type: application/json' -d '{
      "input": {"phase": "request", "method": "tools/call",
                "agent": {"client_id": "agent-support-bot"},
                "resource": {"server": "crm", "name": "delete_customer"},
                "arguments": {"customer_id": "c-003"}, "detections": {"categories": []}}}'
  ```

## AuthZEN

[AuthZEN](https://openid.net/specs/authorization-api-1_0.html) (the OpenID Foundation's
Authorization API, 1.0) is a standard way for an enforcement point to ask a decision
point whether a subject may do an action on a resource. AgentGov speaks it both ways, so
that the decision point and the enforcement points can each be swapped without the other.

### AgentGov as a decision point

With the `authzen-decision-point` [feature](features.md) on (it is off by default), the
control plane answers AuthZEN evaluations with AgentGov's policies, for enforcement points
other than AgentGov's gateway: another gateway, an API, an agent framework's own checks.

| | |
|---|---|
| `GET /.well-known/authzen-configuration` | Its metadata: where to ask |
| `POST /access/v1/evaluation` | One evaluation |
| `POST /access/v1/evaluations` | Several: the batch's `subject`, `action`, `resource` and `context` fill in what each leaves out, run as `options.evaluations_semantic` says (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`) |

Callers authenticate as for AgentGov's API, with a role that reads it, or the service
token. A call, in AuthZEN's terms (as the COAZ binding for MCP has it, with the tool's
server in its ID, since one gateway fronts many servers):

```json
{
  "subject": {"type": "agent", "id": "agent-support-bot"},
  "action": {"name": "tools/call"},
  "resource": {"type": "tool", "id": "crm/get_customer"},
  "context": {"detections": {"categories": ["pii"]}}
}
```

The subject is an agent (its AgentGov ID or client ID), or a person
(`{"type": "user", "id": ..., "properties": {"username", "email", "groups", "roles"}}`)
with the agent acting for them in `context.agent`. The resource is a tool
(`<server>/<tool>`), a model (`<provider>/<model>`, action `chat`) or another agent (its
name, action `SendMessage`). `context.chain` is who handed the work down, and
`context.agentgov` more of AgentGov's own input ([what a policy sees](#what-a-policy-sees)).
The answer is AgentGov's decision, `data.agentgov.authzen.evaluation`:

```json
{
  "decision": false,
  "context": {
    "reason": "denied",
    "reasons": ["crm/export_all is not granted to agent support-bot"],
    "monitored": [],
    "obligations": [],
    "agentgov": {"effect": "deny", "agent": {"id": "agt_…", "name": "support-bot"}}
  }
}
```

`reason` is `allowed`, `denied` or `approval_required` (as the AuthZEN profile for access
requests has it). An allowed call that must have personal data masked carries an
obligation to do it (`{"type": "custom", "properties": {"vendor": "agentgov", "action":
"redact", "categories": ["pii"]}}`): an enforcement point that can't must deny the call.
AgentGov doesn't record these evaluations: the enforcement point that asks records what
it does.

### Your own decision point beside AgentGov's

With the `external-decision-point` feature and `AGENTGOV_AUTHZEN_URL` where the processor
runs, the processor also asks an AuthZEN decision point of yours (Cedar, through a service
such as Amazon Verified Permissions' AuthZEN sample; Cerbos; Topaz; OpenFGA; Keycloak;
another AgentGov) about each call to a tool, a model or another agent that AgentGov's
policies let through, in the shape above, with a bearer token if it needs one
(`AGENTGOV_AUTHZEN_TOKEN`) and the call's decision ID as its `X-Request-ID`. What the call
carries (arguments, prompts, messages) never goes: only who, what and on what, and the
categories of what was found in it.

| Mode | |
|---|---|
| `enforce` | Calls it denies are refused, with its reasons. A call it says needs approval waits for one, through AgentGov's approvals. What its `agentgov` obligation lists is masked; any other obligation on a permit denies the call. If it can't be asked within `AGENTGOV_AUTHZEN_TIMEOUT_SECONDS`, the call is refused |
| `monitor` | Calls go as AgentGov decides; each decision records what it would have done (`external-decision-point: would deny: ...`) |
| `off` (the default) | It isn't asked |

In the Helm chart, set `processor.env.AGENTGOV_AUTHZEN_URL`, and the token from a Secret
through `processor.envFrom`. AgentGov's own controls keep deciding beside it, each as its
feature says; turn those off that your decision point takes over. It isn't asked about what AgentGov already refuses,
nor about the answers that come back, which are AgentGov's to check.

## In-process enforcement with the Agent Governance Toolkit

Agents built with Microsoft's [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
can enforce the same grants inside the agent process (for tools that never cross the
gateway). Configure its OPA backend in remote mode with package `agentos`; it queries
`data.agentos.allow`, which this library defines as a plain boolean:

```python
from agent_os.policies import OPABackend, PolicyEvaluator  # agent-governance-toolkit-core 5.0

evaluator = PolicyEvaluator()  # YAML rules are consulted first, then backends
evaluator.add_backend(
    OPABackend(mode="remote", opa_url="https://opa.internal:8181", package="agentos")
)
```

Plain tool names are matched against grants for the pseudo-server `local`
(`{"server": "local", "tools": ["search_docs"]}`); names written `server/tool` match that
server's grants. OPA's decision logs for these calls are recorded in the ledger as
`decision.inprocess`. OPA logs no other decisions: the processor and the control plane
record the ones they ask it for themselves, and what-if questions from the policies page
aren't decisions.

Things to know, verified against AGT 5.0.0:

* The agent identity in these calls is self-declared by the agent process. Keep the
  gateway as the enforcement point for anything that must hold against a misbehaving agent.
* AGT's adapter refuses plain HTTP to a non-local OPA: use TLS, or an OPA sidecar on localhost.
* With mutual TLS between AgentGov's components ([production](production.md#mutual-tls-between-components),
  on by default), AgentGov's OPA asks every caller for a certificate from AgentGov's
  authority, which agents don't have. Run an OPA sidecar next to the agent instead: it
  fetches AgentGov's bundles from the control plane's internal port with a certificate of
  its own (`agentgov internal-certs DIR --component NAME`, from the authority's directory,
  or cert-manager's issuer), and the agent asks it on localhost.
* Configure AGT with `default_action: deny`. In 5.0.0, `govern()` treats an unreachable OPA
  as "no decision" and falls back to the YAML default.

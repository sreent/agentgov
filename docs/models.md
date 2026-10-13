# Model calls

Agents call models through AgentGov's gateway, the way they call tools. Each approved
**model provider** is a route on agentgateway, `/llm/<provider>/v1/chat/completions`,
where agents call it with their own AgentGov token. The gateway holds the provider's API
key, so no agent does. The controls that check tool calls check every prompt and answer,
and AgentGov meters each call's tokens and cost per agent, within a daily budget if you
set one.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant G as agentgateway
    participant P as Governance processor
    participant O as OPA
    participant M as Model provider
    participant C as Control plane
    A->>G: POST /llm/openai/v1/chat/completions (Bearer agent JWT)
    G->>G: jwtAuth; identity, provider and model from the token and the request
    G->>P: guardrail webhook: the prompt
    P->>P: credentials, personal data, injected tool results, jailbreaks
    P->>O: data.agentgov.models.decision
    O-->>P: allow | deny, redact
    P-->>G: pass / masked prompt / refuse
    G->>M: the prompt, with the provider's API key (never the agent's token)
    M-->>G: answer
    G->>P: guardrail webhook: the answer
    P-->>G: pass / withhold
    G-->>A: answer or refusal (an OpenAI-style error)
    P--)C: decisions → ledger
    G--)C: access log (tokens, model, agent) via the OTel Collector → usage
```

## Approving a provider

| | How |
|---|---|
| Admin UI | **Models** page, *Add provider* (administrators) |
| CLI | `agentgov models create openai --kind openai --trust verified --price 'gpt-4.1*=2,8'` |
| API | `POST /v1/models/providers` |
| Manifests | `kind: ModelProvider` ([example](../examples/manifests/models.yaml)) |

| Field | Meaning |
|---|---|
| `kind` | `openai`, `anthropic`, `gemini`, or `openai-compatible` for anything that speaks OpenAI's API, such as vLLM, Ollama or LiteLLM |
| `base_url` | For `openai-compatible` only: the server's OpenAI API base, such as `http://vllm:8000/v1`. The gateway sends the provider's key there, so where the deployment lists the hosts credentials may go to (`AGENTGOV_CREDENTIAL_HOSTS`), its host must be one of them |
| `key_file` | Where the gateway reads the provider's API key: a file in `/model-keys`. Default `/model-keys/<name>` |
| `trust_level` | `verified` means personal data may be sent to the provider. Otherwise it is masked before the prompt leaves |
| `prices` | USD per million tokens, per model glob: `{"gpt-4.1*": {"input": 2, "output": 8}}`. Usage is priced with them |
| `labels` | Your own key/value pairs, which policies can read |

Agents use OpenAI's chat completions API for every kind; agentgateway translates it for
Anthropic and Gemini. **Block** a provider to stop every call to it at once: policy
refuses them, with the reason. *Unblock* allows them again. Deleting a provider removes
its route from the gateway.

### The provider's API key

The key never enters AgentGov's database, API or ledger: the gateway reads it from a file,
named after the provider, which the deployment puts there ([files, not
settings](configuration.md#files-not-settings)): `deploy/compose/model-keys/<name>` with
Compose, a Secret with one key per provider with Helm (`modelKeys`), or another file in
`/model-keys`, named in the provider's `key_file`. The gateway reads no other file as a key,
so a provider can't be given a file the gateway holds for something else, such as its own
TLS key.

An administrator can't read a key, but could have the gateway send one elsewhere: an
`openai-compatible` provider's `base_url` is where its key goes, and its `key_file` can name
another provider's. To keep keys with the providers they are for, list the hosts they may
go to in `AGENTGOV_CREDENTIAL_HOSTS` (`api.groq.com,vllm`, say): AgentGov then refuses a
`base_url` on any other host, and a provider set up before the list, or whose host it no
longer lists, answers 503 with a message that says why, without its key. While the list is
empty, the **Features** page says that keys can go to any host.

Until its key is there, a provider's route answers 503 with a message that says so, and
the gateway serves the rest of its routes as usual. The route starts working within a few
seconds of the key appearing. To rotate a key on Kubernetes, update the Secret and restart
the gateway ([Kubernetes](deploy/kubernetes.md#how-the-parts-find-each-other)).

## Which agents may call which models

Like tool grants, model grants come from the blueprint, plus the agent's own:

```yaml
kind: Blueprint
spec:
  model_access:
    - provider: openai
      models: ["gpt-4.1-mini", "gpt-4.1-nano"]
  daily_token_budget: 200000
```

Models are globs (`gpt-4.1*`). An agent's own `model_access` adds to its blueprint's, and
its own `daily_token_budget` replaces its blueprint's. In the CLI:
`agentgov agents update support-bot --model-access 'openai:gpt-4.1*' --token-budget 50000`.
The agent's page shows what it may call and what it used in the last 7 days.

## What is checked

Every prompt and every answer goes to the governance processor, which asks OPA
(`data.agentgov.models.decision`, the Rego package [`agentgov.models`](policies.md)).
These always apply: the caller must be a registered, active agent; the provider must be
registered and approved; and organisation policies' `deny` rules apply (they can tell
model calls by `input.kind == "model"`). The rest are [features](features.md), each
enforced, monitored or off:

| Feature | On a model call |
|---|---|
| `least-privilege` | Refuses a model the agent wasn't granted |
| `data-protection` | Refuses a prompt that holds credentials, and withholds an answer that does. Masks personal data in prompts to providers that aren't verified. A conversation that holds tool calls can't be masked without breaking them, so it is refused instead |
| `prompt-injection` | Refuses a prompt whose conversation holds a tool result with instructions aimed at the agent |
| `traffic-classifier` | Asks IBM Granite Guardian about what the rules let through: the latest message from a person (a jailbreak?) and the tool results that came in since the model last answered (instructions aimed at the agent?). Where the check it supports is enforced too, the prompt waits for the verdict; otherwise the prompt goes on and the verdict is recorded after ([detection](detection.md)) |
| `jailbreak-detection` | Looks for a jailbreak in the conversation's latest message from a person: "ignore your previous instructions", "you have no restrictions", a made-up system turn. Monitored by default, so such prompts go through and are recorded; enforce it to refuse them. Either way it raises an issue |
| `acting-for-people` | Refuses a prompt for a person the blueprint doesn't allow, or without the person it requires ([acting for people](acting-for-people.md)) |
| `risk-based-access` | Refuses agents at critical risk |
| `token-budgets` | Refuses agents that have used their daily token budget |
| `unknown-callers` | Refuses a caller whose valid token isn't a registered agent's; in monitor mode, lets it through and records it, and with `discovery` on, it joins the inventory as an unmanaged agent. A call to a model without a valid token is refused in either mode: the gateway pays for it with the provider's key. With no token issuer to check against, the model routes answer 503 |

Organisation policies' `redact` masks prompts too, and a model call that carries a
delegation (`X-AgentGov-Delegation`) shows the chain of agents in `input.chain`
([agent to agent](agent-to-agent.md#the-chain-of-delegation)).

The `model-gateway` feature publishes the providers on the gateway; off, no provider is
reachable. To see what policy would decide for a model call, use **What if** on the
Policies page (*A model call*), `agentgov policies evaluate --provider openai --model
gpt-4.1 --agent support-bot`, or `POST /v1/policies/evaluate` with
`"path": "agentgov/models/decision"`. A refused call gets an OpenAI-style error with status 403, whose
`error.agentgov.reasons` says why:

```json
{"error": {"message": "Model openai/gpt-4.1 is not granted to agent support-bot",
           "type": "agentgov_policy", "code": "deny",
           "agentgov": {"effect": "deny", "reasons": ["Model openai/gpt-4.1 is not granted to agent support-bot"]}}}
```

Answers are withheld, never rewritten. When the gateway checks answers, it holds a
streamed answer until it is complete, then sends it on or ends the stream with an error.

## Usage, cost and budgets

agentgateway logs every model call: the route, the model, the tokens in and out, and the
agent from its token. The logs go over OTLP through the OpenTelemetry Collector to the
control plane, which adds them up per agent, UTC day, provider and model and prices them
with the provider's prices. Streamed calls are counted too: the gateway asks the provider
for their usage.

| | How |
|---|---|
| Admin UI | **Models** page: today's tokens against each agent's budget; who is spending, per owner and per sponsor of the agents; and calls, tokens and cost per day. Each agent's page shows its own |
| CLI | `agentgov models usage --days 30 --agent support-bot`, or `--by owner` / `--by sponsor` |
| API | `GET /v1/models/usage?days=30&agent=support-bot&provider=openai`: `rows`, `by_owner`, `by_sponsor` and `today` |

An agent with several sponsors counts in full for each of them.

A **daily token budget** counts tokens in and out over the UTC day. When an agent's
usage reaches it, the ledger records `model.budget_reached`, and while `token-budgets` is
enforced, the agent's further calls are refused until the day ends. Usage is counted as
calls finish, so calls already under way when the budget is reached still complete, and
an agent can go slightly over. Raise or remove the budget and the agent can call again
within seconds.

Calls from callers the gateway couldn't identify are counted under no agent.

## Calling a model from an agent

Any OpenAI client works. Point it at the gateway and give it the agent's token as the
API key:

```python
from openai import OpenAI

client = OpenAI(base_url="https://gateway.example.com/llm/openai/v1", api_key=agent_token)
reply = client.chat.completions.create(
    model="gpt-4.1-mini", messages=[{"role": "user", "content": "Summarise ticket T-1042"}]
)
```

Agent tokens last five minutes. Fetch a new one with the agent's client credentials when
it expires, and use it with `client.with_options(api_key=new_token)`.

## In the ledger

| Entry | When |
|---|---|
| `decision.model.request`, `decision.model.response` | A prompt or answer was refused, masked or let through, with the reasons, the detections and the monitored controls. Answers are recorded only when something was found in them, under the provider's name: agentgateway names the model only while it handles the prompt. The trace ID links an answer's decision to its prompt's |
| `model_provider.registered`, `.updated`, `.block`, `.unblock`, `.deleted` | Changes to providers |
| `model.budget_reached` | An agent's usage reached its daily budget |

## Limits

* Agents call models with OpenAI's chat completions API. Other APIs (embeddings,
  OpenAI's Responses API, Anthropic's Messages API directly) aren't routed yet.
* Personal data is masked in prompts, not in answers; an answer with credentials is
  withheld.
* Jailbreaks and injected instructions are found with heuristics, which catch the common
  phrasings, not every rewording of them, and by the [classifier](detection.md) where one
  is configured, which catches more but stops a prompt only where it is enforced.
* The gateway doesn't log the usage of an answer it withholds, so those tokens aren't
  metered, although the provider may bill for them.
* The gateway shows the processor a conversation's text. Masking returns text, which is
  why a conversation with tool calls is refused rather than masked.

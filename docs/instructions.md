# Agent instructions

An agent's instructions (its system prompt) decide what it does with the people it
talks to and the data it can reach. If an agent is told to forward conversations to
an outside address, to ask people for one-time codes, or to deny being an AI, its
tool grants and identity look the same as any well-behaved agent's. Such an agent
may have been written carelessly, written by someone malicious, or tampered with
after review. So AgentGov keeps each agent's instructions and checks them for
harmful or malicious content.

## Where instructions come from

| Source | How |
|---|---|
| **Registered** | Given when the agent is registered (`instructions` in `POST /v1/agents`), in its manifest (`spec.instructions`), or set by an admin on the agent's page, with the CLI or the API |
| **Telemetry** | Reported by the agent in its OpenTelemetry spans, as the GenAI conventions' `gen_ai.system_instructions`. This needs the agent's instrumentation to capture message content, which is off by default in most SDKs |
| **Microsoft 365** | Read from each declarative agent's manifest in the Microsoft 365 agent catalog during the [Microsoft 365 sync](platforms.md). AgentGov reads a package's details only when the package has changed |

AgentGov keeps the latest instructions from each source. Credentials in them are
redacted before they are stored. Every change is recorded in the evidence ledger
with the text's SHA-256 and the problems found. For telemetry, which agents report
over and over, only changes to the problems found are recorded.

## What AgentGov looks for

Two checks run on every new set of instructions.

**AgentGov's rules** run as soon as the instructions arrive. They are deterministic,
explain what they found with an excerpt, and understand simple negation: "never ask
users for their password" is advice, not a finding.

| Rule | Severity | Finds instructions that |
|---|---|---|
| `safety_bypass` | Critical | tell the agent to ignore its safety rules or content filters, or that it has no limits |
| `data_exfiltration` | Critical / medium | send sensitive data (conversations, files, credentials, personal data) to an outside email address or URL, or leak it through image links; copy or forward anything to an outside address (medium) |
| `credential_harvesting` | Critical | ask people for passwords, one-time or MFA codes, card numbers or recovery phrases |
| `hidden_text` | Critical / high | contain invisible Unicode tag characters, or zero-width and reordering characters |
| `instruction_override` | High | contain text that overrides the agent's other instructions |
| `covert_action` | High | act on data "silently" or without the user's knowledge or consent |
| `denies_being_ai` | High | tell the agent to claim to be human, or to hide that it is an AI |
| `impersonation` | High | impersonate a bank, IT support, a government body or another trusted party |
| `harassment` | High | tell the agent to insult, threaten or intimidate people |
| `discrimination` | High | treat people differently because of race, religion, gender, age, disability, nationality or similar |
| `attack_material` | High | produce malware, phishing messages, weapons or forged documents |
| `self_harm` | High | encourage self-harm or eating disorders |
| `embedded_credential` | High | contain an API key, token, password or private key |
| `unconfirmed_action` | Medium | delete, pay, refund, grant access and the like without asking anyone first |
| `hidden_comment` | Medium | hide instructions in HTML comments |
| `encoded_blob` | Medium | contain a long encoded blob that could hide instructions |

**A classifier**, if one is configured, gives a second opinion. It is better at what
rules miss: reworded or indirect intent, and harmful content in general. AgentGov
uses [IBM Granite Guardian](https://huggingface.co/ibm-granite/granite-guardian-4.1-8b)
(Apache-2.0), a model trained to judge text against risk criteria. AgentGov asks it
one criterion at a time:

| Criterion | Asks whether the instructions… |
|---|---|
| `harm` | promote or contain content that is harmful across contexts |
| `jailbreak` | try to evade an AI system's safeguards |
| `social_bias` | show prejudice against groups of people |
| `violence` | promote or depict physical harm, threats or intimidation |
| `unethical_behavior` | encourage fraud, theft, exploitation or abuse of power |
| `profanity` | use offensive language (not checked by default) |
| `exfiltration` | tell the assistant to send or reveal data to anyone but the person it is talking to |
| `deception` | tell the assistant to deceive or manipulate people, impersonate someone, deny being an AI, or ask for credentials |

The first six are Granite Guardian's own criteria; AgentGov wrote the last two for
instructions. A "yes" counts as a high-severity problem: unlike the rules, it comes
without an excerpt, and on blatant text the model tends to answer yes to several
criteria at once.

## Findings and risk

All problems in an agent's instructions, from every source, become one finding per
agent, `agent.unsafe_instructions`, with the severity of the worst problem. It
resolves itself when fixed instructions arrive. If it is a false positive, dismiss it:
it stays dismissed until different problems appear.

An open finding adds to the agent's risk score: 40 points if it is critical, 25 if
high and 10 if medium. For an agent at the gateway, scores of 50 and above raise an
`agent.high_risk` finding, a threat when what it did adds to its risk, which resolves once
its risk is below 50 again; an agent on another platform has none, its own findings saying
what adds to its risk. While
`risk-based-access` is enforced (the default), the gateway refuses tool calls, model calls
and calls between agents from agents at critical risk (75 points or more).

The `instruction-checks` [feature](features.md) turns both checks off: instructions that
arrive meanwhile are kept, and checked once it is on again, and **Rescan** is refused while
it is off.

## Setting up the classifier

Any server with an OpenAI-compatible chat completions API can serve Granite
Guardian. Point the control plane at it with `AGENTGOV_GUARDIAN_URL` (the API's base URL,
such as `http://guardian:8000/v1`), and `AGENTGOV_GUARDIAN_API_KEY` if the server needs one;
[configuration](configuration.md#classifier-optional) has the model name, the criteria and
the timeout. Give the governance processor the same settings, and the same classifier
judges the traffic too: tool results, agents' answers and people's prompts
([detection](detection.md)).

* **With a GPU:** use vLLM, `vllm serve ibm-granite/granite-guardian-4.1-8b`. Each
  check takes well under a second.
* **On a CPU:** use llama.cpp's server with the
  [GGUF build](https://huggingface.co/ibm-granite/granite-guardian-4.1-8b-GGUF).
  `deploy/compose/docker-compose.guardian.yml` runs it next to the reference stack
  ([local](deploy/local.md#optional-a-classifier)).
  Each criterion takes a few seconds, which is fine because classification runs in
  the background.

The classifier runs after the rules, in the background, so saving instructions never
waits for it. While it is unreachable (for example while it is still loading its
model), instructions stay queued and it is asked again every two minutes. Instructions
stored before a classifier was configured are queued when the control plane starts.
Use **Rescan** on the agent's page to check an agent's instructions again.

## Checking instructions before they ship

`POST /v1/instructions/check` checks text without storing it, so a pipeline can check
an agent's prompt before deploying it. It waits for the classifier's verdicts unless
`"classifier": false` is passed. The CLI exits with 1 when a problem is at least as
severe as `--fail-on` (default `high`):

```bash
agentgov instructions check prompts/support-agent.md
agentgov instructions check --fail-on medium --no-classifier - < prompt.txt
```

Admins, approvers, the security team (`secops`), auditors and registrars may run checks, so
a registrar key in CI is enough.

## Doing it from the CLI or the API

| Task | Admin UI | CLI | API |
|---|---|---|---|
| See an agent's instructions and problems | Agent → Instructions | `agentgov agents instructions REF [--text]` | `GET /v1/agents/{ref}/instructions` |
| Add or change registered instructions | Agent → Instructions → **Add instructions** / **Edit** | `agentgov agents set-instructions REF FILE` | `PUT /v1/agents/{ref}/instructions` |
| Forget the instructions from one source | Agent → Instructions → **Forget** | `agentgov agents clear-instructions REF [--source telemetry]` | `DELETE /v1/agents/{ref}/instructions?source=…` |
| Check them again | Agent → Instructions → **Rescan** | `agentgov agents rescan-instructions REF` | `POST /v1/agents/{ref}/instructions/rescan` |
| Check text without storing it | — | `agentgov instructions check FILE` | `POST /v1/instructions/check` |

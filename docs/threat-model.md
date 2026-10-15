# Threat model

What AgentGov protects, from whom, what stops each attack, and what it doesn't stop: for
those deploying it, and for an outside reviewer. Each promise names the test that checks
it, so that a review can start from what is claimed and try to break it. The path of each
call and the protection at each boundary are in
[architecture](architecture.md#trust-boundaries-and-failure-modes); how to deploy it
safely is in [SECURITY](../SECURITY.md#deploying-safely).

## What it protects

| | Why it matters |
|---|---|
| The checks at the gateway | Every tool call, model call and call between agents is decided by policy, with the controls as their modes say. A call that skips a check, or is decided for the wrong caller, is the failure AgentGov exists to prevent |
| Who calls, and for whom | Policy, budgets, approvals and the ledger all hang on the agent a call is from and the person it is for |
| The registry and its controls | Which agents and tool servers are approved, what each may call, the controls' modes, and the kill switch |
| The evidence | The ledger (a hash chain, with checkpoints, time-stamps, a witness and a transparency log), and the reports built from it |
| Secrets | Agents' client secrets, model providers' keys, destinations' and service desks' credentials, signed-in administrators' Microsoft tokens, and AgentGov's own keys (the service token, the bundle signing key, the authority's key) |
| People's data | Personal data and credentials in what agents send and receive, masked or withheld as the controls say |
| Spend | Model usage, which budgets limit |

## Who could attack it

| Who | What they hold | Trusted to |
|---|---|---|
| Anyone on the network | Nothing | Nothing |
| An agent, or whoever holds its credentials | Its token (from Keycloak, or a workload identity from an issuer the gateway trusts), and the delegations it is given | Act within its grants. It may be compromised, by prompt injection or otherwise |
| A tool server, a model provider, another agent | What the gateway sends them | Nothing beyond their answers, which are checked too |
| A person who uses agents | Their roles: their issues and the approvals sent to them | Decide on what is theirs |
| Roles for one team | Admin, approver, security, auditor or registrar for one team's agents | That team's agents, as the role allows, and nothing beyond it |
| Roles for every team | Administrators, approvers, security, auditors, registrars | What the role allows, everywhere; administrators configure everything ([below](#what-it-doesnt-stop)) |
| AgentGov's components | Certificates from AgentGov's authority; the service token | Report what the data plane did, and fetch what it needs |
| Whoever runs the deployment | The database, the cluster or the host, the secrets | Everything. The evidence is built so that what they change shows, as far as [the ledger](#the-ledger) says |

## What stops each attack

### At the gateway

| An attacker tries to | What stops it | Checked by |
|---|---|---|
| Call without a valid token | The gateway checks the token (signature, issuer, audience, expiry). Model calls need one in every mode; tool and agent calls, while `unknown-callers` is enforced | `tests/test_gateway.py` |
| Say who they are in headers named as AgentGov's (`X-AgentGov-Agent-Id`, the person, the caller) | The gateway drops every such header as a request arrives, before any route's checks, and tells the processor only what it computed from the checked token. The agent called hears who called from AgentGov alone | `tests/test_promises.py::test_callers_cannot_say_who_they_are` (the real gateway) |
| Put an AgentGov token's claims (`agent_id`, `azp`, `email`) into another issuer's token | Only AgentGov's own tokens (Keycloak's) are believed for which agent and person; another issuer's names an agent by its issuer and subject alone | The same test; `tests/test_gateway_issuers.py` |
| Use a token one install's gateway received at another install's | Keycloak's tokens are each install's own; another issuer's are for the gateway's address unless the issuer names an audience | `tests/test_gateway_issuers.py` |
| Spend a provider's key as a subject of a trusted issuer that is no agent | Model calls from such a subject are refused whatever the mode of unknown callers | `tests/test_gateway_issuers.py::TestProcessor::test_providers_keys_are_spent_for_agents_alone` |
| Replay a delegation an agent passed on, around the gateway | The delegation is for one agent, an hour at most, and an agent that checks takes each once and only fresh | `tests/test_a2a.py` |
| Hide a message from the checks: compressed, in a batch, another binding, a key in another case | Refused while `data-protection` is enforced; recorded as unchecked otherwise | `tests/test_a2a.py` |
| Report usage for another agent and use up its budget | Usage comes from the gateway's access logs, on a collector receiver of their own that takes only AgentGov's certificates (and, in Kubernetes, only the gateway) | `tests/test_promises.py::test_usage_comes_from_the_gateway_alone`, `tests/test_health.py` |
| Keep working after being blocked | A block changes OPA's bundle, which OPA long-polls and the processor asks on every call | `tests/test_promises.py::test_a_blocked_agent_is_refused_within_seconds` |

### At the API

| An attacker tries to | What stops it | Checked by |
|---|---|---|
| Reach a route their role doesn't allow, or any without signing in | Every route admits the roles in a reviewed list, and nobody anonymous reaches anything but the few public ones | `tests/test_authz_matrix.py` against `tests/authz_matrix.txt` |
| Reach another team's agents with a role for one team, or read their data | Routes for agents take a role for the agent's team; lists and details leave other teams' out; out of reach reads as not found | `tests/test_authz_matrix.py` |
| Write what the data plane reports (decisions, OPA's decision logs, telemetry) into the ledger | Only components' service role may, on the internal port with mutual TLS | `tests/test_authz_matrix.py` (its `REPORTS`) |
| Stop or start every team's tool servers with a role for one team | Tool servers' kill switch takes a role for every team | `tests/test_authz_matrix.py` |
| Block and unblock as security for one team, beyond the hand-off level | The hand-off holds security for one team as it holds security for every team | `tests/test_secops.py` |
| Approve an agent or a tool server by blocking it, then unblocking it | Blocking remembers what it was, and unblocking gives that back | `tests/test_secops.py`, `tests/test_registry.py` |
| Loosen what governs their team's agents with a role for one team: a weaker mode for a control, out of a management rule, more tools, models or agents to call | Refused: those are for administrators for every team, and grants for access packages too | `tests/test_team_roles.py` |
| Have personal data unmasked for an agent, or exempt it, by its labels | `pii-access` and labels under `agentgov/` are set by administrators for every team alone | `tests/test_team_roles.py` |
| Pass an agent registered through the API off as another platform's, which rules and scopes treat differently | Where an agent comes from is the server's to say | `tests/test_api.py` |
| Dismiss an issue about an agent they answer for, or decide an access package they asked for | Refused, as accepting the issue's risk is; the person is compared, whatever role they act in | `tests/test_bulk.py`, `tests/test_issue_answers.py`, `tests/test_access_packages.py`, `tests/test_sso.py` |
| Be taken for someone, as an owner, a sponsor or whom an issue went to, by a username like their address, or an API key named after them | A person is the email address the identity provider vouches for; an API key is nobody | `tests/test_sso.py` |
| Learn which agents another team has | Lists, an agent's callers and those it may call, and conflicts leave them out; asked for by name, they aren't found | `tests/test_team_roles.py` |
| Forge a request from a signed-in administrator's browser | Sessions are cookies with `SameSite=Strict`, and every write with a cookie needs the CSRF header | `tests/test_sso.py` |
| Use a stolen API key for long | Keys are stored as hashes, expire, and can be revoked; each request checks | `tests/test_apikey_expiry.py`, `tests/test_api.py` |

### The ledger

Whoever can write to the database is the attacker here: an administrator of the database,
or someone who got its credentials.

| An attacker tries to | What stops it | Checked by |
|---|---|---|
| Edit, remove, insert or reorder an entry | Each entry's hash covers it and the one before; `agentgov ledger verify` walks the chain, and lists every break it finds | `tests/test_promises.py`, `tests/test_ledger.py` |
| Remove the oldest entries as if they had been archived | The chain starts later only where a `ledger.archived` entry in it says so, for that range and hash | `tests/test_promises.py`, `tests/test_ledger.py`, `tests/test_witness.py` |
| Cut the newest entries back, head and all, or slip a row in past the head | Checkpoints past the head, and rows past it, fail verification; nothing serves, counts or sends a row past the head | `tests/test_promises.py`, `tests/test_ledger.py`, `tests/test_secops.py` |
| Rewrite the chain with its hashes worked out again | Checkpoints don't match it: time-stamped by an authority whose signature is checked, and each stamp recorded in the chain, they can't be made to; a stamp given long after its entry vouches only from then | `tests/test_promises.py`, `tests/test_evidence.py` |
| Restore an older copy of the database | The ledger's head is kept outside it too (the witness), and a transparency log can publish each checkpoint | `tests/test_witness.py`, `tests/test_transparency.py` |
| Lose decisions by sending one record the database can't store | Records are cleaned and stored one by one; those still refused are counted as lost, in the ledger | `tests/test_api.py`, `tests/test_processor.py` |

### Secrets and what goes out

| An attacker tries to | What stops it | Checked by |
|---|---|---|
| Read a secret through the API, an export or a report | Secrets are files AgentGov reads, shown only as a path and whether they exist; agents' client secrets go only to administrators who reach the agent, and each read is in the ledger | `tests/test_api.py`, `tests/test_secops.py` |
| Get a provider's key from the gateway | The gateway reads it from a file and never passes the agent's token on | `tests/test_gateway.py` |
| Send a credential to a host of their own, as an administrator, by changing a destination's or a provider's address | Where the deployment lists the hosts credentials may go to (`AGENTGOV_CREDENTIAL_HOSTS`), others are refused when set and again when used; a provider's key is only ever a file in the model keys directory | `tests/test_secops.py::TestCredentialHosts`, `tests/test_models.py`, `tests/test_gateway.py::test_a_key_goes_only_where_it_may` |
| Write a link, a mention or HTML into a ticket, through an agent's name or a reason | What agents, platforms and people wrote shows in tickets as text | `tests/test_tickets.py::TestWhatOthersWrote` |
| Learn a developer's secrets from the MCP servers their machine reports | The scanner reports a server's scheme, host and port and a hash of the rest, and option values redacted; the control plane sanitises again before keeping it | `tests/test_mcp_scan.py`, `tests/test_mcp_registry.py` |
| Turn the calls-around-the-gateway test on cloud metadata or the control plane's machine, or hold it up | It calls only addresses an agent may be at, the one it checked, for ten seconds and 64 KiB at most | `tests/test_reachability.py` |
| Stop notifications with a title that breaks an email's header | Headers are one line; an email that can't be written fails alone | `tests/test_issues.py` |
| Run script in the admin UI | The UI renders what the API returns as text only (React, and a lint rule against setting HTML), and its content security policy allows scripts from itself alone | `tests/test_api.py`, `ui/eslint.config.js` |

## Promises

| Promise | Checked by |
|---|---|
| Every API route admits only the roles listed for it, and no route but the public ones admits anyone who hasn't signed in | `tests/test_authz_matrix.py` |
| One team's roles never reach another team's agents, nor read their data | `tests/test_authz_matrix.py` |
| What the data plane did is reported by the data plane alone | `tests/test_authz_matrix.py` |
| Who calls through the gateway, and for whom, comes from the token it checked: no header a caller sends says it | `tests/test_promises.py` |
| Claims in another issuer's token are never believed | `tests/test_promises.py`, `tests/test_gateway_issuers.py` |
| A blocked agent is refused within seconds | `tests/test_promises.py` |
| Usage comes from the gateway alone | `tests/test_promises.py` |
| Providers' keys are spent for registered agents alone | `tests/test_gateway_issuers.py` |
| A delegation proves one call through the gateway, to the agent it was given to | `tests/test_a2a.py` |
| A change to the ledger's history is found: an entry edited or removed, the oldest removed as if archived, the newest cut back, a row past the head, the chain rewritten | `tests/test_promises.py`, `tests/test_ledger.py`, `tests/test_evidence.py`, `tests/test_witness.py` |

## What it doesn't stop

* **Administrators for every team** can turn controls off or to monitor, approve what
  they like, and read agents' client secrets; and, unless the deployment lists the hosts
  credentials may go to, send destinations' and providers' credentials to a host of their
  own. Each such change is in the ledger, with the values before and after, and monitored
  or off controls show as warnings; four-eyes control over administrators is the identity
  provider's (who gets the role) and the ledger's (who did what).
* **Whoever runs the deployment** can change the database. The ledger shows what they
  changed as far as its checkpoints, time-stamps, witness and transparency log reach
  ([evidence](evidence.md)): the newest entries, since the last checkpoint and the last
  time the witness was written, can be removed unnoticed; and with every hash worked out
  again and the checkpoints stamped anew, a rewrite shows only in what is kept outside the
  database (the witness, evidence packs, a transparency log) and as stamps given late.
  Time-stamps are checked against the authority only with its certificates
  (`AGENTGOV_LEDGER_TSA_CA_FILE`); without them, a made-up stamp with a certificate of its
  own passes, which the Ledger page and **Features** say.
* **Administrators for one team** can't loosen what governs their agents, as above, but
  still set their token budgets and risk tiers, and may switch them to a blueprint that
  asks less of them (approvals, attestation, a workload identity) without granting more:
  each change is in the ledger.
* **Calls around the gateway** aren't governed: the network, or agents that check their
  delegation, must stop them ([calls around the gateway](agent-to-agent.md#calls-around-the-gateway)).
  An agent that holds a provider's key of its own calls the provider directly.
* **Subjects of an issuer the gateway trusts** are callers: anyone the issuer gives a
  token for the gateway's audience. Those no agent has are unknown callers: refused while
  `unknown-callers` is enforced, let through and recorded on tool and agent routes while
  it is monitored.
* **Monitored controls** record; they don't stop. So does a check the gateway can't make
  while it fails open ([when something is down](features.md#when-something-is-down)).
* **What the detectors look for** is found by rules, Presidio and, optionally, a
  classifier: each can miss what is reworded or hidden.
* **In-process agents** (the Agent Governance Toolkit) say who they are themselves.
* **With SPIRE**, every workload in the trust domain has a certificate: the components
  name the callers they take, but the collector's receiver for usage can't, and relies on
  the network policy.
* **agentgateway 1.6** answers 500 to a call between agents whose answer it can't send to
  the processor, while answers are checked, whatever the failure mode; and with
  developer sign-in on, tool servers' routes take Keycloak's tokens alone.

## Reviewing it

Where to start, in the order the promises above depend on each other:

1. **The gateway's configuration**, `src/agentgov/gateway.py`: which tokens each route
   takes (`_providers`, `_jwt_auth`, `issuer_audience`), what it tells the processor and
   from which tokens (`_own`, `identity_headers`, `identity_metadata`), and the headers it
   drops (`DROPPED`). `tests/test_promises.py` runs the real agentgateway with it.
2. **The processor's decisions**, `src/agentgov/processor/`: `server.py` (tool calls),
   `model_guard.py`, `a2a_guard.py`, `a2a_answers.py`; and the policies they ask,
   `src/agentgov/policies/agentgov/` (`context.rego` first).
3. **The API's authorization**, `src/agentgov/api/auth.py` and `src/agentgov/api/reach.py`
   (`src/agentgov/web/auth.py` applies them to the routes on Django), and the reviewed list
   of who may call what, `tests/authz_matrix.txt`
   (`python -m tests.test_authz_matrix` writes it again).
4. **The ledger**, `src/agentgov/ledger.py`, `src/agentgov/retention.py`,
   `src/agentgov/witness.py` and `src/agentgov/timestamping.py`.
5. **Secrets and calls out**: destinations and service desks, model providers' keys, and
   Microsoft's tokens (`src/agentgov/identity/delegation.py`).

`scripts/ci.sh --quick` runs the checks and the tests; `--e2e` runs the whole stack and a
demo agent through every control.

## Reviews

**October 2026, by AgentGov's own AI reviewers: not an independent audit.** Four
adversarial reviews, each from the code alone, each trying to break one area and proving
what it found with a script: identity at the gateway (with agentgateway 1.6's source), the
API's authorization, the evidence ledger, and secrets, calls out and the admin UI.
Alongside, the authorization matrix and the promise tests above. What they found, fixed in
the same pass:

* **At the gateway:** usage could be reported by whatever sent traces, and use up an
  agent's budget; a delegation could be taken twice, around the gateway; a trusted
  issuer's unknown subjects could spend providers' keys while unknown callers were
  monitored; the identity-assertion endpoint took any token of Keycloak's as an ID token;
  calls between agents could hide what they carried from the checks; caller-sent headers
  named as AgentGov's reached the agents, tool servers and providers called.
* **At the API:** security for one team could stop every team's tool servers, and slipped
  past the hand-off level; blocking then unblocking approved; administrators could write
  the data plane's reports into the ledger; roles for one team could exempt their agents
  from controls and rules (labels, environment, source) and widen their grants; dismissing
  an issue skipped the separation of duties accepting its risk keeps; a username like
  someone's address made one that person; other teams' agents could be named.
* **The ledger:** a made-up archive start let the oldest entries go unnoticed;
  time-stamps' signatures weren't checked, and a stamp taken away was asked for again;
  verification stopped at the head both ways, and at the first break; a value of another
  type broke the chain for good; one record the database refused lost every decision after
  it.
* **Secrets and calls out:** text others wrote rendered as markup in Jira and ServiceNow;
  developers' MCP scan reports carried secrets in URLs and options; administrators could
  send credentials to any host, and have any file the gateway holds sent as a provider's
  key; the calls-around-the-gateway test had no limits and could reach metadata services;
  a line break in a title stopped notifications; SECURITY.md said Microsoft sign-ins were
  kept in memory, when they are sealed in the database.

What they checked and found sound is in each area's tests. An outside review is the next
step: start from [Reviewing it](#reviewing-it).

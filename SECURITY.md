# Security policy

AgentGov sits on the path between AI agents and the tools they use, so we treat security
reports as our highest priority.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
[private vulnerability reporting](https://github.com/sreent/ai-agent-governance-platform/security/advisories/new)
(Security → Advisories → *Report a vulnerability*).

Include what you can of the following: the affected component and version or commit,
a description of the issue and its impact, steps to reproduce or a proof of concept, and
any suggested fix. We aim to acknowledge reports within three working days and to agree
a disclosure timeline with you. Credit is given in the advisory unless you prefer
otherwise.

## Scope

In scope: the code in this repository, which is the control plane, the governance
processor, the Rego library, the CLI, the admin UI and the reference deployment.

Vulnerabilities in the components AgentGov composes (Keycloak, OPA, agentgateway,
Presidio, the OpenTelemetry Collector, PostgreSQL, Langfuse) should be reported to those
projects. If the way AgentGov configures or uses a component makes it exploitable, that is
in scope here.

Examples of issues we especially want to hear about:

* A tool call that reaches an MCP server without passing the processor, or that is
  allowed when policy should deny it (including through malformed MCP messages,
  encodings, or batching).
* An agent obtaining another agent's identity or grants, or acting after being blocked.
* Redaction that can be bypassed so that detected personal data or secrets reach an agent.
* Tampering with the evidence ledger that `agentgov ledger verify` does not detect.
* Authentication or authorization flaws in the control plane API or UI.
* Denial of service through crafted input (for example super-linear scanning).
* Ways to hide what the agent-instruction rules are meant to catch (see
  [Agent instructions](docs/instructions.md)), or to make them flag safe text at will.

## Supported versions

AgentGov is pre-1.0. Security fixes are made on `main` and included in the next release.

## Deploying safely

The reference stack in `deploy/compose` is for evaluation. For anything else:

* Replace every default secret (`deploy/compose/.env.example` lists them), in particular
  `AGENTGOV_ADMIN_TOKEN`, `AGENTGOV_SERVICE_TOKEN`, the Keycloak client secrets and
  database passwords. Use long random values.
* Delete the realm's demo users (`admin`, `alice`, `audrey`) and sign people in through
  your own directory, federated into Keycloak, with the `agentgov-*` roles assigned to
  groups. Use role-scoped API keys for automation, and keep the bootstrap admin token for
  break-glass access only.
* Terminate TLS in front of the control plane, Keycloak and agentgateway, and set
  `AGENTGOV_PUBLIC_URL` to the control plane's `https://` address so that session
  cookies are marked `Secure`.
* Keep OPA, the processor, Presidio and the MCP servers on a private network that agents
  cannot reach, so that the gateway is the only path to tools.
* Keep `AGENTGOV_UNKNOWN_AGENT_MODE=reject` (the default) and the processor fail-closed.
  Use `monitor` only for discovery and only where that is acceptable.
* Back up PostgreSQL, export the ledger regularly (`GET /v1/ledger/export`) and store the
  exports somewhere the platform cannot modify.
* If you sync the Microsoft 365 agent catalog, give the Entra app only
  `CopilotPackages.Read.All`, and rotate its client secret like any other credential.
* If you run the instruction classifier, keep it on the private network: it receives
  agents' instructions (with credentials already redacted).

## Known limitations

* The prompt-injection and tool-poisoning detectors are heuristics. They raise the cost
  of common attacks; they are not a guarantee.
* The checks on agents' instructions are rules plus, optionally, a model. Both can miss
  reworded or obfuscated instructions and can flag legitimate ones; treat a finding as a
  reason to review, and its absence as no proof of safety.
* Agents on Microsoft 365 and Copilot Studio are read, not controlled: blocking one in
  AgentGov does not stop it. Block it in Microsoft's admin centers too.
* Personal-data detection is as good as Presidio's recognizers for your languages and
  data, and the configured confidence thresholds.
* AgentGov governs tool traffic that goes through the gateway (and, with the Agent
  Governance Toolkit, calls inside instrumented agents). It does not sandbox agent
  processes or see traffic that bypasses the gateway.
* Connections between components are not mutually authenticated yet (mTLS is on the
  [roadmap](docs/roadmap.md)); rely on network isolation.
* Administrators' roles are read from the identity provider when they sign in. Removing a
  role or disabling an account there takes effect at the next sign-in; a session that is
  already open lasts until it expires (`AGENTGOV_SESSION_HOURS`, default 8), the person
  signs out, or an admin signs them out on the Access page (`agentgov access sign-out`).
  Back-channel logout, which would end it automatically, is on the
  [roadmap](docs/roadmap.md).

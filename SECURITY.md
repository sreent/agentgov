# Security policy

AgentGov sits on the path between AI agents and the tools and models they use, so we
treat security reports as our highest priority.

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
* A model call that reaches a provider without passing the processor, or with a prompt
  policy should have refused or masked; or an agent calling a model it wasn't granted,
  or past its budget while `token-budgets` is enforced.
* A model provider's API key reaching an agent, the control plane's API, its database
  or the ledger.
* An agent obtaining another agent's identity or grants, or acting after being blocked.
* A call between agents that reaches the agent called without passing the processor, or
  a delegation AgentGov accepts although it didn't give it to that agent for that person
  (forged, expired, or someone else's), or headers about who handed the work down that a
  caller can set.
* Redaction that can be bypassed so that detected personal data or secrets reach an agent.
* Tampering with the evidence ledger that `agentgov ledger verify` does not detect.
* Authentication or authorization flaws in the control plane API or UI.
* Denial of service through crafted input (for example super-linear scanning).
* Ways to hide what the agent-instruction rules are meant to catch (see
  [Agent instructions](docs/instructions.md)), or to make them flag safe text at will.
* A call to the Copilot Studio threat-detection endpoint that AgentGov accepts without a
  token Microsoft Entra ID issued to an allowed caller, or a Copilot Studio tool call it
  allows in `enforce` mode when policy should deny it.

## Supported versions

AgentGov is pre-1.0. Security fixes are made on `main` and included in the next release.

## Deploying safely

The defaults of the Compose stack and of the Helm chart are for evaluation
([checklist](docs/deploy/README.md#before-others-rely-on-it)). The control plane refuses to
start when people reach it anywhere but on its own machine and it holds a secret from
AgentGov's examples. On one server, `docker-compose.server.yml` does most of what follows
([one server](docs/deploy/server.md)). For anything else:

* Replace every default secret (`deploy/compose/.env.example` lists them), in particular
  `AGENTGOV_ADMIN_TOKEN`, `AGENTGOV_SERVICE_TOKEN`, the Keycloak client secrets and
  database passwords. Use long random values.
* Delete the realm's demo users (`admin`, `alice`, `sofia`, `audrey`, `sam`) and the demo
  app `agentgov-demo-chat`, which accepts people's passwords directly, and name your own apps
  in `AGENTGOV_PEOPLE_APP_CLIENTS` (the Helm value `peopleApps`). Sign people in through your
  own directory, federated into Keycloak, with the `agentgov-*` roles assigned to groups. Use
  role-scoped API keys for automation, and keep the bootstrap admin token for break-glass
  access only.
* Terminate TLS in front of the control plane, Keycloak and agentgateway, and set
  `AGENTGOV_PUBLIC_URL` to the control plane's `https://` address so that session
  cookies are marked `Secure`.
* Keep OPA, the processor, Presidio and the MCP servers on a private network that agents
  cannot reach, so that the gateway is the only path to tools. Let only the gateway reach
  agents' A2A endpoints, so that it is the only path between agents and the headers it
  sets for the agent called can be relied on ([agent to agent](docs/agent-to-agent.md)). Give model providers' API
  keys to the gateway only ([model calls](docs/models.md)), not to agents, so that the
  gateway is the only path to models too. Keep destinations' credentials (SIEM tokens,
  Teams and Slack webhook URLs) in your secret store, mounted into the control plane only
  ([security operations](docs/secops.md)). On Kubernetes, turn on the
  Helm chart's network policies (`networkPolicy.enabled=true`), run its Keycloak in
  production mode without the demo users (`keycloak.mode=production`,
  `keycloak.demoUsers=false`, both before the first install) or use your own, and keep
  Keycloak's admin console (`/admin`) off the internet if your load balancer can.
* Keep the controls at the gateway enforced, as they are by default, and the processor
  fail-closed. Jailbreak detection starts in monitor mode: enforce it once its issues
  show what it would refuse. Monitor mode and turning a control off are for rollout and evaluation
  ([features](docs/features.md)). Both are recorded in the ledger as warnings, and only
  administrators can choose them. To keep the choice with the deployment, pin the
  features in `AGENTGOV_FEATURES` (the Helm value `features`). Monitor `unknown-callers`
  only for discovery, and only where that is acceptable.
* Back up PostgreSQL, before every upgrade too (upgrades migrate its schema), export the
  ledger regularly (`GET /v1/ledger/export`) and store the exports somewhere the platform
  cannot modify.
* If you connect AgentGov's app registration to Microsoft, grant it only the application
  permissions of the [connections](docs/microsoft-connections.md) you use
  (`CopilotPackages.Read.All`, `AgentIdentity.Read.All`, `AuditLogsQuery.Read.All`,
  `SecurityAlert.Read.All`), all of them read-only, and rotate its client secret like
  any other credential. `AuditLogsQuery.Read.All` can read the tenant's whole audit
  log, even though AgentGov asks only for agents' records.
* Copilot Studio threat detection needs `<AGENTGOV_PUBLIC_URL>/integrations/copilot-studio`
  to be reachable from Microsoft's cloud. AgentGov accepts a call there only with a token
  that Microsoft Entra ID signed for your tenant and AgentGov's API, issued to an app in
  `AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS`. If you can, publish only that path to the
  internet and keep the rest of the control plane private.
* Pushing the connector allowlist into Power Platform blocks every other connector for
  every app, flow and agent in the environments it applies to. It takes an AgentGov admin
  signed in through Entra ID who also holds Microsoft's Power Platform administrator
  role, and AgentGov shows what it would do first.
* If admins sign in through Entra ID with `AGENTGOV_MICROSOFT_ADMIN_ACTIONS` on, the
  control plane keeps each signed-in admin's Microsoft refresh token for as long as their
  session lasts, in its database, so that every replica can act as them: sealed
  (AES-256-GCM) with a key derived from the app's client secret
  (`AGENTGOV_OIDC_CLIENT_SECRET`), and never in the ledger
  ([how AgentGov holds the sign-in](docs/platforms.md#how-agentgov-holds-the-sign-in)).
  The database, or a backup of it, gives none of them away alone. With the client secret,
  it gives the refresh tokens of the admins signed in when it was taken, which Microsoft
  takes until Entra ID expires or revokes them (AgentGov deleting its copy when a session
  ends doesn't): enough to act as those admins in Microsoft 365 and Power Platform, with
  the app's delegated permissions. Give the app registration only the delegated
  permissions in [docs/platforms.md](docs/platforms.md#setting-it-up), keep the client
  secret away from the database's backups, and treat both, and the control plane's host,
  as Microsoft admin credentials. If both may have leaked, give the app a new client
  secret and delete the old one in Entra ID: the tokens are useless without it.
* `agentgov login` saves the CLI's session token in the user's agentgov config directory,
  readable only by that user. It is a bearer credential with the person's roles until it
  expires: run `agentgov logout` on shared machines, and end lost sessions on the Access
  page.
* If you run the classifier (IBM Granite Guardian), keep it on the private network, as
  Presidio: it receives agents' instructions (with credentials already redacted) and,
  while `traffic-classifier` is on, the tool results, answers and prompts it judges, as
  they are.
* The MCP registry (`mcp-registry`, off by default) is served without credentials, as
  developers' MCP clients read it: anyone who can reach the control plane can read the
  names, descriptions and addresses of the servers listed for developers. Serve it where
  only your developers can reach it, and list there only what they may see.
* Reports of developers' MCP servers (`agentgov mcp scan --report`) need an API key of
  the `registrar` role. Give device management its own key, and revoke it if the
  machines it runs on are lost.
* Model providers' API keys are files that the gateway and its config sidecar read
  (`deploy/compose/model-keys`, or the Helm chart's `modelKeys` Secret), in `/model-keys`:
  a provider's `key_file` can name no other file. Keep them out of version control (the
  Compose directory ignores everything but the demo's key). To rotate one, replace the file
  (or the Secret) and restart the gateway. Mark a provider `verified` only if personal data
  may go to it unmasked.
* List the hosts credentials may go to in `AGENTGOV_CREDENTIAL_HOSTS`: your SIEMs', chats'
  and service desks', and your `openai-compatible` model providers'. Administrators can't
  read destinations' credentials or providers' keys, but without the list they can send
  them to any host, by changing a destination's `url` or a provider's `base_url`; with it,
  AgentGov refuses other hosts, when they are set and again when it sends. The
  **Features** page says when the list is empty
  ([security operations](docs/secops.md#credentials), [model calls](docs/models.md)).

## Known limitations

* The prompt-injection, jailbreak and tool-poisoning detectors are heuristics, and the
  classifier that can back up the first two is a model. They raise the cost of common and
  reworded attacks; they are not a guarantee. A verdict the classifier gives in the
  background (its default, monitored) comes after the call went on: it raises an issue,
  it doesn't stop the call ([detection](docs/detection.md)).
* The gateway checks agents' answers to other agents as they stream, event by event. An
  answer, or an event, over 4 MiB, or one compressed although the gateway asked for it
  plain, is withheld where `data-protection` or `prompt-injection` is enforced, and goes
  through unchecked where neither is.
* The checks on agents' instructions are rules plus, optionally, a model. Both can miss
  reworded or obfuscated instructions and can flag legitimate ones; treat an issue as a
  reason to review, and its absence as no proof of safety.
* Agents on Microsoft 365 and Copilot Studio are read, not controlled: blocking one in
  AgentGov does not stop it. Block it in Microsoft's admin centers too, or have an admin
  signed in through Entra ID quarantine or block it from AgentGov. With Copilot Studio
  threat detection enforcing, a blocked Copilot Studio agent can't call tools, but it
  can still answer from its instructions and knowledge.
* Copilot Studio waits less than a second for threat detection's answer. If AgentGov
  doesn't answer in time, the tool runs, unless the environment is set to block when
  the provider fails. Microsoft asks only about agents that use generative
  orchestration.
* What AgentGov reads from Microsoft (Entra Agent ID, the Purview audit log, Defender) is
  as current as the last sync, an hour apart by default; audit records arrive about two
  hours late.
* The CLI's sign-in brings the browser back to a loopback port (`127.0.0.1`) with a
  one-time code. The code is useless without the PKCE verifier that only the CLI holds,
  and it works once, but another program on the same computer could see it in transit.
* Personal-data detection is as good as Presidio's recognizers for your languages and
  data, and the configured confidence thresholds.
* AgentGov governs tool and model traffic that goes through the gateway (and, with the
  Agent Governance Toolkit, calls inside instrumented agents). It does not sandbox agent
  processes or see traffic that bypasses the gateway: an agent that holds a provider's
  API key of its own can call the provider directly.
* Token budgets count usage from the gateway's access logs as calls finish. Calls that
  run at the same time can take an agent past its budget, and the tokens of answers the
  gateway withholds aren't counted.
* AgentGov's components authenticate each other with mutual TLS, from an authority of
  AgentGov's own, and OPA verifies the bundles the control plane signs
  ([production](docs/production.md)); both are on by default in the Helm chart and the
  Compose stack. Presidio's analyzer and Keycloak are outside it: keep Presidio reachable
  from the processor only (the network policies do), and give Keycloak TLS of its own.
  The authority's key (in the chart, the Secret `<release>-tls-ca`) can issue any
  component's certificate: guard it as you guard the service token, and don't let the
  authority issue certificates to anything else (with cert-manager, the chart makes one
  for the release unless you name an Issuer of your own). The components read their
  certificates when they start, and OPA every minute: after cert-manager renews one,
  restart the pods.
* Administrators' roles are read from the identity provider when they sign in. Removing a
  role or disabling an account there takes effect at the next sign-in; a session that is
  already open lasts until it expires (`AGENTGOV_SESSION_HOURS`, default 8), the person
  signs out, or an admin signs them out on the Access page (`agentgov access sign-out`).
  Back-channel logout, which would end it automatically, is on the
  [roadmap](docs/roadmap.md).

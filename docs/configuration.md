# Configuration

AgentGov's parts read their settings from environment variables named `AGENTGOV_*`. The
Compose stack and the Helm chart set the ones that connect the parts to each other. You
choose a handful more (the addresses people and agents use, and the secrets), and can leave
the rest at their defaults. A part stops at start-up, naming the setting, when a value is
invalid or the setting was retired. Names it doesn't know are ignored, so check the spelling.

Most of what AgentGov does is chosen in the app instead, by administrators: the
[features](features.md) and how strictly each applies, blueprints, policies and
destinations. Settings are for what the deployment decides.

## Where to set them

### Docker Compose

`deploy/compose/.env` (copy `.env.example`) holds the secrets and the settings
`docker-compose.yml` passes on, such as `AGENTGOV_PUBLIC_URL` or the Microsoft 365
connection. Add any other setting to the service that reads it in
`deploy/compose/docker-compose.override.yml`, which Git ignores:

```yaml
services:
  control-plane:
    environment:
      AGENTGOV_AUTO_BLOCK_RISK_SCORE: "80"
  processor:
    environment:
      AGENTGOV_PII_ENTITIES: EMAIL_ADDRESS:0.5,PHONE_NUMBER:0.4,US_SSN:0.5,CREDIT_CARD:0.5,IBAN_CODE:0.5,CRYPTO:0.5,PERSON:0.85
```

Compose reads the override when you start the stack from `deploy/compose`. From elsewhere,
name both files: `docker compose -f deploy/compose/docker-compose.yml -f
deploy/compose/docker-compose.override.yml up -d`. The
[inventory stack](deploy/local.md#just-the-inventory), `docker-compose.inventory.yml`, gives
the control plane every setting in `.env` itself.

### Helm

The chart's values set what connects the parts (see [below](#what-the-helm-chart-sets)).
Give other settings to the control plane in `controlPlane.env` and to the governance
processor in `processor.env`, and secret ones from a Secret of yours with `envFrom`:

```yaml
controlPlane:
  env:
    AGENTGOV_AUTO_BLOCK_RISK_SCORE: "80"
    AGENTGOV_M365_TENANT_ID: 00000000-0000-0000-0000-000000000000
    AGENTGOV_M365_CLIENT_ID: 00000000-0000-0000-0000-000000000000
  envFrom:
    - secretRef:
        name: agentgov-microsoft      # holds AGENTGOV_M365_CLIENT_SECRET
processor:
  env:
    AGENTGOV_PRESIDIO_FAILURE_MODE: closed
```

### Running the parts yourself

`agentgov server` (the control plane), `agentgov processor` (the governance processor) and
`agentgov gateway-config` (the gateway's configuration sidecar) read the environment they
are started in. Without any settings, `agentgov server` runs on its own against a SQLite
file, which is how [CONTRIBUTING.md](../CONTRIBUTING.md) develops it.

## Which part reads what

| Part | Reads |
|---|---|
| Control plane | Everything below, apart from the governance processor's section, of which it reads `AGENTGOV_PROMPT_INJECTION_THRESHOLD` (for Copilot Studio's checks) |
| Governance processor | The governance processor's section, `AGENTGOV_OPA_URL` and `AGENTGOV_SERVICE_TOKEN` |
| The gateway's configuration sidecar | `AGENTGOV_CONTROL_PLANE_URL` and `AGENTGOV_SERVICE_TOKEN` |
| OPA and the OpenTelemetry Collector | `AGENTGOV_SERVICE_TOKEN`, in their configuration files ([Compose's](../deploy/compose/opa/config.yaml)) |

## What the Helm chart sets

| Value | Settings |
|---|---|
| `urls.controlPlane`, `urls.gateway` (with `gateway.enabled`) | `AGENTGOV_PUBLIC_URL`, `AGENTGOV_GATEWAY_PUBLIC_URL` |
| `urls.keycloak`, the issuer, with the bundled Keycloak (reached at its Service, in the realm `agentgov`); or `externalKeycloak.url`, `.realm` and `.issuer`; neither without the gateway | `AGENTGOV_KEYCLOAK_URL`, `AGENTGOV_KEYCLOAK_REALM`, `AGENTGOV_KEYCLOAK_ISSUER`, `AGENTGOV_KEYCLOAK_JWKS_URL` |
| `secrets.existingSecret` (or the Secret the chart generates) | `AGENTGOV_ADMIN_TOKEN`, `AGENTGOV_SERVICE_TOKEN`, `AGENTGOV_KEYCLOAK_CLIENT_SECRET`, `AGENTGOV_OIDC_CLIENT_SECRET` |
| `postgresql.enabled`, or `externalDatabase.existingSecret` and `.key` | `AGENTGOV_DATABASE_URL` |
| `controlPlane.autoMigrate` | `AGENTGOV_DATABASE_AUTO_MIGRATE` |
| `features`, `featurePreset` | `AGENTGOV_FEATURES`, `AGENTGOV_FEATURE_PRESET` |
| `peopleApps` (and the demo app, with `keycloak.demoUsers`) | `AGENTGOV_PEOPLE_APP_CLIENTS` |
| `presidio.enabled` | `AGENTGOV_PRESIDIO_URL` |
| `otelCollector.enabled` | `AGENTGOV_GATEWAY_OTLP_ENDPOINT` |
| `opa.enabled` | `AGENTGOV_OPA_URL` |
| `gateway.enabled` | `AGENTGOV_PROCESSOR_ADDRESS`, `AGENTGOV_PROCESSOR_WEBHOOK_ADDRESS`, and the processor's and the sidecar's `AGENTGOV_CONTROL_PLANE_URL` |
| always | `AGENTGOV_DESTINATION_SECRETS_DIR` |

Don't set these in `controlPlane.env` too: the chart's values are where they are kept
consistent across the parts. An Entra ID app's client secret, for administrators' sign-in,
goes in the Secret's `oidc-client-secret` key
([Kubernetes](deploy/kubernetes.md#signing-in-with-microsoft-entra-id)).

## Files, not settings

Some credentials are files that a single part mounts, so that they never enter AgentGov's
database or settings:

| What | Read by | Compose | Helm |
|---|---|---|---|
| Model providers' API keys, one file per provider named after it ([model calls](models.md)) | The gateway and its configuration sidecar, at `/model-keys` | `deploy/compose/model-keys/` | `modelKeys.existingSecret` |
| Destinations' credentials, one file per destination named after it ([security operations](secops.md)) | The control plane, at `AGENTGOV_DESTINATION_SECRETS_DIR` (`/destination-secrets`) | `deploy/compose/destination-secrets/` | `destinationSecrets.existingSecret` |
| The Keycloak realm: the control plane's client, the sign-in client, roles and demo users | Keycloak, on its first start only | `deploy/compose/keycloak/agentgov-realm.json` | the same file, in the chart |

With Compose, `AGENTGOV_MODEL_KEYS_DIR` and `AGENTGOV_DESTINATION_SECRETS_DIR` in `.env` move
the folders on the host; inside the containers they stay where the table says. A key or
credential that changes is read again within seconds; on Kubernetes, restart the gateway after
changing a model key ([Kubernetes](deploy/kubernetes.md#how-the-parts-find-each-other)).

## Features the deployment pins

`AGENTGOV_FEATURES` (the Helm value `features`) pins features to a mode, such as
`least-privilege=monitor,discovery=off`. Administrators see pinned features in the app but
can't change them there; they choose the modes of the others. [Features](features.md) lists
them all.

## The command line

The `agentgov` command reads its own variables:

| Variable | What it does |
|---|---|
| `AGENTGOV_URL` | The control plane it talks to (default `http://localhost:8000`) |
| `AGENTGOV_TOKEN` | An API key or the bootstrap token to call it with (or `AGENTGOV_ADMIN_TOKEN`); `agentgov login` signs in with single sign-on instead |
| `AGENTGOV_CONFIG_DIR` | Where `agentgov login` keeps its session (default: the user's configuration folder) |

The control plane validates organisation policies with the `opa` command; set
`AGENTGOV_OPA_BINARY` where it isn't on the `PATH` (the image has it).

## Settings that changed

Settings that became features, or that something else replaced, stop the part that is given
them, saying what to use instead:

| Setting | Use instead |
|---|---|
| `AGENTGOV_UNKNOWN_AGENT_MODE=reject\|monitor` | The feature `unknown-callers=enforce\|monitor` |
| `AGENTGOV_REGISTRATION_REQUIRES_APPROVAL=true\|false` | The feature `registration-approval=on\|off` |
| `AGENTGOV_COPILOT_STUDIO_THREAT_DETECTION=off\|monitor\|enforce` | The feature `copilot-studio-threat-detection=off\|monitor\|enforce` |
| `AGENTGOV_ALERT_WEBHOOK_URL` | A Teams or Slack destination, with the hand-off to [security operations](secops.md) at `inform` or above |

## Reference

Every setting, from [`src/agentgov/config.py`](../src/agentgov/config.py) (the defaults
are the program's; Compose and the chart set some of them, as above). Settings marked
*secret* hold credentials: keep them in `.env`, a Kubernetes Secret or your secret store,
never in a values file you share.

<!-- BEGIN settings reference: generated by scripts/settings-doc.py -->

### Control plane

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_DATABASE_URL` (secret) | `sqlite:///./agentgov.db` | SQLite is fine for development; use PostgreSQL (postgresql+psycopg://...) for anything shared. |
| `AGENTGOV_DATABASE_AUTO_MIGRATE` | `true` | Bring the database's schema up to date when the control plane starts. Turn it off where a deployment job runs `agentgov db upgrade` before new versions start. |
| `AGENTGOV_PUBLIC_URL` | `http://localhost:8000` | Externally reachable URL of the control plane (UI, API, OPA bundles). |
| `AGENTGOV_HTTP_KEEPALIVE_SECONDS` | `620` | Seconds the control plane keeps an idle HTTP connection open. Behind a load balancer, keep it longer than the load balancer's own (600 on Google Cloud), or the load balancer may send a request on a connection the control plane just closed. |
| `AGENTGOV_ADMIN_TOKEN` (secret) | — | Bootstrap administrator bearer token for the admin API and UI. |
| `AGENTGOV_DEV_MODE` | `false` | Development only: without an admin token, the control plane makes one up and logs it. |
| `AGENTGOV_SERVICE_TOKEN` (secret) | — | Shared token for internal components (OPA, governance processor, OTel collector) calling the control plane. |
| `AGENTGOV_FEATURES` | empty | Features pinned by the deployment, e.g. `least-privilege=monitor,discovery=off` ([features](features.md)). Administrators choose the others in the app. |
| `AGENTGOV_FEATURE_PRESET` | empty | A starting point for the features' modes, applied once, when the control plane starts with one it hasn't applied yet: `monitor` (every control records what it would do and stops nothing) or `inventory` (no gateway: AgentGov finds agents and checks them). Administrators change the modes from there; pinned features keep their pins. |
| `AGENTGOV_APPROVAL_TTL_SECONDS` | `86400` | How long an approval request waits for a decision before it expires. |
| `AGENTGOV_SOFT_DELETE_RETENTION_DAYS` | `30` | Deleted agents can be restored for this many days, then they are purged (Agent 365 parity). 0 keeps them. |
| `AGENTGOV_AUTO_BLOCK_RISK_SCORE` | `0` | When &gt; 0, agents whose risk score reaches this value are blocked. |
| `AGENTGOV_RISK_WINDOW_HOURS` | `24` | How long risk signals (denied calls, credentials, prompt injections) count towards an agent's risk score. |
| `AGENTGOV_STALE_AGENT_DAYS` | `30` | Agents not seen for this many days raise a stale-agent finding. |
| `AGENTGOV_POSTURE_INTERVAL_SECONDS` | `300` | Seconds between posture scans (owners, sponsors, attestations, stale agents); 0 turns the scheduled scan off. |

### Security operations

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_DESTINATION_SECRETS_DIR` | `/destination-secrets` | Where destinations' credentials are: a file per destination, named after it (a mounted secret). Never in the database. |
| `AGENTGOV_DELIVERY_INTERVAL_SECONDS` | `10` | How often destinations are sent what is new in the ledger (also as soon as it is written, on the replica that wrote it). 0 turns delivery off. |

### Issues

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_ISSUE_ESCALATION_HOURS` | `critical:4,high:24,medium:72,low:168,info:168` | Hours an issue waits at each step of its chain (owner, sponsors, team) for someone to acknowledge it, before it goes to the next, by severity. |
| `AGENTGOV_ISSUES_INTERVAL_SECONDS` | `60` | Seconds between rounds of routing issues, escalating them and sending what is due. |
| `AGENTGOV_ISSUES_NOTIFY_SEVERITY` | `info` | Issues below this severity reach people in AgentGov only, without an email or a chat message. info: every issue is sent. |
| `AGENTGOV_ISSUES_QUIET_FIRST_SYNC` | `true` | What a platform's first sync finds reaches people in AgentGov only, without an email or a chat message: what was there before AgentGov looked doesn't flood inboxes. Found again after it is resolved, it is sent as any other. |
| `AGENTGOV_THREAT_FINDING_DAYS` | `30` | Days a threat finding stays open without happening again before it is resolved (it opens again if it happens again). 0 keeps threats open until someone closes them. |
| `AGENTGOV_SMTP_URL` | — | The mail server for issues' emails: smtp://host:587 (STARTTLS) or smtps://host:465 (TLS). Without it, issues reach people in AgentGov and in their teams' chats only. |
| `AGENTGOV_SMTP_FROM` | — | The sender of issues' emails, such as agentgov@example.com. |
| `AGENTGOV_SMTP_USERNAME`<br>`AGENTGOV_SMTP_PASSWORD` (secret) | —<br>— | The mail server's user and password, if it needs them. |

### Evidence and retention

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_LEDGER_RETENTION_DAYS` | `0` | Days the ledger keeps its entries in the database: older ones are archived to `AGENTGOV_LEDGER_ARCHIVE_DIR`, then removed, and the chain goes on from the checkpoint at their end. 0 keeps every entry; otherwise at least 183 (six months). |
| `AGENTGOV_LEDGER_ARCHIVE_DIR` | — | Where the ledger's archives go, as gzipped JSON Lines files (a mounted volume, or a bucket mounted as one). Needed with `AGENTGOV_LEDGER_RETENTION_DAYS`. |
| `AGENTGOV_LEDGER_CHECKPOINT_HOURS` | `24` | Hours between ledger checkpoints: the chain's head, kept, and time-stamped when a time-stamping authority is set. 0 makes them only on demand. |
| `AGENTGOV_LEDGER_TSA_URL` | — | An RFC 3161 time-stamping authority, such as `https://freetsa.org/tsr`. It signs each checkpoint with its own time, which proves the chain existed then, unchanged since. |
| `AGENTGOV_LEDGER_REKOR_URL` | — | A transparency log, Sigstore's Rekor v2: its public shard (such as `https://log2025-1.rekor.sigstore.dev`) or a rekor-tiles of your own. Each checkpoint is signed with `AGENTGOV_LEDGER_REKOR_SIGNING_KEY_FILE` and added to it, where anyone can see that it was published: AgentGov can't later show another checkpoint for the same entry without the log holding both. What the log publishes, for good, is the statement's SHA-256, the signature and AgentGov's public key. |
| `AGENTGOV_LEDGER_REKOR_SIGNING_KEY_FILE` | — | AgentGov's key for the log: an ECDSA P-256 private key (PEM). `agentgov transparency-key DIR` makes one. |
| `AGENTGOV_LEDGER_REKOR_LOG_KEY_FILE` | — | The log's public key (PEM, Ed25519), to check each answer's proof that the log holds the entry. Unset, entries are kept unchecked. |
| `AGENTGOV_LEDGER_REKOR_ORIGIN` | — | The log's name in its checkpoints (its origin). Unset: the URL's host name. |
| `AGENTGOV_DATA_RETENTION_DAYS` | `0` | Days AgentGov keeps the operational records whose history the ledger has: daily activity and model usage, risk signals, notifications sent, decided approvals, resolved findings, ended access assignments, and developers' MCP servers not reported since. 0 keeps them; otherwise at least 30. |

### Keycloak (agent identity)

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_KEYCLOAK_URL` | — | Base URL the control plane uses to reach Keycloak's admin API. |
| `AGENTGOV_KEYCLOAK_REALM` | `agentgov` | The realm agents' clients, identity issuers and people live in. |
| `AGENTGOV_KEYCLOAK_CLIENT_ID` | `agentgov-control-plane` | The client the control plane provisions agents' clients with. |
| `AGENTGOV_KEYCLOAK_CLIENT_SECRET` (secret) | — | Its secret. Provisioning in Keycloak is on when this and `AGENTGOV_KEYCLOAK_URL` are set. |
| `AGENTGOV_KEYCLOAK_ISSUER` | — | Issuer that appears in agent tokens (Keycloak's frontend URL + realm). |
| `AGENTGOV_KEYCLOAK_JWKS_URL` | — | JWKS URL the gateway uses to validate agent tokens. |
| `AGENTGOV_IDENTITY_FULL_SYNC_SECONDS` | `900` | Seconds between passes that sync every agent with Keycloak, which also repair what was changed in Keycloak itself. The passes between, every minute and after each change, sync only the agents whose clients should change. 0: every pass is full. |
| `AGENTGOV_GATEWAY_AUDIENCE` | `agentgov-gateway` | Audience every agent token carries; the gateway requires it. |
| `AGENTGOV_PEOPLE_APP_CLIENTS` | empty | Keycloak clients of the apps people sign in to and use agents from (comma-separated client IDs). Each agent that acts for people has a client scope named after its client ID, which these apps may request: the person's token is then one the agent can exchange for a token of its own, on the person's behalf. |
| `AGENTGOV_ASSERTION_LIFETIME_SECONDS` | `300` | Seconds the identity assertions (ID-JAG) AgentGov gives agents for MCP servers outside the gateway last, at most 300: the agent trades one for an access token at once ([acting-for-people](acting-for-people.md)#mcp-servers-outside-the-gateway). |

### Administrator single sign-on (OIDC)

The control plane signs administrators in with an OIDC provider (Keycloak by default) as a confidential client and keeps the session server-side: the browser only holds an HttpOnly cookie. Enabled when a client secret is set.

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_OIDC_CLIENT_ID` | `agentgov-admin` | The client AgentGov signs administrators in as. |
| `AGENTGOV_OIDC_CLIENT_SECRET` (secret) | — | Its secret. Single sign-on is on when this is set. |
| `AGENTGOV_OIDC_ISSUER` | — | Defaults to `AGENTGOV_KEYCLOAK_ISSUER`. Endpoints default to Keycloak's paths: the authorization and logout endpoints under the issuer (browser-facing), the token endpoint and JWKS under `AGENTGOV_KEYCLOAK_URL` when set (server-to-server). |
| `AGENTGOV_OIDC_AUTHORIZATION_ENDPOINT`<br>`AGENTGOV_OIDC_TOKEN_ENDPOINT`<br>`AGENTGOV_OIDC_JWKS_URL`<br>`AGENTGOV_OIDC_END_SESSION_ENDPOINT` | —<br>—<br>—<br>— | The provider's endpoints, where they aren't Keycloak's or Microsoft Entra ID's. |
| `AGENTGOV_OIDC_SCOPES` | `openid profile email` | The scopes asked for at sign-in. |
| `AGENTGOV_OIDC_ROLES_CLAIM` | `realm_access.roles` | Where role names are found in the tokens (a dot path). |
| `AGENTGOV_OIDC_ROLE_PREFIX` | `agentgov-` | The prefix that marks AgentGov roles: `agentgov-approver` grants the approver role. |
| `AGENTGOV_SESSION_HOURS` | `8` | The longest an administrator's session lasts. |
| `AGENTGOV_MICROSOFT_ADMIN_ACTIONS` | `false` | Act in Microsoft 365 and Power Platform as the administrator who is signed in (quarantine Copilot Studio agents, read the Power Platform inventory, block Microsoft 365 agents): Microsoft accepts these only from a signed-in admin. Needs sign-in through Microsoft Entra ID (`AGENTGOV_OIDC_ISSUER` `https://login.microsoftonline.com/<tenant>/v2.0`) and an app registration with the delegated permissions listed in [platforms](platforms.md). |

### Microsoft 365 agent inventory

AgentGov's Entra app registration, for the connections to Microsoft's services ([microsoft-connections](microsoft-connections.md)), each turned on by the application permission it needs: CopilotPackages.Read.All for the agent catalog (which also needs a Microsoft Agent 365 licence), AgentIdentity.Read.All, AuditLogsQuery.Read.All, SecurityAlert.Read.All and EntitlementManagement.Read.All. The connections are on when all three are set.

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_M365_TENANT_ID` | — | The Microsoft Entra tenant (directory) ID. |
| `AGENTGOV_M365_CLIENT_ID`<br>`AGENTGOV_M365_CLIENT_SECRET` (secret) | —<br>— | The app registration's application (client) ID, and its client secret. |
| `AGENTGOV_M365_SYNC_INTERVAL_SECONDS` | `3600` | 0 turns the scheduled sync off; admins can still sync on demand. |
| `AGENTGOV_M365_PACKAGE_TYPES` | `custom,shared,external` | Package types to import: custom (built in your organisation), shared (shared by its users), external (from partners) and microsoft (Microsoft's own). |
| `AGENTGOV_GRAPH_URL`<br>`AGENTGOV_ENTRA_LOGIN_URL`<br>`AGENTGOV_POWER_PLATFORM_URL` | `https://graph.microsoft.com`<br>`https://login.microsoftonline.com`<br>`https://api.powerplatform.com` | Microsoft's endpoints: change them for a national cloud (such as `https://graph.microsoft.us` and `https://login.microsoftonline.us`). |

### Copilot Studio threat detection (optional)

Copilot Studio asks AgentGov before each tool call its agents make, once a Power Platform admin connects AgentGov to an environment ([microsoft-connections](microsoft-connections.md)). Turned on with the feature copilot-studio-threat-detection (monitor or enforce) once these are set.

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_COPILOT_STUDIO_CALLER_APP_IDS` | empty | The app registrations that may call (the one connected to Copilot Studio), comma-separated application (client) IDs. |
| `AGENTGOV_COPILOT_STUDIO_AUDIENCES` | empty | Accepted token audiences, comma-separated: AgentGov's API's application ID URI (by default the origin of `AGENTGOV_PUBLIC_URL`) and, for v2.0 tokens, its client ID. |
| `AGENTGOV_COPILOT_STUDIO_TENANT_ID` | — | The tenant ID (a GUID) whose apps may call. By default the tenant of `AGENTGOV_M365_TENANT_ID` or of sign-in through Entra ID, when that is a GUID. |
| `AGENTGOV_COPILOT_STUDIO_ON_ERROR` | `block` | The answer when AgentGov cannot decide in time (enforce mode): `block` or `allow`. |

### Agents on other platforms

AgentGov reads the agents on AWS, Google Cloud, Salesforce, Databricks and Microsoft Foundry into the inventory, each where its settings below are set ([other-platforms](other-platforms.md)).

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_PLATFORM_SYNC_INTERVAL_SECONDS` | `3600` | Seconds between reads of each platform; 0 reads them only on demand. |
| `AGENTGOV_AWS_REGIONS` | empty | AWS: the regions to read Amazon Bedrock agents, AgentCore's harnesses, agent runtimes and gateways, Amazon Quick's agents and AWS Agent Registry's in, comma-separated, such as us-east-1,eu-west-1 (empty: AWS isn't read). AgentGov signs its requests with AWS credentials from the usual places: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, IAM roles for service accounts or Pod Identity on EKS, or the instance's role. |
| `AGENTGOV_AWS_ROLE_ARNS` | empty | Roles to assume, comma-separated ARNs, to read other AWS accounts too (in the same regions), with the credentials above. |
| `AGENTGOV_AWS_EXTERNAL_ID` | — | The external ID those roles' trust policies ask for, if any. |
| `AGENTGOV_AWS_READ` | `bedrock-agents,agentcore,agentcore-gateways,quick,agent-registry` | What to read in each account's regions, comma-separated: bedrock-agents (Amazon Bedrock agents), agentcore (AgentCore's harnesses and agent runtimes), agentcore-gateways (its gateways), quick (Amazon Quick's agents) and agent-registry (AWS Agent Registry's agents and MCP servers; with auto-detection, an organisation's registry has the AgentCore runtimes and gateways of all its accounts). |
| `AGENTGOV_GOOGLE_CLOUD_PROJECTS` | empty | Google Cloud: the projects to read Agent Runtime (formerly Vertex AI Agent Engine) agents in, comma-separated project IDs (empty: Google Cloud isn't read). AgentGov gets its tokens where Google's libraries do: the file GOOGLE_APPLICATION_CREDENTIALS names (a workload identity federation configuration, or a service account key), gcloud's application default credentials, or the metadata server (Workload Identity on GKE). |
| `AGENTGOV_GOOGLE_CLOUD_REGIONS` | `us-central1` | The regions to read them in, comma-separated (us and eu for the multi-regions). |
| `AGENTGOV_GOOGLE_CLOUD_READ` | `agent-runtime,agent-registry` | What to read in each project, comma-separated: agent-runtime (its agents, in each region) and agent-registry (Agent Registry's agents and MCP servers, in each region and global: agents on Cloud Run and GKE, Gemini Enterprise's, and those registered by hand). |
| `AGENTGOV_SALESFORCE_URL` | — | Salesforce: the org to read Agentforce agents in, by its My Domain URL, such as `https://contoso.my.salesforce.com` (empty: Salesforce isn't read). |
| `AGENTGOV_SALESFORCE_CLIENT_ID`<br>`AGENTGOV_SALESFORCE_CLIENT_SECRET` (secret) | —<br>— | The External Client App AgentGov signs in with: its consumer key, and its consumer secret, for the client credentials flow (as the app's Run As user). |
| `AGENTGOV_SALESFORCE_USERNAME`<br>`AGENTGOV_SALESFORCE_PRIVATE_KEY_FILE` | —<br>— | Instead of the secret, the JWT bearer flow: the user AgentGov signs in as, and the private key (PEM) of the certificate uploaded to the app. |
| `AGENTGOV_DATABRICKS_HOSTS` | empty | Databricks: the workspaces to read agents in, comma-separated URLs, such as `https://dbc-1234.cloud.databricks.com` (empty: Databricks isn't read). |
| `AGENTGOV_DATABRICKS_CLIENT_ID`<br>`AGENTGOV_DATABRICKS_CLIENT_SECRET` (secret) | —<br>— | The service principal AgentGov reads as (OAuth machine-to-machine): its application ID and an OAuth secret of its own. |
| `AGENTGOV_DATABRICKS_TOKEN` (secret) | — | Instead, a personal access token, valid in the workspaces named. |
| `AGENTGOV_DATABRICKS_READ` | `serving,apps,genie,mcp-services` | What to read in each, comma-separated: serving (agents on Model Serving), apps (Agent Bricks agents), genie (Genie agents) and mcp-services (the MCP services registered in Unity Catalog, read catalog by catalog). |
| `AGENTGOV_FOUNDRY_PROJECTS` | empty | Microsoft Foundry: the projects to read agents in, comma-separated project endpoints, such as `https://contoso.services.ai.azure.com/api/projects/support`. AgentGov reads them as its Microsoft app registration (`AGENTGOV_M365_`*), which needs a role on each project that may read agents. |
| `AGENTGOV_FOUNDRY_SUBSCRIPTIONS` | empty | Azure subscriptions to find Foundry projects in, comma-separated IDs: every project of every Foundry resource the app may see there (Reader on the subscription). |
| `AGENTGOV_FOUNDRY_AUDIENCE`<br>`AGENTGOV_AZURE_MANAGEMENT_URL` | `https://ai.azure.com`<br>`https://management.azure.com` | Foundry's token audience and Azure Resource Manager: change them for a national cloud. |

### Classifier, optional

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_GUARDIAN_URL` | — | IBM Granite Guardian behind an OpenAI-compatible API (vLLM, llama.cpp, Ollama), e.g. `http://guardian:8000/v1`. The control plane asks it about agent instructions, and the processor about tool results, agents' answers and people's prompts (the traffic-classifier feature). Without it, AgentGov's rules decide alone. |
| `AGENTGOV_GUARDIAN_MODEL`<br>`AGENTGOV_GUARDIAN_API_KEY` (secret) | `ibm-granite/granite-guardian-4.1-8b`<br>— | The name the server serves the model under, and its API key if it needs one. |
| `AGENTGOV_GUARDIAN_CRITERIA` | `harm,jailbreak,social_bias,violence,unethical_behavior,exfiltration,deception` | Criteria to judge agent instructions by (one classifier call each): harm, jailbreak, social_bias, violence, profanity, unethical_behavior, exfiltration, deception. |
| `AGENTGOV_GUARDIAN_TIMEOUT_SECONDS` | `60.0` | The longest one classifier call may take. |
| `AGENTGOV_CLASSIFIER_TIMEOUT_SECONDS` | `3.0` | How long the processor waits for the classifier's verdict on a call where it is enforced; past that, `AGENTGOV_GUARDIAN_FAILURE_MODE` says what happens, and the ledger says so. |
| `AGENTGOV_GUARDIAN_FAILURE_MODE` | `open` | Where the processor waits for the classifier and gets no verdict (it is down, or too slow): `open` lets the rules decide alone; `closed` counts the text as flagged, so the call is refused. |
| `AGENTGOV_CLASSIFIER_CONCURRENCY` | `4` | Classifier calls one processor makes at a time. In the background, what waits beyond a few hundred goes unclassified rather than piling up. |

### OPA (policy decisions)

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_OPA_URL` | — | Where the processor asks OPA for decisions, and the control plane for What if, such as `http://opa:8181`. |
| `AGENTGOV_AUTHZEN_URL` | — | An AuthZEN decision point of your own (OpenID AuthZEN Authorization API 1.0), which the processor also asks about the calls AgentGov's policies let through, as the external-decision-point feature says: its base URL, such as `https://pdp.example.com` ([policies](policies.md)#authzen). |
| `AGENTGOV_AUTHZEN_TOKEN` (secret) | — | The bearer token it asks for, if it asks for one. |
| `AGENTGOV_AUTHZEN_TIMEOUT_SECONDS` | `2.0` | Seconds to wait for its answer. |
| `AGENTGOV_AUTHZEN_FAILURE_MODE` | `closed` | When it can't be asked while the external-decision-point feature is enforced: `closed` refuses the call; `open` lets AgentGov's own decision stand. Monitored, it never stops a call. |
| `AGENTGOV_BUNDLE_LONG_POLL_SECONDS` | `30` | Longest a bundle long-poll request is held open. |
| `AGENTGOV_BUNDLE_SIGNING_KEY_FILE` | — | A PEM private key (RSA, or EC P-256 or P-384) the control plane signs OPA's bundles with; OPA verifies each with the matching certificate or public key, and refuses one that doesn't verify ([production](production.md)). `agentgov bundle-signing-key DIR` makes a pair. Unset, bundles go unsigned. |
| `AGENTGOV_BUNDLE_SIGNING_KEY_ID` | `agentgov` | The key's name: OPA's configuration names the same one (bundles.&lt;name&gt;.signing.keyid). |

### agentgateway (enforcement)

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_GATEWAY_CONFIG_PATH` | — | Where the generated agentgateway config is written (shared volume). |
| `AGENTGOV_GATEWAY_PUBLIC_URL` | `http://localhost:8080` | The gateway's address as agents reach it, which the app and the API show. |
| `AGENTGOV_MCP_REGISTRY_NAMESPACE` | empty | The namespace of tool servers' names in the MCP registry (`<namespace>/<name>`); by default the control plane's host name reversed, such as com.contoso.agentgov. |
| `AGENTGOV_GATEWAY_PORT` | `8080` | The port agentgateway listens on, in the configuration generated for it. |
| `AGENTGOV_PROCESSOR_ADDRESS` | `processor:50051` | Where agentgateway reaches the governance processor for tool calls (gRPC). |
| `AGENTGOV_PROCESSOR_WEBHOOK_ADDRESS` | `processor:8091` | ...and for model calls and calls between agents (HTTP). |
| `AGENTGOV_GATEWAY_FAILURE_MODE` | `modes` | When a call through the gateway can't be checked (OPA can't decide, or the governance processor can't be reached or fails): `closed` refuses it; `open` lets it through unchecked, and recorded where the processor can; `modes` refuses it only while a control at the gateway is enforced, so that controls in monitor mode never stop a call. Set it alike where the control plane (which configures the gateway) and the processor run. |
| `AGENTGOV_GATEWAY_OTLP_ENDPOINT` | — | OTLP/gRPC endpoint for gateway traces, e.g. `http://otel-collector:4317`. |
| `AGENTGOV_GATEWAY_IPV6` | `false` | agentgateway binds IPv6 sockets by default, which fails on IPv4-only hosts. |
| `AGENTGOV_TRACE_URL` | — | Link to a trace in your trace viewer, with {trace_id} where the W3C trace ID goes, such as `http://localhost:16686/trace/{trace_id}` for Jaeger. Ledger entries recorded at the gateway then link to their trace. |

### Mutual TLS between components

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_TLS_DIR` | — | Where this component finds its certificate (tls.crt), its key (tls.key) and the certificate of the authority that issued every component's (ca.crt), as cert-manager writes them. Set, AgentGov's components talk over mutual TLS: each serves TLS on its internal ports and asks callers for a certificate from the same authority, and the control plane gives the service role only on its internal port. `agentgov internal-certs DIR` makes an authority and the certificates. |
| `AGENTGOV_TLS_RELOAD_SECONDS` | `60.0` | Seconds between looks at those files for a renewed certificate (cert-manager's, or an X.509-SVID spiffe-helper writes from SPIRE): a new one serves the next connections, with no restart. 0 reads them once, at start. |
| `AGENTGOV_TLS_PEERS` | empty | The callers this component's TLS listeners take, comma-separated: their SPIFFE IDs (the chart's: spiffe://example.org/ns/agentgov/agentgov/agentgov-gateway) or DNS names, exact or with a trailing * for a prefix. Empty: any certificate from the authority, which then must issue AgentGov's components' only; with SPIRE, which gives every workload one, list them. |
| `AGENTGOV_INTERNAL_PORT` | `8443` | The control plane's port for AgentGov's other components, over mutual TLS. |
| `AGENTGOV_GATEWAY_TLS_DIR` | `/tls` | Where agentgateway finds its tls.crt, tls.key and ca.crt, to call the processor over mutual TLS (the control plane writes it into the gateway's configuration). |

### Governance processor

| Variable | Default | What it does |
|---|---|---|
| `AGENTGOV_PROCESSOR_LISTEN` | `0.0.0.0:50051` | Where it answers agentgateway about tool calls (gRPC). |
| `AGENTGOV_PROCESSOR_WEBHOOK_LISTEN` | `0.0.0.0:8091` | Where it answers agentgateway's guardrail webhook for model calls, and its external authorization of calls between agents. |
| `AGENTGOV_CONTROL_PLANE_URL` | `http://localhost:8000` | Control plane URL as seen from the processor. |
| `AGENTGOV_COMPONENT_REPORT_SECONDS` | `60` | Seconds between the processor's reports to the control plane of what it can reach (OPA, Presidio, Granite Guardian, your decision point), which say on the Features page whether each control can do what its mode says; 0 sends none. |
| `AGENTGOV_PRESIDIO_URL` | — | Presidio's analyzer, such as `http://presidio-analyzer:3000`. Without it, personal data isn't looked for. |
| `AGENTGOV_PII_ENTITIES` | `EMAIL_ADDRESS:0.5,PHONE_NUMBER:0.4,US_SSN:0.5,CREDIT_CARD:0.5,IBAN_CODE:0.5,CRYPTO:0.5` | Presidio entities treated as personal data, with per-entity minimum scores. Noisy recognisers (DATE_TIME, URL, LOCATION, ...) are deliberately absent; add PERSON:0.85 to also mask names (it has false positives). |
| `AGENTGOV_PRESIDIO_MAX_CHARS` | `16000` | Presidio costs ~40 ms per KB; text beyond this budget is not sent to it. |
| `AGENTGOV_PRESIDIO_FAILURE_MODE` | `closed` | When Presidio is unreachable: `closed` denies the call, `open` skips PII scanning. |
| `AGENTGOV_PROMPT_INJECTION_THRESHOLD` | `0.7` | The score (0 to 1) from which text counts as a prompt injection or a jailbreak (also for the control plane's Copilot Studio checks). |

<!-- END settings reference -->

# Requirements

What AgentGov needs to run: for evaluation on one machine, and on Kubernetes for others
to rely on. [Deploying AgentGov](deploy/README.md) has the guides.

## At a glance

| | Evaluation | Production |
|---|---|---|
| Runs on | One machine with Docker (Compose) | Kubernetes 1.30 or later, installed with Helm |
| Memory | About 4 GB free | About 3.2 GiB of requests, and 1 vCPU, as the cloud guides run it: a managed PostgreSQL, the bundled Keycloak, and two of each part on the decision path. Two or three nodes of 2 vCPUs and 8 GiB leave room to grow |
| Database | The bundled PostgreSQL | A managed PostgreSQL, 15 or later, with two databases: AgentGov's and Keycloak's |
| Identity | The bundled Keycloak, in development mode | The bundled Keycloak in production mode, with its data in your PostgreSQL, or a Keycloak 26.6 or later of your own; your directory federated into it |
| Addresses | `localhost` ports | Three HTTPS addresses: the control plane, the gateway and Keycloak |
| Secrets | `deploy/compose/.env` | Kubernetes Secrets, ideally filled from your secret store |

## Software

| | Version |
|---|---|
| Docker, with Compose v2 | Current releases, for the Compose stack and to build the image |
| Kubernetes | 1.30 or later. The chart uses stable APIs (`apps/v1`, `networking.k8s.io/v1`, `v1`), and the Gateway API's `gateway.networking.k8s.io/v1` for routes if you choose them over ingresses. CI checks it against Kubernetes 1.30's schemas and runs it on kind |
| Helm | 3 (CI uses 3.19) |
| PostgreSQL | 15 or later. Compose and the chart run 17 |
| Keycloak | 26.6 or later. The bundled one is 26.8.0. SPIFFE identity issuers need its `spiffe` feature ([agents' own identities](agent-identity.md)) |
| Python | 3.11 to 3.13, for the `agentgov` command and the demo. The image has the command too: `docker run --rm IMAGE --help` |
| Browser | A current Chrome, Edge, Firefox or Safari, for the admin UI |

The other parts are pinned and come with the stack: agentgateway 1.6.0, OPA 1.21.1,
Presidio 2.2.364 and the OpenTelemetry Collector (contrib) 0.162.0. The
[README](../README.md#components) lists them with their licences.

## Resources

Measured on the Compose stack, at rest and after the demo's full run:

| Part | Memory at rest | After the demo |
|---|---|---|
| Presidio | 1.44 GiB | 1.44 GiB |
| Keycloak | 652 MiB | 725 MiB |
| Control plane | 96 MiB | 103 MiB |
| PostgreSQL | 72 MiB | 83 MiB |
| Governance processor | 59 MiB | 61 MiB |
| Gateway's configuration sidecar | 53 MiB | 53 MiB |
| OpenTelemetry Collector | 34 MiB | 39 MiB |
| OPA | 16 MiB | 18 MiB |
| agentgateway | 7 MiB | 13 MiB |
| **Total** | **2.4 GiB** | **2.5 GiB** |

The demo's stand-ins (a tool server, a model, an agent, an identity issuer and the security
team's tools) add about 150 MiB. CPU stays low between calls: the work is per call,
mostly Presidio's (about 40 ms per KB of text it reads).

The Helm chart reserves:

| Part | Requests | Limits |
|---|---|---|
| Control plane | 100m CPU, 256 MiB | 1 GiB |
| Governance processor | 100m, 128 MiB | 512 MiB |
| Gateway (agentgateway and its configuration sidecar) | 110m, 128 MiB | 640 MiB |
| OPA | 50m, 64 MiB | 512 MiB |
| Presidio | 100m, 1.5 GiB | 2.5 GiB |
| OpenTelemetry Collector | 50m, 64 MiB | 512 MiB |
| PostgreSQL (bundled) | 100m, 256 MiB, and an 8 GiB volume | 1 GiB |
| Keycloak (bundled) | 200m, 768 MiB | 1.5 GiB |
| **Total** | **810m CPU, 3.1 GiB** (510m, 2.1 GiB without the bundled two) | |

Each component's `resources` value changes them ([Kubernetes](deploy/kubernetes.md)); GKE
Autopilot and AKS Automatic raise requests below their minimums, so AgentGov reserves a
little more there. The
decision path scales out together: more gateway, processor and OPA replicas, each about
260m CPU and 320 MiB more. For high availability, run two control-plane replicas or more
on PostgreSQL, connected directly or through a pooler in session mode: they use
`LISTEN`/`NOTIFY` and advisory locks ([production](production.md#several-replicas)).

Optional additions:

| | Plan on |
|---|---|
| Langfuse, to explore traces (Compose override) | About 3 GB more memory |
| Granite Guardian on a CPU, to classify agents' instructions and, in the background, their traffic | About 8 GB more memory, and a 5 GB model download; a GPU with vLLM for faster checks, and for calls to wait for its verdicts ([detection](detection.md)) |

## Network

Who reaches whom, from outside the deployment:

| From | To | Why |
|---|---|---|
| People's browsers | Control plane, Keycloak (HTTPS) | The admin UI, and signing in |
| Agents | Gateway (HTTPS) | Tool calls, model calls, calls to other agents |
| Agents | Keycloak (HTTPS) | Tokens: the token endpoint of the `agentgov` realm |
| Agents | OpenTelemetry Collector (OTLP, 4317 gRPC or 4318 HTTP) | Traces, for discovery and activity. Optional; the chart keeps the collector inside the cluster |
| Developers' tools | Control plane (HTTPS) | The MCP registry, `agentgov mcp scan --report`, the CLI |
| Microsoft | Control plane (HTTPS, public) | Copilot Studio's threat detection calls. Optional |

Within the deployment, the gateway calls the processor (50051 gRPC, 8091 HTTP); the
processor calls OPA (8181), Presidio (3000) and the control plane (8000); OPA, the
collector and the gateway's sidecar call the control plane; the control plane calls OPA;
and the control plane and Keycloak use PostgreSQL (5432). With the chart's network policies
on (`networkPolicy.enabled`), only these parts reach OPA, the processor, Presidio and
PostgreSQL; the control plane, the gateway, the collector and Keycloak take connections on
their ports from anywhere, for people and agents.

Going out, as you use them:

| From | To |
|---|---|
| Gateway | Your MCP servers, model providers' APIs, the A2A endpoints of agents it publishes, and Keycloak's keys, to check agents' tokens |
| Control plane | Keycloak's admin API; Microsoft Entra ID (`login.microsoftonline.com`), Microsoft Graph and the Power Platform API; your SIEM, Splunk, Teams and Slack; the Granite Guardian server; your mail server; a time-stamping authority and a transparency log, for the ledger's checkpoints ([evidence](evidence.md)) |
| Governance processor | The Granite Guardian server, for the classifier's second opinion on traffic ([detection](detection.md)) |
| Keycloak | The keys of the identity issuers agents authenticate with, and the identity providers people sign in through |

## Accounts and permissions

Only what you turn on needs any:

| To | You need |
|---|---|
| Read the Microsoft 365 agent catalog, Entra Agent ID, the Purview audit log or Defender's alerts | A Microsoft Entra app registration with the Microsoft Graph application permission for each, admin-consented ([connections](microsoft-connections.md)). The catalog needs a Microsoft Agent 365 licence |
| Quarantine Copilot Studio agents, block Microsoft 365 agents, push connector policies | Administrators who sign in through Microsoft Entra ID, and the delegated permissions in [platforms](platforms.md#setting-it-up) |
| Copilot Studio threat detection | A public HTTPS address for the control plane, an app registration, and a Power Platform administrator to connect it ([connections](microsoft-connections.md#copilot-studio-threat-detection)) |
| Model calls | Each provider's API key, given to the gateway only ([model calls](models.md)) |
| Security operations | Your SIEM's endpoint or token, and Teams or Slack webhooks ([security operations](secops.md)) |
| Agents' own identities | Keycloak able to reach each identity issuer's keys ([agents' own identities](agent-identity.md)) |

# AgentGov Helm chart

Installs AgentGov on Kubernetes: the control plane, the governance processor, OPA,
agentgateway, Presidio and the OpenTelemetry Collector, plus PostgreSQL and Keycloak for
evaluation. It runs the same stack as the [Compose deployment](../../compose/README.md),
and CI runs the same demo against it: `scripts/ci.sh --e2e` runs the chart's pods with
Docker (`scripts/chart-on-docker.py`), and `scripts/ci.sh --kind` installs it on a kind
cluster.

## Try it

```bash
helm install agentgov deploy/helm/agentgov -n agentgov --create-namespace --wait
```

Nothing is exposed outside the cluster by default. Forward the ports the demo uses, and
read the bootstrap admin token from the Secret the chart created:

```bash
kubectl -n agentgov port-forward svc/agentgov-control-plane 8000:8000 &
kubectl -n agentgov port-forward svc/agentgov-gateway 8080:8080 &
kubectl -n agentgov port-forward svc/agentgov-keycloak 8180:8080 &
export AGENTGOV_URL=http://localhost:8000
export AGENTGOV_TOKEN=$(kubectl -n agentgov get secret agentgov -o jsonpath='{.data.admin-token}' | base64 -d)
agentgov apply -f examples/manifests
```

Then open <http://localhost:8000/ui>. The demo users `admin`, `alice` and `audrey` sign in
with the `demo-password` from the same Secret.

The image is published to `ghcr.io/sreent/agentgov` for each release. To run a build of
your own, push it to a registry the cluster can pull from and set `image.repository` and
`image.tag`; with kind, `kind load docker-image` and `image.pullPolicy=Never` will do.

## Production

The defaults are for evaluation. Before anyone else relies on the installation:

* **Use your own PostgreSQL.** Put its URL,
  `postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE`, in a Secret and set
  `postgresql.enabled=false`, `externalDatabase.existingSecret` (and
  `externalDatabase.key`, `database-url` by default). Back it up, before every upgrade
  too.
* **Use your own Keycloak**, run with its operator or chart rather than in development
  mode. Import [`files/agentgov-realm.json`](files/agentgov-realm.json) into it (or create
  the `agentgov-control-plane` and `agentgov-admin` clients it describes), then set
  `keycloak.enabled=false`, `externalKeycloak.url` and, if its tokens name a different
  issuer, `externalKeycloak.issuer`. To sign administrators in through Microsoft Entra
  ID instead, see [platforms.md](../../../docs/platforms.md#setting-it-up) and pass the
  settings in `controlPlane.env` and `controlPlane.envFrom`.
* **Manage the secrets.** Create a Secret with `admin-token`, `service-token`,
  `keycloak-client-secret` and `oidc-client-secret` (long random values; the two client
  secrets must match the Keycloak clients) and set `secrets.existingSecret`. Without one,
  the chart generates random values once and keeps them. Put model providers' API keys
  in a Secret of your own too, one key per provider name, and set
  `modelKeys.existingSecret`: `modelKeys.keys` keeps them in your values, which is for
  evaluation.
* **Set the addresses and TLS.** `urls.controlPlane`, `urls.gateway` and `urls.keycloak`
  are what people, agents and outside services use, with `https://`. Turn on
  `controlPlane.ingress`, `gateway.ingress` (and `keycloak.ingress` for the bundled
  Keycloak) with your ingress class and TLS, or expose the Services another way.
* **Turn on the network policies** (`networkPolicy.enabled=true`, with a CNI that
  enforces them). OPA, the processor, Presidio and PostgreSQL then accept connections
  only from AgentGov's own parts. Agents that use the Agent Governance Toolkit query OPA
  directly: allow them with a policy of your own.
* **Turn off the demo users** (`keycloak.demoUsers=false`) if you keep the bundled
  Keycloak.

## Settings

Everything the control plane reads is an `AGENTGOV_*` environment variable
([`src/agentgov/config.py`](../../../src/agentgov/config.py)). The chart sets the ones that
wire the parts together; set the rest with `controlPlane.env`, and the secret ones with
`controlPlane.envFrom`, for example:

```yaml
controlPlane:
  env:
    AGENTGOV_AUTO_BLOCK_RISK_SCORE: "80"
    AGENTGOV_M365_TENANT_ID: 00000000-0000-0000-0000-000000000000
    AGENTGOV_M365_CLIENT_ID: 00000000-0000-0000-0000-000000000000
  envFrom:
    - secretRef:
        name: agentgov-microsoft   # holds AGENTGOV_M365_CLIENT_SECRET
```

| Value | Default | What it does |
|---|---|---|
| `image.repository`, `image.tag` | `ghcr.io/sreent/agentgov`, the chart's appVersion | The AgentGov image |
| `urls.controlPlane`, `urls.gateway`, `urls.keycloak` | `http://localhost:8000`, `:8080`, `:8180` | Addresses users and agents use |
| `secrets.existingSecret` | generated | The Secret with tokens and client secrets |
| `controlPlane.replicas` | `1` | Keep one (see [scaling notes](../../../docs/architecture.md#scaling-notes)) |
| `controlPlane.autoMigrate` | `true` | Migrate the database when the control plane starts |
| `controlPlane.env`, `controlPlane.envFrom` | — | More settings |
| `features` | — | Features the deployment pins, such as `{least-privilege: monitor}` ([features.md](../../../docs/features.md)); administrators choose the rest in the app |
| `controlPlane.ingress`, `gateway.ingress`, `keycloak.ingress` | off | Ingresses, at the hosts of the URLs above unless set |
| `gateway.replicas` | `1` | agentgateway replicas; each fetches its configuration from the control plane |
| `gateway.configInterval` | `5` | Seconds between checks for configuration changes |
| `processor.replicas`, `opa.replicas` | `1` | Scale the decision path with the gateway |
| `presidio.enabled` | `true` | Personal-data detection |
| `otelCollector.enabled` | `true` | Receive agents' traces (OTLP) for discovery and activity |
| `postgresql.enabled` | `true` | The bundled PostgreSQL; otherwise `externalDatabase` |
| `keycloak.enabled` | `true` | The bundled Keycloak (development mode); otherwise `externalKeycloak` |
| `keycloak.demoUsers` | `true` | Import the demo users |
| `networkPolicy.enabled` | `false` | Restrict traffic between AgentGov's parts |
| `modelKeys.existingSecret`, `modelKeys.keys` | — | Model providers' API keys, one per provider name, for the gateway only ([model calls](../../../docs/models.md)) |

Each component also takes `resources`, `nodeSelector`, `tolerations` and `affinity`.
[`values.yaml`](values.yaml) documents every value.

## How the parts find each other

The gateway's configuration is generated by the control plane from the registry. As in
Compose, an `agentgov gateway-config` init container and sidecar in each gateway pod
fetch it from the control plane (`GET /v1/gateway/config`, with the service token) and
keep the file agentgateway reads current. They and agentgateway mount the model keys'
Secret at `/model-keys`, and the sidecar holds back a model provider's route, which
answers 503, until its key is there. To rotate a key, update the Secret and restart the
gateway (`kubectl -n agentgov rollout restart deployment/agentgov-gateway`).
OPA long-polls the control plane for policies and registry data as in Compose, so
blocking an agent reaches every gateway within a second. The gateway sends its access
logs to the collector, which passes the model calls' usage on to the control plane.

## Upgrading

```bash
helm upgrade agentgov deploy/helm/agentgov -n agentgov --reuse-values
```

The control plane migrates the database when the new version starts, and replicas
starting together migrate one at a time. To migrate from a job of your own instead, set
`controlPlane.autoMigrate=false` and run `agentgov db upgrade` with the control plane's
`AGENTGOV_DATABASE_URL` before upgrading; the control plane then refuses to start until
the schema is current. `helm test agentgov -n agentgov` checks that the control plane
and the gateway answer.

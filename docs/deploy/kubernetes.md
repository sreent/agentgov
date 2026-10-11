# AgentGov on Kubernetes

The Helm chart, [`deploy/helm/agentgov`](../../deploy/helm/agentgov), installs AgentGov on
any Kubernetes cluster: the control plane, the governance processor, OPA, agentgateway,
Presidio and the OpenTelemetry Collector, and, for evaluation, PostgreSQL and Keycloak.
This page covers any cluster; the [Google Cloud](gcp.md), [Azure](azure.md) and
[AWS](aws.md) guides add each cloud's database, secrets, load balancer and certificates.

## The image

Each release will publish the AgentGov image to `ghcr.io/sreent/agentgov` (amd64 and arm64)
and the chart to `oci://ghcr.io/sreent/charts/agentgov`; the chart installs its own version of
the image. Until the first release, or to run a build of your own, build the image and push it
to a registry your cluster pulls from:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t REGISTRY/agentgov:0.1.0 --push .
```

Then set `image.repository=REGISTRY/agentgov` and `image.tag=0.1.0`. With kind,
`kind load docker-image` and `image.pullPolicy=Never` do instead.

## Try it

```bash
helm install agentgov deploy/helm/agentgov -n agentgov --create-namespace --wait \
  --set image.repository=REGISTRY/agentgov --set image.tag=0.1.0
```

Nothing is exposed outside the cluster by default. Forward the ports the CLI and the demo
use, and read the bootstrap admin token from the Secret the chart created. The CLI comes with
the Python package (`pip install -e ".[demo]"` in a clone):

```bash
kubectl -n agentgov port-forward svc/agentgov-control-plane 8000:8000 &
kubectl -n agentgov port-forward svc/agentgov-gateway 8080:8080 &
kubectl -n agentgov port-forward svc/agentgov-keycloak 8180:8080 &
export AGENTGOV_URL=http://localhost:8000
export AGENTGOV_TOKEN=$(kubectl -n agentgov get secret agentgov -o jsonpath='{.data.admin-token}' | base64 -d)
agentgov apply -f examples/manifests
```

Then open <http://localhost:8000/ui>. The demo users `admin`, `alice`, `sofia` and
`audrey` sign in with the `demo-password` from the same Secret, and `sam`, a person agents
act for, signs in to the demo app `agentgov-demo-chat`
([local](local.md#signing-in) lists what each may do). The example manifests expect the
demo's tool server and model beside the chart, as `scripts/ci.sh --kind` sets them up
([kind](local.md#kubernetes-with-kind)); with your own, register them instead.

## Before others rely on it

The defaults are for evaluation. For an installation others use:

* **A managed PostgreSQL**, backed up, before every upgrade too, with two databases,
  `agentgov` and `keycloak`, each owned by a user of its own. Put AgentGov's URL,
  `postgresql+psycopg://USER:PASSWORD@HOST:5432/agentgov?sslmode=verify-full&sslrootcert=system`,
  in a Secret and set `postgresql.enabled=false` and `externalDatabase.existingSecret` (with
  `externalDatabase.key`, `database-url` by default). `sslrootcert=system` trusts the public
  certificate authorities; for a server whose certificate comes from a private one, mount its
  certificate (`controlPlane.extraVolumes` and `extraVolumeMounts`) and give its path instead.
* **Keycloak for production.** Either the bundled one in production mode
  (`keycloak.mode=production`), which keeps its data in your PostgreSQL: set
  `keycloak.externalDatabase.url` (`jdbc:postgresql://HOST:5432/keycloak?sslmode=verify-full`
  and, for a public certificate authority, `&sslfactory=org.postgresql.ssl.DefaultJavaSSLFactory`,
  or `&sslrootcert=PATH` for a private one) and the Secret and key with its user's password.
  Or your own Keycloak, 26.6 or later, run with its operator or chart: see
  [your own Keycloak](#your-own-keycloak).
* **Your own Secret** (`secrets.existingSecret`), with long random values, filled from your
  secret store (the cloud guides use the External Secrets Operator):

  | Key | For |
  |---|---|
  | `admin-token` | The bootstrap administrator's token |
  | `service-token` | AgentGov's parts calling the control plane |
  | `keycloak-client-secret` | The control plane's Keycloak client, `agentgov-control-plane` |
  | `oidc-client-secret` | Administrators' single sign-on: the client `agentgov-admin`, or your Entra ID app |
  | `keycloak-admin-password` | The bundled Keycloak's first administrator |
  | `demo-password` | The demo users, while `keycloak.demoUsers` is on |
  | `postgres-password` | The bundled PostgreSQL |

  The same Secret can hold `database-url` and Keycloak's database password, if
  `externalDatabase` and `keycloak.externalDatabase` name it. Without a Secret of your own,
  the chart generates random values once and keeps them across upgrades. Model providers'
  API keys go in a Secret with one key per provider name (`modelKeys.existingSecret`), and
  destinations' credentials in one with a key per destination name
  (`destinationSecrets.existingSecret`).
* **HTTPS addresses.** `urls.controlPlane`, `urls.gateway` and `urls.keycloak` are what
  people, agents and outside services use, with `https://`. Expose the three with
  `controlPlane.ingress`, `gateway.ingress` and `keycloak.ingress` (your ingress class,
  annotations and TLS), or with Gateway API routes, `controlPlane.httpRoute`, `gateway.httpRoute`
  and `keycloak.httpRoute`, attached to a Gateway you manage. The gateway holds streams open
  for MCP clients and agents: give its load balancer a timeout of minutes, not seconds.
* **Network policies on** (`networkPolicy.enabled=true`, with a network plugin that
  enforces them): OPA, the processor, Presidio and PostgreSQL then take connections only
  from AgentGov's own parts. Agents that use the Agent Governance Toolkit query OPA
  directly: allow them with a policy of your own.
* **No demo users** (`keycloak.demoUsers=false`), which also leaves out the demo app
  `agentgov-demo-chat`, set before the first install: Keycloak imports AgentGov's realm on
  its first start only ([below](#keycloaks-realm)). Name the apps people use agents from in
  `peopleApps`.

A values file for that, with the Secret created beforehand:

```yaml
urls:
  controlPlane: https://agentgov.example.com
  gateway: https://gateway.agentgov.example.com
  keycloak: https://auth.agentgov.example.com
secrets:
  existingSecret: agentgov
postgresql:
  enabled: false
externalDatabase:
  existingSecret: agentgov                 # key database-url
keycloak:
  mode: production
  demoUsers: false
  externalDatabase:
    url: jdbc:postgresql://db.example.com:5432/keycloak?sslmode=verify-full&sslfactory=org.postgresql.ssl.DefaultJavaSSLFactory
    existingSecret: agentgov               # key keycloak-database-password
  ingress:
    enabled: true
    className: YOUR-INGRESS-CLASS
    tls: [{secretName: agentgov-auth-tls, hosts: [auth.agentgov.example.com]}]
modelKeys:
  existingSecret: agentgov-model-keys
destinationSecrets:
  existingSecret: agentgov-destinations
networkPolicy:
  enabled: true
controlPlane:
  ingress:
    enabled: true
    className: YOUR-INGRESS-CLASS
    tls: [{secretName: agentgov-tls, hosts: [agentgov.example.com]}]
gateway:
  replicas: 2
  ingress:
    enabled: true
    className: YOUR-INGRESS-CLASS
    tls: [{secretName: agentgov-gateway-tls, hosts: [gateway.agentgov.example.com]}]
processor:
  replicas: 2
opa:
  replicas: 2
```

### Keycloak's realm

Keycloak imports AgentGov's realm on its first start only, from the values of the time: the
client secrets, the control plane's address in the redirect URIs of the client
`agentgov-admin`, and the demo users and the demo app while `keycloak.demoUsers` is on. Set
them before the first install. Later changes to any of them are made in Keycloak's admin
console: turning `keycloak.demoUsers` off afterwards leaves the demo users and
`agentgov-demo-chat` in the realm until you delete them.

In production mode, run one Keycloak until it has imported the realm, then as many as you
like (`keycloak.replicas`): they find each other through the database.

### Your own Keycloak

Import [`files/agentgov-realm.json`](../../deploy/helm/agentgov/files/agentgov-realm.json) into
it, at start-up (`--import-realm`) or with `kc.sh import --file agentgov-realm.json`. Keycloak
fills in its `${…}` placeholders from its environment then: set `AGENTGOV_KEYCLOAK_CLIENT_SECRET`
and `AGENTGOV_OIDC_CLIENT_SECRET` to the values in your Secret. After the import, in the
`agentgov` realm:

* change the redirect URIs of the client `agentgov-admin` from `http://localhost:8000` to your
  control plane's address (`/auth/callback` and `/ui/`);
* delete the demo users (`admin`, `alice`, `sofia`, `audrey` and `sam`) and the client
  `agentgov-demo-chat`.

Then set `keycloak.enabled=false`, `externalKeycloak.url` and, if its tokens name a different
issuer, `externalKeycloak.issuer`. SPIFFE identity issuers need its `spiffe` feature.

## Signing in with Microsoft Entra ID

Administrators can sign in to AgentGov with Microsoft Entra ID instead of Keycloak, which also
lets AgentGov act in Microsoft 365 as them. Register the app as
[platforms](../platforms.md#setting-it-up) describes, put its client secret in your Secret's
`oidc-client-secret` key, and add to your values:

```yaml
controlPlane:
  env:
    AGENTGOV_OIDC_ISSUER: https://login.microsoftonline.com/<tenant ID>/v2.0
    AGENTGOV_OIDC_CLIENT_ID: <application (client) ID>
    AGENTGOV_OIDC_ROLES_CLAIM: roles
    AGENTGOV_MICROSOFT_ADMIN_ACTIONS: "true"
```

The chart always sets `AGENTGOV_OIDC_CLIENT_SECRET` from the Secret, so a value given in
`controlPlane.envFrom` wouldn't take effect.

## Values

| Value | Default | What it does |
|---|---|---|
| `image.repository`, `image.tag` | `ghcr.io/sreent/agentgov`, the chart's appVersion | The AgentGov image |
| `urls.controlPlane`, `urls.gateway`, `urls.keycloak` | `http://localhost:8000`, `:8080`, `:8180` | The addresses people and agents use |
| `secrets.existingSecret` | generated | The Secret with the tokens and client secrets |
| `controlPlane.replicas` | `1` | Keep one ([scaling notes](../architecture.md#scaling-notes)) |
| `controlPlane.autoMigrate` | `true` | Migrate the database when the control plane starts |
| `controlPlane.env`, `controlPlane.envFrom`, `processor.env`, `processor.envFrom` | — | More settings ([configuration](../configuration.md#helm)) |
| `controlPlane.extraVolumes`, `controlPlane.extraVolumeMounts` | — | More volumes, such as the database's certificate authority |
| `features` | — | Features the deployment pins, such as `{least-privilege: monitor}` ([features](../features.md)); administrators choose the rest in the app |
| `controlPlane.ingress`, `gateway.ingress`, `keycloak.ingress` | off | Ingresses, at the hosts of the addresses above unless `host` is set |
| `controlPlane.httpRoute`, `gateway.httpRoute`, `keycloak.httpRoute` | off | Gateway API routes instead, attached to the Gateway in `parentRefs`, with optional `timeouts` |
| `gateway.replicas`, `processor.replicas`, `opa.replicas` | `1` | The decision path; scale them together |
| `gateway.configInterval` | `5` | Seconds between the gateway's checks for configuration changes |
| `presidio.enabled` | `true` | Personal-data detection |
| `otelCollector.enabled` | `true` | Receive agents' traces (OTLP) for discovery and activity |
| `postgresql.enabled` | `true` | The bundled PostgreSQL; otherwise `externalDatabase` |
| `externalDatabase.existingSecret`, `externalDatabase.key` | —, `database-url` | The Secret with AgentGov's database URL |
| `keycloak.enabled` | `true` | The bundled Keycloak; otherwise `externalKeycloak` |
| `keycloak.mode` | `dev` | `dev` for evaluation, `production` behind TLS with its own database |
| `keycloak.replicas` | `1` | Keycloaks in production mode |
| `keycloak.externalDatabase` | — | Keycloak's database with `postgresql.enabled=false`: `url`, `username` (`keycloak`), and the Secret and key with its password |
| `keycloak.extraVolumes`, `keycloak.extraVolumeMounts` | — | More volumes, such as the database's certificate authority |
| `keycloak.demoUsers` | `true` | Import the demo users and the demo app `agentgov-demo-chat` |
| `keycloak.features` | `[spiffe]` | Keycloak features to turn on: SPIFFE identity issuers need the `spiffe` preview |
| `keycloak.mountServiceAccountToken` | `false` | Let Keycloak read this cluster's service account keys from the API server ([below](#agents-in-the-cluster)) |
| `peopleApps` | `[]` | Keycloak clients of the apps people use agents from ([acting for people](../acting-for-people.md)) |
| `networkPolicy.enabled` | `false` | Restrict traffic to AgentGov's internal parts |
| `modelKeys.existingSecret`, `modelKeys.keys` | — | Model providers' API keys, one per provider name, for the gateway only ([model calls](../models.md)); `keys` creates the Secret from your values, for evaluation |
| `destinationSecrets.existingSecret`, `destinationSecrets.values` | — | Destinations' credentials, one per destination name, for the control plane only ([security operations](../secops.md)) |
| `serviceAccount.annotations` | — | For your cloud's workload identity, if pods need it |

Each component also takes `resources`, `nodeSelector`, `tolerations` and `affinity`;
[requirements](../requirements.md#resources) has what they reserve.
[`values.yaml`](../../deploy/helm/agentgov/values.yaml) documents every value.

## Agents in the cluster

Agents running in a cluster can authenticate with their pods' service account tokens
instead of client secrets, through an identity issuer of kind `kubernetes`
([agents' own identities](../agent-identity.md#kubernetes)). Its issuer is the `iss` of the
cluster's tokens (`kubectl get --raw /.well-known/openid-configuration | jq -r .issuer`):

* On **GKE, AKS and EKS**, the cluster's own OIDC issuer, which the cloud publishes on the
  internet, also for agents in the cluster Keycloak runs in. Keycloak reads its keys there,
  wherever Keycloak runs. Each cloud guide shows it.
* On a cluster that keeps the default issuer, `https://kubernetes.default.svc.cluster.local`
  (kind, kubeadm), Keycloak reads the keys from that cluster's API server, so it must run in
  the same cluster, with `keycloak.mountServiceAccountToken=true`.

## How the parts find each other

The control plane generates the gateway's configuration from the registry. An
`agentgov gateway-config` init container and sidecar in each gateway pod fetch it from the
control plane (`GET /v1/gateway/config`, with the service token) and keep the file
agentgateway reads current. They and agentgateway mount the model keys' Secret at
`/model-keys`, and the sidecar holds back a model provider's route, which answers 503, until
its key is there. To rotate a key, update the Secret and restart the gateway
(`kubectl -n agentgov rollout restart deployment/agentgov-gateway`). OPA long-polls the
control plane for policies and registry data, so blocking an agent reaches every gateway
within a second. The gateway sends its access logs to the collector, which passes the model
calls' usage on to the control plane.

## Upgrading

Keep your values in a file, and upgrade with it:

```bash
helm upgrade agentgov deploy/helm/agentgov -n agentgov -f my-values.yaml --wait
```

`--reuse-values` would take the old release's values without the new chart's defaults, so a
value the chart has gained since would be missing; with Helm 3.14 or later,
`--reset-then-reuse-values` takes the new defaults and your earlier values.

Back up the database first. The control plane migrates it when the new version starts,
and replicas starting together migrate one at a time. To migrate from a job of your own
instead, set `controlPlane.autoMigrate=false` and run `agentgov db upgrade` with the control
plane's `AGENTGOV_DATABASE_URL` before upgrading; the control plane then refuses to start
until the schema is current. `helm test agentgov -n agentgov` checks that the control plane
and the gateway answer.

If your Keycloak realm was imported before agents could have their own identities, give the
control plane's service account the two roles it now needs: in Keycloak's admin console, open
the `agentgov` realm, then Clients, `agentgov-control-plane`, Service account roles, Assign
role, and assign `realm-management`'s `manage-identity-providers` and
`view-identity-providers`. Until then, identity issuers show an error saying so.

## Removing it

```bash
helm uninstall agentgov -n agentgov
```

The bundled PostgreSQL's volume claim stays, with the data; delete it
(`kubectl -n agentgov delete pvc data-agentgov-postgresql-0`) to start over. Installing again
over a kept volume needs the same passwords: the Secret the chart generated goes with the
release, so keep a copy of it first, or use a Secret of your own (`secrets.existingSecret`).

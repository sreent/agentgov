# Running AgentGov in production

What makes AgentGov dependable once others rely on it: several control-plane replicas, so
that one can go without the others noticing; many people working at once without undoing
each other's work; components that prove who they are to each other; and policies that OPA
takes only from the control plane. The [Helm chart](deploy/kubernetes.md) and the
[Compose stack](deploy/local.md) set all of it up.

## Several replicas

The control plane runs as two or more replicas on one PostgreSQL database
(`controlPlane.replicas` in the chart). Any replica answers any request: what they share
is in the database, and they coordinate through it.

* **Changes reach every replica at once.** A transaction that changes what OPA, the
  gateway or a scheduled job acts on (an agent blocked, a feature switched, a tool server
  approved) tells the other replicas when it commits, with PostgreSQL's `NOTIFY`. Each
  acts on it as on its own: OPA instances long-polling any replica get the new bundle at
  once, so a block stops the agent everywhere within a second, whichever replica an
  administrator used and whichever one each OPA asks. A replica that loses the database
  and finds it again acts as if everything changed; and no replica serves a bundle older
  than a minute without building it again.
* **Scheduled work runs on one replica at a time, the leader**: posture scans, the
  management rules, retention, the Microsoft sync, identity reconciliation, issues and
  their messages. The leader holds a PostgreSQL advisory lock; when it stops, or loses the
  database, the lock goes with its connection and another replica takes over within
  seconds. Security operations' delivery runs on every replica: each claims a destination
  before it sends to it.
* **A job runs once at a time** across replicas, however it started: a scan, a round of
  rules, retention or a Microsoft sync an administrator asks for waits for a run already
  going (15 seconds at most), then answers 409.
* **Nothing lives in one replica's memory.** Administrators' Microsoft sign-ins are kept
  in the database, sealed with a key derived from the client secret, so any replica acts
  as them ([platforms](platforms.md#how-agentgov-holds-the-sign-in)); sign-in attempts and
  sessions already were. OPA instances' status reports are kept there too, so every
  replica shows each instance and the bundle it runs.

The **Overview** page shows the replicas and which one leads, and warns when the replica
answering has lost touch with the others; so do `agentgov replicas` and `GET /v1/replicas`.
Another AgentGov on the same PostgreSQL server, on a database of its own, has replicas and
a leader of its own.

Several replicas need PostgreSQL's session features, `LISTEN` and advisory locks: connect
the control plane to the database directly, or through a pooler in session mode (PgBouncer
in transaction mode can't carry them). SQLite is for one process. With the ledger's
archives on a volume ([evidence](evidence.md#retention)), every replica needs to write it:
a ReadWriteMany volume (`controlPlane.ledgerArchive.accessMode`), as the chart checks. The
chart gives each part that runs several replicas a PodDisruptionBudget, so that a node
drain takes them one at a time.

## People working at once

AgentGov serves many people at once; two things keep them from undoing each other's work.

**Decisions take turns.** Deciding locks the row it decides until it commits: when two
approvers decide the same approval request at the same moment, one decision stands and the
other is told the request was already decided, rather than overwriting it. The same goes
for access package requests (deciding, revoking, reviewing), findings (acknowledging,
accepting the risk, resolving, dismissing), agents' lifecycle (approving, blocking,
deleting, attesting), the status of tool servers, model providers, identity issuers and
destinations, and an approval being used: two identical calls at once use it once.

**Edits made from an older copy are refused.** Agents, blueprints, tool servers, model
providers, identity issuers, destinations, policies, teams, access packages and management
rules each have a `version`, which every edit raises (what the scheduled work changes, such
as when an agent was last seen or its risk score, doesn't). An edit that names the version
it was made from is refused when the object has moved on since:

| Where | How |
|---|---|
| Admin UI | Each form sends the version it opened with. If someone saved meanwhile, it says so, and you open it again to see their change and make yours on top |
| CLI | `agentgov <kind> update ... --if-version N` (the version from `get`) |
| API | `If-Match: "N"` on `PATCH` (or `PUT` for policies); `412 Precondition Failed` when the object is past version `N`. Without `If-Match`, an edit changes the fields it gives, whatever the version |
| Manifests | `agentgov apply` describes how things should be, whatever they were, and raises the version |

## Mutual TLS between components

Each of AgentGov's components (the control plane, the governance processor, OPA,
agentgateway and the OpenTelemetry Collector) holds a certificate from AgentGov's own
certificate authority. With them, every hop inside AgentGov is TLS in both directions:

| Hop | What each side shows |
|---|---|
| Gateway → processor: tool calls (gRPC), model calls (the webhook), calls between agents (external authorization) and their answers (external processing, gRPC) | The processor asks for the gateway's certificate; the gateway checks the processor's |
| Processor → OPA, control plane → OPA | OPA asks every caller for a certificate (its health checks too) |
| Processor, OPA, the gateway's config sidecar, the collector → control plane | They call the control plane's internal port (8443), which asks for a certificate |

Nothing else on the network can pose as the processor that decides on tool calls, or as
OPA, or reach either. On its internal port the control plane takes a component's
certificate as its proof (OPA sends no token); on its public port it no longer gives the
service role at all, by the service token or an API key with the role, so a stolen one is
no use from outside. People and automation use the public port as before.

| Setting | Default | What it does |
|---|---|---|
| `AGENTGOV_TLS_DIR` | none | The component's certificate, key and the authority's certificate (`tls.crt`, `tls.key`, `ca.crt`, as cert-manager writes them). Set, mutual TLS is on |
| `AGENTGOV_INTERNAL_PORT` | 8443 | The control plane's port for the other components |
| `AGENTGOV_GATEWAY_TLS_DIR` | `/tls` | Where agentgateway finds its own, for the processor |

The chart makes the authority and a certificate for each component on install, and keeps
them on upgrades (`internalTLS`); or cert-manager issues them (`internalTLS.certManager`).
Whatever issues them, the authority must issue AgentGov's certificates only, because the
control plane and OPA take any certificate from it as one of AgentGov's components. So
cert-manager makes an authority for the release alone unless you name an issuer: an
Issuer in the release's namespace whose CA issues nothing else (the chart refuses a
ClusterIssuer, which issues to any namespace that asks). The components read their
certificates when they start, and OPA every minute: cert-manager's certificates last ten
years unless you set `internalTLS.certManager.duration`, and with a shorter life, restart
the pods after each renewal (with Reloader, for example). `agentgov internal-certs DIR`
makes the certificates where neither is there, as the Compose stack does on its first
start. Presidio and Keycloak are outside it:
Presidio's analyzer doesn't serve TLS (keep it to the processor with the
[network policy](deploy/kubernetes.md)), and Keycloak has TLS settings of its own.

## Signed bundles

The control plane signs each OPA bundle with its own key, and OPA refuses a bundle that
doesn't verify against the matching certificate: whoever reaches OPA, or the path to it,
can't hand it policies or registry data of their own. OPA keeps enforcing its last good
bundle, and its status report raises a critical finding
([architecture](architecture.md#trust-boundaries-and-failure-modes)).

The signature is a JWT in the bundle's `.signatures.json` listing every other file with its
SHA-256, in OPA's [bundle signing format](https://www.openpolicyagent.org/docs/management-bundles#signing).

| Setting | Default | What it does |
|---|---|---|
| `AGENTGOV_BUNDLE_SIGNING_KEY_FILE` | none | The private key bundles are signed with: RSA (RS256), or EC on P-256 or P-384 (ES256, ES384) |
| `AGENTGOV_BUNDLE_SIGNING_KEY_ID` | `agentgov` | The key's name, as OPA's configuration names it |

The chart makes the key and its certificate on install and keeps them (`bundleSigning`),
or takes a `kubernetes.io/tls` Secret of yours; OPA gets only the certificate.
`agentgov bundle-signing-key DIR` makes a pair, as the Compose stack does on its first
start.

## Tested on PostgreSQL

Production runs on PostgreSQL, so the tests run there as well as on SQLite: `scripts/ci.sh
--postgres` (and `--e2e`) runs every test on a database of its own in a throwaway
PostgreSQL, and the `ci` workflow does on every pull request. The tests of replicas and of
decisions taken together run only there: two replicas on one database, the kill switch
reaching an OPA long-polling the other replica within a second, a leader that stops and
another that takes over, two approvers at once.

## In the demo

The demo's stacks run all of it: mutual TLS between the components and signed bundles in
both the Compose stack and the Helm chart's pods, and two control-plane replicas from the
chart, behind a stand-in for a Kubernetes Service that hands each connection to the next
replica. Step 13 of `python examples/agents/demo_agent.py` blocks the agent through one
replica or the other and fails unless its calls stop within seconds.

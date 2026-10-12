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
  going (15 seconds at most), then answers 409. A job's lock is held by its connection to
  the database: when the database restarts mid-run, or drops that connection, another
  replica may start the job, and the run that lost its lock stops at its next commit,
  with nothing more written.
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
destinations, and an approval being used: two identical calls at once use it once. Each
transaction writes its ledger entries last, as it commits, so decisions that lock the same
rows in another order wait for each other rather than deadlock.

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
| `AGENTGOV_TLS_RELOAD_SECONDS` | 60 | How often it looks at those files for a renewed certificate. 0 reads them once, at start |
| `AGENTGOV_TLS_PEERS` | none | The callers its listeners take, by their SPIFFE IDs or DNS names (a trailing `*` for a prefix). None: any certificate from the authority |
| `AGENTGOV_INTERNAL_PORT` | 8443 | The control plane's port for the other components |
| `AGENTGOV_GATEWAY_TLS_DIR` | `/tls` | Where agentgateway finds its own, for the processor |

### Where the certificates come from

The chart gives the components their certificates one of three ways (`internalTLS`):

| | Issued by | Renewed |
|---|---|---|
| The chart (the default) | An authority the chart makes on install, and keeps on upgrades | Not: they last ten years |
| cert-manager (`internalTLS.certManager`) | An authority cert-manager makes for the release, or your Issuer | When cert-manager renews them (`duration`, ten years by default) |
| SPIRE (`internalTLS.spire`) | Your SPIRE server: each pod's X.509-SVID, by its SPIFFE ID | Half way through their life (an hour, by default) |

The authority of the first two must issue AgentGov's certificates only, because the
control plane and OPA take any certificate from it as one of AgentGov's components. So
cert-manager makes an authority for the release alone unless you name an issuer: an
Issuer in the release's namespace whose CA issues nothing else (the chart refuses a
ClusterIssuer, which issues to any namespace that asks). SPIRE is different: it gives
every workload a certificate, so there the components name the callers they take
([below](#workload-identities-from-spire)). `agentgov internal-certs DIR` makes the
certificates where none of these is there, as the Compose stack does on its first start,
and `agentgov internal-certs DIR --renew` renews them. Presidio and Keycloak are outside
it: Presidio's analyzer doesn't serve TLS (keep it to the processor with the
[network policy](deploy/kubernetes.md)), and Keycloak has TLS settings of its own.

### Renewed certificates

A renewed certificate takes effect without a restart, within a minute or so:

| Component | How it takes a renewed certificate |
|---|---|
| Control plane, processor, the gateway's config sidecar | They read their files every `AGENTGOV_TLS_RELOAD_SECONDS`. Once the certificate and its key fit together (a writer may have written one, not yet the other), the next connections get the new one: the servers present it from the next handshake (gRPC too), and new connections to other components present it |
| OPA | `--tls-cert-refresh-period=1m` for the certificate it serves; the one it shows the control plane, to fetch its bundles, is read for each new connection |
| OpenTelemetry Collector | `reload_interval: 1m` on its exporter's certificate |
| agentgateway | It reads the certificate it shows the processor only as it loads its configuration: the config sidecar adds the certificate's fingerprint to the configuration, so a renewed one rewrites it, and agentgateway loads it, and the certificate, again |

Connections already open keep their certificate until they close. A new authority (a new
`ca.crt`, not a renewed certificate from the same one) is a change to plan: the
components above take it as they take a certificate, except the two that check the
control plane's with it, OPA as it fetches its bundles and the Collector as it exports,
which read it only at start. Restart them after it.

### Workload identities from SPIRE

With `internalTLS.spire.enabled`, SPIRE issues the components' certificates. Each
component's pod gets its X.509-SVID through the SPIFFE CSI driver, and spiffe-helper, run
before the component and then beside it, writes it into `/tls` as `tls.crt`, `tls.key` and
`ca.crt`; as SPIRE renews it, the component takes each new one (above). It needs SPIRE
installed with its CSI driver and controller manager, as the SPIFFE project's
[Helm charts](https://github.com/spiffe/helm-charts-hardened) install them: the chart
registers each component with a `ClusterSPIFFEID`, which the controller manager turns into
SPIRE's registration entries.

| Value | Default | What it does |
|---|---|---|
| `internalTLS.spire.enabled` | off | SPIRE issues the components' certificates |
| `internalTLS.spire.trustDomain` | `example.org` | Your SPIRE's trust domain |
| `internalTLS.spire.className` | `spire-server-spire` | The controller manager's class, so that it takes the chart's `ClusterSPIFFEID`s (`<namespace>-<release>` of SPIRE's chart) |
| `internalTLS.spire.csiDriver` | `csi.spiffe.io` | The SPIFFE CSI driver |
| `internalTLS.spire.ttl` | SPIRE's | How long the components' SVIDs last |
| `internalTLS.spire.helper.image`, `.resources` | `ghcr.io/spiffe/spiffe-helper:0.12.2` | spiffe-helper |

Each component's SPIFFE ID is `spiffe://<trust domain>/ns/<namespace>/agentgov/<name>`,
such as `spiffe://example.org/ns/agentgov/agentgov/agentgov-processor`, and its SVID also
carries its Services' DNS names, which callers check. SPIRE gives every workload in the
trust domain a certificate, so a certificate from it doesn't make its holder one of
AgentGov's components. The components name the callers they take instead: the control
plane's internal port takes the processor, the gateway, OPA and the Collector, and the
processor takes the gateway (`AGENTGOV_TLS_PEERS`, which the chart sets), and OPA takes the
processor and the control plane, by their SPIFFE IDs (a `system.authz` policy, with
`--authorization=basic`). A caller from the trust domain that isn't one of them is turned
away: as its connection opens at the control plane and the processor's webhook, and at
each call to the processor's gRPC services and to OPA. SPIRE gives a component's identity
to the pods with its labels in the release's namespace, so, as with certificates in
Secrets, whoever may run pods there may get one: keep the namespace to AgentGov.

SPIRE signs SVIDs with an authority of its own, or under an upstream authority of yours
(its `UpstreamAuthority` plugins), and spiffe-helper writes that root as `ca.crt`. An
authority `agentgov internal-certs` makes can be SPIRE's upstream (SPIRE's `disk` plugin):
it leaves room below it for SPIRE's intermediate.

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
replica or the other and fails unless its calls stop within seconds. In the Compose stack,
the control plane and the processor name their callers (`AGENTGOV_TLS_PEERS`), and
`scripts/ci.sh --e2e` renews every component's certificate before the demo, waits until
each serves its new one and agentgateway has loaded its own, and runs the demo on them.

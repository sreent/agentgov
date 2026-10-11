# AgentGov on Google Cloud

This guide installs AgentGov on Google Kubernetes Engine (GKE), with Google Cloud's managed
services around it:

| What | On Google Cloud |
|---|---|
| Kubernetes | GKE Autopilot, which enforces network policies and has Workload Identity Federation and the Gateway API on |
| The image | Artifact Registry |
| The database | Cloud SQL for PostgreSQL 17, on a private IP address only |
| Secrets | Secret Manager, synced into the cluster by the External Secrets Operator |
| HTTPS | GKE's Gateway: a global external Application Load Balancer, with a Google-managed certificate from Certificate Manager |
| DNS | Cloud DNS, or wherever your domain is |
| Sign-in | Keycloak in production mode, in the same Cloud SQL instance |

The chart's values and the manifests applied beside it are in
[`deploy/kubernetes/gke`](../../deploy/kubernetes/gke). [Kubernetes](kubernetes.md) explains the
chart, and [requirements](../requirements.md) what AgentGov needs. CI renders these values and
validates the manifests. The Google Cloud commands follow Google's documentation as of
October 2026, which each step links to, but CI doesn't run them on Google Cloud.

## Before you start

* The gcloud CLI, kubectl with the `gke-gcloud-auth-plugin`, Helm 3.14 or later, jq, and
  Docker with buildx to build the image, from a clone of this repository.
* A project where you are Owner, or hold the roles to create clusters, Cloud SQL instances,
  secrets, certificates, service accounts and IAM bindings.
* A domain for AgentGov's three addresses, for example `agentgov.example.com` (people, the
  CLI), `gateway.agentgov.example.com` (agents) and `auth.agentgov.example.com` (Keycloak). The
  steps use a Cloud DNS zone for it; with another DNS provider, create the same records there.

Choose the names once and keep them in a file that you `source` in every new shell:

```bash
# agentgov.env
export PROJECT=my-project REGION=europe-west1
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT --format='value(projectNumber)')
export DOMAIN=agentgov.example.com           # also gateway.$DOMAIN and auth.$DOMAIN
export ZONE=example-com                      # the Cloud DNS zone that holds it
gcloud config set project $PROJECT
```

Later steps use variables that earlier ones set, such as the database passwords: run them in
one shell, or add those variables to the file too.

Turn on the services the steps use:

```bash
gcloud services enable container.googleapis.com artifactregistry.googleapis.com \
  sqladmin.googleapis.com servicenetworking.googleapis.com secretmanager.googleapis.com \
  certificatemanager.googleapis.com dns.googleapis.com
```

## 1. The cluster

An Autopilot cluster always enforces network policies (GKE Dataplane V2) and has Workload
Identity Federation and the Gateway API on
([choosing a mode](https://cloud.google.com/kubernetes-engine/docs/concepts/choose-cluster-mode)).
Its nodes run as a service account of their own, which may pull images from the registry of
step 2 ([node service accounts](https://docs.cloud.google.com/kubernetes-engine/security/configure-node-service-accounts)):

```bash
gcloud iam service-accounts create gke-nodes
gcloud projects add-iam-policy-binding $PROJECT --role=roles/container.defaultNodeServiceAccount \
  --member=serviceAccount:gke-nodes@$PROJECT.iam.gserviceaccount.com
gcloud container clusters create-auto agentgov --location=$REGION \
  --service-account=gke-nodes@$PROJECT.iam.gserviceaccount.com
gcloud container clusters get-credentials agentgov --location=$REGION
```

Autopilot bills for what pods request and raises requests to its minimums and CPU-to-memory
ratios: with these values, AgentGov requests about 1 vCPU and 3.2 GiB before that. A
Standard cluster works too, created with `--enable-dataplane-v2`, `--workload-pool` and
`--gateway-api=standard`.

## 2. The image

Until releases are published at `ghcr.io/sreent/agentgov`, build the image into Artifact
Registry:

```bash
gcloud artifacts repositories create agentgov --repository-format=docker --location=$REGION
gcloud artifacts repositories add-iam-policy-binding agentgov --location=$REGION \
  --role=roles/artifactregistry.reader \
  --member=serviceAccount:gke-nodes@$PROJECT.iam.gserviceaccount.com
gcloud auth configure-docker $REGION-docker.pkg.dev
docker buildx build --platform linux/amd64 \
  -t $REGION-docker.pkg.dev/$PROJECT/agentgov/agentgov:0.1.0 --push .
```

## 3. The database

Cloud SQL reaches the cluster's network over private services access
([private IP](https://cloud.google.com/sql/docs/postgres/configure-private-services-access)). One
instance holds two databases, `agentgov` and `keycloak`, each owned by its own user. It takes
only TLS connections, and has a certificate authority of its own, so that a client which
checks the server's certificate against it knows it reached this instance
([server CA modes](https://cloud.google.com/sql/docs/postgres/configure-ssl-instance)):

```bash
gcloud compute addresses create google-managed-services-default --global \
  --purpose=VPC_PEERING --prefix-length=16 --network=default
gcloud services vpc-peerings connect --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services-default --network=default
PG_ADMIN_PASSWORD=$(openssl rand -base64 24)
gcloud sql instances create agentgov --database-version=POSTGRES_17 --edition=enterprise \
  --cpu=2 --memory=8GiB --region=$REGION --availability-type=regional \
  --network=default --no-assign-ip --ssl-mode=ENCRYPTED_ONLY \
  --server-ca-mode=GOOGLE_MANAGED_INTERNAL_CA \
  --enable-point-in-time-recovery --retained-backups-count=14 --deletion-protection \
  --root-password="$PG_ADMIN_PASSWORD"
export PG_IP=$(gcloud sql instances describe agentgov --format='value(ipAddresses[0].ipAddress)')
gcloud sql ssl server-ca-certs list --instance=agentgov --format='value(cert)' > server-ca.pem
```

`--availability-type=regional` keeps a standby in another zone, at twice the cost; leave it out
for a staging installation.

Create the users and the databases from inside the network, with a pod in the cluster.
`GRANT … TO postgres` lets the administrator create databases that the users own. This
one-off connection is encrypted without checking the certificate; AgentGov's and Keycloak's
check it against `server-ca.pem`:

```bash
AGENTGOV_DB_PASSWORD=$(openssl rand -hex 24)
KEYCLOAK_DB_PASSWORD=$(openssl rand -hex 24)
kubectl run psql --rm -it --restart=Never --image=postgres:17-alpine \
  --env PGPASSWORD="$PG_ADMIN_PASSWORD" -- \
  psql "host=$PG_IP user=postgres dbname=postgres sslmode=require" \
  -c "CREATE ROLE agentgov LOGIN PASSWORD '$AGENTGOV_DB_PASSWORD'" \
  -c "CREATE ROLE keycloak LOGIN PASSWORD '$KEYCLOAK_DB_PASSWORD'" \
  -c "GRANT agentgov, keycloak TO postgres" \
  -c "CREATE DATABASE agentgov OWNER agentgov" \
  -c "CREATE DATABASE keycloak OWNER keycloak"
```

## 4. Secrets

Every secret lives in Secret Manager. The External Secrets Operator copies them into one
Kubernetes Secret, `agentgov`, which the chart reads. The operator reads them as its own
Kubernetes service account, which Workload Identity Federation lets IAM name directly
([the operator's guide](https://external-secrets.io/latest/provider/google-secrets-manager/)):

```bash
ESO=principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$PROJECT.svc.id.goog/subject/ns/external-secrets/sa/external-secrets
secret() {   # secret NAME VALUE: store it, and let the operator read it
  printf %s "$2" | gcloud secrets create "agentgov-$1" --data-file=-
  gcloud secrets add-iam-policy-binding "agentgov-$1" \
    --role=roles/secretmanager.secretAccessor --member="$ESO" >/dev/null
}
for key in admin-token service-token keycloak-client-secret oidc-client-secret keycloak-admin-password; do
  secret $key "$(openssl rand -hex 32)"
done
secret database-url \
  "postgresql+psycopg://agentgov:$AGENTGOV_DB_PASSWORD@$PG_IP:5432/agentgov?sslmode=verify-ca&sslrootcert=/etc/cloudsql/server-ca.pem"
secret keycloak-database-password "$KEYCLOAK_DB_PASSWORD"
```

Install the operator, then apply the namespace, the store and the `agentgov` Secret's
definition, with your names put in by `names`. The database's certificate authority goes in a
ConfigMap beside it, which the values mount for the control plane and Keycloak:

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace --wait

names() {
  sed -e "s/<project>/$PROJECT/g; s/<region>/$REGION/g; s/<postgres-ip>/$PG_IP/g" \
      -e "s/agentgov\.example\.com/$DOMAIN/g" "$@"
}
names deploy/kubernetes/gke/manifests/secrets.yaml | kubectl apply -f -
kubectl -n agentgov create configmap cloudsql-ca --from-file=server-ca.pem
kubectl -n agentgov get externalsecret agentgov      # STATUS: SecretSynced
```

GKE also syncs Secret Manager into Kubernetes Secrets itself
([Secret Manager's sync](https://cloud.google.com/secret-manager/docs/sync-k8-secrets)), with
`--enable-secret-sync` on the cluster, if you would rather not run the operator.

## 5. HTTPS

Reserve the address, and get a Google-managed certificate for the three names. Certificate
Manager proves you control the domain with a DNS record
([DNS authorization](https://cloud.google.com/certificate-manager/docs/deploy-google-managed-dns-auth)):

```bash
gcloud compute addresses create agentgov --global
gcloud certificate-manager dns-authorizations create agentgov --domain=$DOMAIN
read -r NAME DATA < <(gcloud certificate-manager dns-authorizations describe agentgov \
  --format='value(dnsResourceRecord.name,dnsResourceRecord.data)')
gcloud dns record-sets create $NAME --zone=$ZONE --type=CNAME --ttl=300 --rrdatas=$DATA
gcloud certificate-manager certificates create agentgov \
  --domains="$DOMAIN,*.$DOMAIN" --dns-authorizations=agentgov
gcloud certificate-manager maps create agentgov
gcloud certificate-manager maps entries create agentgov --map=agentgov \
  --certificates=agentgov --hostname=$DOMAIN
gcloud certificate-manager maps entries create agentgov-subdomains --map=agentgov \
  --certificates=agentgov --hostname="*.$DOMAIN"
kubectl apply -f deploy/kubernetes/gke/manifests/gateway.yaml
```

The Gateway ([`gateway.yaml`](../../deploy/kubernetes/gke/manifests/gateway.yaml)) is a global
external Application Load Balancer at the reserved address, with the certificates of the map
([securing a Gateway](https://cloud.google.com/kubernetes-engine/docs/how-to/secure-gateway)).
Plain HTTP redirects to HTTPS. Two kinds of policies go with it:

* The load balancer's timeout counts from the request to the end of the response, 30 seconds
  by default. Agents' streams through the gateway may last an hour (`GCPBackendPolicy`), after
  which clients reconnect.
* The load balancer checks each part at its own health endpoint (`HealthCheckPolicy`), and
  Keycloak at its management port.

## 6. Install AgentGov

Make your copy of the values, with your names, and keep it (in your own repository) for
upgrades:

```bash
names deploy/kubernetes/gke/values.yaml > agentgov-values.yaml
helm install agentgov deploy/helm/agentgov -n agentgov -f agentgov-values.yaml --wait --timeout 15m
```

The values ([`values.yaml`](../../deploy/kubernetes/gke/values.yaml)) turn off the bundled
PostgreSQL, run the bundled Keycloak in production mode on Cloud SQL, without the demo users,
attach routes to the Gateway, turn on the network policies and run two of each part on the
decision path. On its first start, Keycloak builds itself for production and imports
AgentGov's realm, which takes a few minutes. Once it has, you can run two
(`keycloak.replicas: 2`).

## 7. DNS

Point the three names at the reserved address:

```bash
IP=$(gcloud compute addresses describe agentgov --global --format='value(address)')
for host in $DOMAIN gateway.$DOMAIN auth.$DOMAIN; do
  gcloud dns record-sets create $host. --zone=$ZONE --type=A --ttl=300 --rrdatas=$IP
done
```

The certificate becomes active once its DNS authorization is checked
(`gcloud certificate-manager certificates describe agentgov`), and the load balancer a few
minutes after the Gateway is programmed.

## 8. Check it, and sign in

```bash
curl -fsS https://$DOMAIN/readyz
curl -fsS https://gateway.$DOMAIN/healthz
curl -fsS https://auth.$DOMAIN/realms/agentgov/.well-known/openid-configuration >/dev/null && echo keycloak ok

export AGENTGOV_URL=https://$DOMAIN
export AGENTGOV_TOKEN=$(gcloud secrets versions access latest --secret=agentgov-admin-token)
agentgov whoami
```

The bootstrap token is for the first steps and for break-glass access. Then:

* Sign in to Keycloak's admin console at `https://auth.agentgov.example.com/admin` as `admin`,
  with the password in `agentgov-keycloak-admin-password`. That account is temporary: create
  your own administrator and delete it.
* Let people sign in with single sign-on: add your identity provider (Google Workspace, or
  any OpenID Connect or SAML provider) to the `agentgov` realm, and give people AgentGov's
  [roles](../administration.md#roles). Automation uses API keys.
* Work through the [checklist](README.md#before-others-rely-on-it).

## Model keys and destinations

Model providers' API keys and destinations' credentials go in Secret Manager too, one secret
each, and into the Secrets the values name: `agentgov-model-keys`, with a key per provider
name ([model calls](../models.md)), and `agentgov-destinations`, with a key per destination
name ([security operations](../secops.md)). For an OpenAI provider named `openai`, with the
`secret` function of step 4:

```bash
secret model-openai "$OPENAI_API_KEY"
kubectl apply -f - <<'EOF'
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: agentgov-model-keys, namespace: agentgov}
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: SecretStore, name: google-secret-manager}
  target: {name: agentgov-model-keys}
  data:
    - {secretKey: openai, remoteRef: {key: agentgov-model-openai}}
EOF
```

The operator refreshes the Secret every hour. After a key changes, restart the gateway
(`kubectl -n agentgov rollout restart deployment/agentgov-gateway`).

## Agents in the cluster

Agents running in this cluster can authenticate with their pods' service account tokens
instead of client secrets ([agents' own identities](../agent-identity.md#kubernetes)). The
issuer is the cluster's own,
`https://container.googleapis.com/v1/projects/<project>/locations/<region>/clusters/agentgov`,
whose keys Google publishes on the internet, so Keycloak reads them there:

```bash
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
```

Google rotates the keys without notice; Keycloak fetches new keys when a token names one it
hasn't seen.

## Upgrading and removing it

```bash
helm upgrade agentgov deploy/helm/agentgov -n agentgov -f agentgov-values.yaml --wait
```

Note the time before upgrading: Cloud SQL restores to any point in the last 14 days
([Kubernetes](kubernetes.md#upgrading) has the rest). To remove it, uninstall the release and
delete the cluster, the Cloud SQL instance (after turning off its deletion protection), the
secrets, the certificate, its map and DNS authorization, the address and the DNS records.

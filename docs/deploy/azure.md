# AgentGov on Azure

This guide installs AgentGov on Azure Kubernetes Service (AKS), with Azure's managed
services around it:

| What | On Azure |
|---|---|
| Kubernetes | AKS, with Azure CNI powered by Cilium, which enforces network policies, and workload identity |
| The image | Azure Container Registry |
| The database | Azure Database for PostgreSQL flexible server 17, reachable only from the cluster's virtual network |
| Secrets | Azure Key Vault, synced into the cluster by the External Secrets Operator |
| HTTPS | The application routing add-on's Gateway API, with the certificate in Key Vault |
| DNS | Azure DNS, or wherever your domain is |
| Sign-in | Keycloak in production mode, in the same database server |

The chart's values and the manifests applied beside it are in
[`deploy/kubernetes/aks`](../../deploy/kubernetes/aks). [Kubernetes](kubernetes.md) explains the
chart, and [requirements](../requirements.md) what AgentGov needs. CI renders these values and
validates the manifests. The Azure commands follow Microsoft's documentation as of October
2026, which each step links to, but CI doesn't run them on Azure.

## Before you start

* The Azure CLI 2.86 or later (`az upgrade`), kubectl (`az aks install-cli`), Helm 3.14 or
  later, and Docker with buildx to build the image, from a clone of this repository.
* In the subscription, permission to create resources and role assignments: Owner, or
  Contributor and Role Based Access Control Administrator.
* A domain for AgentGov's three addresses, for example `agentgov.example.com` (people, the
  CLI), `gateway.agentgov.example.com` (agents) and `auth.agentgov.example.com` (Keycloak),
  and a certificate for them from your certificate authority, as a PFX file.

Choose the names once and keep them in a file that you `source` in every new shell:

```bash
# agentgov.env
export LOCATION=westeurope RG=agentgov CLUSTER=agentgov
export ACR=agentgov7f3a1c                    # unique in Azure: letters and digits
export KEYVAULT=agentgov-7f3a1c              # unique in Azure
export PG=agentgov-7f3a1c                    # unique in Azure
export DOMAIN=agentgov.example.com           # also gateway.$DOMAIN and auth.$DOMAIN
export TENANT_ID=$(az account show --query tenantId -o tsv)
```

Later steps use variables that earlier ones set, such as the database passwords: run them in
one shell, or add those variables to the file too.

## 1. The network and the cluster

The database is reachable only from a virtual network, so create the network first, with a
subnet for the cluster's nodes and one delegated to the database
([private access](https://learn.microsoft.com/azure/postgresql/network/concepts-networking-private)):

```bash
az group create -n $RG -l $LOCATION
az network vnet create -g $RG -n agentgov --address-prefixes 10.42.0.0/16 \
  --subnet-name nodes --subnet-prefixes 10.42.0.0/22
az network vnet subnet create -g $RG --vnet-name agentgov -n postgres \
  --address-prefixes 10.42.8.0/28 --delegations Microsoft.DBforPostgreSQL/flexibleServers
```

Then the cluster, and the Gateway API implementation of its application routing add-on
([Microsoft's guide](https://learn.microsoft.com/azure/aks/app-routing-gateway-api)):

```bash
az aks create -g $RG -n $CLUSTER --tier standard \
  --node-count 3 --node-vm-size Standard_D2s_v5 --zones 1 2 3 \
  --vnet-subnet-id "$(az network vnet subnet show -g $RG --vnet-name agentgov -n nodes --query id -o tsv)" \
  --network-plugin azure --network-plugin-mode overlay \
  --network-dataplane cilium --network-policy cilium \
  --enable-oidc-issuer --enable-workload-identity \
  --enable-addons azure-keyvault-secrets-provider \
  --enable-app-routing --app-routing-default-nginx-controller None \
  --generate-ssh-keys
az aks update -g $RG -n $CLUSTER --enable-gateway-api --enable-app-routing-istio
az aks get-credentials -g $RG -n $CLUSTER
```

* `--network-policy cilium` makes the cluster enforce the chart's network policies; without
  it, AKS enforces none
  ([Azure CNI powered by Cilium](https://learn.microsoft.com/azure/aks/azure-cni-powered-by-cilium)).
* The application routing add-on reads the Gateway's certificate from Key Vault, through the
  secrets provider. Its NGINX ingress controller is left out: Microsoft supports it only until
  November 2026, and its Gateway API implementation is the successor.
* Three nodes of 2 vCPUs and 8 GiB, one per zone, leave room for AgentGov's requests (about
  1 vCPU and 3.2 GiB with these values) and the Gateway's proxies. Leave out `--zones` in a
  region without availability zones.
* AKS Automatic clusters have Cilium, workload identity and, from Kubernetes 1.36, the Gateway
  API set up already. This guide uses AKS Standard so that each setting is visible.

## 2. The image

Until releases are published at `ghcr.io/sreent/agentgov`, build the image into a registry
the cluster pulls from:

```bash
az acr create -g $RG -n $ACR --sku Standard
az aks update -g $RG -n $CLUSTER --attach-acr $ACR
az acr login -n $ACR
docker buildx build --platform linux/amd64 -t $ACR.azurecr.io/agentgov:0.1.0 --push .
```

## 3. The database

One flexible server holds two databases, `agentgov` and `keycloak`, each owned by its own
user. A private DNS zone, linked to the network, resolves the server's name to its private
address:

```bash
az network private-dns zone create -g $RG -n agentgov.private.postgres.database.azure.com
az network private-dns link vnet create -g $RG -z agentgov.private.postgres.database.azure.com \
  -n agentgov -v agentgov -e false
PG_ADMIN_PASSWORD=$(openssl rand -base64 24)
az postgres flexible-server create -g $RG -n $PG -l $LOCATION --version 17 \
  --tier GeneralPurpose --sku-name Standard_D2ds_v5 --storage-size 64 \
  --zonal-resiliency Enabled --backup-retention 14 \
  --vnet agentgov --subnet postgres \
  --private-dns-zone agentgov.private.postgres.database.azure.com \
  --admin-user pgadmin --admin-password "$PG_ADMIN_PASSWORD" --yes
```

`--zonal-resiliency Enabled` keeps a standby in another zone, at twice the compute cost;
leave it out for a staging installation. Backups allow a point-in-time restore over the last
14 days.

Create the users and the databases from inside the network, with a pod in the cluster.
`GRANT … TO pgadmin` lets the administrator create databases that the users own:

```bash
AGENTGOV_DB_PASSWORD=$(openssl rand -hex 24)
KEYCLOAK_DB_PASSWORD=$(openssl rand -hex 24)
kubectl run psql --rm -it --restart=Never --image=postgres:17-alpine \
  --env PGPASSWORD="$PG_ADMIN_PASSWORD" -- \
  psql "host=$PG.postgres.database.azure.com user=pgadmin dbname=postgres sslmode=verify-full sslrootcert=system" \
  -c "CREATE ROLE agentgov LOGIN PASSWORD '$AGENTGOV_DB_PASSWORD'" \
  -c "CREATE ROLE keycloak LOGIN PASSWORD '$KEYCLOAK_DB_PASSWORD'" \
  -c "GRANT agentgov, keycloak TO pgadmin" \
  -c "CREATE DATABASE agentgov OWNER agentgov" \
  -c "CREATE DATABASE keycloak OWNER keycloak"
```

AgentGov and Keycloak connect with TLS and check the server's certificate and name
(`sslmode=verify-full`). Its certificate chains to a public root,
[as Microsoft describes](https://learn.microsoft.com/azure/postgresql/security/security-tls),
that AgentGov's image (`sslrootcert=system`) and Keycloak's Java runtime
(`DefaultJavaSSLFactory`) already trust.

## 4. Secrets

Every secret lives in Key Vault. The External Secrets Operator copies them into one
Kubernetes Secret, `agentgov`, which the chart reads.

```bash
az keyvault create -g $RG -n $KEYVAULT -l $LOCATION --enable-rbac-authorization true
KEYVAULT_ID=$(az keyvault show -n $KEYVAULT --query id -o tsv)
# Yourself, to write the secrets and import the certificate (it can take a few minutes to apply)
az role assignment create --assignee "$(az ad signed-in-user show --query id -o tsv)" \
  --role "Key Vault Administrator" --scope $KEYVAULT_ID

for key in admin-token service-token signing-secret keycloak-client-secret oidc-client-secret keycloak-admin-password; do
  az keyvault secret set --vault-name $KEYVAULT -n agentgov-$key --value "$(openssl rand -hex 32)" -o none
done
az keyvault secret set --vault-name $KEYVAULT -n agentgov-database-url -o none --value \
  "postgresql+psycopg://agentgov:$AGENTGOV_DB_PASSWORD@$PG.postgres.database.azure.com:5432/agentgov?sslmode=verify-full&sslrootcert=system"
az keyvault secret set --vault-name $KEYVAULT -n agentgov-keycloak-database-password -o none \
  --value "$KEYCLOAK_DB_PASSWORD"
```

A managed identity reads them, and the Gateway's certificate, as the Kubernetes service
account `agentgov-azure`, through a federated credential
([workload identity](https://learn.microsoft.com/azure/aks/workload-identity-deploy-cluster)):

```bash
az identity create -g $RG -n agentgov
export CLIENT_ID=$(az identity show -g $RG -n agentgov --query clientId -o tsv)
az role assignment create --role "Key Vault Secrets User" --scope $KEYVAULT_ID \
  --assignee-object-id "$(az identity show -g $RG -n agentgov --query principalId -o tsv)" \
  --assignee-principal-type ServicePrincipal
az identity federated-credential create -g $RG --identity-name agentgov -n agentgov-azure \
  --issuer "$(az aks show -g $RG -n $CLUSTER --query oidcIssuerProfile.issuerUrl -o tsv)" \
  --subject system:serviceaccount:agentgov:agentgov-azure --audiences api://AzureADTokenExchange
```

Install the [External Secrets Operator](https://external-secrets.io/latest/provider/azure-key-vault/),
then apply the namespace, the service account, the store and the `agentgov` Secret's
definition, with your names put in by `names`:

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace --wait

names() {
  sed -e "s/<registry>/$ACR/g; s/<postgres>/$PG/g; s/<keyvault>/$KEYVAULT/g" \
      -e "s/<client-id>/$CLIENT_ID/g; s/<tenant-id>/$TENANT_ID/g" \
      -e "s/agentgov\.example\.com/$DOMAIN/g" "$@"
}
names deploy/kubernetes/aks/manifests/secrets.yaml | kubectl apply -f -
kubectl -n agentgov get externalsecret agentgov      # STATUS: SecretSynced
```

## 5. HTTPS

Import the certificate into Key Vault. It must cover the three names, as names of its own or
as `agentgov.example.com` and `*.agentgov.example.com`:

```bash
az keyvault certificate import --vault-name $KEYVAULT -n agentgov -f agentgov.pfx  # --password if it has one
names deploy/kubernetes/aks/manifests/gateway.yaml | kubectl apply -f -
kubectl -n agentgov wait --for=condition=programmed gateway/agentgov --timeout=5m
```

The Gateway has an HTTPS listener for each address. The application routing add-on reads the
certificate for them from Key Vault, as `agentgov-azure`, and picks up a renewed certificate
by itself ([TLS with Key Vault](https://learn.microsoft.com/azure/aks/app-routing-gateway-api-dns-tls)).
The chart's routes attach to the listeners. The Gateway keeps its public IP address for as long
as it exists.

## 6. Install AgentGov

Make your copy of the values, with your names, and keep it (in your own repository) for
upgrades:

```bash
names deploy/kubernetes/aks/values.yaml > agentgov-values.yaml
helm install agentgov deploy/helm/agentgov -n agentgov -f agentgov-values.yaml --wait --timeout 15m
```

The values ([`values.yaml`](../../deploy/kubernetes/aks/values.yaml)) turn off the bundled
PostgreSQL, run the bundled Keycloak in production mode on the flexible server, without the
demo users, attach routes to the Gateway, turn on the network policies and run two of each
part on the decision path. On its first start, Keycloak builds itself for production and
imports AgentGov's realm, which takes a few minutes. Once it has, you can run two
(`keycloak.replicas: 2`).

## 7. DNS

Point the three names at the Gateway's address. In an Azure DNS zone:

```bash
IP=$(kubectl -n agentgov get gateway agentgov -o jsonpath='{.status.addresses[0].value}')
ZONE=example.com ZONE_RG=dns                 # your zone, and its resource group
for host in $DOMAIN gateway.$DOMAIN auth.$DOMAIN; do
  az network dns record-set a add-record -g $ZONE_RG -z $ZONE -n ${host%.$ZONE} -a $IP
done
```

Elsewhere, create the same three A records with your DNS provider.

## 8. Check it, and sign in

```bash
curl -fsS https://$DOMAIN/readyz
curl -fsS https://gateway.$DOMAIN/healthz
curl -fsS https://auth.$DOMAIN/realms/agentgov/.well-known/openid-configuration >/dev/null && echo keycloak ok

export AGENTGOV_URL=https://$DOMAIN
export AGENTGOV_TOKEN=$(az keyvault secret show --vault-name $KEYVAULT -n agentgov-admin-token --query value -o tsv)
agentgov whoami
```

The bootstrap token is for the first steps and for break-glass access. Then:

* Sign in to Keycloak's admin console at `https://auth.agentgov.example.com/admin` as `admin`,
  with the password in `agentgov-keycloak-admin-password`. That account is temporary: create
  your own administrator and delete it.
* Let people sign in with single sign-on: add Microsoft Entra ID to the `agentgov` realm as an
  identity provider, or sign administrators in with Entra ID directly
  ([Kubernetes](kubernetes.md#signing-in-with-microsoft-entra-id)), and give them AgentGov's
  [roles](../administration.md#roles). Automation uses API keys.
* Work through the [checklist](README.md#before-others-rely-on-it).

## Model keys and destinations

Model providers' API keys and destinations' credentials go in Key Vault too, one secret each,
and into the Secrets the values name: `agentgov-model-keys`, with a key per provider name
([model calls](../models.md)), and `agentgov-destinations`, with a key per destination name
([security operations](../secops.md)). For an OpenAI provider named `openai`:

```bash
az keyvault secret set --vault-name $KEYVAULT -n agentgov-model-openai --value "$OPENAI_API_KEY" -o none
kubectl apply -f - <<'EOF'
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: agentgov-model-keys, namespace: agentgov}
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: SecretStore, name: azure-key-vault}
  target: {name: agentgov-model-keys}
  data:
    - {secretKey: openai, remoteRef: {key: agentgov-model-openai}}
EOF
```

The operator refreshes the Secret every hour. After a key changes, restart the gateway
(`kubectl -n agentgov rollout restart deployment/agentgov-gateway`).

## Microsoft 365

To connect AgentGov to Microsoft 365, Entra Agent ID, Purview and Defender, register its app
([Microsoft connections](../microsoft-connections.md#agentgovs-app-registration)) and put the
app's client secret in Key Vault as `agentgov-m365-client-secret`. Sync it into a Secret of its
own, as above, with `secretKey: AGENTGOV_M365_CLIENT_SECRET` and target `agentgov-microsoft`,
and add to your values:

```yaml
controlPlane:
  env:
    AGENTGOV_M365_TENANT_ID: <tenant ID>
    AGENTGOV_M365_CLIENT_ID: <the app's client ID>
  envFrom:
    - secretRef: {name: agentgov-microsoft}
```

## Agents in the cluster

Agents running in this cluster can authenticate with their pods' service account tokens
instead of client secrets ([agents' own identities](../agent-identity.md#kubernetes)). The
issuer is the cluster's OIDC issuer, which Azure publishes on the internet, so Keycloak reads
its keys there:

```bash
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
```

When you rotate the cluster's signing keys (`az aks oidc-issuer rotate-signing-keys`),
Keycloak fetches the new ones.

## Upgrading and removing it

```bash
helm upgrade agentgov deploy/helm/agentgov -n agentgov -f agentgov-values.yaml --wait
```

Note the time before upgrading: the flexible server restores to any point in its backup
retention ([Kubernetes](kubernetes.md#upgrading) has the rest). To remove everything this
guide created, delete the resource group (`az group delete -n $RG`) and the DNS records.

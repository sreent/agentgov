# AgentGov on AWS

This guide installs AgentGov on Amazon Elastic Kubernetes Service (EKS), with AWS's managed
services around it:

| What | On AWS |
|---|---|
| Kubernetes | EKS Auto Mode, which runs the nodes, the load balancers and EKS Pod Identity, and enforces network policies |
| The image | Amazon ECR |
| The database | Amazon RDS for PostgreSQL 17, in the cluster's private subnets |
| Secrets | AWS Secrets Manager, synced into the cluster by the External Secrets Operator |
| HTTPS | One Application Load Balancer for the three addresses, with a certificate from AWS Certificate Manager |
| DNS | Amazon Route 53, or wherever your domain is |
| Sign-in | Keycloak in production mode, in the same RDS instance |

The chart's values and the manifests applied beside it are in
[`deploy/kubernetes/eks`](../../deploy/kubernetes/eks). [Kubernetes](kubernetes.md) explains the
chart, and [requirements](../requirements.md) what AgentGov needs. CI renders these values and
validates the manifests. The AWS commands follow AWS's documentation as of October 2026,
which each step links to, but CI doesn't run them on AWS.

## Before you start

* The AWS CLI v2, eksctl 0.195 or later, kubectl, Helm 3.14 or later, jq, and Docker with
  buildx to build the image, from a clone of this repository.
* An account where you can create EKS clusters, RDS instances, IAM roles, secrets and
  certificates.
* A domain for AgentGov's three addresses, for example `agentgov.example.com` (people, the
  CLI), `gateway.agentgov.example.com` (agents) and `auth.agentgov.example.com` (Keycloak). The
  steps use a Route 53 hosted zone for it; with another DNS provider, create the same records
  there.

Choose the names once and keep them in a file that you `source` in every new shell:

```bash
# agentgov.env
export AWS_REGION=eu-west-1
export ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export DOMAIN=agentgov.example.com           # also gateway.$DOMAIN and auth.$DOMAIN
export ZONE_ID=Z0123456789ABCDEFGHIJ         # the Route 53 hosted zone that holds it
```

Later steps use variables that earlier ones set, such as the database passwords: run them in
one shell, or add those variables to the file too.

## 1. The cluster

EKS Auto Mode runs the nodes and the Application Load Balancer controller, and has EKS Pod
Identity built in ([eksctl and Auto Mode](https://docs.aws.amazon.com/eks/latest/eksctl/auto-mode.html)).
eksctl creates a VPC with public and private subnets; move the cluster to the private ones,
so that Auto Mode launches nodes there:

```bash
eksctl create cluster --name agentgov --region $AWS_REGION --enable-auto-mode
export VPC=$(aws eks describe-cluster --name agentgov --query cluster.resourcesVpcConfig.vpcId --output text)
PRIVATE=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC \
  Name=tag:kubernetes.io/role/internal-elb,Values=1 --query 'Subnets[].SubnetId' --output text)
eksctl utils update-cluster-vpc-config --cluster agentgov --region $AWS_REGION \
  --control-plane-subnet-ids "$(echo $PRIVATE | tr ' ' ',')" --approve
kubectl apply -f deploy/kubernetes/eks/manifests/network-policy.yaml
```

The last command turns on Auto Mode's network policy controller, which enforces the chart's
network policies ([network policies](https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html)).
Auto Mode chooses the instances; AgentGov requests about 1 vCPU and 3.2 GiB with these values.

## 2. The image

Until releases are published at `ghcr.io/sreent/agentgov`, build the image into ECR. Auto
Mode's nodes may pull from the account's repositories:

```bash
aws ecr create-repository --repository-name agentgov --image-tag-mutability IMMUTABLE
aws ecr get-login-password | docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com
docker buildx build --platform linux/amd64 \
  -t $ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/agentgov:0.1.0 --push .
```

## 3. The database

One RDS instance holds two databases, `agentgov` and `keycloak`, each owned by its own user.
It sits in the private subnets and takes connections only from the cluster's security group,
which Auto Mode's nodes use. RDS keeps the administrator's password in Secrets Manager:

```bash
CLUSTER_SG=$(aws eks describe-cluster --name agentgov \
  --query cluster.resourcesVpcConfig.clusterSecurityGroupId --output text)
aws rds create-db-subnet-group --db-subnet-group-name agentgov \
  --db-subnet-group-description AgentGov --subnet-ids $PRIVATE
DB_SG=$(aws ec2 create-security-group --group-name agentgov-db --description "AgentGov database" \
  --vpc-id $VPC --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $DB_SG --protocol tcp --port 5432 \
  --source-group $CLUSTER_SG
aws rds create-db-instance --db-instance-identifier agentgov --engine postgres --engine-version 17 \
  --db-instance-class db.t4g.medium --allocated-storage 20 --storage-type gp3 --storage-encrypted \
  --multi-az --db-subnet-group-name agentgov --vpc-security-group-ids $DB_SG \
  --no-publicly-accessible --master-username postgres --manage-master-user-password \
  --backup-retention-period 14 --deletion-protection
aws rds wait db-instance-available --db-instance-identifier agentgov
export DB_HOST=$(aws rds describe-db-instances --db-instance-identifier agentgov \
  --query 'DBInstances[0].Endpoint.Address' --output text)
```

`--multi-az` keeps a standby in another zone, at twice the cost; leave it out for a staging
installation.

Create the users and the databases from inside the VPC, with a pod in the cluster.
`GRANT … TO postgres` lets the administrator create databases that the users own. This
one-off connection is encrypted without checking the certificate; AgentGov's and Keycloak's
check it against RDS's certificate authorities
([SSL with RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)):

```bash
PG_ADMIN_PASSWORD=$(aws secretsmanager get-secret-value --query SecretString --output text \
  --secret-id "$(aws rds describe-db-instances --db-instance-identifier agentgov \
    --query 'DBInstances[0].MasterUserSecret.SecretArn' --output text)" | jq -r .password)
AGENTGOV_DB_PASSWORD=$(openssl rand -hex 24)
KEYCLOAK_DB_PASSWORD=$(openssl rand -hex 24)
kubectl run psql --rm -it --restart=Never --image=postgres:17-alpine \
  --env PGPASSWORD="$PG_ADMIN_PASSWORD" -- \
  psql "host=$DB_HOST user=postgres dbname=postgres sslmode=require" \
  -c "CREATE ROLE agentgov LOGIN PASSWORD '$AGENTGOV_DB_PASSWORD'" \
  -c "CREATE ROLE keycloak LOGIN PASSWORD '$KEYCLOAK_DB_PASSWORD'" \
  -c "GRANT agentgov, keycloak TO postgres" \
  -c "CREATE DATABASE agentgov OWNER agentgov" \
  -c "CREATE DATABASE keycloak OWNER keycloak"
```

## 4. Secrets

The secrets live in one Secrets Manager secret, `agentgov`: a JSON object whose keys are the
ones the chart reads. The External Secrets Operator copies it into the Kubernetes Secret
`agentgov`.

```bash
new() { openssl rand -hex 32; }
aws secretsmanager create-secret --name agentgov --secret-string "$(jq -n \
  --arg admin_token "$(new)" --arg service_token "$(new)" \
  --arg keycloak_client_secret "$(new)" --arg oidc_client_secret "$(new)" \
  --arg keycloak_admin_password "$(new)" \
  --arg database_url "postgresql+psycopg://agentgov:$AGENTGOV_DB_PASSWORD@$DB_HOST:5432/agentgov?sslmode=verify-full&sslrootcert=/etc/rds/global-bundle.pem" \
  --arg keycloak_database_password "$KEYCLOAK_DB_PASSWORD" \
  '$ARGS.named | with_entries(.key |= gsub("_"; "-"))')"
```

The operator reads it with an IAM role of its own, which EKS Pod Identity gives its service
account ([Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html)):

```bash
aws iam create-role --role-name agentgov-external-secrets --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"},
                 "Action": ["sts:AssumeRole", "sts:TagSession"]}]}'
aws iam put-role-policy --role-name agentgov-external-secrets --policy-name read-agentgov-secrets \
  --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow",
                 "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                 "Resource": "arn:aws:secretsmanager:'$AWS_REGION':'$ACCOUNT':secret:agentgov*"}]}'
aws eks create-pod-identity-association --cluster-name agentgov \
  --namespace external-secrets --service-account external-secrets \
  --role-arn arn:aws:iam::$ACCOUNT:role/agentgov-external-secrets
```

Install the [External Secrets Operator](https://external-secrets.io/latest/provider/aws-secrets-manager/),
then apply the namespace, the store and the `agentgov` Secret's definition, with your names put
in by `names`. RDS's certificate authorities go in a ConfigMap beside it, which the values
mount for the control plane and Keycloak:

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace --wait

names() {
  sed -e "s|<account>|$ACCOUNT|g; s|<region>|$AWS_REGION|g; s|<postgres-host>|$DB_HOST|g" \
      -e "s|<certificate-arn>|$CERT_ARN|g; s|agentgov\.example\.com|$DOMAIN|g" "$@"
}
names deploy/kubernetes/eks/manifests/secrets.yaml | kubectl apply -f -
curl -fsSO https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
kubectl -n agentgov create configmap rds-ca --from-file=global-bundle.pem
kubectl -n agentgov get externalsecret agentgov      # STATUS: SecretSynced
```

## 5. HTTPS

Request a certificate for the three names from AWS Certificate Manager, and prove you control
the domain with the DNS record it asks for
([DNS validation](https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html)). A few
seconds after the request, the record is there to read:

```bash
export CERT_ARN=$(aws acm request-certificate --domain-name $DOMAIN \
  --subject-alternative-names "*.$DOMAIN" --validation-method DNS \
  --query CertificateArn --output text)
read -r NAME VALUE < <(aws acm describe-certificate --certificate-arn $CERT_ARN \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord.[Name,Value]' --output text)
aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID --change-batch "$(jq -n \
  --arg name "$NAME" --arg value "$VALUE" '{Changes: [{Action: "UPSERT", ResourceRecordSet:
    {Name: $name, Type: "CNAME", TTL: 300, ResourceRecords: [{Value: $value}]}}]}')"
aws acm wait certificate-validated --certificate-arn $CERT_ARN
names deploy/kubernetes/eks/manifests/ingress-class.yaml | kubectl apply -f -
```

The ingress class ([`ingress-class.yaml`](../../deploy/kubernetes/eks/manifests/ingress-class.yaml))
gives the chart's three Ingresses one internet-facing Application Load Balancer, with the
certificate, TLS 1.2 or later, and an idle timeout of ten minutes for agents' quiet streams
([Auto Mode's load balancers](https://docs.aws.amazon.com/eks/latest/userguide/auto-configure-alb.html)).
The values add the HTTPS listener, the redirect from HTTP and each part's health check.

## 6. Install AgentGov

Make your copy of the values, with your names, and keep it (in your own repository) for
upgrades:

```bash
names deploy/kubernetes/eks/values.yaml > agentgov-values.yaml
helm install agentgov deploy/helm/agentgov -n agentgov -f agentgov-values.yaml --wait --timeout 15m
```

The values ([`values.yaml`](../../deploy/kubernetes/eks/values.yaml)) turn off the bundled
PostgreSQL, run the bundled Keycloak in production mode on RDS, without the demo users, add
the ingresses, turn on the network policies and run two of each part on the decision path. On
its first start, Keycloak builds itself for production and imports AgentGov's realm, which
takes a few minutes. Once it has, you can run two (`keycloak.replicas: 2`).

## 7. DNS

Point the three names at the load balancer, with alias records:

```bash
ALB=$(kubectl -n agentgov get ingress agentgov-control-plane \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
ALB_ZONE=$(aws elbv2 describe-load-balancers \
  --query "LoadBalancers[?DNSName=='$ALB'].CanonicalHostedZoneId" --output text)
for host in $DOMAIN gateway.$DOMAIN auth.$DOMAIN; do
  aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID --change-batch "$(jq -n \
    --arg name "$host" --arg alb "$ALB" --arg zone "$ALB_ZONE" '{Changes: [{Action: "UPSERT",
      ResourceRecordSet: {Name: $name, Type: "A",
        AliasTarget: {HostedZoneId: $zone, DNSName: $alb, EvaluateTargetHealth: false}}}]}')"
done
```

## 8. Check it, and sign in

```bash
curl -fsS https://$DOMAIN/readyz
curl -fsS https://gateway.$DOMAIN/healthz
curl -fsS https://auth.$DOMAIN/realms/agentgov/.well-known/openid-configuration >/dev/null && echo keycloak ok

export AGENTGOV_URL=https://$DOMAIN
export AGENTGOV_TOKEN=$(aws secretsmanager get-secret-value --secret-id agentgov \
  --query SecretString --output text | jq -r '."admin-token"')
agentgov whoami
```

The bootstrap token is for the first steps and for break-glass access. Then:

* Sign in to Keycloak's admin console at `https://auth.agentgov.example.com/admin` as `admin`,
  with the `keycloak-admin-password` in the secret. That account is temporary: create your
  own administrator and delete it.
* Let people sign in with single sign-on: add your identity provider (IAM Identity Center,
  or any OpenID Connect or SAML provider) to the `agentgov` realm, and give people AgentGov's
  [roles](../administration.md#roles). Automation uses API keys.
* Work through the [checklist](README.md#before-others-rely-on-it).

## Model keys and destinations

Model providers' API keys and destinations' credentials go in Secrets Manager too, as JSON
objects in the secrets `agentgov-model-keys`, with a key per provider name
([model calls](../models.md)), and `agentgov-destinations`, with a key per destination name
([security operations](../secops.md)). The operator's role may read both. For an OpenAI
provider named `openai`:

```bash
aws secretsmanager create-secret --name agentgov-model-keys \
  --secret-string "$(jq -n --arg key "$OPENAI_API_KEY" '{openai: $key}')"
kubectl apply -f - <<'EOF'
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: agentgov-model-keys, namespace: agentgov}
spec:
  refreshInterval: 1h
  secretStoreRef: {kind: SecretStore, name: aws-secrets-manager}
  target: {name: agentgov-model-keys}
  dataFrom:
    - extract: {key: agentgov-model-keys}
EOF
```

The operator refreshes the Secret every hour. After a key changes, restart the gateway
(`kubectl -n agentgov rollout restart deployment/agentgov-gateway`).

## Agents in the cluster

Agents running in this cluster can authenticate with their pods' service account tokens
instead of client secrets ([agents' own identities](../agent-identity.md#kubernetes)). The
issuer is the cluster's OIDC issuer, `https://oidc.eks.<region>.amazonaws.com/id/<ID>`, whose
keys AWS publishes on the internet, so Keycloak reads them there
([the issuer's keys](https://docs.aws.amazon.com/eks/latest/userguide/irsa-fetch-keys.html)):

```bash
kubectl get --raw /.well-known/openid-configuration | jq -r .issuer
```

## Agents built on AWS

AgentGov can read the Amazon Bedrock agents and AgentCore agents in your accounts into its
inventory ([other platforms](../other-platforms.md#aws)). Give its service account a role
that may read them, with Pod Identity, where `read-agents.json` holds the policy from that
page, then name the regions to read:

```bash
aws iam create-role --role-name agentgov-agent-reader --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"},
                 "Action": ["sts:AssumeRole", "sts:TagSession"]}]}'
aws iam put-role-policy --role-name agentgov-agent-reader --policy-name read-agents \
  --policy-document file://read-agents.json
aws eks create-pod-identity-association --cluster-name agentgov \
  --namespace agentgov --service-account agentgov \
  --role-arn arn:aws:iam::$ACCOUNT:role/agentgov-agent-reader
helm upgrade agentgov deploy/helm/agentgov -n agentgov --reuse-values \
  --set controlPlane.env.AGENTGOV_AWS_REGIONS=$AWS_REGION
```

AgentGov's pods share that service account, so each of them may read the agents; only the
control plane does.

## Upgrading and removing it

```bash
helm upgrade agentgov deploy/helm/agentgov -n agentgov -f agentgov-values.yaml --wait
```

Note the time before upgrading: RDS restores to any point in the last 14 days
([Kubernetes](kubernetes.md#upgrading) has the rest). To remove it, uninstall the release so
that Auto Mode deletes the load balancer, then delete the cluster (`eksctl delete cluster
--name agentgov`), the RDS instance (after turning off its deletion protection), its subnet
group and security group, the secrets, the certificate, the IAM role, the ECR repository and
the DNS records.

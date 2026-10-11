# Agents' own identities

An agent that runs where it already has an identity can authenticate with it instead of
a client secret: a pod with its Kubernetes service account, a workload with its SPIFFE
ID, an agent with its Microsoft Entra Agent ID, or a workload whose cloud or CI gives it
an OpenID Connect token (Okta, AWS, Google Cloud, GitHub Actions). There's no secret to
store, leak or rotate, and blocking where the identities come from stops all of their
agents at once.

An administrator approves an **identity issuer**, and each agent names its **subject**
there. AgentGov makes the issuer an identity provider in Keycloak, and the agent's client
one that authenticates with that issuer's token for that subject: Keycloak's
[federated client authentication](https://www.keycloak.org/2026/01/federated-client-authentication).
The agent still gets an AgentGov access token for the gateway, so everything else is as
before: its grants, the controls, approvals, the ledger and the kill switch.

```mermaid
sequenceDiagram
    autonumber
    participant Ad as Administrator
    participant CP as AgentGov
    participant K as Keycloak
    participant P as Platform (Kubernetes, SPIRE, Entra ID)
    participant Ag as Agent
    participant G as agentgateway
    Ad->>CP: approve an issuer; give an agent its subject there
    CP->>K: an identity provider for the issuer; the agent's client takes its tokens
    P-->>Ag: a short-lived token for the workload (subject, audience Keycloak's realm)
    Ag->>K: client credentials, with the token as client assertion
    K->>K: signature (the issuer's keys), issuer, subject, audience, expiry
    K-->>Ag: an AgentGov access token
    Ag->>G: tool and model calls, governed as always
```

## Issuers

| Kind | Its tokens | `issuer` | `keys_url` | An agent's subject |
|---|---|---|---|---|
| `kubernetes` | Service account tokens | The `iss` of the cluster's tokens: the cloud's OpenID Connect issuer on GKE, AKS and EKS, such as `https://oidc.eks.<region>.amazonaws.com/id/<ID>`; `https://kubernetes.default.svc.cluster.local` on a cluster that keeps the default, such as kind or kubeadm ([below](#kubernetes)) | Its OpenID Connect discovery URL, when Keycloak can't read it at the issuer | `system:serviceaccount:<namespace>:<name>` |
| `spiffe` | JWT-SVIDs, from SPIRE or another SPIFFE implementation | The trust domain, `spiffe://example.org` | Its SPIFFE bundle endpoint (required) | A SPIFFE ID in the trust domain, `spiffe://example.org/ns/agents/sa/support-bot` |
| `oidc` | Any OpenID Connect issuer's JWTs: Microsoft Entra ID, Okta, AWS, Google Cloud, GitHub Actions | The issuer as its tokens name it | Its JWKS URL; found from its discovery document otherwise | The tokens' `sub` |

An `oidc` issuer also takes:

* `audience`: what its tokens carry when it can't be Keycloak's realm URL, such as the
  application ID of AgentGov's API registration in Microsoft Entra ID
  ([below](#microsoft-entra-agent-id)). Keycloak then takes that audience instead.
* `allow_reuse`: Keycloak takes each token once unless this is on, so a stolen token is
  worth less. Tokens without a `jti` claim, such as Entra ID's, need it on.

Each issuer is one identity provider in Keycloak, named `agentgov-<name>`, used only to
check agents' tokens: no one signs in with it. Two issuers can't have the same `issuer`.

| | How |
|---|---|
| Admin UI | **Access** → *Agent identity issuers*: **Add issuer**, **Edit**, **Block**, **Delete**; the card shows each issuer's agents and whether Keycloak has it |
| CLI | `agentgov issuers create prod-cluster --kind kubernetes --issuer https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE`; `list`, `get`, `update`, `block`, `unblock`, `delete` |
| API | `GET` and `POST /v1/identity-issuers`; `GET`, `PATCH` and `DELETE /v1/identity-issuers/{name}`; `POST /v1/identity-issuers/{name}/block` and `/unblock` |
| Manifests | `kind: IdentityIssuer` ([example](../examples/manifests/identity.yaml)) |

**Blocking** an issuer disables its identity provider: within seconds, Keycloak takes none
of its tokens, so none of its agents get a new access token, and the ones they have
expire within five minutes. Block an agent itself to stop it at once
([kill switch](administration.md)). An issuer that agents use can't be deleted.

## Giving an agent its identity

| | How |
|---|---|
| Admin UI | The agent's **Edit**: *Authentication*, an issuer and the agent's subject there |
| CLI | `agentgov agents update support-bot --workload-identity prod-cluster:system:serviceaccount:agents:support-bot` (the issuer, then the subject); `--no-workload-identity` goes back to a client secret |
| API | `workload_identity: {"issuer": "prod-cluster", "subject": "system:serviceaccount:agents:support-bot"}` in `POST /v1/agents` and `PATCH /v1/agents/{name}`; `null` goes back to a client secret |
| Manifests | `workload_identity` in an `Agent`'s spec |

One subject at an issuer is one agent. Once an agent has its identity, Keycloak replaces
its client secret, so the secret it had stops working; `agentgov agents credentials
support-bot` then shows what token authenticates it instead, with no secret to rotate:

```json
{
  "client_id": "agent-support-bot",
  "method": "workload-identity",
  "issuer": "prod-cluster",
  "subject": "system:serviceaccount:agents:support-bot",
  "token_endpoint": "https://keycloak.example.com/realms/agentgov/protocol/openid-connect/token",
  "assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "assertion_audience": "https://keycloak.example.com/realms/agentgov",
  "audience": "agentgov-gateway"
}
```

The agent asks for its access token as with a secret, sending its workload's token as the
client assertion ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)):

```python
import httpx

token = httpx.post(
    token_endpoint,
    data={
        "grant_type": "client_credentials",
        "client_id": "agent-support-bot",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": open("/var/run/secrets/tokens/agentgov").read(),
    },
).json()["access_token"]
```

**Requiring it.** A blueprint with `require_workload_identity` (admin UI: *Require a
workload identity*; CLI: `--require-workload-identity`) has agents that can't be
activated without a workload identity, nor have it taken away while active. Active agents
that predate the requirement show up as findings (*authenticates with a client secret*)
until they get one.

## Kubernetes

Give the agent's pod a service account token for Keycloak's realm with a projected
volume. The kubelet renews it before it expires; read the file each time.

```yaml
spec:
  serviceAccountName: support-bot
  containers:
    - name: agent
      volumeMounts:
        - {name: agentgov-token, mountPath: /var/run/secrets/tokens, readOnly: true}
  volumes:
    - name: agentgov-token
      projected:
        sources:
          - serviceAccountToken:
              path: agentgov
              audience: https://keycloak.example.com/realms/agentgov  # the realm's URL
              expirationSeconds: 3600  # Keycloak takes tokens valid for an hour at most
```

The issuer is the `iss` in the cluster's service account tokens
(`kubectl get --raw /.well-known/openid-configuration | jq -r .issuer`, or decode a pod's
token):

* On **GKE, AKS and EKS**, it is the cluster's OpenID Connect issuer, also for agents in the
  cluster Keycloak runs in: `https://container.googleapis.com/v1/projects/<project>/locations/<location>/clusters/<cluster>`,
  `https://<region>.oic.prod-aks.azure.com/<tenant ID>/<GUID>/` or
  `https://oidc.eks.<region>.amazonaws.com/id/<ID>`. The cloud publishes the keys on the
  internet, so Keycloak reads them there, wherever it runs, without a service account token.
  The [cloud guides](deploy/README.md) show it for each cluster.
* On a cluster that keeps the default issuer, `https://kubernetes.default.svc.cluster.local`
  (kind, kubeadm), Keycloak reads the keys from that cluster's API server with its own
  service account token: it must run in that cluster, with
  `keycloak.mountServiceAccountToken=true` in the Helm chart, and only one such cluster can
  be an issuer, because two issuers can't share an `issuer`
  ([Kubernetes](deploy/kubernetes.md#agents-in-the-cluster)).

## SPIFFE

The agent fetches a JWT-SVID with the realm's URL as its audience from the SPIFFE
Workload API (with SPIRE, `spire-agent api fetch jwt -audience
https://keycloak.example.com/realms/agentgov`, or a SPIFFE library), and sends it with the
SPIFFE assertion type, `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`, which
`agentgov agents credentials` gives. The issuer's `keys_url` is the trust domain's bundle
endpoint, served over HTTPS that Keycloak trusts (SPIRE's `https_web` profile).

SPIFFE issuers need Keycloak's `spiffe` preview feature. The Compose stack and the Helm
chart turn it on (`KC_FEATURES=spiffe`; in Helm, `keycloak.features`); turn it on for
your own Keycloak too.

## Microsoft Entra Agent ID

Agents built on Microsoft's agent platform have an agent identity in Microsoft Entra
Agent ID, and get app-only tokens from Entra ID for the APIs they call:

1. Register AgentGov as an API in Entra ID: an app registration with an application ID
   URI, such as `api://agentgov`. Let it accept v2 tokens (`"requestedAccessTokenVersion":
   2` in its manifest).
2. Add an `oidc` issuer: `issuer` `https://login.microsoftonline.com/<tenant ID>/v2.0`,
   `audience` the API registration's application (client) ID, which v2 tokens carry in
   `aud`, and `allow_reuse` on (Entra ID's tokens carry no `jti`, and its libraries reuse a
   token until it expires). With v1 tokens, the issuer is
   `https://sts.windows.net/<tenant ID>/`, the `audience` `api://agentgov` and `keys_url`
   `https://login.microsoftonline.com/<tenant ID>/discovery/keys`.
3. Give the agent its identity: the subject is its agent identity in Entra ID, which app-only
   tokens name in `sub`. For an agent linked to its Entra Agent ID
   ([platforms](platforms.md)), the agent's form fills in its object ID when you choose an
   Entra issuer; decode one of its tokens to check.
4. The agent asks Entra ID for a token for `api://agentgov/.default` and sends it as its
   client assertion.

## Other issuers

| Where the agent runs | Its token | The issuer |
|---|---|---|
| GitHub Actions | `core.getIDToken('<realm URL>')`, or the `ACTIONS_ID_TOKEN_REQUEST_URL` endpoint with `audience=<realm URL>` | `oidc`, `https://token.actions.githubusercontent.com`; subject such as `repo:acme/agents:ref:refs/heads/main` |
| Google Cloud | The metadata server's identity token, `audience=<realm URL>` | `oidc`, `https://accounts.google.com`; subject the service account's unique ID |
| Amazon EKS | A projected service account token, as above | `kubernetes`, the cluster's OpenID Connect issuer URL |
| AWS, elsewhere | `sts:GetWebIdentityToken` ([outbound identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html)), audience the realm URL | `oidc`, the account's issuer URL |
| Okta | A token from an authorization server for the agent's service app | `oidc`, the authorization server's issuer; `audience` the server's audience |

Most of these tokens carry a `jti`, and agents can fetch a fresh one for each sign-in, so
`allow_reuse` can stay off; turn it on when an agent presents the same token more than
once, or its tokens lack a `jti`.

## In policy

The agents in OPA's data say how each authenticates:

```json
"workload_identity": {"issuer": "prod-cluster", "subject": "system:serviceaccount:agents:support-bot"}
```

`null` for an agent that uses a client secret. An organisation policy can, for example,
keep production tools for agents with their own identity:

```rego
package agentgov.custom.prod_needs_identity

import data.agentgov.context as ctx

deny contains "Production agents must authenticate with a workload identity" if {
	ctx.agent.environment == "prod"
	ctx.agent.workload_identity == null
}
```

## The feature switch

`workload-identity` ([features](features.md)) is on by default. Off, every issuer's
identity provider is disabled, so agents with a workload identity can't authenticate
until it is on again; agents with a client secret aren't affected.

## Setting it up

* Keycloak 26.6 or later. The control plane's service account needs `realm-management`'s
  `manage-identity-providers` and `view-identity-providers`: AgentGov's realm file gives
  them, and an issuer says so when Keycloak refuses it. A realm imported before this
  version needs them added by hand ([Compose](deploy/local.md#upgrading),
  [Kubernetes](deploy/kubernetes.md#upgrading)).
* SPIFFE issuers need Keycloak's `spiffe` preview feature.
* An issuer that can't be put in Keycloak shows why on the Access page, and as a finding.
  A blocked issuer that Keycloak hasn't been told about is a high-severity finding: until
  then, its agents can still authenticate.

## Trying it

The Compose stack, and CI's runs of the Helm chart (`scripts/ci.sh --e2e` and `--kind`),
include a stand-in Kubernetes cluster
([`examples/identity/workload-issuer`](../examples/identity/workload-issuer/server.py))
whose service account tokens agents authenticate with, and its issuer, `demo-cluster`, in
the example manifests. In step 13 of the demo, `python examples/agents/demo_agent.py`
registers an agent with no secret, gets its access token with a service account token, calls
a tool, and blocks and unblocks the issuer.

## Limits

* Keycloak checks the tokens, and AgentGov sets it up: Keycloak's checks are what apply
  (signature, issuer, subject, audience, at most an hour of validity).
* Tokens from Keycloak's identity providers for an issuer are for client authentication
  only; people don't sign in with them.
* SPIFFE support in Keycloak is a preview.
* AgentGov checks the subject's form for SPIFFE IDs only; for other issuers, check it
  against a real token.

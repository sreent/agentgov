# AgentGov on one server

For an organisation without Kubernetes, or that doesn't want it for this: AgentGov on one
Linux server, with Docker Compose, HTTPS in front from [Caddy](https://caddyserver.com),
secrets of your own and none of the demo's parts. Two sizes:

| | What runs | Addresses | Memory |
|---|---|---|---|
| [The inventory](#the-inventory) | The control plane and PostgreSQL | One: the control plane | About 250 MB |
| [All of it](#all-of-it) | Also the gateway, the governance processor, OPA, Presidio, Keycloak, the OpenTelemetry Collector and the transparency log | Three: the control plane, the gateway and Keycloak | About 2.5 GB |

Starting with the inventory and adding the gateway later keeps the registry, its findings
and the ledger: it is the same control plane and database.

One server is one place to fail. While it is down, nobody can approve anything, and agents'
calls through its gateway stop. For several control-plane replicas, a managed database and
network policies, use [Kubernetes](kubernetes.md).

## What you need

* A Linux server with Docker Engine and Docker Compose 2.24.4 or later
  (`docker compose version`), and a clone of this repository on it.
* A DNS name for each address, pointing at the server: say `agentgov.example.com`, and for
  all of it `gateway.example.com` and `auth.example.com` too. The addresses are `https://`
  and these names, without a port: Caddy answers on 443.
* Ports 80 and 443 open to the people and agents who use it.
* Certificates for the names: Caddy gets them from Let's Encrypt, from an ACME server of
  yours or from an authority of its own, or uses yours ([certificates](#certificates)).

## The inventory

In `deploy/compose`, write `.env` and start the stack:

```bash
cd deploy/compose
cat > .env <<EOF
AGENTGOV_ADMIN_TOKEN=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 32)
AGENTGOV_PUBLIC_URL=https://agentgov.example.com
AGENTGOV_CERTIFICATES=letsencrypt
COMPOSE_PROFILES=https
EOF
docker compose -f docker-compose.inventory.yml up -d --build --wait
```

Open <https://agentgov.example.com/ui> and sign in with the admin token
(`grep ADMIN_TOKEN .env`). To sign administrators in with your identity provider, set
`AGENTGOV_OIDC_*` in `.env` ([configuration](../configuration.md#administrator-single-sign-on-oidc);
for Microsoft Entra ID, [setting it up](../platforms.md#setting-it-up)) and start the stack
again. [Just the inventory](local.md#just-the-inventory) says what it does from there.

## All of it

In `deploy/compose`, write `.env` with a random value for each secret, the three addresses,
and the files and profile Compose uses, then start the stack:

```bash
cd deploy/compose
{
  for name in AGENTGOV_ADMIN_TOKEN AGENTGOV_SERVICE_TOKEN AGENTGOV_SIGNING_SECRET \
      AGENTGOV_KEYCLOAK_CLIENT_SECRET AGENTGOV_OIDC_CLIENT_SECRET KEYCLOAK_ADMIN_PASSWORD \
      POSTGRES_PASSWORD; do
    echo "$name=$(openssl rand -hex 32)"
  done
  cat <<'EOF'
AGENTGOV_PUBLIC_URL=https://agentgov.example.com
AGENTGOV_GATEWAY_PUBLIC_URL=https://gateway.example.com
AGENTGOV_KEYCLOAK_PUBLIC_URL=https://auth.example.com
AGENTGOV_CERTIFICATES=letsencrypt
COMPOSE_FILE=docker-compose.yml:docker-compose.server.yml
COMPOSE_PROFILES=https
EOF
} > .env
docker compose up -d --build --wait
```

The first start takes a few minutes: Keycloak builds itself for production and imports
AgentGov's realm. `docker-compose.server.yml` changes the evaluation stack
([Docker Compose](local.md#docker-compose)) this way:

| | The evaluation stack | With `docker-compose.server.yml` |
|---|---|---|
| Secrets | Defaults everybody knows | Yours, from `.env`: it doesn't start without them |
| Keycloak | Development mode; the realm with the demo's people and app | Production mode, behind Caddy; the realm at your addresses, without them (`agentgov keycloak-realm`) |
| The demo's tool server, model, agents and stand-ins | Running | Not running |
| The ledger checkpoints' time-stamps | From the demo's stand-in | From an authority you name in `AGENTGOV_LEDGER_TSA_URL`, such as `https://freetsa.org/tsr`, or none ([evidence](../evidence.md)) |
| After a reboot | Stopped | Started again |
| HTTPS | None | Caddy, with `COMPOSE_PROFILES=https` |

Every other setting goes in `.env` or `docker-compose.override.yml` as for the evaluation
stack ([settings and secrets](local.md#settings-and-secrets)). The services' own ports
(8000, 8080, 8180, 8181, 4317 and 4318) still listen on this machine only: leave them so,
and let Caddy take people's and agents' connections. Agents elsewhere that send traces to
the collector need its port 4318: open that one to them, in `docker-compose.override.yml`
(`ports: !override ["4318:4318"]` under `otel-collector`) and the server's firewall.

### Signing in

The realm has no people in it. Connect your directory to Keycloak as an identity provider
(OIDC or SAML) or through user federation (LDAP, Active Directory), and give its groups the
`agentgov-*` realm roles ([signing in](local.md#signing-in)); until then, sign in to the
admin UI with the admin token. Keycloak's admin console is at
`https://auth.example.com/admin`, as `admin` with `KEYCLOAK_ADMIN_PASSWORD`: a temporary
administrator, so make one of your own there and delete it. Caddy lets only private
addresses reach the console: name others in `AGENTGOV_KEYCLOAK_CONSOLE_FROM`, such as
`203.0.113.0/24`. It is a second lock, not the first: the console still asks for a
password.

Administrators can sign in with another identity provider instead
([configuration](../configuration.md#administrator-single-sign-on-oidc)). Name the apps
your people use agents from in `AGENTGOV_PEOPLE_APP_CLIENTS`
([acting for people](../acting-for-people.md)). Agents get their tokens at
`https://auth.example.com/realms/agentgov/protocol/openid-connect/token` and call tools
at `https://gateway.example.com/mcp/<server>` ([agents' credentials](../agent-identity.md)).

## Certificates

`AGENTGOV_CERTIFICATES` in `.env` says where Caddy gets the certificates. It renews them
itself, and keeps them on the `caddy-data` volume.

| `AGENTGOV_CERTIFICATES` | From | For |
|---|---|---|
| `letsencrypt` (the default) | Let's Encrypt | Names in public DNS, when Let's Encrypt reaches the server on ports 80 and 443 |
| `acme` | An ACME server of yours, such as step-ca or your PKI's, at `AGENTGOV_ACME_CA` (its directory URL) | Inside your network, from your own authority |
| `files` | `tls.crt` (with its chain) and `tls.key` in `deploy/compose/https`, or `AGENTGOV_HTTPS_DIR`: one certificate for every name | Certificates your PKI issues by hand |
| `internal` | An authority of Caddy's own | Trying it out: people's browsers and agents must trust its root |

With `files`, put new ones in place before they expire, then run
`docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile`
(`inventory.Caddyfile` for the inventory). With `internal`, copy the root out
(`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .`) for people's
machines and agents to trust: Python reads it from `SSL_CERT_FILE`.

With a load balancer or reverse proxy of your own that ends TLS, leave
`COMPOSE_PROFILES=https` out and point it at ports 8000 (the control plane), 8080 (the
gateway) and 8180 (Keycloak): on this machine, or from its network, with
`AGENTGOV_LISTEN_ADDRESS` set to the server's private address. It must set
`X-Forwarded-For` and `X-Forwarded-Proto`, which Keycloak reads.

## The published image

Each release publishes the image at `ghcr.io/sreent/agentgov`, signed by the repository's
release workflow ([Kubernetes](kubernetes.md#the-image)). To run it instead of building the
clone, check its signature, then name it in `.env`:

```bash
cosign verify ghcr.io/sreent/agentgov:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/sreent/ai-agent-governance-platform/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
echo "AGENTGOV_IMAGE=ghcr.io/sreent/agentgov:0.1.0" >> .env
docker compose pull && docker compose up -d --wait
```

Without `--build`: with it, Compose builds the clone and gives it that name. Until the first
release, build the clone, as above.

## Running it

* **Backups**: PostgreSQL every night, away from the server
  ([backing up](../backup.md#with-compose)). With `internal` certificates, back up the
  `caddy-data` volume too: it holds the authority people's machines trust.
* **Upgrades**: back up, then `git pull` and `docker compose up -d --build --wait`, or a new
  `AGENTGOV_IMAGE`, `pull` and `up`. The control plane migrates its database as it starts
  ([upgrading](local.md#upgrading)).
* **A restored database** shows: the ledger's head is kept on the `ledger-witness` volume
  ([a rewound ledger](../backup.md#a-rewound-ledger)).
* **Health and logs**: `docker compose ps` and `docker compose logs <service>`; the rest of
  [running it](README.md#running-it) holds here too.
* **Secrets everybody knows**: the control plane doesn't start when people reach it
  anywhere but on this machine (`AGENTGOV_PUBLIC_URL`) and it holds a secret from
  `.env.example` or the evaluation stack's defaults.

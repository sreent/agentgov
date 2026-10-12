# Developer tools

Developers give their coding assistants MCP servers too: GitHub Copilot in VS Code and
other editors, Claude, Cursor, Codex. AgentGov keeps one list of approved MCP servers for
agents and for developers, and serves the developers' part in the format their MCP
clients read: an **MCP registry**. GitHub Copilot can then offer developers only those
servers. Developers' MCP clients can reach the servers on the gateway with the developer's
own token, which they sign in for as the MCP specification has them do, so the gateway's
controls check their calls too. AgentGov also finds out which MCP servers developers have
actually set up, and raises a finding for each one that isn't approved.

## Listing servers for developers

A tool server can be used by agents, by developers, or both:

| Field | Meaning |
|---|---|
| `gateway` | Published on the gateway at `/mcp/<name>`, for agents (the default) |
| `developers` | Listed in the MCP registry for developers' MCP clients |
| `packages` | For a server developers run on their machines: the package, such as `npm` `@playwright/mcp` `0.0.41` (`registry_type` is one of `npm`, `pypi`, `oci`, `nuget`, `cargo` and `mcpb`) |
| `registry_name` | Its name in the registry. By default `<namespace>/<name>`, where the namespace is `AGENTGOV_MCP_REGISTRY_NAMESPACE`, or the control plane's host name reversed (`com.contoso.agentgov`), or `local.agentgov` for a host name without a dot, such as `localhost` |

A server listed for developers and published on the gateway is listed with the
gateway's address. A server only for developers (`gateway: false`) is listed with its
own address, such as a SaaS vendor's MCP server, or with its packages. AgentGov doesn't
route those: developers reach them directly.

| | How |
|---|---|
| Admin UI | **Tool servers** → **Register tool server** or **Edit**, *Who uses it* |
| CLI | `agentgov toolservers create playwright --no-gateway --developers --package npm:@playwright/mcp@0.0.41`; `agentgov toolservers update crm --developers` |
| API | `gateway`, `developers`, `packages`, `registry_name` in `POST /v1/toolservers` and `PATCH /v1/toolservers/{name}` |
| Manifests | The same fields in a `ToolServer`'s spec ([example](../examples/manifests/toolservers.yaml)) |

Developers can ask for a server with a `registrar` API key, as for any tool server: it
waits for an administrator's approval before it is listed.

## The MCP registry for GitHub Copilot

With the `mcp-registry` [feature](features.md) on, the control plane serves the
registry at `<control plane>/registry`: the MCP Registry API, version 0.1
(`GET /registry/v0.1/servers`, and each server's `/versions`). Copilot reads it without
credentials, so it is served without them, and the feature is off until you turn it on.
It lists approved servers only; a blocked server is listed as deleted to clients that
ask for those.

To have Copilot use it, as an enterprise owner on GitHub:

1. Go to **AI controls** → **MCP**, and set **MCP servers in Copilot** to *Enabled
   everywhere*.
2. Under **MCP Registry URL**, enter `<control plane>/registry`, without `/v0.1/servers`
   (Copilot adds it), and save.
3. Under **Restrict MCP access to registry servers**, choose **Registry only**.

An organisation owner can do the same in the organisation's **Copilot** → **Policies**.
Copilot in VS Code, Visual Studio, JetBrains IDEs, Eclipse and Xcode, and the Copilot
CLI, then offer developers the registry's servers and run only those
([GitHub's documentation](https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-mcp-server-access)).
The Developer tools page shows the address to enter, and what the registry lists.

When a listed server's address, description or packages change, its version in the
registry goes up, so developers' clients pick the change up.

### The managed-settings allowlist

Copilot matches the registry's servers by name, which developers can change in their
configuration files. GitHub's enterprise managed settings (`managed-settings.json`)
match servers by URL and by command instead. **Developer tools** → *managed-settings.json*,
`agentgov mcp managed-settings -o managed-settings.json` or
`GET /v1/mcp/managed-settings` write the registry's servers as that file's
`allowedMcpServers`: each server's address, and each package's command
(`npx @playwright/mcp@0.0.41`, `uvx <package>==<version>`,
`docker run -i --rm <image>:<version>`). Where developers start a package differently,
give the package its own `command` (in the API or a manifest; the CLI's `--package` doesn't
set it). Store the file in your enterprise's
`.github-private` repository, or deploy it to developers' machines with your device
management ([GitHub's documentation](https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-enterprise-allowlist)).

## Signing in at the gateway

An MCP client calls a server on the gateway, `<gateway>/mcp/<server>`, with a token
for the gateway, as agents do. Developers' MCP clients get one by signing the developer
in, as the MCP specification's authorization has them do: the gateway answers a call
without a token with where to sign in, and the client signs the developer in to Keycloak
in their browser (OAuth 2.1, with PKCE). The gateway then takes the developer's token, and
the processor checks each call with the controls agents' calls get, with the developer
as the person the agent acts for.

1. **Register an agent for developers' MCP clients**, whose tokens are for the people who
   sign in to it: a *public client* (`client_type: public`). Give it a blueprint whose
   agents act for people (`acts_for: people`), such as developers (`people_groups:
   [developers]`), and that grants the tools they may call. One agent can stand for every
   MCP client, or one for each (VS Code, Claude Code, Cursor), to tell them apart in the
   ledger and grant them differently.
2. **Turn on the `developer-sign-in` [feature](features.md).** Each tool server's route on
   the gateway then serves its OAuth protected resource metadata (RFC 9728) at
   `<gateway>/.well-known/oauth-protected-resource/mcp/<server>`, which names Keycloak,
   and answers a call without a token `401` with a pointer to it.
3. **Developers add the server's address on the gateway** to their MCP client, as the MCP
   registry lists it. On their first call, the client finds where to sign in and opens
   their browser. Keycloak doesn't let MCP clients register themselves, so when the client
   asks for a client ID, developers give the agent's (`agent-<name>`: the Developer tools
   page lists it). The sign-in returns to the client on their machine.

| Field | Meaning |
|---|---|
| `client_type` | `service` (the default): the agent gets tokens for itself, with a client secret or its workload identity, and exchanges people's tokens to act for them; `public`: people sign in to it, and it acts for them with their own token. It has no secret, no workload identity and no service account |
| `redirect_uris` | Where a sign-in to a public client may return, with `*` only at the end. By default the developer's machine at any port, `http://127.0.0.1/*` and `http://localhost/*`, where MCP clients such as VS Code and Claude Code listen for it. Add the others your MCP clients use, such as `https://vscode.dev/redirect` for VS Code for the Web. Plain `http` only to the machine itself |

| | How |
|---|---|
| Admin UI | **Agents** → **Register agent** or **Edit**, *Authentication*: its tokens are for people who sign in to it; the agent's **How people sign in**. **Developer tools** lists the agents developers sign in to |
| CLI | `agentgov agents create coding-assistant --blueprint coding-assistants --sponsor alice@example.com --client-type public`; `--redirect-uri` (repeatable), and `--default-redirect-uris` on `agents update`; `agentgov agents credentials coding-assistant` says where people sign in |
| API | `client_type` and `redirect_uris` in `POST /v1/agents` and `PATCH /v1/agents/{id}`; `POST /v1/agents/{id}/credentials` says where people sign in, without a secret |
| Manifests | The same fields in an `Agent`'s spec ([example](../examples/manifests/agents.yaml)) |

AgentGov makes the agent's Keycloak client a public one: the authorization code flow with
PKCE (`S256`), its redirect URIs, and none of the client credentials grant, the password
grant or token exchange. Its tokens carry the agent's claims, as other agents' do, and
say that the person signed in to it (`agentgov_sign_in`). The ledger records the call
for the agent and the developer, and how the agent came to act for them: `via: sign-in`
([acting for people](acting-for-people.md#telling-the-agent-from-the-person)).

The route checks the token as it checks agents' (the issuer, the gateway's audience, the
signature), with agentgateway's MCP authentication instead of its plain JWT
authentication. With the feature off, the gateway takes the same tokens, but doesn't
tell MCP clients where to sign in.

Things to know:

* Keycloak must be reachable from developers' machines at `AGENTGOV_KEYCLOAK_ISSUER`, the
  issuer the gateway checks tokens against.
* The metadata names the server's address at `AGENTGOV_GATEWAY_PUBLIC_URL`. MCP clients
  check that it is the address they called, so developers use that address.
* While `unknown-callers` is monitored, the gateway lets a call without a token through,
  as it does any caller's, so MCP clients aren't asked to sign in.
* MCP clients that register themselves with the authorization server (dynamic client
  registration) can't with Keycloak's defaults: they ask for a client ID instead.

## The MCP servers developers set up

`agentgov mcp scan` lists the MCP servers set up on the machine it runs on: user-wide,
and in the projects given with `--dir` (by default the current directory).

| Client | Files |
|---|---|
| VS Code (and Insiders) | the user profile's `mcp.json`; a project's `.vscode/mcp.json` |
| GitHub Copilot CLI | `~/.copilot/mcp-config.json` (or `$COPILOT_HOME`) |
| Claude Desktop | `claude_desktop_config.json` in the application data folder |
| Claude Code | `~/.claude.json`, including its projects; a project's `.mcp.json` |
| Cursor | `~/.cursor/mcp.json`; a project's `.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json`; a project's `.gemini/settings.json` |
| Codex | `~/.codex/config.toml` |

With `--report`, it sends the list to AgentGov, at `AGENTGOV_URL` with the API key in
`AGENTGOV_TOKEN` ([the command line](configuration.md#the-command-line)), of the `registrar`
role or an administrator's. Each report replaces the previous one from the same machine and
person. Run it from your device management to cover every machine; `--home` scans
another person's home directory.

Configuration files hold credentials, and none of them leave the machine. Environment
variables and headers are reported by name only, addresses without their query or user
information, and command arguments that look like credentials, or follow options such
as `--token` and `--api-key`, as `<redacted>`.

AgentGov compares each server with the approved tool servers, by its address, or by
the package or command that starts it:

| Status | Meaning | Finding |
|---|---|---|
| Approved | A tool server's gateway address, a developer server's own address, or an approved package | — |
| Past the gateway | The address of a server agents reach through the gateway, used directly: none of the gateway's controls apply | `mcp.gateway_bypass` (high) |
| Blocked | A blocked tool server | `mcp.blocked_server` (high) |
| Not approved | Anything else: shadow MCP | `mcp.unapproved_server` (medium) |

Findings resolve themselves when the server is approved, or no report includes it any
more. **Developer tools** lists every server reported, with the machines and people
that have it; **Register** starts a tool server from one that isn't approved. In the
CLI, `agentgov mcp sightings`; in the API, `GET /v1/mcp/sightings`. Servers no machine
has reported for 90 days are forgotten. Turning the `mcp-discovery` feature off refuses
reports.

## Limits

* Developers' MCP clients reach the servers on the gateway once developers sign in, but
  the servers developers reach directly, and those they run on their machines, are
  outside the gateway: AgentGov lists them and finds them, but doesn't check their calls.
* Copilot's registry enforcement matches servers by name, and GitHub notes that editing
  configuration files can get around it. The managed-settings allowlist matches by URL
  and command.
* The scanner knows the clients above. Others' MCP servers aren't found, nor servers
  started some other way, such as by an extension at run time.

# Developer tools

Developers give their coding assistants MCP servers too: GitHub Copilot in VS Code and
other editors, Claude, Cursor, Codex. AgentGov keeps one list of approved MCP servers for
agents and for developers, and serves the developers' part in the format their MCP
clients read: an **MCP registry**. GitHub Copilot can then offer developers only those
servers. AgentGov also finds out which MCP servers developers have actually set up, and
raises a finding for each one that isn't approved.

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

* Developers' clients reach a server through the gateway with an agent's token, which
  coding assistants don't hold. Agents [act for people](acting-for-people.md) with a
  token they get for the person, but the gateway doesn't take people's own tokens from
  their MCP clients yet (see the [roadmap](roadmap.md)): list for developers the servers
  they reach directly, and packages.
* Copilot's registry enforcement matches servers by name, and GitHub notes that editing
  configuration files can get around it. The managed-settings allowlist matches by URL
  and command.
* The scanner knows the clients above. Others' MCP servers aren't found, nor servers
  started some other way, such as by an extension at run time.

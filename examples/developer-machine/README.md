# A developer's machine

MCP clients set up the way a developer's might be, for the demo's last steps and for
trying `agentgov mcp scan` ([developer tools](../../docs/developer-tools.md)):

```bash
agentgov mcp scan --home examples/developer-machine/home --dir examples/developer-machine/project
```

* `home/.copilot/mcp-config.json` (GitHub Copilot CLI): the CRM server through the
  gateway, and the Playwright package; both approved in `examples/manifests`.
* `home/.cursor/mcp.json` (Cursor): GitHub's MCP server, which isn't approved.
* `home/.codex/config.toml` (Codex): a filesystem server with access to `/`, not approved.
* `project/.vscode/mcp.json` (VS Code): the CRM server at its own address, past the
  gateway.

The credentials in them are placeholders, and the scan reports only variable and header
names, never their values.

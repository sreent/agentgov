"""The ``agentgov`` command line: run the services and administer the registry.

The administration commands are a thin layer over the HTTP API and follow the
admin UI's pages: agents, blueprints, tool servers, policies, approvals,
findings, the ledger and access (API keys). Whatever the UI can change, the CLI
can change too, through the same endpoints and with the same role checks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

import httpx
import typer

from agentgov import __version__

app = typer.Typer(help="AgentGov: open-source AI agent governance.", no_args_is_help=True)
agents_app = typer.Typer(help="Agent inventory and lifecycle.", no_args_is_help=True)
blueprints_app = typer.Typer(
    help="Blueprints: tool grants, risk tier, sponsor and review rules.", no_args_is_help=True
)
toolservers_app = typer.Typer(
    help="MCP tool servers published through the gateway.", no_args_is_help=True
)
policies_app = typer.Typer(
    help="Organisation Rego policies, and what-if evaluation.", no_args_is_help=True
)
approvals_app = typer.Typer(help="Human-in-the-loop approvals.", no_args_is_help=True)
findings_app = typer.Typer(
    help="Posture and threat findings (lists open findings by default).",
    invoke_without_command=True,
)
ledger_app = typer.Typer(help="The tamper-evident evidence ledger.", no_args_is_help=True)
apikeys_app = typer.Typer(
    help="Role-scoped API keys for the CLI and automation.", no_args_is_help=True
)
app.add_typer(agents_app, name="agents")
app.add_typer(blueprints_app, name="blueprints")
app.add_typer(toolservers_app, name="toolservers")
app.add_typer(policies_app, name="policies")
app.add_typer(approvals_app, name="approvals")
app.add_typer(findings_app, name="findings")
app.add_typer(ledger_app, name="ledger")
app.add_typer(apikeys_app, name="apikeys")

YES = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation.")


# ------------------------------------------------------------------ plumbing


def _client() -> httpx.Client:
    url = os.environ.get("AGENTGOV_URL", "http://localhost:8000")
    token = os.environ.get("AGENTGOV_TOKEN") or os.environ.get("AGENTGOV_ADMIN_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.Client(base_url=url, headers=headers, timeout=30)


def _call(method: str, path: str, **kwargs: Any) -> Any:
    with _client() as client:
        resp = client.request(method, path, **kwargs)
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        typer.secho(f"error {resp.status_code}: {detail}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    content_type = resp.headers.get("content-type", "")
    return resp.json() if content_type.startswith("application/json") else resp.text


def _fail(message: str) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(2)


def _print(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2) if not isinstance(data, str) else data)


def _table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    def cell(row: dict[str, Any], column: str) -> str:
        value = row.get(column)
        return "" if value is None else str(value)

    widths = {c: max([len(c)] + [len(cell(r, c)) for r in rows]) for c in columns}
    typer.echo("  ".join(c.upper().ljust(widths[c]) for c in columns).rstrip())
    for row in rows:
        typer.echo("  ".join(cell(row, c).ljust(widths[c]) for c in columns).rstrip())


def _done(kind: str, name: str, outcome: str) -> None:
    typer.echo(f"{kind}/{name}: {outcome}")


def _confirm(question: str, yes: bool) -> None:
    if not yes:
        typer.confirm(question, abort=True)


def _split(values: list[str] | None) -> list[str]:
    """Values of a repeatable option, each of which may also be comma-separated."""
    return [item.strip() for value in values or [] for item in value.split(",") if item.strip()]


def _labels(values: list[str] | None) -> dict[str, str]:
    labels = {}
    for item in _split(values):
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            _fail(f"labels look like key=value (got {item!r})")
        labels[key.strip()] = value.strip()
    return labels


def _grants(values: list[str] | None) -> list[dict[str, Any]]:
    """Tool grants written as ``server:tool,tool`` (``server:*`` for every tool)."""
    grants = []
    for value in values or []:
        server, sep, tools = value.partition(":")
        names = [t.strip() for t in tools.split(",") if t.strip()]
        if not sep or not server.strip() or not names:
            _fail(f"grants look like server:tool,tool (got {value!r}); use server:* for all tools")
        grants.append({"server": server.strip(), "tools": names})
    return grants


def _given(**fields: Any) -> dict[str, Any]:
    """The options that were passed (``None`` means "leave unchanged")."""
    return {key: value for key, value in fields.items() if value is not None}


# ----------------------------------------------------------------- top level


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


@app.command()
def whoami() -> None:
    """Show the identity and role of the configured token."""
    _print(_call("GET", "/v1/me"))


@app.command()
def server(
    host: str = typer.Option("0.0.0.0", help="Bind address."),  # noqa: S104
    port: int = typer.Option(8000, help="Port."),
    dev: bool = typer.Option(False, help="Development mode (generates an admin token)."),
) -> None:
    """Run the control plane (API, admin UI, OPA bundle server)."""
    import uvicorn

    if dev:
        os.environ.setdefault("AGENTGOV_DEV_MODE", "true")
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    uvicorn.run("agentgov.api.app:create_app", factory=True, host=host, port=port)


@app.command()
def processor() -> None:
    """Run the governance processor (agentgateway ExtMcp gRPC server)."""
    from agentgov.config import Settings
    from agentgov.processor.server import serve

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    asyncio.run(serve(Settings.from_env()))


@app.command()
def apply(
    files: list[Path] = typer.Option(..., "--file", "-f", help="Manifest file or directory."),
) -> None:
    """Apply declarative manifests (Blueprint, ToolServer, Policy, Agent)."""
    docs: list[str] = []
    for path in files:
        targets = (
            sorted(p for p in path.rglob("*") if p.suffix in (".yaml", ".yml"))
            if path.is_dir()
            else [path]
        )
        for target in targets:
            text = target.read_text()
            docs.append(_inline_rego(text, target.parent))
    result = _call(
        "POST",
        "/v1/apply",
        content="\n---\n".join(docs),
        headers={"Content-Type": "application/yaml"},
    )
    for item in result["results"]:
        typer.echo(f"{item['kind'].lower()}/{item['name']} {item['action']}")


def _inline_rego(text: str, base: Path) -> str:
    """Replace ``regoFile: path`` in Policy manifests with the file's contents."""
    import yaml

    out = []
    for doc in yaml.safe_load_all(text):
        if isinstance(doc, dict) and doc.get("kind") == "Policy":
            spec = doc.setdefault("spec", {})
            if "regoFile" in spec:
                spec["rego"] = (base / spec.pop("regoFile")).read_text()
        if doc is not None:
            out.append(doc)
    return yaml.safe_dump_all(out, sort_keys=False)


@app.command()
def export() -> None:
    """Export the registry as manifests."""
    typer.echo(_call("GET", "/v1/export"))


@app.command()
def overview() -> None:
    """Show the governance overview."""
    _print(_call("GET", "/v1/overview"))


# -------------------------------------------------------------------- agents


@agents_app.command("list")
def agents_list(status: str | None = None) -> None:
    """List agents (all but deleted ones, unless --status is given)."""
    rows = _call("GET", "/v1/agents", params={"status": status} if status else None)
    for r in rows:
        r["risk"] = f"{r['risk']['level']} ({r['risk']['score']})"
    _table(rows, ["name", "status", "blueprint", "owner", "risk", "last_seen_at"])


@agents_app.command("get")
def agents_get(ref: str) -> None:
    """Show an agent (by name, ID or client ID)."""
    _print(_call("GET", f"/v1/agents/{ref}"))


def _agent_fields(
    *,
    description: str | None,
    blueprint: str | None,
    owner: str | None,
    sponsors: list[str] | None,
    environment: str | None,
    framework: str | None,
    platform: str | None,
    models: list[str] | None,
    grants: list[str] | None,
    labels: list[str] | None,
    risk_tier: str | None,
) -> dict[str, Any]:
    body = _given(description=description, risk_tier=risk_tier)
    # An empty string clears these.
    for key, value in (
        ("blueprint", blueprint),
        ("owner", owner),
        ("environment", environment),
        ("framework", framework),
        ("platform", platform),
    ):
        if value is not None:
            body[key] = value or None
    if sponsors is not None:
        body["sponsors"] = _split(sponsors)
    if models is not None:
        body["models"] = _split(models)
    if grants is not None:
        body["permissions"] = _grants(grants)
    if labels is not None:
        body["labels"] = _labels(labels)
    return body


DESCRIPTION = typer.Option(None, help="What it is for.")
OWNER = typer.Option(None, help="Accountable team or person.")
LABEL = typer.Option(None, "--label", help="key=value (repeatable).")
AGENT_BLUEPRINT = typer.Option(None, help="Blueprint whose tools it gets ('' for none).")
SPONSOR = typer.Option(None, "--sponsor", help="Sponsor (repeatable, or comma-separated).")
ENVIRONMENT = typer.Option(None, help="For example prod, staging or dev.")
MODEL = typer.Option(None, "--model", help="Model the agent uses (repeatable).")
GRANT = typer.Option(None, "--grant", help="Extra tool grant server:tool,tool (repeatable).")
RISK_TIER = typer.Option(None, help="minimal, low, medium, high or critical.")


@agents_app.command("create")
def agents_create(
    name: str,
    description: str | None = DESCRIPTION,
    blueprint: str | None = AGENT_BLUEPRINT,
    owner: str | None = OWNER,
    sponsor: list[str] | None = SPONSOR,
    environment: str | None = ENVIRONMENT,
    framework: str | None = None,
    platform: str | None = None,
    model: list[str] | None = MODEL,
    grant: list[str] | None = GRANT,
    label: list[str] | None = LABEL,
    risk_tier: str | None = RISK_TIER,
    approve: bool = typer.Option(False, "--approve", help="Activate it now (admins only)."),
) -> None:
    """Register an agent. It waits in pending review unless --approve is given."""
    body = _agent_fields(
        description=description,
        blueprint=blueprint,
        owner=owner,
        sponsors=sponsor,
        environment=environment,
        framework=framework,
        platform=platform,
        models=model,
        grants=grant,
        labels=label,
        risk_tier=risk_tier,
    )
    agent = _call("POST", "/v1/agents", json={"name": name, **body, "approve": approve})
    _done("agent", agent["name"], agent["status"])


@agents_app.command("update")
def agents_update(
    ref: str,
    description: str | None = DESCRIPTION,
    blueprint: str | None = AGENT_BLUEPRINT,
    owner: str | None = OWNER,
    sponsor: list[str] | None = typer.Option(
        None, "--sponsor", help="Sponsors (replace the current ones; repeatable)."
    ),
    environment: str | None = ENVIRONMENT,
    framework: str | None = None,
    platform: str | None = None,
    model: list[str] | None = MODEL,
    grant: list[str] | None = typer.Option(
        None, "--grant", help="Extra grants server:tool,tool (replace the current ones)."
    ),
    clear_grants: bool = typer.Option(False, "--clear-grants", help="Remove the extra grants."),
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    risk_tier: str | None = RISK_TIER,
) -> None:
    """Change an agent's details. Only the options you pass are changed."""
    body = _agent_fields(
        description=description,
        blueprint=blueprint,
        owner=owner,
        sponsors=sponsor,
        environment=environment,
        framework=framework,
        platform=platform,
        models=model,
        grants=[] if clear_grants else grant,
        labels=label,
        risk_tier=risk_tier,
    )
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    agent = _call("PATCH", f"/v1/agents/{ref}", json=body)
    _done("agent", agent["name"], "updated")


def _lifecycle(ref: str, action: str, reason: str | None) -> None:
    agent = _call("POST", f"/v1/agents/{ref}/{action}", json={"reason": reason} if reason else {})
    _done("agent", agent["name"], agent["status"])


REASON = typer.Option(None, help="Recorded in the evidence ledger.")


@agents_app.command("approve")
def agents_approve(ref: str, reason: str | None = REASON) -> None:
    """Approve a pending agent: it becomes active (needs a sponsor)."""
    _lifecycle(ref, "approve", reason)


@agents_app.command("block")
def agents_block(ref: str, reason: str = typer.Option("blocked from CLI", help="Why.")) -> None:
    """Kill switch: block the agent everywhere (identity, gateway, in-process OPA)."""
    _lifecycle(ref, "block", reason)


@agents_app.command("unblock")
def agents_unblock(ref: str, reason: str | None = REASON) -> None:
    """Unblock an agent: its calls are evaluated against policy again."""
    _lifecycle(ref, "unblock", reason)


@agents_app.command("delete")
def agents_delete(ref: str, reason: str | None = REASON) -> None:
    """Delete an agent (soft: it can be restored, or purged for good)."""
    _lifecycle(ref, "delete", reason)


@agents_app.command("restore")
def agents_restore(ref: str, reason: str | None = REASON) -> None:
    """Restore a deleted agent; it comes back pending review."""
    _lifecycle(ref, "restore", reason)


@agents_app.command("lifecycle")
def agents_lifecycle(
    ref: str,
    action: str = typer.Argument(..., help="approve | block | unblock | delete | restore | adopt"),
    reason: str | None = None,
) -> None:
    """Run any lifecycle action, including adopting a discovered agent."""
    _lifecycle(ref, action, reason)


@agents_app.command("purge")
def agents_purge(ref: str, yes: bool = YES) -> None:
    """Remove a deleted agent and its OAuth client permanently."""
    _confirm(f"Permanently delete agent {ref}? This cannot be undone.", yes)
    _call("DELETE", f"/v1/agents/{ref}")
    _done("agent", ref, "purged")


@agents_app.command("attest")
def agents_attest(
    ref: str, note: str | None = typer.Option(None, help="Recorded in the ledger.")
) -> None:
    """Confirm the agent is still needed (sponsors and admins)."""
    agent = _call("POST", f"/v1/agents/{ref}/attest", json={"note": note} if note else {})
    _done("agent", agent["name"], f"attested, next review {agent['attestation']['expires_at']}")


@agents_app.command("credentials")
def agents_credentials(ref: str, rotate: bool = False) -> None:
    """Print the agent's OAuth client credentials (--rotate issues a new secret)."""
    _print(_call("POST", f"/v1/agents/{ref}/credentials", json={"rotate": rotate}))


@agents_app.command("risk")
def agents_risk(ref: str, refresh: bool = typer.Option(False, help="Recompute it now.")) -> None:
    """Show the agent's risk score and the factors behind it."""
    risk = (
        _call("POST", f"/v1/agents/{ref}/risk/refresh")
        if refresh
        else _call("GET", f"/v1/agents/{ref}/risk")
    )
    typer.echo(f"{risk['level']} risk, score {risk['score']} of 100")
    for factor in risk.get("factors", []):
        detail = f" ({factor['detail']})" if factor.get("detail") else ""
        typer.echo(f"  +{factor['points']}  {factor['factor']}{detail}")


# ---------------------------------------------------------------- blueprints


@blueprints_app.command("list")
def blueprints_list() -> None:
    """List blueprints and the servers they grant."""
    rows = _call("GET", "/v1/blueprints")
    for r in rows:
        r["grants"] = "; ".join(f"{g['server']}:{','.join(g['tools'])}" for g in r["permissions"])
        r["review"] = f"{r['attestation_days']}d" if r["attestation_days"] else "none"
    _table(rows, ["name", "risk_tier", "require_sponsor", "review", "grants"])


@blueprints_app.command("get")
def blueprints_get(name: str) -> None:
    """Show a blueprint."""
    _print(_call("GET", f"/v1/blueprints/{name}"))


def _blueprint_fields(
    description: str | None,
    grant: list[str] | None,
    risk_tier: str | None,
    review_days: int | None,
    no_review: bool,
    require_sponsor: bool | None,
    label: list[str] | None,
) -> dict[str, Any]:
    body = _given(description=description, risk_tier=risk_tier, require_sponsor=require_sponsor)
    if grant is not None:
        body["permissions"] = _grants(grant)
    if no_review:
        body["attestation_days"] = None
    elif review_days is not None:
        body["attestation_days"] = review_days
    if label is not None:
        body["labels"] = _labels(label)
    return body


BP_GRANT = typer.Option(None, "--grant", help="Tool grant server:tool,tool (repeatable).")
REVIEW_DAYS = typer.Option(None, help="Sponsors re-attest agents every N days.")
NO_REVIEW = typer.Option(False, "--no-review", help="No periodic attestation.")
REQUIRE_SPONSOR = typer.Option(
    None, "--require-sponsor/--no-sponsor", help="Whether activation needs a sponsor."
)


@blueprints_app.command("create")
def blueprints_create(
    name: str,
    description: str | None = DESCRIPTION,
    grant: list[str] | None = BP_GRANT,
    risk_tier: str | None = RISK_TIER,
    review_days: int | None = REVIEW_DAYS,
    no_review: bool = NO_REVIEW,
    require_sponsor: bool | None = REQUIRE_SPONSOR,
    label: list[str] | None = LABEL,
) -> None:
    """Create a blueprint."""
    body = _blueprint_fields(
        description, grant, risk_tier, review_days, no_review, require_sponsor, label
    )
    bp = _call("POST", "/v1/blueprints", json={"name": name, **body})
    _done("blueprint", bp["name"], "created")


@blueprints_app.command("update")
def blueprints_update(
    name: str,
    description: str | None = DESCRIPTION,
    grant: list[str] | None = typer.Option(
        None, "--grant", help="Tool grants server:tool,tool (replace the current ones)."
    ),
    risk_tier: str | None = RISK_TIER,
    review_days: int | None = REVIEW_DAYS,
    no_review: bool = NO_REVIEW,
    require_sponsor: bool | None = REQUIRE_SPONSOR,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
) -> None:
    """Change a blueprint. Every agent on it gets the change."""
    body = _blueprint_fields(
        description, grant, risk_tier, review_days, no_review, require_sponsor, label
    )
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    bp = _call("PATCH", f"/v1/blueprints/{name}", json=body)
    _done("blueprint", bp["name"], "updated")


@blueprints_app.command("delete")
def blueprints_delete(name: str, yes: bool = YES) -> None:
    """Delete a blueprint that no agent uses."""
    _confirm(f"Delete blueprint {name}?", yes)
    _call("DELETE", f"/v1/blueprints/{name}")
    _done("blueprint", name, "deleted")


# -------------------------------------------------------------- tool servers


@toolservers_app.command("list")
def toolservers_list(status: str | None = None) -> None:
    """List tool servers."""
    rows = _call("GET", "/v1/toolservers", params={"status": status} if status else None)
    for r in rows:
        r["tools"] = len(r["tools"])
    _table(rows, ["name", "status", "trust_level", "data_classification", "tools", "gateway_url"])


@toolservers_app.command("get")
def toolservers_get(name: str) -> None:
    """Show a tool server and its tool catalog."""
    _print(_call("GET", f"/v1/toolservers/{name}"))


TRUST = typer.Option(None, "--trust", help="verified or unverified.")
CLASSIFICATION = typer.Option(None, help="public, internal, confidential or restricted.")


def _toolserver_fields(
    url: str | None,
    description: str | None,
    owner: str | None,
    trust: str | None,
    classification: str | None,
    label: list[str] | None,
) -> dict[str, Any]:
    body = _given(
        url=url, description=description, trust_level=trust, data_classification=classification
    )
    if owner is not None:
        body["owner"] = owner or None
    if label is not None:
        body["labels"] = _labels(label)
    return body


@toolservers_app.command("create")
def toolservers_create(
    name: str,
    url: str = typer.Option(..., help="The server's streamable HTTP MCP endpoint."),
    description: str | None = DESCRIPTION,
    owner: str | None = OWNER,
    trust: str | None = TRUST,
    classification: str | None = CLASSIFICATION,
    label: list[str] | None = LABEL,
) -> None:
    """Register a tool server (admins: approved at once; registrars: pending review)."""
    body = _toolserver_fields(url, description, owner, trust, classification, label)
    ts = _call("POST", "/v1/toolservers", json={"name": name, **body})
    _done("toolserver", ts["name"], f"{ts['status']}, published at {ts['gateway_url']}")


@toolservers_app.command("update")
def toolservers_update(
    name: str,
    url: str | None = typer.Option(None, help="New upstream MCP endpoint."),
    description: str | None = DESCRIPTION,
    owner: str | None = OWNER,
    trust: str | None = TRUST,
    classification: str | None = CLASSIFICATION,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
) -> None:
    """Change a tool server's details."""
    body = _toolserver_fields(url, description, owner, trust, classification, label)
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    ts = _call("PATCH", f"/v1/toolservers/{name}", json=body)
    _done("toolserver", ts["name"], "updated")


@toolservers_app.command("delete")
def toolservers_delete(name: str, yes: bool = YES) -> None:
    """Delete a tool server and its catalog (block it instead to keep the catalog)."""
    _confirm(f"Delete tool server {name} and its tool catalog?", yes)
    _call("DELETE", f"/v1/toolservers/{name}")
    _done("toolserver", name, "deleted")


def _server_action(name: str, action: str) -> None:
    ts = _call("POST", f"/v1/toolservers/{name}/{action}")
    _done("toolserver", ts["name"], ts["status"])


@toolservers_app.command("approve")
def toolservers_approve(name: str) -> None:
    """Approve a server that is pending review."""
    _server_action(name, "approve")


@toolservers_app.command("block")
def toolservers_block(name: str) -> None:
    """Refuse every call to the server (its catalog is kept)."""
    _server_action(name, "block")


@toolservers_app.command("unblock")
def toolservers_unblock(name: str) -> None:
    """Allow calls to a blocked server again."""
    _server_action(name, "unblock")


@toolservers_app.command("approve-tool")
def toolservers_approve_tool(name: str, tool: str) -> None:
    """Accept a tool's changed definition (lifts its rug-pull quarantine)."""
    _call("POST", f"/v1/toolservers/{name}/tools/{tool}/approve")
    _done("toolserver", f"{name}/{tool}", "definition approved")


# ------------------------------------------------------------------ policies


@policies_app.command("list")
def policies_list() -> None:
    """List organisation policies."""
    rows = _call("GET", "/v1/policies")
    _table(rows, ["name", "package", "enabled", "version", "updated_at"])


@policies_app.command("get")
def policies_get(
    name: str, rego: bool = typer.Option(False, help="Print only the source.")
) -> None:
    """Show a policy."""
    policy = _call("GET", f"/v1/policies/{name}")
    _print(policy["rego"] if rego else policy)


REGO_FILE = typer.Option(
    None, "--file", "-f", help="Rego source file.", exists=True, dir_okay=False
)


@policies_app.command("create")
def policies_create(
    name: str,
    file: Path = typer.Option(
        ..., "--file", "-f", help="Rego source file.", exists=True, dir_okay=False
    ),
    description: str | None = DESCRIPTION,
    disabled: bool = typer.Option(False, "--disabled", help="Store it without enforcing it."),
) -> None:
    """Add a policy. It must declare package agentgov.custom.<name> (hyphens as _)."""
    body = {"name": name, "rego": file.read_text(), "enabled": not disabled}
    if description is not None:
        body["description"] = description
    policy = _call("POST", "/v1/policies", json=body)
    _done("policy", policy["name"], f"version {policy['version']}, enabled={policy['enabled']}")


@policies_app.command("update")
def policies_update(
    name: str,
    file: Path | None = REGO_FILE,
    description: str | None = DESCRIPTION,
) -> None:
    """Replace a policy's source or description (checked before it is saved)."""
    body = _given(description=description)
    if file is not None:
        body["rego"] = file.read_text()
    if not body:
        _fail("nothing to change: pass --file or --description")
    policy = _call("PUT", f"/v1/policies/{name}", json=body)
    _done("policy", policy["name"], f"version {policy['version']}")


@policies_app.command("enable")
def policies_enable(name: str) -> None:
    """Enforce a disabled policy again."""
    policy = _call("PUT", f"/v1/policies/{name}", json={"enabled": True})
    _done("policy", policy["name"], "enabled")


@policies_app.command("disable")
def policies_disable(name: str) -> None:
    """Stop enforcing a policy but keep its source."""
    policy = _call("PUT", f"/v1/policies/{name}", json={"enabled": False})
    _done("policy", policy["name"], "disabled")


@policies_app.command("delete")
def policies_delete(name: str, yes: bool = YES) -> None:
    """Delete a policy."""
    _confirm(f"Delete policy {name}?", yes)
    _call("DELETE", f"/v1/policies/{name}")
    _done("policy", name, "deleted")


@policies_app.command("evaluate")
def policies_evaluate(
    server: str = typer.Option(..., help="Tool server name."),
    tool: str = typer.Option(..., help="Tool name."),
    agent: str | None = typer.Option(None, help="Agent (default: an unregistered caller)."),
    phase: str = typer.Option("request", help="request (the call) or response (the result)."),
    pii: bool = typer.Option(False, "--pii", help="Personal data was detected."),
    secret: bool = typer.Option(False, "--secret", help="A credential was detected."),
    injection: bool = typer.Option(False, "--injection", help="Prompt injection in the result."),
    as_json: bool = typer.Option(False, "--json", help="Print OPA's full result."),
) -> None:
    """What if: ask the live OPA what it would decide for a tool call. Nothing is recorded."""
    if agent:
        found = _call("GET", f"/v1/agents/{agent}")
        caller = {"agent_id": found["id"], "client_id": found["identity"]["client_id"]}
    else:
        caller = {"client_id": "agent-not-registered"}
    categories = [c for c, on in (("pii", pii), ("secret", secret)) if on]
    decision_input = {
        "phase": phase,
        "method": "tools/call",
        "agent": {k: v for k, v in caller.items() if v},
        "resource": {"server": server, "name": tool},
        "detections": {
            "categories": categories,
            "prompt_injection": injection,
            "injection_score": 0.95 if injection else 0,
        },
    }
    result = _call("POST", "/v1/policies/evaluate", json={"input": decision_input})["result"]
    if as_json or not result:
        _print(result)
        return
    typer.echo(result.get("effect", "none"))
    for reason in result.get("reasons", []):
        typer.echo(f"  - {reason}")
    if result.get("redact"):
        typer.echo(f"  redact: {', '.join(result['redact'])}")


# ----------------------------------------------------------------- approvals


@approvals_app.command("list")
def approvals_list(status: str = "pending") -> None:
    """List approval requests (pending ones by default)."""
    rows = _call("GET", "/v1/approvals", params={"status": status})
    _table(rows, ["id", "agent_name", "resource", "status", "requested_at"])


@approvals_app.command("approve")
def approvals_approve(approval_id: str, note: str | None = None) -> None:
    """Approve a held tool call; the agent's retry goes through once."""
    r = _call("POST", f"/v1/approvals/{approval_id}/approve", json={"note": note})
    typer.echo(f"{r['id']}: {r['status']}")


@approvals_app.command("deny")
def approvals_deny(approval_id: str, note: str | None = None) -> None:
    """Deny a held tool call."""
    r = _call("POST", f"/v1/approvals/{approval_id}/deny", json={"note": note})
    typer.echo(f"{r['id']}: {r['status']}")


# ------------------------------------------------------------------ findings

FINDING_STATUS = typer.Option("open", help="open, resolved, dismissed or all.")


def _list_findings(status: str) -> None:
    rows = _call("GET", "/v1/findings", params={"status": status})
    _table(rows, ["id", "severity", "status", "type", "title"])


@findings_app.callback()
def findings_main(ctx: typer.Context, status: str = FINDING_STATUS) -> None:
    if ctx.invoked_subcommand is None:
        _list_findings(status)


@findings_app.command("list")
def findings_list(status: str = FINDING_STATUS) -> None:
    """List findings."""
    _list_findings(status)


def _finding_action(finding_id: str, action: str) -> None:
    f = _call("POST", f"/v1/findings/{finding_id}/{action}")
    _done("finding", f["id"], f["status"])


@findings_app.command("resolve")
def findings_resolve(finding_id: str) -> None:
    """Mark a finding as resolved."""
    _finding_action(finding_id, "resolve")


@findings_app.command("dismiss")
def findings_dismiss(finding_id: str) -> None:
    """Dismiss a finding (accepted risk or false positive)."""
    _finding_action(finding_id, "dismiss")


@findings_app.command("reopen")
def findings_reopen(finding_id: str) -> None:
    """Reopen a resolved or dismissed finding."""
    _finding_action(finding_id, "reopen")


# -------------------------------------------------------------------- ledger


@ledger_app.command("verify")
def ledger_verify() -> None:
    """Recompute the hash chain and report tampering."""
    result = _call("GET", "/v1/ledger/verify")
    _print(result)
    if not result.get("valid"):
        raise typer.Exit(2)


@ledger_app.command("tail")
def ledger_tail(
    limit: int = 20,
    type: str | None = typer.Option(None, help="Event type; * is a wildcard (decision.*)."),
    agent: str | None = typer.Option(None, help="Only this agent's entries."),
    decision: str | None = typer.Option(None, help="allow, deny or require_approval."),
) -> None:
    """Show the latest ledger entries, oldest first."""
    params: dict[str, Any] = {"limit": limit, **_given(type=type, agent=agent, decision=decision)}
    rows = list(reversed(_call("GET", "/v1/ledger", params=params)))
    _table(rows, ["seq", "ts", "type", "agent_name", "resource", "decision", "reason"])


@ledger_app.command("export")
def ledger_export() -> None:
    """Write the whole chain as JSON Lines (for a SIEM, or offline verification)."""
    with _client() as client, client.stream("GET", "/v1/ledger/export") as resp:
        if resp.status_code >= 400:
            resp.read()
            typer.secho(f"error {resp.status_code}: {resp.text}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        for line in resp.iter_lines():
            typer.echo(line)


# ------------------------------------------------------------------ api keys


@apikeys_app.command("list")
def apikeys_list() -> None:
    """List API keys (never the keys themselves)."""
    rows = _call("GET", "/v1/apikeys")
    for r in rows:
        r["status"] = "revoked" if r["revoked_at"] else "active"
    _table(rows, ["id", "name", "role", "prefix", "status", "created_at", "last_used_at"])


@apikeys_app.command("create")
def apikeys_create(
    name: str,
    role: str = typer.Option(..., help="admin, approver, auditor, registrar or service."),
) -> None:
    """Create a key. It is printed once, on standard output, and only its hash is kept."""
    key = _call("POST", "/v1/apikeys", json={"name": name, "role": role})
    typer.echo(f"apikey/{key['id']} ({key['role']}) created for {key['name']}.", err=True)
    typer.echo("Copy the key now; it cannot be shown again:", err=True)
    typer.echo(key["token"])


@apikeys_app.command("revoke")
def apikeys_revoke(key_id: str, yes: bool = YES) -> None:
    """Revoke a key: requests made with it are refused from now on."""
    _confirm(f"Revoke API key {key_id}?", yes)
    key = _call("DELETE", f"/v1/apikeys/{key_id}")
    _done("apikey", key["id"], f"revoked ({key['name']})")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

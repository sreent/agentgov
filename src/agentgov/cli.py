"""The ``agentgov`` command line: run the services and administer the registry."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import typer

from agentgov import __version__

app = typer.Typer(help="AgentGov: open-source AI agent governance.", no_args_is_help=True)
agents_app = typer.Typer(help="Agent inventory and lifecycle.", no_args_is_help=True)
approvals_app = typer.Typer(help="Human-in-the-loop approvals.", no_args_is_help=True)
ledger_app = typer.Typer(help="The tamper-evident evidence ledger.", no_args_is_help=True)
app.add_typer(agents_app, name="agents")
app.add_typer(approvals_app, name="approvals")
app.add_typer(ledger_app, name="ledger")


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


def _print(data: Any) -> None:
    typer.echo(json.dumps(data, indent=2) if not isinstance(data, str) else data)


def _table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    widths = {c: max([len(c)] + [len(str(r.get(c, ""))) for r in rows]) for c in columns}
    typer.echo("  ".join(c.upper().ljust(widths[c]) for c in columns))
    for row in rows:
        typer.echo("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in columns))


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


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


@app.command()
def findings(status: str = "open") -> None:
    """List posture and threat findings."""
    rows = _call("GET", "/v1/findings", params={"status": status})
    _table(rows, ["id", "severity", "type", "title"])


@agents_app.command("list")
def agents_list(status: str | None = None) -> None:
    rows = _call("GET", "/v1/agents", params={"status": status} if status else None)
    for r in rows:
        r["risk"] = f"{r['risk']['level']} ({r['risk']['score']})"
    _table(rows, ["name", "status", "blueprint", "owner", "risk", "last_seen_at"])


@agents_app.command("get")
def agents_get(ref: str) -> None:
    _print(_call("GET", f"/v1/agents/{ref}"))


@agents_app.command("lifecycle")
def agents_lifecycle(
    ref: str,
    action: str = typer.Argument(..., help="approve | block | unblock | delete | restore | adopt"),
    reason: str | None = None,
) -> None:
    agent = _call("POST", f"/v1/agents/{ref}/{action}", json={"reason": reason} if reason else {})
    typer.echo(f"{agent['name']}: {agent['status']}")


@agents_app.command("block")
def agents_block(ref: str, reason: str = typer.Option("blocked from CLI", help="Why.")) -> None:
    """Kill switch: block the agent everywhere (identity, gateway, in-process OPA)."""
    agent = _call("POST", f"/v1/agents/{ref}/block", json={"reason": reason})
    typer.echo(f"{agent['name']}: {agent['status']}")


@agents_app.command("credentials")
def agents_credentials(ref: str, rotate: bool = False) -> None:
    """Print the agent's OAuth client credentials."""
    _print(_call("POST", f"/v1/agents/{ref}/credentials", json={"rotate": rotate}))


@approvals_app.command("list")
def approvals_list(status: str = "pending") -> None:
    rows = _call("GET", "/v1/approvals", params={"status": status})
    _table(rows, ["id", "agent_name", "resource", "status", "requested_at"])


@approvals_app.command("approve")
def approvals_approve(approval_id: str, note: str | None = None) -> None:
    r = _call("POST", f"/v1/approvals/{approval_id}/approve", json={"note": note})
    typer.echo(f"{r['id']}: {r['status']}")


@approvals_app.command("deny")
def approvals_deny(approval_id: str, note: str | None = None) -> None:
    r = _call("POST", f"/v1/approvals/{approval_id}/deny", json={"note": note})
    typer.echo(f"{r['id']}: {r['status']}")


@ledger_app.command("verify")
def ledger_verify() -> None:
    """Recompute the hash chain and report tampering."""
    result = _call("GET", "/v1/ledger/verify")
    _print(result)
    if not result.get("valid"):
        raise typer.Exit(2)


@ledger_app.command("tail")
def ledger_tail(limit: int = 20, type: str | None = None) -> None:
    params: dict[str, Any] = {"limit": limit}
    if type:
        params["type"] = type
    rows = list(reversed(_call("GET", "/v1/ledger", params=params)))
    _table(rows, ["seq", "ts", "type", "agent_name", "resource", "decision", "reason"])


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

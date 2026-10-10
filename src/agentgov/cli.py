"""The ``agentgov`` command line: run the services and administer the registry.

The administration commands are a thin layer over the HTTP API and follow the
admin UI's pages: agents, blueprints, tool servers, policies, approvals,
findings, the ledger, access (API keys) and platforms, plus a checker for agent
instructions. Whatever the UI can change, the CLI can change too, through the
same endpoints and with the same role checks.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import http.server
import json
import logging
import os
import secrets
import sys
import threading
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, quote, urlencode, urlsplit

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
access_app = typer.Typer(
    help="Who has access: people signed in with single sign-on, and their sessions.",
    no_args_is_help=True,
)
app.add_typer(access_app, name="access")
platforms_app = typer.Typer(
    help="Agents on Microsoft 365 and Copilot Studio, and the connector allowlist.",
    no_args_is_help=True,
)
app.add_typer(platforms_app, name="platforms")
instructions_app = typer.Typer(
    help="Check agent instructions (system prompts) for unsafe content.", no_args_is_help=True
)
app.add_typer(instructions_app, name="instructions")

YES = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation.")


# ------------------------------------------------------------------ plumbing


def _url() -> str:
    return os.environ.get("AGENTGOV_URL", "http://localhost:8000").rstrip("/")


def _env_token() -> str | None:
    return os.environ.get("AGENTGOV_TOKEN") or os.environ.get("AGENTGOV_ADMIN_TOKEN")


def _token(url: str) -> str | None:
    """AGENTGOV_TOKEN (or AGENTGOV_ADMIN_TOKEN), else the session from `agentgov login`."""
    return _env_token() or _stored_session(url).get("token")


def _client() -> httpx.Client:
    url = _url()
    token = _token(url)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.Client(base_url=url, headers=headers, timeout=30)


def _call(method: str, path: str, **kwargs: Any) -> Any:
    try:
        with _client() as client:
            resp = client.request(method, path, **kwargs)
    except httpx.TimeoutException:
        typer.secho(
            "error: the control plane did not answer in time", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(1) from None
    except httpx.HTTPError as exc:
        typer.secho(f"error: cannot reach the control plane: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        if resp.status_code == 401 and not _env_token():
            detail = f"{detail} (sign in with `agentgov login`, or set AGENTGOV_TOKEN)"
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


# ------------------------------------------------------------------- sign-in

# How long to wait for the browser; the control plane keeps a sign-in open as long.
LOGIN_WAIT_SECONDS = 600
# Reasons /auth/callback sends back (?error=...), as the admin UI words them.
LOGIN_ERRORS = {
    "no_role": "you signed in, but your account has no AgentGov role. Ask an administrator "
    "for agentgov-admin, agentgov-approver or agentgov-auditor.",
    "state": "that sign-in could not be completed in this browser. Start again.",
    "expired": "that sign-in expired or was already used. Start again.",
    "provider": "the identity provider could not complete the sign-in. Try again.",
    "token": "the control plane could not verify the identity provider's response. Ask an "
    "administrator to check the single sign-on settings.",
}


def _sessions_file() -> Path:
    base = os.environ.get("AGENTGOV_CONFIG_DIR") or typer.get_app_dir("agentgov")
    return Path(base) / "sessions.json"


def _sessions() -> dict[str, Any]:
    try:
        data = json.loads(_sessions_file().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_sessions(sessions: dict[str, Any]) -> None:
    """Write the sessions file, readable by this user only (it holds bearer tokens)."""
    path = _sessions_file()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(sessions, f, indent=2)
    os.replace(tmp, path)


def _stored_session(url: str) -> dict[str, Any]:
    """The session `agentgov login` keeps for ``url``, unless it has ended."""
    entry = _sessions().get(url)
    if not isinstance(entry, dict) or not entry.get("token"):
        return {}
    try:
        if datetime.fromisoformat(entry["expires_at"]) <= datetime.now(UTC):
            return {}
    except (KeyError, TypeError, ValueError):
        return {}
    return entry


class _LoginCallback(http.server.BaseHTTPRequestHandler):
    """The loopback page the browser lands on after signing in."""

    server: _LoginServer

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path != "/callback" or not ({"code", "error"} & query.keys()):
            self.send_error(404)
            return
        if self.server.done.is_set():
            self._page("This sign-in is already finished. You can close this tab.")
            return
        ok, message = self.server.finish(query)
        self._page(message if ok else f"Sign-in failed: {message}")
        self.server.done.set()

    def _page(self, text: str) -> None:
        body = (
            '<!doctype html><meta charset="utf-8"><title>AgentGov</title>'
            '<body style="font-family:system-ui,sans-serif;margin:3rem auto;max-width:36rem">'
            f"<h1>AgentGov</h1><p>{html.escape(text)}</p>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # the terminal shows the outcome instead


class _LoginServer(http.server.HTTPServer):
    def __init__(self, port: int, verifier: str) -> None:
        super().__init__(("127.0.0.1", port), _LoginCallback)
        self.verifier = verifier
        self.done = threading.Event()
        self.session: dict[str, Any] = {}
        self.error = ""

    def finish(self, query: dict[str, str]) -> tuple[bool, str]:
        """Exchange the one-time code for a session; returns ``(ok, message)``."""
        if "error" in query:
            self.error = LOGIN_ERRORS.get(query["error"], LOGIN_ERRORS["provider"])
            return False, self.error
        try:
            with _client() as client:
                resp = client.post(
                    "/auth/cli/token", json={"code": query["code"], "verifier": self.verifier}
                )
        except httpx.HTTPError as exc:
            self.error = f"cannot reach the control plane: {exc}"
            return False, self.error
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if resp.status_code != 200 or not isinstance(body, dict) or "token" not in body:
            detail = body.get("detail") if isinstance(body, dict) else None
            self.error = str(detail or f"the control plane answered {resp.status_code}")
            return False, self.error
        self.session = body
        return True, (
            f"You're signed in to the AgentGov command line as {body.get('name')}. "
            "You can close this tab."
        )


@app.command()
def login(
    browser: bool = typer.Option(
        True, "--browser/--no-browser", help="Open the sign-in page in a browser."
    ),
    port: int = typer.Option(
        0, help="Loopback port for the browser to come back to (default: any free port)."
    ),
) -> None:
    """Sign in through single sign-on, as yourself.

    You sign in in a browser on this computer; the CLI then keeps a session for
    AGENTGOV_URL and uses it until the session ends or you run `agentgov logout`.
    Admins signed in through Microsoft Entra ID can also act in Microsoft 365 and
    Power Platform (see docs/platforms.md). To sign in on a remote machine, forward
    a port over SSH (ssh -L 8765:127.0.0.1:8765 HOST) and run
    `agentgov login --no-browser --port 8765` there.
    """
    url = _url()
    if port and not 1024 <= port <= 65535:
        _fail("choose a --port from 1024 to 65535")
    info = _call("GET", "/v1/info")
    if not (info.get("sso") or {}).get("enabled"):
        _fail(f"{url} has no single sign-on; use an API key (AGENTGOV_TOKEN) instead")
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    try:
        server = _LoginServer(port, verifier)
    except OSError as exc:
        _fail(f"cannot listen on 127.0.0.1:{port}: {exc}")
    query = {"cli_port": server.server_port, "cli_challenge": challenge.rstrip(b"=").decode()}
    login_url = f"{url}/auth/login?{urlencode(query)}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        if browser and webbrowser.open(login_url):
            typer.echo(f"Opened a browser to sign in. If it didn't open, visit:\n  {login_url}")
        else:
            typer.echo(f"Open this link in a browser on this computer to sign in:\n  {login_url}")
        typer.echo("Waiting for you to sign in (Ctrl+C to cancel)...")
        finished = server.done.wait(LOGIN_WAIT_SECONDS)
    except KeyboardInterrupt:
        finished = False
        server.error = "cancelled"
    finally:
        server.shutdown()
        server.server_close()
    if not finished and not server.error:
        server.error = "timed out waiting for you to sign in"
    if not server.session:
        _fail(f"sign-in failed: {server.error}")
    session = server.session
    sessions = _sessions()
    sessions[url] = {
        "token": session["token"],
        "expires_at": session["expires_at"],
        "name": session.get("name"),
    }
    _save_sessions(sessions)
    until = datetime.fromisoformat(session["expires_at"]).astimezone()
    typer.echo(
        f"Signed in to {url} as {session['name']} ({', '.join(session['roles'])}) "
        f"until {until:%Y-%m-%d %H:%M %Z}."
    )
    if session.get("microsoft"):
        typer.echo("While it lasts, AgentGov can act as you in Microsoft 365 and Power Platform.")
    if _env_token():
        typer.secho(
            "AGENTGOV_TOKEN or AGENTGOV_ADMIN_TOKEN is set, so the CLI keeps using it: "
            "unset it to use this sign-in.",
            fg=typer.colors.YELLOW,
            err=True,
        )


@app.command()
def logout() -> None:
    """End the session `agentgov login` started for AGENTGOV_URL."""
    url = _url()
    sessions = _sessions()
    entry = sessions.pop(url, None)
    if not isinstance(entry, dict) or not entry.get("token"):
        typer.echo(f"Not signed in to {url}.")
        return
    try:
        with _client() as client:
            client.post("/auth/logout", headers={"Authorization": f"Bearer {entry['token']}"})
    except httpx.HTTPError as exc:
        typer.secho(
            f"warning: cannot reach the control plane, so the session stays valid there until "
            f"it ends or an admin ends it: {exc}",
            fg=typer.colors.YELLOW,
            err=True,
        )
    _save_sessions(sessions)
    typer.echo(f"Signed out of {url}.")


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
def agents_list(
    status: str | None = None,
    source: str | None = typer.Option(
        None, help="registered, discovered:<how>, or platform:microsoft-365|copilot-studio."
    ),
) -> None:
    """List agents (all but deleted ones, unless --status is given)."""
    rows = _call("GET", "/v1/agents", params=_given(status=status, source=source))
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


IN_PLATFORM = typer.Option(
    False,
    "--in-platform",
    help="For agents on Microsoft 365 or Copilot Studio: also do it there, as you "
    "(needs `agentgov login` through Microsoft Entra ID).",
)


@agents_app.command("block")
def agents_block(
    ref: str,
    reason: str = typer.Option("blocked from CLI", help="Why."),
    in_platform: bool = IN_PLATFORM,
) -> None:
    """Kill switch: block the agent everywhere (identity, gateway, in-process OPA)."""
    # AgentGov first, then the platform: if the platform refuses, AgentGov has still blocked it.
    _lifecycle(ref, "block", reason)
    if in_platform:
        _platform_block(ref, blocked=True)


@agents_app.command("unblock")
def agents_unblock(ref: str, reason: str | None = REASON, in_platform: bool = IN_PLATFORM) -> None:
    """Unblock an agent: its calls are evaluated against policy again."""
    # AgentGov first: if it refuses (an agent needs a sponsor), the platform keeps it blocked.
    _lifecycle(ref, "unblock", reason)
    if in_platform:
        _platform_block(ref, blocked=False)


def _platform_block(ref: str, *, blocked: bool) -> None:
    out = _call("POST", f"/v1/agents/{ref}/platform/{'block' if blocked else 'unblock'}")
    verb = "blocked" if blocked else "unblocked"
    _done("agent", out["agent"], f"{verb} in {out['platform']}")


@agents_app.command("platform-block")
def agents_platform_block(ref: str) -> None:
    """Block the agent in its own platform, as you: quarantine a Copilot Studio agent, or
    block a Microsoft 365 agent for the organisation. Its AgentGov status stays as it is."""
    _platform_block(ref, blocked=True)


@agents_app.command("platform-unblock")
def agents_platform_unblock(ref: str) -> None:
    """Undo a block in the agent's own platform, as you."""
    _platform_block(ref, blocked=False)


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


SEVERITIES = ("critical", "high", "medium", "low")
# For calls that wait on slow work: a classifier on a CPU, or paging through an inventory.
LONG_TIMEOUT = 600


def _read_text(file: Path) -> str:
    try:
        return sys.stdin.read() if str(file) == "-" else file.read_text()
    except OSError as exc:
        _fail(f"cannot read {file}: {exc}")


def _issues(issues: list[dict[str, Any]]) -> None:
    if not issues:
        typer.echo("  no problems found")
        return
    rows = [{**i, "excerpt": (i.get("excerpt") or "")[:70].replace("\n", " ")} for i in issues]
    _table(rows, ["severity", "rule", "title", "excerpt"])


def _classifier_state(classifier: dict[str, Any]) -> str:
    state = classifier.get("state", "off")
    if state == "done":
        flagged = [c for c, v in (classifier.get("verdicts") or {}).items() if v == "yes"]
        return f"classifier ({classifier.get('model')}): " + (
            "flagged " + ", ".join(flagged) if flagged else "nothing flagged"
        )
    if state == "error":
        return f"classifier failed: {classifier.get('error')}"
    return {"off": "classifier: not configured", "pending": "classifier: pending"}.get(
        state, f"classifier: {state}"
    )


@agents_app.command("instructions")
def agents_instructions(
    ref: str, text: bool = typer.Option(False, "--text", help="Print the instructions too.")
) -> None:
    """The agent's instructions from each source, and the problems found in them."""
    view = _call("GET", f"/v1/agents/{ref}/instructions")
    if not view["sources"]:
        typer.echo("No instructions known for this agent.")
    for src in view["sources"]:
        typer.echo(
            f"{src['source_name']} instructions, from {src['reported_by']}, "
            f"changed {src['updated_at']}"
        )
        _issues(src["issues"])
        typer.echo(f"  {_classifier_state(src['classifier'])}")
        if text:
            typer.echo("")
            typer.echo(src["text"])
        typer.echo("")


@agents_app.command("set-instructions")
def agents_set_instructions(
    ref: str, file: Path = typer.Argument(..., help="A text file, or - for standard input.")
) -> None:
    """Set the agent's registered instructions; they are checked straight away."""
    row = _call("PUT", f"/v1/agents/{ref}/instructions", json={"text": _read_text(file)})
    _done("agent", ref, f"instructions set ({len(row['issues'])} problems found)")
    _issues(row["issues"])


@agents_app.command("clear-instructions")
def agents_clear_instructions(
    ref: str,
    source: str = typer.Option("registered", help="registered, telemetry or microsoft-365."),
    yes: bool = YES,
) -> None:
    """Forget the agent's instructions from one source."""
    _confirm(f"Forget the {source} instructions of {ref}?", yes)
    _call("DELETE", f"/v1/agents/{ref}/instructions", params={"source": source})
    _done("agent", ref, f"{source} instructions cleared")


@agents_app.command("rescan-instructions")
def agents_rescan_instructions(ref: str) -> None:
    """Check the stored instructions again (the classifier runs in the background)."""
    out = _call("POST", f"/v1/agents/{ref}/instructions/rescan")
    _done("agent", ref, f"{out['rescanned']} sets of instructions rescanned")


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
    traces: bool = typer.Option(False, "--traces", help="Add links to the trace viewer."),
) -> None:
    """Show the latest ledger entries, oldest first."""
    params: dict[str, Any] = {"limit": limit, **_given(type=type, agent=agent, decision=decision)}
    rows = list(reversed(_call("GET", "/v1/ledger", params=params)))
    columns = ["seq", "ts", "type", "agent_name", "resource", "decision", "reason"]
    _table(rows, columns + (["trace_url"] if traces else []))


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


# -------------------------------------------------------------------- access


@access_app.command("list")
def access_list() -> None:
    """People who have signed in with single sign-on, or were refused."""
    view = _call("GET", "/v1/access")
    if view["bootstrap_token"]:
        typer.echo(
            "note: the bootstrap admin token is set; anyone who has it is an admin", err=True
        )
    if not view["sso_enabled"]:
        typer.echo("note: single sign-on is not set up; people use API keys", err=True)
    rows = [
        {**p, "roles": ",".join(p["roles"]) or "-", "sessions": p["active_sessions"]}
        for p in view["people"]
    ]
    _table(rows, ["name", "status", "roles", "sessions", "last_sign_in", "subject"])


@access_app.command("sessions")
def access_sessions() -> None:
    """Sessions open now."""
    rows = [{**r, "roles": ",".join(r["roles"])} for r in _call("GET", "/v1/access")["sessions"]]
    _table(rows, ["id", "name", "roles", "started_at", "expires_at"])


@access_app.command("sign-out")
def access_sign_out(
    person: str = typer.Argument(..., help="The person's name (email) or subject."),
) -> None:
    """End every session of a person. Signing in again re-reads their roles."""
    people = _call("GET", "/v1/access")["people"]
    matches = [p for p in people if person in (p["name"], p["subject"])]
    if not matches:
        _fail(f"nobody called {person!r} has signed in")
    if len(matches) > 1:
        _fail(f"{len(matches)} people are called {person!r}; pass the subject instead")
    target = matches[0]
    out = _call("POST", f"/v1/access/people/{quote(target['subject'], safe='')}/sign-out")
    _done("person", target["name"], f"signed out ({out['ended']} sessions ended)")


@access_app.command("end-session")
def access_end_session(session_id: str) -> None:
    """End one session (see `agentgov access sessions`)."""
    _call("DELETE", f"/v1/access/sessions/{session_id}")
    _done("session", session_id, "ended")


# ----------------------------------------------------------------- platforms


def _synced(source: str, verb: str, counts: dict[str, int]) -> None:
    outcome = f"{counts['created']} new, {counts['updated']} updated, {counts['skipped']} skipped"
    if "findings" in counts:
        outcome += f"; {counts['findings']} open findings"
    _done("platform", source, f"{verb} ({outcome})")


@platforms_app.command("status")
def platforms_status() -> None:
    """Each source of platform agents and how its last sync or import went."""
    view = _call("GET", "/v1/platforms")
    rows = []
    for src in view["sources"]:
        last = src["last_sync"] or {}
        state = "not configured" if not src["configured"] else "never"
        if last:
            state = "ok" if last["ok"] else f"failed: {last['message']}"
        rows.append({**src, "last_sync": last.get("at"), "state": state})
    _table(rows, ["source", "mode", "agents", "last_sync", "state"])


@platforms_app.command("sync")
def platforms_sync(
    source: str = typer.Argument(
        "microsoft-365",
        help="microsoft-365 (as AgentGov's app), or copilot-studio (as you, after "
        "`agentgov login` through Microsoft Entra ID).",
    ),
) -> None:
    """Read a platform's agents now (the Microsoft 365 catalog is also read on a schedule)."""
    if source not in ("microsoft-365", "copilot-studio"):
        _fail("the source is microsoft-365 or copilot-studio")
    counts = _call("POST", f"/v1/platforms/{source}/sync", timeout=LONG_TIMEOUT)
    _synced(source, "synced", counts)


@platforms_app.command("import")
def platforms_import(
    file: Path = typer.Argument(
        ..., help="JSON from `pac resource-query` or the Power Platform API."
    ),
) -> None:
    """Import Copilot Studio agents from a Power Platform inventory export."""
    try:
        payload = json.loads(file.read_text())
    except (OSError, ValueError) as exc:
        _fail(f"cannot read {file}: {exc}")
    counts = _call("POST", "/v1/platforms/copilot-studio/import", json=payload)
    _synced("copilot-studio", "imported", counts)


@platforms_app.command("connectors")
def platforms_connectors() -> None:
    """Connectors Copilot Studio agents use, and whether each is on the allowlist."""
    view = _call("GET", "/v1/platforms/connectors")
    if not view["allowlist_active"]:
        typer.echo(
            "note: the allowlist is empty, so no connector is flagged yet; "
            "approve connectors to start checking",
            err=True,
        )
    rows = [
        {
            **r,
            "approved": "yes" if r["approved"] else "no",
            "agents": len(r["agents"]),
            "maker": r["maker_connections"],
        }
        for r in view["connectors"]
    ]
    _table(rows, ["connector_id", "approved", "agents", "maker", "note"])


def _connector(connector_id: str) -> str:
    """``shared_office365``, also given ``/providers/Microsoft.PowerApps/apis/shared_office365``."""
    return quote(connector_id.strip().rstrip("/").rsplit("/", 1)[-1], safe="")


@platforms_app.command("approve-connector")
def platforms_approve_connector(
    connector_id: str = typer.Argument(..., help="For example shared_office365."),
    note: str | None = typer.Option(None, help="Why it is allowed."),
) -> None:
    """Put a connector on the allowlist; agents using others get a finding."""
    out = _call(
        "PUT",
        f"/v1/platforms/connectors/{_connector(connector_id)}/approval",
        json={"note": note or ""},
    )
    _done("connector", out["connector_id"], "approved")


@platforms_app.command("unapprove-connector")
def platforms_unapprove_connector(connector_id: str) -> None:
    """Take a connector off the allowlist."""
    out = _call("DELETE", f"/v1/platforms/connectors/{_connector(connector_id)}/approval")
    _done("connector", out["connector_id"], "no longer approved")


# -------------------------------------------------------------- instructions


@instructions_app.command("check")
def instructions_check(
    file: Path = typer.Argument(..., help="A text file, or - for standard input."),
    classifier: bool = typer.Option(
        True, help="Also ask the classifier, when the control plane has one."
    ),
    fail_on: str = typer.Option(
        "high", help="Exit with 1 at or above this severity: critical, high, medium or low."
    ),
) -> None:
    """Check instructions without storing them, for example in a CI pipeline."""
    if fail_on not in SEVERITIES:
        _fail(f"--fail-on takes {', '.join(SEVERITIES)}")
    result = _call(
        "POST",
        "/v1/instructions/check",
        json={"text": _read_text(file), "classifier": classifier},
        timeout=LONG_TIMEOUT,
    )
    _issues(result["issues"])
    typer.echo(_classifier_state(result["classifier"]), err=True)
    worst = result["severity"]
    if worst is not None and SEVERITIES.index(worst) <= SEVERITIES.index(fail_on):
        raise typer.Exit(1)


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

"""The ``agentgov`` command line: run the services and administer the registry.

The administration commands are a thin layer over the HTTP API and follow the
admin UI's pages: agents, blueprints, tool servers, policies, approvals,
findings, the ledger, access (API keys), platforms, features and security
operations, plus a checker for agent instructions. Whatever the UI can change,
the CLI can change too, through the same endpoints and with the same role checks.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import csv
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
from collections.abc import Iterator
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
    help="Posture and threat findings, and the issues they are for the people responsible "
    "(lists open findings by default).",
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
db_app = typer.Typer(
    help="The control plane's database schema (run where the control plane runs, with "
    "AGENTGOV_DATABASE_URL).",
    no_args_is_help=True,
)
app.add_typer(db_app, name="db")
models_app = typer.Typer(
    help="Model providers agents call through the gateway, and what agents spend.",
    no_args_is_help=True,
)
app.add_typer(models_app, name="models")
mcp_app = typer.Typer(
    help="The MCP registry for developers' MCP clients, and the MCP servers developers set up.",
    no_args_is_help=True,
)
app.add_typer(mcp_app, name="mcp")
features_app = typer.Typer(
    help="Which features are used, and how strictly (off, monitor or enforce).",
    no_args_is_help=True,
)
app.add_typer(features_app, name="features")
issuers_app = typer.Typer(
    help="Identity issuers whose tokens agents authenticate with instead of client secrets.",
    no_args_is_help=True,
)
app.add_typer(issuers_app, name="issuers")
secops_app = typer.Typer(
    help="Security operations: what AgentGov hands to the security team's tools.",
    no_args_is_help=True,
)
app.add_typer(secops_app, name="secops")
destinations_app = typer.Typer(
    help="SIEMs, and Teams and Slack channels, that get AgentGov's events and alerts.",
    no_args_is_help=True,
)
app.add_typer(destinations_app, name="destinations")
teams_app = typer.Typer(
    help="Teams: people and chat channels that own agents, and that issues escalate to.",
    no_args_is_help=True,
)
app.add_typer(teams_app, name="teams")
packages_app = typer.Typer(
    help="Access packages: grants agents hold for a while once approved.",
    no_args_is_help=True,
)
app.add_typer(packages_app, name="access-packages")
rules_app = typer.Typer(
    help="Management rules: what to do about agents that meet some conditions for long enough.",
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")
evidence_app = typer.Typer(
    help="Compliance evidence: what AgentGov does towards the EU AI Act, ISO/IEC 42001 and "
    "the NIST AI RMF, and an evidence pack for assessors.",
    no_args_is_help=True,
)
app.add_typer(evidence_app, name="evidence")

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


IF_VERSION = typer.Option(
    None,
    "--if-version",
    help="Only if it is still at this version (from get): refused if someone changed it since.",
)


def _if_version(version: int | None) -> dict[str, Any]:
    """The request's If-Match, for an edit made from a version (registry/versions)."""
    return {"headers": {"If-Match": f'"{version}"'}} if version is not None else {}


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
    if not resp.content:  # 204 No Content
        return None
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


# A cell a spreadsheet would take for a formula (names and descriptions come from the
# platforms): kept as text.
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _csv(rows: list[dict[str, Any]], columns: list[str]) -> None:
    """The rows as CSV, for a spreadsheet: a header, then a line each."""
    out = csv.writer(sys.stdout, lineterminator="\n")
    out.writerow(columns)
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column)
            text = (
                ""
                if value is None
                else "; ".join(map(str, value))
                if isinstance(value, list)
                else str(value)
            )
            cells.append(f"'{text}" if text.startswith(FORMULA_START) else text)
        out.writerow(cells)


def _done(kind: str, name: str, outcome: str) -> None:
    typer.echo(f"{kind}/{name}: {outcome}")


# The control plane takes this many agents or findings a call: more are sent in turns.
AT_ONCE = 500


def _at_once(kind: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/{kind}s/bulk with every one named, in turns, the answers put together."""
    out: dict[str, Any] = {"done": [], "left": []}
    names = body[f"{kind}s"]
    for start in range(0, len(names), AT_ONCE):
        part = _call(
            "POST", f"/v1/{kind}s/bulk", json={**body, f"{kind}s": names[start : start + AT_ONCE]}
        )
        out["done"] += part["done"]
        out["left"] += part["left"]
    return out


def _many(
    kind: str, out: dict[str, Any], outcome: str | None = None, note: str | None = None
) -> None:
    """What one call did to many agents or findings: each done, then each left as it was,
    and why. Fails if it left any."""
    for row in out["done"]:
        _done(kind, row[kind], outcome or row["status"])
    if note:
        typer.echo(note, err=True)
    for row in out["left"]:
        typer.echo(f"{kind}/{row[kind]}: left as it was: {row['why']}", err=True)
    if out["left"]:
        raise typer.Exit(1)


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


def _model_access(values: list[str] | None) -> list[dict[str, Any]]:
    """Model grants written as ``provider:model,model`` (``provider:*`` for every model)."""
    grants = []
    for value in values or []:
        provider, sep, models = value.partition(":")
        names = [m.strip() for m in models.split(",") if m.strip()]
        if not sep or not provider.strip() or not names:
            _fail(f"model access looks like provider:model,model (got {value!r}); use provider:*")
        grants.append({"provider": provider.strip(), "models": names})
    return grants


def _model_fields(access: list[str] | None, budget: int | None, no_budget: bool) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if access is not None:
        body["model_access"] = _model_access(access)
    if no_budget:
        body["daily_token_budget"] = None
    elif budget is not None:
        body["daily_token_budget"] = budget
    return body


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
    "for agentgov-admin, agentgov-approver, agentgov-secops or agentgov-auditor.",
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
    """Run the control plane (API, admin UI, OPA bundle server). With AGENTGOV_TLS_DIR, it
    also listens on AGENTGOV_INTERNAL_PORT for AgentGov's other components, over mutual
    TLS."""
    import uvicorn

    from agentgov.config import Settings

    if dev:
        os.environ.setdefault("AGENTGOV_DEV_MODE", "true")
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    settings = Settings.from_env()
    if not settings.tls_dir:
        uvicorn.run(
            "agentgov.api.app:create_app",
            factory=True,
            host=host,
            port=port,
            timeout_keep_alive=settings.http_keepalive_seconds,
        )
        return
    asyncio.run(_serve_two(settings, host, port))


async def _serve_two(settings: Any, host: str, port: int) -> None:
    """The control plane on its public port, and on its internal one over mutual TLS: one
    app, one runtime."""
    import uvicorn

    from agentgov.api.app import create_app
    from agentgov.tls import InternalListener

    class Inner(uvicorn.Server):
        """The internal listener: the public one handles the process's signals."""

        @contextlib.contextmanager
        def capture_signals(self) -> Iterator[None]:
            yield

    app = create_app(settings)
    keepalive = settings.http_keepalive_seconds
    public = uvicorn.Server(uvicorn.Config(app, host=host, port=port, timeout_keep_alive=keepalive))
    internal = Inner(
        uvicorn.Config(
            InternalListener(app),
            host=host,
            port=settings.internal_port,
            timeout_keep_alive=keepalive,
            lifespan="off",
            **settings.tls().uvicorn_options(),
        )
    )
    serving = asyncio.create_task(public.serve())
    # Components wait for the runtime the public server starts.
    while not public.started and not serving.done():
        await asyncio.sleep(0.1)
    inner = asyncio.create_task(internal.serve())
    try:
        await serving
    finally:
        internal.should_exit = True
        await inner


@app.command()
def processor() -> None:
    """Run the governance processor (agentgateway ExtMcp gRPC server)."""
    from agentgov.config import Settings
    from agentgov.processor.server import serve

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    asyncio.run(serve(Settings.from_env()))


def _database() -> Any:
    from agentgov.config import Settings
    from agentgov.db import Database

    return Database(Settings.from_env().database_url)


@db_app.command("status")
def db_status() -> None:
    """The schema's revision, and the migrations this version would apply."""
    from agentgov import migrations

    db = _database()
    try:
        state = migrations.status(db.engine)
    except migrations.SchemaError as exc:
        _fail(str(exc))
    finally:
        db.dispose()
    if state.unversioned:
        current = "none: created before migrations (adopted at the next upgrade)"
    else:
        current = state.current or "none: an empty database"
    typer.echo(f"current: {current}")
    typer.echo(f"head:    {state.head}")
    typer.echo("pending: " + (", ".join(state.pending) or "nothing, the schema is up to date"))
    if not state.up_to_date:
        raise typer.Exit(1)


@db_app.command("upgrade")
def db_upgrade(
    sql: bool = typer.Option(
        False, "--sql", help="Print the SQL instead of running it, for review."
    ),
) -> None:
    """Bring the schema up to date (the control plane also does this when it starts,
    unless AGENTGOV_DATABASE_AUTO_MIGRATE is false)."""
    from agentgov import migrations

    db = _database()
    try:
        if sql:
            typer.echo(migrations.upgrade_sql(db.engine), nl=False)
            return
        adopted = migrations.status(db.engine).unversioned
        applied = migrations.upgrade(db.engine)
    except migrations.SchemaError as exc:
        _fail(str(exc))
    finally:
        db.dispose()
    if adopted:
        _done("database", migrations.BASELINE, "adopted (created before migrations)")
        applied = [revision for revision in applied if revision != migrations.BASELINE]
    if applied:
        _done("database", migrations.head(), "migrated (" + ", ".join(applied) + ")")
    else:
        _done("database", migrations.head(), "already up to date")


# AgentGov's components, by the names Compose reaches them by.
COMPONENTS = ["control-plane", "processor", "opa", "gateway", "otel-collector"]


@app.command("internal-certs")
def internal_certs(
    directory: Path = typer.Argument(
        ..., help="Where the authority (ca/) and each component's certificate (<name>/) go."
    ),
    component: list[str] | None = typer.Option(
        None,
        "--component",
        help="NAME, or NAME=HOST,HOST: a component and the names others reach it by "
        f"(default: {', '.join(COMPONENTS)}, each by its name).",
    ),
    renew: bool = typer.Option(
        False,
        "--renew",
        help="Give each component a new key and certificate from the same authority; they "
        "take it without a restart (AGENTGOV_TLS_RELOAD_SECONDS).",
    ),
) -> None:
    """Make AgentGov's own certificate authority, and a certificate for each component, for
    mutual TLS between them (AGENTGOV_TLS_DIR=<directory>/<name>). Each component's
    directory holds tls.crt, tls.key and ca.crt, as cert-manager writes them. What is
    there already is kept, unless --renew."""
    from agentgov import tls

    authority = tls.make_authority(directory / "ca")
    for spec in component or COMPONENTS:
        name, _, hosts = spec.partition("=")
        names = [h for h in hosts.split(",") if h] or [name]
        folder = tls.issue(
            authority,
            directory / name,
            f"agentgov-{name}",
            [*names, "localhost", "127.0.0.1"],
            renew=renew,
        )
        typer.echo(f"{name}: {folder}")


@app.command("bundle-signing-key")
def bundle_signing_key(
    directory: Path = typer.Argument(..., help="Where key.pem and cert.pem go."),
) -> None:
    """Make a key for signing OPA's bundles (key.pem, for AGENTGOV_BUNDLE_SIGNING_KEY_FILE)
    and a certificate OPA verifies them with (cert.pem). A pair already there is kept."""
    from agentgov.opa.signing import generate

    key, cert = generate(directory)
    typer.echo(f"key: {key}\ncertificate: {cert}")


@app.command("transparency-key")
def transparency_key(
    directory: Path = typer.Argument(..., help="Where the key and its public half go."),
    log: bool = typer.Option(
        False, "--log", help="A key for a log of your own (rekor-tiles) instead."
    ),
) -> None:
    """Make the key AgentGov signs the ledger's checkpoints with for a transparency log
    (key.pem, for AGENTGOV_LEDGER_REKOR_SIGNING_KEY_FILE: ECDSA P-256) and its public half
    (public.pem, for those who check the entries); with --log, the key a log of your own
    signs its checkpoints with (log.pem, for rekor-tiles' --signer-filepath: Ed25519) and
    its public half (log.pub, for AGENTGOV_LEDGER_REKOR_LOG_KEY_FILE). A key already there
    is kept."""
    from agentgov import transparency

    key, public = (
        transparency.generate_log_key(directory) if log else transparency.generate(directory)
    )
    typer.echo(f"key: {key}\npublic key: {public}")


@app.command("gateway-config")
def gateway_config(
    output: Path = typer.Option(
        ..., "--output", "-o", help="The file agentgateway reads (-f), on a shared volume."
    ),
    once: bool = typer.Option(
        False, "--once", help="Write it once and stop (as an init container)."
    ),
    interval: float = typer.Option(5.0, help="Seconds between checks for changes."),
    heartbeat: Path | None = typer.Option(
        None, help="A file to touch every round, for a liveness probe."
    ),
) -> None:
    """Keep agentgateway's configuration current from the control plane, for gateways
    that don't share a volume with it (a sidecar in Kubernetes). Uses
    AGENTGOV_CONTROL_PLANE_URL and AGENTGOV_SERVICE_TOKEN."""
    import httpx

    from agentgov.config import Settings
    from agentgov.gateway import keep_current

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # One request every few seconds: log what changes, not each check.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    settings = Settings.from_env()
    if not settings.service_token:
        _fail("set AGENTGOV_SERVICE_TOKEN (the control plane's service token)")
    identity = settings.tls()  # mutual TLS: the control plane's internal port
    with httpx.Client(
        base_url=settings.control_plane_url,
        headers={"Authorization": f"Bearer {settings.service_token}"},
        timeout=10,
        transport=identity.transport() if identity else None,
    ) as client:
        keep_current(
            client,
            str(output),
            interval=interval,
            once=once,
            heartbeat=str(heartbeat) if heartbeat else None,
            # The gateway's certificate (the same files as its own): a renewed one rewrites
            # the file, so that agentgateway reads it again.
            certificates=identity,
        )


@app.command()
def apply(
    files: list[Path] = typer.Option(..., "--file", "-f", help="Manifest file or directory."),
) -> None:
    """Apply declarative manifests (Feature, Destination, Team, IdentityIssuer, Blueprint,
    ToolServer, ModelProvider, AccessPackage, Policy, Agent)."""
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
def start(
    place: list[str] = typer.Option(
        [],
        "--place",
        help="Where your agents are (repeat it): copilot-studio, microsoft-365, entra-agent-id, "
        "aws, google-cloud, salesforce, databricks, microsoft-foundry, gateway.",
    ),
    hide: bool | None = typer.Option(None, "--hide/--show", help="Hide the checklist, or show it."),
) -> None:
    """Where to start: say where your agents are, then follow the checklist."""
    if place:
        result = _call("PUT", "/v1/start", json={"places": place})
    elif hide is not None:
        result = _call("PUT", "/v1/start", json={"hidden": hide})
    else:
        result = _call("GET", "/v1/start")
    for step in result["steps"]:
        mark = "x" if step["done"] else " "
        detail = f": {step['detail']}" if step.get("detail") else ""
        typer.echo(f"[{mark}] {step['title']}{detail}")
        if step["key"] == "agents" and not step["done"]:
            for how in step.get("how") or []:
                typer.echo(f"      {how['name']}: {how['how']}")
    if not result["places"]:
        typer.echo("\nSay where your agents are: agentgov start --place copilot-studio ...")


@app.command()
def overview() -> None:
    """Show the governance overview."""
    _print(_call("GET", "/v1/overview"))


@app.command()
def replicas() -> None:
    """The control plane's replicas, and the one that runs the scheduled work."""
    rows = _call("GET", "/v1/replicas")
    for r in rows:
        r["role"] = "leader" if r["leader"] else ""
        r["answering"] = "this one" if r.get("this") else ""
        if r.get("this") and r.get("listening") is False:
            r["answering"] += ", out of touch with the others"
    _table(rows, ["name", "role", "answering", "connected_since"])


# -------------------------------------------------------------------- agents


AS_CSV = typer.Option(False, "--csv", help="As CSV, with more columns: for a spreadsheet.")
REASON = typer.Option(None, help="Recorded in the evidence ledger.")
AGENT_REFS = typer.Argument(..., help="The agents, by name or ID: one, or several at once.")
AGENT_CSV = [
    "name",
    "id",
    "status",
    "risk_level",
    "risk_score",
    "owner",
    "sponsors",
    "team",
    "blueprint",
    "source",
    "environment",
    "maker",
    "created_at",
    "last_seen_at",
    "description",
]


@agents_app.command("list")
def agents_list(
    status: str | None = None,
    source: str | None = typer.Option(
        None,
        help="registered, discovered:<how>, or platform:<platform> (microsoft-365, "
        "copilot-studio, aws, google-cloud, salesforce, databricks, microsoft-foundry).",
    ),
    risk: str | None = typer.Option(None, help="Only those at this risk level."),
    as_csv: bool = AS_CSV,
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Only their names, one a line: to give other commands."
    ),
) -> None:
    """List agents (all but deleted ones, unless --status is given)."""
    rows = _call("GET", "/v1/agents", params=_given(status=status, source=source, risk_level=risk))
    if quiet:
        for r in rows:
            typer.echo(r["name"])
        return
    if as_csv:
        for r in rows:
            r["risk_level"], r["risk_score"] = r["risk"]["level"], r["risk"]["score"]
            maker = r.get("maker") or {}
            r["maker"] = maker.get("email") or maker.get("name") or maker.get("entra_id")
        _csv(rows, AGENT_CSV)
        return
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
MODEL_ACCESS = typer.Option(
    None, "--model-access", help="Models it may call, provider:model,model (repeatable)."
)
TOKEN_BUDGET = typer.Option(None, help="Tokens it may use per day (UTC), in and out.")
NO_TOKEN_BUDGET = typer.Option(False, "--no-token-budget", help="No daily token budget.")
TEAM = typer.Option(
    None,
    help="The team issues about it escalate to after its owner and sponsors, instead of its "
    "blueprint's ('' for its blueprint's).",
)
BP_TEAM = typer.Option(
    None,
    help="The team issues about its agents escalate to after their owners and sponsors ('' "
    "for the default team).",
)


def _team_field(team: str | None) -> dict[str, Any]:
    # An empty string clears it.
    return {} if team is None else {"team": team or None}


WORKLOAD_IDENTITY = typer.Option(
    None,
    "--workload-identity",
    help="Authenticate with this identity instead of a client secret: ISSUER:SUBJECT, such "
    "as cluster:system:serviceaccount:agents:support-bot.",
)


A2A_URL = typer.Option(
    None,
    "--a2a-url",
    help="Where it serves A2A (its JSON-RPC endpoint): other agents call it through the "
    "gateway at /a2a/<name>.",
)
AGENT_ACCESS = typer.Option(
    None,
    "--agent-access",
    help="Agents it may call over A2A, by name or pattern such as billing-* (repeatable or "
    "comma-separated).",
)
A2A_PROTECTION = typer.Option(
    None,
    "--a2a-protection",
    help="What stops calls to it that don't come through the gateway: network (only the "
    "gateway can reach it) or delegation (it refuses calls without the delegation the "
    "gateway gives with each one).",
)


def _a2a_fields(
    a2a_url: str | None,
    agent_access: list[str] | None,
    *,
    no_a2a: bool = False,
    no_agent_access: bool = False,
    a2a_protection: str | None = None,
    no_a2a_protection: bool = False,
) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if no_a2a:
        body["a2a_url"] = None
    elif a2a_url is not None:
        body["a2a_url"] = a2a_url
    if no_a2a_protection:
        body["a2a_protection"] = None
    elif a2a_protection is not None:
        body["a2a_protection"] = a2a_protection
    if no_agent_access:
        body["agent_access"] = []
    elif agent_access is not None:
        body["agent_access"] = _split(agent_access)
    return body


CLIENT_TYPE = typer.Option(
    None,
    "--client-type",
    help="service (the default): it gets tokens for itself, with a secret or its workload "
    "identity; or public: people sign in to it on their own machines, such as developers' "
    "MCP clients, and it acts for them.",
)
REDIRECT_URI = typer.Option(
    None,
    "--redirect-uri",
    help="Where a sign-in to a public client may return (repeatable; * only at the end). By "
    "default, the machine itself at any port: http://127.0.0.1/* and http://localhost/*.",
)


def _client_fields(
    client_type: str | None, redirect_uris: list[str] | None, *, default_redirects: bool = False
) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if client_type is not None:
        body["client_type"] = client_type
    if default_redirects:
        body["redirect_uris"] = []
    elif redirect_uris is not None:
        body["redirect_uris"] = _split(redirect_uris)
    return body


def _workload_identity(value: str | None, *, clear: bool = False) -> dict[str, Any]:
    if clear:
        return {"workload_identity": None}
    if value is None:
        return {}
    issuer, sep, subject = value.partition(":")
    if not sep or not issuer or not subject:
        _fail(
            "--workload-identity looks like ISSUER:SUBJECT, such as "
            "cluster:system:serviceaccount:agents:support-bot"
        )
    return {"workload_identity": {"issuer": issuer, "subject": subject}}


@agents_app.command("create")
def agents_create(
    name: str,
    description: str | None = DESCRIPTION,
    blueprint: str | None = AGENT_BLUEPRINT,
    owner: str | None = OWNER,
    sponsor: list[str] | None = SPONSOR,
    team: str | None = TEAM,
    environment: str | None = ENVIRONMENT,
    framework: str | None = None,
    platform: str | None = None,
    model: list[str] | None = MODEL,
    grant: list[str] | None = GRANT,
    model_access: list[str] | None = MODEL_ACCESS,
    token_budget: int | None = TOKEN_BUDGET,
    label: list[str] | None = LABEL,
    risk_tier: str | None = RISK_TIER,
    workload_identity: str | None = WORKLOAD_IDENTITY,
    a2a_url: str | None = A2A_URL,
    agent_access: list[str] | None = AGENT_ACCESS,
    a2a_protection: str | None = A2A_PROTECTION,
    client_type: str | None = CLIENT_TYPE,
    redirect_uri: list[str] | None = REDIRECT_URI,
    approve: bool = typer.Option(False, "--approve", help="Activate it now (admins only)."),
) -> None:
    """Register an agent. It waits in pending review unless --approve is given."""
    body = (
        _model_fields(model_access, token_budget, False)
        | _team_field(team)
        | _workload_identity(workload_identity)
        | _client_fields(client_type, redirect_uri)
        | _a2a_fields(a2a_url, agent_access, a2a_protection=a2a_protection)
        | _agent_fields(
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
    )
    agent = _call("POST", "/v1/agents", json={"name": name, **body, "approve": approve})
    _done("agent", agent["name"], agent["status"])


# What an edit to several agents at once may change (and --add-sponsor, --remove-sponsor).
EDITS_AT_ONCE = {"owner", "team", "sponsors", "blueprint", "environment", "risk_tier"}


@agents_app.command("update")
def agents_update(
    refs: list[str] = AGENT_REFS,
    description: str | None = DESCRIPTION,
    blueprint: str | None = AGENT_BLUEPRINT,
    owner: str | None = OWNER,
    sponsor: list[str] | None = typer.Option(
        None, "--sponsor", help="Sponsors (replace the current ones; repeatable)."
    ),
    add_sponsor: list[str] | None = typer.Option(
        None, "--add-sponsor", help="Add a sponsor to each one's own (repeatable)."
    ),
    remove_sponsor: list[str] | None = typer.Option(
        None, "--remove-sponsor", help="Take a sponsor from each one's own (repeatable)."
    ),
    reason: str | None = REASON,
    team: str | None = TEAM,
    environment: str | None = ENVIRONMENT,
    framework: str | None = None,
    platform: str | None = None,
    model: list[str] | None = MODEL,
    grant: list[str] | None = typer.Option(
        None, "--grant", help="Extra grants server:tool,tool (replace the current ones)."
    ),
    clear_grants: bool = typer.Option(False, "--clear-grants", help="Remove the extra grants."),
    model_access: list[str] | None = typer.Option(
        None, "--model-access", help="Extra model access provider:model,model (replace it)."
    ),
    token_budget: int | None = TOKEN_BUDGET,
    no_token_budget: bool = typer.Option(
        False, "--no-token-budget", help="Use its blueprint's budget."
    ),
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    risk_tier: str | None = RISK_TIER,
    workload_identity: str | None = WORKLOAD_IDENTITY,
    no_workload_identity: bool = typer.Option(
        False, "--no-workload-identity", help="Go back to a client secret."
    ),
    a2a_url: str | None = A2A_URL,
    no_a2a: bool = typer.Option(False, "--no-a2a", help="It no longer serves A2A."),
    agent_access: list[str] | None = typer.Option(
        None, "--agent-access", help="Agents it may call over A2A (replace them)."
    ),
    no_agent_access: bool = typer.Option(
        False, "--no-agent-access", help="Only the agents its blueprint may call."
    ),
    a2a_protection: str | None = A2A_PROTECTION,
    no_a2a_protection: bool = typer.Option(
        False,
        "--no-a2a-protection",
        help="Nothing is known to stop calls to it that don't come through the gateway.",
    ),
    client_type: str | None = CLIENT_TYPE,
    redirect_uri: list[str] | None = typer.Option(
        None, "--redirect-uri", help="Where a sign-in to it may return (replace them)."
    ),
    default_redirect_uris: bool = typer.Option(
        False,
        "--default-redirect-uris",
        help="Back to the machine itself, at any port.",
    ),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change an agent's details. Only the options you pass are changed."""
    body = (
        _model_fields(model_access, token_budget, no_token_budget)
        | _team_field(team)
        | _workload_identity(workload_identity, clear=no_workload_identity)
        | _client_fields(client_type, redirect_uri, default_redirects=default_redirect_uris)
        | _a2a_fields(
            a2a_url,
            agent_access,
            no_a2a=no_a2a,
            no_agent_access=no_agent_access,
            a2a_protection=a2a_protection,
            no_a2a_protection=no_a2a_protection,
        )
        | _agent_fields(
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
    )
    if len(refs) > 1 or add_sponsor or remove_sponsor or reason:
        # Several at once, each on its own: who is accountable for them, and how they are
        # governed.
        if if_version is not None:
            _fail(
                "--if-version goes with one agent, without --add-sponsor, --remove-sponsor or "
                "--reason"
            )
        other = sorted(set(body) - EDITS_AT_ONCE)
        if other:
            _fail(
                "several agents at once, or with --add-sponsor, --remove-sponsor or --reason, "
                "take --owner, --team, --sponsor, --blueprint, --environment and --risk-tier: "
                f"change {', '.join(other)} one agent at a time"
            )
        if add_sponsor:
            body["add_sponsors"] = _split(add_sponsor)
        if remove_sponsor:
            body["remove_sponsors"] = _split(remove_sponsor)
        if not body:
            _fail("nothing to change: pass at least one option (see --help)")
        out = _at_once("agent", _given(action="update", agents=refs, fields=body, reason=reason))
        _many("agent", out, "updated")
        return
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    agent = _call("PATCH", f"/v1/agents/{refs[0]}", json=body, **_if_version(if_version))
    _done("agent", agent["name"], "updated")


@agents_app.command("a2a")
def agents_a2a(ref: str) -> None:
    """Agent to agent: where other agents call it, whom it may call, who may call it."""
    view = _call("GET", f"/v1/agents/{ref}/a2a")
    if view["published"]:
        typer.echo(f"serves A2A at {view['a2a_url']}; other agents call it at {view['url']}")
        typer.echo(f"its card: {view['card_url']}")
    elif view["serves"]:
        typer.echo(f"serves A2A at {view['a2a_url']}; not on the gateway: {view['unpublished']}")
    else:
        typer.echo("doesn't serve A2A (agentgov agents update REF --a2a-url URL)")
    typer.echo(f"may call: {', '.join(view['may_call']) or 'no agent'}")
    if view["agent_access"]:
        typer.echo(f"  (grants: {', '.join(view['agent_access'])})")
    typer.echo(f"called by: {', '.join(view['called_by']) or 'no agent'}")
    if view["serves"]:
        around = view["around_gateway"]
        says = AROUND_THE_GATEWAY.get(around["protection"] or "")
        typer.echo(
            f"calls around the gateway: stopped by {says}"
            if says
            else "calls around the gateway: its owners haven't said what stops them"
        )
        test = around["test"]
        if test:
            typer.echo(f"  tested {test['checked_at']}: {test['state']}, {test['detail']}")
        elif around["mode"] != "test":
            typer.echo(f"  not tested (calls-around-gateway is {around['mode']})")


AROUND_THE_GATEWAY = {
    "network": "the network (only the gateway can reach it)",
    "delegation": "the agent (it refuses calls without the gateway's delegation)",
}


def _lifecycle(refs: str | list[str], action: str, reason: str | None) -> None:
    """One agent, or several at once: each on its own, those it can't do left as they are."""
    names = [refs] if isinstance(refs, str) else list(refs)
    if len(names) == 1:
        agent = _call(
            "POST", f"/v1/agents/{names[0]}/{action}", json={"reason": reason} if reason else {}
        )
        _done("agent", agent["name"], agent["status"])
        return
    out = _at_once("agent", _given(action=action, agents=names, reason=reason))
    elsewhere = sorted({row["platform"] for row in out["done"] if row.get("platform")})
    note = (
        f"Those on {', '.join(elsewhere)} still run there: this changed AgentGov, not "
        f"{'it' if len(elsewhere) == 1 else 'them'}."
        if elsewhere and action in ("block", "delete")
        else None
    )
    _many("agent", out, note=note)


@agents_app.command("approve")
def agents_approve(refs: list[str] = AGENT_REFS, reason: str | None = REASON) -> None:
    """Approve pending agents: each becomes active (needs a sponsor)."""
    _lifecycle(refs, "approve", reason)


IN_PLATFORM = typer.Option(
    False,
    "--in-platform",
    help="For agents on Microsoft 365 or Copilot Studio: also do it there, as you "
    "(needs `agentgov login` through Microsoft Entra ID).",
)


@agents_app.command("block")
def agents_block(
    refs: list[str] = AGENT_REFS,
    reason: str = typer.Option("blocked from CLI", help="Why."),
    in_platform: bool = IN_PLATFORM,
) -> None:
    """Kill switch: block agents everywhere (identity, gateway, in-process OPA)."""
    if in_platform and len(refs) > 1:
        _fail("--in-platform blocks one agent at a time")
    # AgentGov first, then the platform: if the platform refuses, AgentGov has still blocked it.
    _lifecycle(refs, "block", reason)
    if in_platform:
        _platform_block(refs[0], blocked=True)


@agents_app.command("unblock")
def agents_unblock(
    refs: list[str] = AGENT_REFS, reason: str | None = REASON, in_platform: bool = IN_PLATFORM
) -> None:
    """Unblock agents: their calls are evaluated against policy again."""
    if in_platform and len(refs) > 1:
        _fail("--in-platform unblocks one agent at a time")
    # AgentGov first: if it refuses (an agent needs a sponsor), the platform keeps it blocked.
    _lifecycle(refs, "unblock", reason)
    if in_platform:
        _platform_block(refs[0], blocked=False)


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
def agents_delete(refs: list[str] = AGENT_REFS, reason: str | None = REASON) -> None:
    """Delete agents (soft: they can be restored, or purged for good)."""
    _lifecycle(refs, "delete", reason)


@agents_app.command("restore")
def agents_restore(refs: list[str] = AGENT_REFS, reason: str | None = REASON) -> None:
    """Restore deleted agents; they come back pending review."""
    _lifecycle(refs, "restore", reason)


@agents_app.command("adopt")
def agents_adopt(
    refs: list[str] = typer.Argument(
        None, help="The agents, by name or ID; with --platform, those it found as well."
    ),
    platform: str | None = typer.Option(
        None,
        "--platform",
        help="Every agent found on this platform that waits to be adopted (copilot-studio, "
        "aws, ...).",
    ),
    makers: bool = typer.Option(
        False,
        "--makers",
        help="Make each agent's maker on its platform its owner and sponsor, where AgentGov "
        "knows them.",
    ),
    owner: str | None = typer.Option(
        None, "--owner", help="A team or a person: for all, or those whose maker isn't known."
    ),
    sponsor: list[str] = typer.Option(None, "--sponsor", help="Repeatable."),
    reason: str | None = REASON,
) -> None:
    """Adopt agents found on platforms, several at once: each pending review, with an owner
    and sponsors. Those that can't be adopted are left, each with why."""
    names = list(refs or [])
    if platform:
        listed = _call(
            "GET", "/v1/agents", params={"status": "discovered", "source": f"platform:{platform}"}
        )
        names += [a["name"] for a in listed]
    if not names:
        _fail("name the agents to adopt, or a --platform")
    if not makers and not owner:
        _fail("give them an --owner, or their --makers")
    body: dict[str, Any] = {"agents": names, "makers": makers}
    if owner:
        body["owner"] = owner
    if sponsor:
        body["sponsors"] = _split(sponsor)
    if reason:
        body["reason"] = reason
    out = _call("POST", "/v1/agents/adopt", json=body)
    for adopted in out["adopted"]:
        typer.echo(f"adopted {adopted['agent']}: owner {adopted['owner']}")
    for left in out["left"]:
        typer.echo(f"left {left['agent']}: {left['why']}", err=True)


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
    """Print the agent's OAuth client credentials (--rotate issues a new secret); for an
    agent with a workload identity, how it authenticates without a secret; and for a public
    client, where people sign in to it."""
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
    return {
        "off": "classifier: not configured",
        "pending": "classifier: pending",
        "unchecked": "not checked: instruction checks were off",
    }.get(state, f"classifier: {state}")


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
        if src["classifier"].get("state") != "unchecked":
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
    _table(rows, ["name", "risk_tier", "require_sponsor", "review", "acts_for", "grants"])


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


REQUIRE_WORKLOAD_IDENTITY = typer.Option(
    None,
    "--require-workload-identity/--allow-secrets",
    help="Whether its agents must authenticate with a workload identity, never a secret.",
)


def _people_fields(
    acts_for: str | None,
    people_groups: list[str] | None,
    all_people: bool,
    approvals_by: str | None,
) -> dict[str, Any]:
    body = _given(acts_for=acts_for, approvals_by=approvals_by)
    if all_people:
        body["people_groups"] = []
    elif people_groups is not None:
        body["people_groups"] = _split(people_groups)
    return body


ACTS_FOR = typer.Option(
    None,
    help="Who its agents act for: people (only for a person), itself (only on their own) "
    "or either.",
)
PEOPLE_GROUPS = typer.Option(
    None,
    "--people-groups",
    help="Groups the people its agents act for must be in (repeatable or comma-separated).",
)
ALL_PEOPLE = typer.Option(False, "--all-people", help="Act for people in any group.")
APPROVALS_BY = typer.Option(
    None,
    help="Who decides approval requests made for a person: approvers or person (the "
    "person the agent acted for).",
)
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
    model_access: list[str] | None = MODEL_ACCESS,
    token_budget: int | None = TOKEN_BUDGET,
    acts_for: str | None = ACTS_FOR,
    people_groups: list[str] | None = PEOPLE_GROUPS,
    approvals_by: str | None = APPROVALS_BY,
    require_workload_identity: bool | None = REQUIRE_WORKLOAD_IDENTITY,
    agent_access: list[str] | None = AGENT_ACCESS,
    team: str | None = BP_TEAM,
    label: list[str] | None = LABEL,
) -> None:
    """Create a blueprint."""
    body = (
        _blueprint_fields(
            description, grant, risk_tier, review_days, no_review, require_sponsor, label
        )
        | _team_field(team)
        | _model_fields(model_access, token_budget, False)
        | _a2a_fields(None, agent_access)
        | _people_fields(acts_for, people_groups, False, approvals_by)
        | _given(require_workload_identity=require_workload_identity)
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
    model_access: list[str] | None = typer.Option(
        None, "--model-access", help="Model access provider:model,model (replace it)."
    ),
    token_budget: int | None = TOKEN_BUDGET,
    no_token_budget: bool = NO_TOKEN_BUDGET,
    acts_for: str | None = ACTS_FOR,
    people_groups: list[str] | None = typer.Option(
        None, "--people-groups", help="Groups the people must be in (replace them)."
    ),
    all_people: bool = ALL_PEOPLE,
    approvals_by: str | None = APPROVALS_BY,
    require_workload_identity: bool | None = REQUIRE_WORKLOAD_IDENTITY,
    agent_access: list[str] | None = typer.Option(
        None, "--agent-access", help="Agents its agents may call over A2A (replace them)."
    ),
    no_agent_access: bool = typer.Option(
        False, "--no-agent-access", help="Its agents may call no other agent."
    ),
    team: str | None = BP_TEAM,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change a blueprint. Every agent on it gets the change."""
    body = (
        _blueprint_fields(
            description, grant, risk_tier, review_days, no_review, require_sponsor, label
        )
        | _team_field(team)
        | _model_fields(model_access, token_budget, no_token_budget)
        | _people_fields(acts_for, people_groups, all_people, approvals_by)
        | _given(require_workload_identity=require_workload_identity)
        | _a2a_fields(None, agent_access, no_agent_access=no_agent_access)
    )
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    bp = _call("PATCH", f"/v1/blueprints/{name}", json=body, **_if_version(if_version))
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


def _packages(values: list[str]) -> list[dict[str, Any]]:
    """Packages written as ``type:identifier[@version]``: npm:@playwright/mcp@0.0.41."""
    packages = []
    for value in values:
        kind, sep, rest = value.partition(":")
        identifier, at, version = rest.rpartition("@")
        if not at or not identifier:  # no version, or only a scope's "@"
            identifier, version = rest, ""
        if not sep or not identifier:
            _fail(f"packages look like type:identifier@version, e.g. npm:@playwright/mcp@0.0.41 "
                  f"(got {value!r})")  # fmt: skip
        packages.append(
            {
                "registry_type": kind,
                "identifier": identifier,
                **({"version": version} if version else {}),
            }
        )
    return packages


def _toolserver_fields(
    url: str | None,
    description: str | None,
    owner: str | None,
    trust: str | None,
    classification: str | None,
    label: list[str] | None,
    *,
    gateway: bool | None = None,
    developers: bool | None = None,
    package: list[str] | None = None,
    registry_name: str | None = None,
    authorization_server: str | None = None,
    oauth_client_id: str | None = None,
) -> dict[str, Any]:
    body = _given(
        url=url,
        description=description,
        trust_level=trust,
        data_classification=classification,
        gateway=gateway,
        developers=developers,
    )
    if owner is not None:
        body["owner"] = owner or None
    if label is not None:
        body["labels"] = _labels(label)
    if package is not None:
        body["packages"] = _packages(package)
    if registry_name is not None:
        body["registry_name"] = registry_name or None
    if authorization_server is not None:
        body["authorization_server"] = authorization_server or None
    if oauth_client_id is not None:
        body["oauth_client_id"] = oauth_client_id or None
    return body


GATEWAY = typer.Option(
    None, "--gateway/--no-gateway", help="Publish it on the gateway for agents (default)."
)
DEVELOPERS = typer.Option(
    None,
    "--developers/--no-developers",
    help="List it for developers, in the MCP registry their MCP clients read.",
)
PACKAGE = typer.Option(
    None,
    "--package",
    help="A package developers run, type:identifier@version (repeatable; replaces them).",
)
REGISTRY_NAME = typer.Option(
    None, help="Its name in the MCP registry (default <namespace>/<name>)."
)
AUTHORIZATION_SERVER = typer.Option(
    None,
    "--authorization-server",
    help="For a server outside the gateway: the issuer of the authorization server it takes "
    "access tokens from. Agents get identity assertions (ID-JAG) for it from AgentGov ('' "
    "to remove it).",
)
OAUTH_CLIENT_ID = typer.Option(
    None,
    "--oauth-client-id",
    help="The client AgentGov's agents are at that authorization server (default: each "
    "agent's own client ID; '' to go back to it).",
)


@toolservers_app.command("create")
def toolservers_create(
    name: str,
    url: str | None = typer.Option(
        None, help="The server's streamable HTTP MCP endpoint (for the gateway: required)."
    ),
    description: str | None = DESCRIPTION,
    owner: str | None = OWNER,
    trust: str | None = TRUST,
    classification: str | None = CLASSIFICATION,
    label: list[str] | None = LABEL,
    gateway: bool | None = GATEWAY,
    developers: bool | None = DEVELOPERS,
    package: list[str] | None = PACKAGE,
    registry_name: str | None = REGISTRY_NAME,
    authorization_server: str | None = AUTHORIZATION_SERVER,
    oauth_client_id: str | None = OAUTH_CLIENT_ID,
) -> None:
    """Register a tool server (admins: approved at once; registrars: pending review)."""
    body = _toolserver_fields(
        url, description, owner, trust, classification, label,
        gateway=gateway, developers=developers, package=package, registry_name=registry_name,
        authorization_server=authorization_server, oauth_client_id=oauth_client_id,
    )  # fmt: skip
    ts = _call("POST", "/v1/toolservers", json={"name": name, **body})
    where = [f"published at {ts['gateway_url']}"] if ts["gateway_url"] else []
    if ts["developers"]:
        where.append("listed for developers")
    if ts.get("authorization_server"):
        where.append(f"reached with assertions for {ts['authorization_server']}")
    _done("toolserver", ts["name"], ", ".join([ts["status"], *where]))


@toolservers_app.command("update")
def toolservers_update(
    name: str,
    url: str | None = typer.Option(None, help="New upstream MCP endpoint."),
    description: str | None = DESCRIPTION,
    owner: str | None = OWNER,
    trust: str | None = TRUST,
    classification: str | None = CLASSIFICATION,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    gateway: bool | None = GATEWAY,
    developers: bool | None = DEVELOPERS,
    package: list[str] | None = PACKAGE,
    registry_name: str | None = REGISTRY_NAME,
    authorization_server: str | None = AUTHORIZATION_SERVER,
    oauth_client_id: str | None = OAUTH_CLIENT_ID,
    if_version: int | None = IF_VERSION,
) -> None:
    """Change a tool server's details."""
    body = _toolserver_fields(
        url, description, owner, trust, classification, label,
        gateway=gateway, developers=developers, package=package, registry_name=registry_name,
        authorization_server=authorization_server, oauth_client_id=oauth_client_id,
    )  # fmt: skip
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    ts = _call("PATCH", f"/v1/toolservers/{name}", json=body, **_if_version(if_version))
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
    if_version: int | None = IF_VERSION,
) -> None:
    """Replace a policy's source or description (checked before it is saved)."""
    body = _given(description=description)
    if file is not None:
        body["rego"] = file.read_text()
    if not body:
        _fail("nothing to change: pass --file or --description")
    policy = _call("PUT", f"/v1/policies/{name}", json=body, **_if_version(if_version))
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
    server: str | None = typer.Option(None, help="Tool server name (with --tool)."),
    tool: str | None = typer.Option(None, help="Tool name."),
    provider: str | None = typer.Option(
        None, help="Model provider name (with --model), for a model call instead."
    ),
    model: str | None = typer.Option(None, help="Model the agent asks for."),
    call_agent: str | None = typer.Option(
        None, "--call-agent", help="Another agent it calls over A2A, for a call between agents."
    ),
    agent: str | None = typer.Option(None, help="Agent (default: an unregistered caller)."),
    phase: str = typer.Option(
        "request", help="request (the call or prompt) or response (the result or answer)."
    ),
    pii: bool = typer.Option(False, "--pii", help="Personal data was detected."),
    secret: bool = typer.Option(False, "--secret", help="A credential was detected."),
    injection: bool = typer.Option(
        False,
        "--injection",
        help="Prompt injection in the result (in a model call: in a tool result it holds).",
    ),
    jailbreak: bool = typer.Option(False, "--jailbreak", help="The prompt is a jailbreak."),
    tool_calls: bool = typer.Option(
        False, "--tool-calls", help="The model call's conversation holds tool calls."
    ),
    user: str | None = typer.Option(
        None, "--user", help="The person the agent acts for (default: it acts on its own)."
    ),
    groups: list[str] | None = typer.Option(
        None, "--groups", help="The person's groups (repeatable or comma-separated)."
    ),
    via: str = typer.Option(
        "exchange", help="How the agent got the person's token: exchange or delegation."
    ),
    as_json: bool = typer.Option(False, "--json", help="Print OPA's full result."),
) -> None:
    """What if: ask the live OPA what it would decide for a tool call, a model call or a
    call to another agent. Nothing is recorded."""
    kinds = [bool(server and tool), bool(provider and model), bool(call_agent)]
    if kinds.count(True) != 1:
        _fail(
            "give --server and --tool for a tool call, --provider and --model for a model "
            "call, or --call-agent for a call to another agent"
        )
    if agent:
        found = _call("GET", f"/v1/agents/{agent}")
        caller = {"agent_id": found["id"], "client_id": found["identity"]["client_id"]}
    else:
        caller = {"client_id": "agent-not-registered"}
    categories = [c for c, on in (("pii", pii), ("secret", secret)) if on]
    detections: dict[str, Any] = {
        "categories": categories,
        "prompt_injection": injection,
        "injection_score": 0.95 if injection else 0,
    }
    if call_agent:
        path = "agentgov/a2a/decision"
        decision_input = {
            "kind": "a2a",
            "method": "SendMessage",
            "agent": {k: v for k, v in caller.items() if v},
            "target": call_agent,
            "chain": [],
            "detections": detections,
        }
    elif provider:
        path = "agentgov/models/decision"
        decision_input: dict[str, Any] = {
            "kind": "model",
            "phase": phase,
            "agent": {k: v for k, v in caller.items() if v},
            "provider": provider,
            "model": model,
            "detections": {**detections, "jailbreak": jailbreak},
            "tool_calls": tool_calls,
        }
    else:
        path = "agentgov/mcp/decision"
        decision_input = {
            "phase": phase,
            "method": "tools/call",
            "agent": {k: v for k, v in caller.items() if v},
            "resource": {"server": server, "name": tool},
            "detections": detections,
        }
    if user:
        if via not in ("exchange", "delegation"):
            _fail(f"--via is exchange or delegation (got {via!r})")
        decision_input["user"] = {
            "id": user,
            "username": user,
            "groups": _split(groups),
            "roles": [],
            "via": via,
        }
        if call_agent:
            decision_input["chain"] = [{"type": "person", "id": user, "name": user}]
    body = {"path": path, "input": decision_input}
    result = _call("POST", "/v1/policies/evaluate", json=body)["result"]
    if as_json or not result:
        _print(result)
        return
    typer.echo(result.get("effect", "none"))
    for reason in result.get("reasons", []):
        typer.echo(f"  - {reason}")
    if result.get("redact"):
        typer.echo(f"  redact: {', '.join(result['redact'])}")
    for monitored in result.get("monitored") or []:
        typer.echo(f"  monitored: {monitored}")


# ----------------------------------------------------------------- approvals


@approvals_app.command("list")
def approvals_list(
    status: str = typer.Option("pending", help="pending, approved, denied, used, expired or all."),
    mine: bool = typer.Option(
        False, "--mine", help="Only the requests sent to you: agents acted for you."
    ),
) -> None:
    """List approval requests (pending ones by default)."""
    path = "/v1/me/approvals" if mine else "/v1/approvals"
    rows = _call("GET", path, params={"status": status} if status != "all" else {})
    _table(rows, ["id", "agent_name", "resource", "on_behalf_of", "status", "requested_at"])


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

FINDING_STATUS = typer.Option("open", help="open, resolved, dismissed, accepted or all.")
MINE = typer.Option(
    False,
    "--mine",
    help="Only the issues sent to you: about agents you own or sponsor, or to your teams.",
)


def _with(f: dict[str, Any]) -> str:
    """Who an issue is with, and whether they took it on."""
    if f.get("status") == "accepted":
        return f"risk accepted until {f['accepted_until'][:10]}"
    if not f.get("level"):
        return ""
    who = ", ".join(f.get("assignees") or [])
    if f["level"] != "team":
        who += f" ({f['level']})"
    return f"{who}, acknowledged" if f.get("acknowledged_at") else who


FINDING_TYPE = typer.Option(None, "--type", help="Only findings of this type.")
FINDING_SEVERITY = typer.Option(None, help="Only findings of this severity.")
FINDING_LIMIT = typer.Option(500, help="At most this many, newest first (up to 2000).")
FINDING_QUIET = typer.Option(
    False, "--quiet", "-q", help="Only their IDs, one a line: to give other commands."
)
FINDING_CSV = [
    "id",
    "severity",
    "status",
    "category",
    "type",
    "title",
    "agent_id",
    "subject",
    "with",
    "verified",
    "occurrences",
    "first_seen",
    "last_seen",
    "resolved_by",
    "accepted_until",
]


def _list_findings(
    status: str,
    mine: bool = False,
    type_: str | None = None,
    severity: str | None = None,
    limit: int = 500,
    as_csv: bool = False,
    quiet: bool = False,
) -> None:
    if mine:
        rows = _call("GET", "/v1/me/issues", params={"status": status})
    else:
        params = {"status": status, "type": type_, "severity": severity, "limit": limit}
        rows = _call("GET", "/v1/findings", params={k: v for k, v in params.items() if v})
    for row in rows:
        row["with"] = _with(row)
    if quiet:
        for row in rows:
            typer.echo(row["id"])
    elif as_csv:
        _csv(rows, FINDING_CSV)
    else:
        for row in rows:
            if row.get("verified") is False:
                row["status"] = f"{row['status']} (unverified)"
        _table(rows, ["id", "severity", "status", "type", "with", "title"])
    if not mine and len(rows) == limit:
        typer.echo(
            f"The newest {limit}: there may be more. Narrow them with --type or --severity, "
            "or raise --limit.",
            err=True,
        )


@findings_app.callback()
def findings_main(
    ctx: typer.Context,
    status: str = FINDING_STATUS,
    mine: bool = MINE,
    type_: str | None = FINDING_TYPE,
    severity: str | None = FINDING_SEVERITY,
    limit: int = FINDING_LIMIT,
    as_csv: bool = AS_CSV,
    quiet: bool = FINDING_QUIET,
) -> None:
    if ctx.invoked_subcommand is None:
        _list_findings(status, mine, type_, severity, limit, as_csv, quiet)


@findings_app.command("list")
def findings_list(
    status: str = FINDING_STATUS,
    mine: bool = MINE,
    type_: str | None = FINDING_TYPE,
    severity: str | None = FINDING_SEVERITY,
    limit: int = FINDING_LIMIT,
    as_csv: bool = AS_CSV,
    quiet: bool = FINDING_QUIET,
) -> None:
    """List findings, newest first."""
    _list_findings(status, mine, type_, severity, limit, as_csv, quiet)


@findings_app.command("get")
def findings_get(finding_id: str) -> None:
    """Show a finding: who it goes to, the messages sent about it, and what happened to it."""
    f = _call("GET", f"/v1/findings/{quote(finding_id)}")
    typer.echo(f"{f['id']}  {f['severity']}  {f['status']}  {f['type']}")
    typer.echo(f["title"])
    if f.get("description"):
        typer.echo(f"\n{f['description']}")
    if f.get("remediation"):
        typer.echo(f"\nWhat to do: {f['remediation']}")
    if f.get("verified") is False:
        why = f.get("unverified_reason") or "the sync that checks it failed"
        typer.echo(f"\nUnverified: {why}; it may no longer hold.")
    if f.get("status") == "accepted":
        typer.echo(f"\nRisk accepted until {f['accepted_until']}: {f['accepted_reason']}")
    if f.get("acknowledged_at"):
        typer.echo(f"\nAcknowledged by {f['acknowledged_by']} at {f['acknowledged_at']}")
    if f.get("chain"):
        typer.echo("\nWho it goes to:")
        for step in f["chain"]:
            mark = "->" if step["current"] else ("  " if not step["reached"] else " +")
            typer.echo(f" {mark} {step['level']}: {', '.join(step['who'])}")
        if f.get("escalate_at"):
            typer.echo(f"    goes further at {f['escalate_at']} unless someone acknowledges it")
    if f.get("notifications"):
        typer.echo("\nMessages:")
        _table(f["notifications"], ["level", "channel", "recipient", "status", "attempts"])


FINDING_IDS = typer.Argument(..., help="The findings' IDs: one, or several at once.")


def _findings_at_once(ids: list[str], action: str, **body: Any) -> None:
    """Several findings at once: each on its own, those it can't do left as they are."""
    _many("finding", _at_once("finding", _given(action=action, findings=ids, **body)))


@findings_app.command("acknowledge")
def findings_acknowledge(finding_ids: list[str] = FINDING_IDS) -> None:
    """Take issues on: they go no further up their chains."""
    if len(finding_ids) > 1:
        return _findings_at_once(finding_ids, "acknowledge")
    f = _call("POST", f"/v1/findings/{quote(finding_ids[0])}/acknowledge")
    _done("finding", f["id"], f"acknowledged by {f['acknowledged_by']}")


@findings_app.command("accept")
def findings_accept(
    finding_ids: list[str] = FINDING_IDS,
    reason: str = typer.Option(..., help="Why the risk is acceptable."),
    until: str = typer.Option(
        ...,
        help="Until when: a date (2026-12-31), a time, or a number of days (90). A year at most.",
    ),
) -> None:
    """Accept findings' risk until a date: each opens again then if it still holds."""
    when: str | int = int(until) if until.isdigit() else until
    if len(finding_ids) > 1:
        return _findings_at_once(finding_ids, "accept", reason=reason, until=when)
    f = _call(
        "POST",
        f"/v1/findings/{quote(finding_ids[0])}/accept",
        json={"reason": reason, "until": when},
    )
    _done("finding", f["id"], f"risk accepted until {f['accepted_until']}")


@findings_app.command("not-mine")
def findings_not_mine(
    finding_id: str,
    reason: str = typer.Option(..., help="Why it isn't yours: whose it is, if you know."),
) -> None:
    """Say an issue isn't yours: it goes on to the next people responsible for it at once."""
    out = _call(
        "POST", f"/v1/findings/{quote(finding_id)}/not-mine", json={"reason": reason}
    )  # fmt: skip
    went = ", ".join(out["went_to"])
    _done(
        "finding", out["id"], f"passed on to {went}" if went else "recorded; it stays where it is"
    )


@findings_app.command("ask-exception")
def findings_ask_exception(
    finding_id: str,
    reason: str = typer.Option(..., help="Why its risk is acceptable, for now."),
    until: str = typer.Option(
        ..., help="Until when: a date (2026-12-31), a time, or a number of days. A year at most."
    ),
) -> None:
    """Ask an approver to accept an issue's risk until a date. It stays with you meanwhile."""
    when: str | int = int(until) if until.isdigit() else until
    f = _call(
        "POST",
        f"/v1/findings/{quote(finding_id)}/exception",
        json={"reason": reason, "until": when},
    )
    _done("finding", f["id"], "exception asked for: an approver decides")


@findings_app.command("decline-exception")
def findings_decline_exception(
    finding_id: str, reason: str = typer.Option(..., help="Why not.")
) -> None:
    """Turn down a request to accept an issue's risk: it stays with whoever asked."""
    f = _call(
        "POST", f"/v1/findings/{quote(finding_id)}/exception/decline", json={"reason": reason}
    )
    _done("finding", f["id"], "exception declined")


@findings_app.command("recheck")
def findings_recheck(finding_id: str) -> None:
    """Say you fixed what an issue is about: AgentGov checks it again now, where it can."""
    out = _call("POST", f"/v1/findings/{quote(finding_id)}/recheck", timeout=LONG_TIMEOUT)
    outcome = "gone: resolved" if out["fixed"] else "still there"
    note = f" ({out['note']})" if out.get("note") else ""
    _done("finding", out["finding"]["id"], f"checked again ({out['checked']}), {outcome}{note}")
    if not out["fixed"]:
        raise typer.Exit(1)


def _finding_action(finding_ids: list[str], action: str) -> None:
    if len(finding_ids) > 1:
        return _findings_at_once(finding_ids, action)
    f = _call("POST", f"/v1/findings/{quote(finding_ids[0])}/{action}")
    _done("finding", f["id"], f["status"])


@findings_app.command("resolve")
def findings_resolve(finding_ids: list[str] = FINDING_IDS) -> None:
    """Mark findings as resolved."""
    _finding_action(finding_ids, "resolve")


@findings_app.command("dismiss")
def findings_dismiss(
    finding_ids: list[str] = FINDING_IDS,
    reason: str = typer.Option(..., help="Why it is wrong."),
    until: str | None = typer.Option(
        None, help="Open it again then if it still holds: a date, a time, or a number of days."
    ),
) -> None:
    """Dismiss findings that are wrong (to accept a risk, use accept)."""
    body: dict[str, Any] = {"reason": reason}
    if until:
        body["until"] = int(until) if until.isdigit() else until
    if len(finding_ids) > 1:
        return _findings_at_once(finding_ids, "dismiss", **body)
    f = _call("POST", f"/v1/findings/{quote(finding_ids[0])}/dismiss", json=body)
    _done("finding", f["id"], f["status"])


@findings_app.command("reopen")
def findings_reopen(finding_ids: list[str] = FINDING_IDS) -> None:
    """Reopen resolved, dismissed or accepted findings."""
    _finding_action(finding_ids, "reopen")


@findings_app.command("types")
def findings_types() -> None:
    """Each type of finding: on or off, its severity if set here, and how many are open."""
    rows = _call("GET", "/v1/finding-types")
    for row in rows:
        row["severity"] = row["severity"] or "(its checks')"
    _table(rows, ["type", "mode", "severity", "open", "total"])


@findings_app.command("type")
def findings_type(
    type_: str = typer.Argument(..., metavar="TYPE", help="Such as agent.no_owner."),
    on: bool | None = typer.Option(
        None, "--on/--off", help="Raise it, or keep what it finds dismissed."
    ),
    severity: str | None = typer.Option(
        None, help="info, low, medium, high or critical; 'default' for its checks' own."
    ),
    yes: bool = YES,
) -> None:
    """Set how a type of finding is handled here."""
    body: dict[str, Any] = {}
    if on is not None:
        body["mode"] = "on" if on else "off"
    if severity is not None:
        body["severity"] = None if severity == "default" else severity
    if not body:
        _fail("give --on, --off or --severity")
    if body.get("mode") == "off":
        _confirm(
            f"Turn {type_} off? Its open findings are dismissed, and what it finds is kept "
            "dismissed.",
            yes,
        )
    out = _call("PUT", f"/v1/finding-types/{quote(type_)}", json=body)
    severity_text = f"severity {out['severity']}" if out["severity"] else "its checks' severity"
    _done("finding-type", type_, f"{out['mode']}, {severity_text}")


# -------------------------------------------------------------------- ledger


@ledger_app.command("verify")
def ledger_verify(
    file: list[Path] | None = typer.Option(
        None,
        "--file",
        help="Check these exports or archives offline, in order, without the control "
        "plane (repeatable).",
    ),
    follows: str | None = typer.Option(
        None, "--follows", help="Offline: the hash the first entry must follow (a checkpoint's)."
    ),
) -> None:
    """Recompute the hash chain and report tampering; offline, check exports and archives."""
    if not file:
        result = _call("GET", "/v1/ledger/verify")
        _print(result)
        if not result.get("valid"):
            raise typer.Exit(2)
        return
    from agentgov import ledger, retention

    start: tuple[int, str] | None = None
    for path in file:
        records = list(retention.read_archive(path))
        if start is None and follows and records:
            start = (records[0]["seq"] - 1, follows)
        result = ledger.verify_records(records, start=start)
        state = (
            "valid" if result["valid"] else f"BROKEN at {result['broken_at']}: {result['problem']}"
        )
        typer.echo(
            f"{path}: {state}, entries {result.get('first')} to {result.get('last')} "
            f"({result['checked']} checked)"
        )
        if not result["valid"]:
            raise typer.Exit(2)
        if result["last"] is not None:
            # The next file must go on from this one.
            start = (result["last"], result["head"])
    if start is not None:
        typer.echo(f"last entry {start[0]}, hash {start[1]}")


@ledger_app.command("checkpoints")
def ledger_checkpoints(limit: int = 20) -> None:
    """List the ledger's checkpoints: their time-stamps and archives."""
    rows = _call("GET", "/v1/ledger/checkpoints", params={"limit": limit})
    for row in rows:
        row["stamped"] = (
            row["timestamped_at"]
            if row["timestamped"]
            else (f"failed: {row['timestamp_error']}" if row["timestamp_error"] else "")
        )
        row["archived"] = (
            f"{row['archived_from']}-{row['seq']} {row['archive']}" if row["archive"] else ""
        )
        log = row.get("log") or {}
        row["logged"] = (
            f"#{log['index']}" + ("" if log["checked"] else " (unchecked)")
            if log.get("logged")
            else (f"failed: {log['error']}" if log.get("error") else "")
        )
    _table(rows, ["seq", "entry_ts", "stamped", "logged", "archived", "hash"])


@ledger_app.command("checkpoint")
def ledger_checkpoint() -> None:
    """Keep the chain's head as a checkpoint now (time-stamped, if an authority is set)."""
    out = _call("POST", "/v1/ledger/checkpoints")
    stamped = f", time-stamped at {out['timestamped_at']}" if out["timestamped"] else ""
    _done("checkpoint", str(out["seq"]), f"{out['hash']}{stamped}")


@ledger_app.command("proof")
def ledger_proof(
    seq: int,
    out: Path = typer.Option(Path("."), "--out", "-o", help="The directory to write to."),
) -> None:
    """Write a checkpoint's statement, its time-stamp, to verify with OpenSSL, and its
    entry in the transparency log, to verify with cosign or agentgov ledger
    verify-log-entry."""
    points = _call("GET", "/v1/ledger/checkpoints", params={"limit": 1000})
    point = next((p for p in points if p["seq"] == seq), None)
    if point is None:
        _fail(f"no checkpoint at entry {seq}: see agentgov ledger checkpoints")
    out.mkdir(parents=True, exist_ok=True)
    statement = out / f"checkpoint-{seq}.txt"
    statement.write_text(point["statement"])
    typer.echo(f"wrote {statement}")
    wrote = False
    with _client() as client:
        resp = client.get(f"/v1/ledger/checkpoints/{seq}/timestamp")
        if resp.status_code < 400:
            token = out / f"checkpoint-{seq}.tsr"
            token.write_bytes(resp.content)
            wrote = True
            typer.echo(f"wrote {token}; check it with:")
            typer.echo(f"  openssl ts -verify -data {statement} -in {token} -CAfile TSA-CA.pem")
        if (point.get("log") or {}).get("logged"):
            entry = client.get(f"/v1/ledger/checkpoints/{seq}/log-entry")
            log = client.get("/v1/ledger/transparency-log")
            if entry.status_code < 400 and log.status_code < 400:
                bundle = out / f"checkpoint-{seq}.sigstore.json"
                bundle.write_bytes(entry.content)
                wrote = True
                about = log.json()
                key = out / "agentgov-rekor.pub"
                if about.get("signer_key"):
                    key.write_text(about["signer_key"])
                typer.echo(f"wrote {bundle}; check it offline with:")
                if about.get("trusted_root"):
                    root = out / "rekor-trusted-root.json"
                    root.write_text(json.dumps(about["trusted_root"], indent=2))
                    (out / "rekor.pub").write_text(about["log_key"])
                    typer.echo(
                        f"  cosign verify-blob --key {key} --bundle {bundle} "
                        f"--trusted-root {root} {statement}"
                    )
                typer.echo(
                    f"  agentgov ledger verify-log-entry {statement} {bundle} "
                    f"--log-key {out / 'rekor.pub'} --origin {about.get('origin')} --key {key}"
                )
    if not wrote:
        _fail(f"checkpoint {seq} isn't time-stamped nor in a transparency log yet")


@ledger_app.command("verify-log-entry")
def ledger_verify_log_entry(
    statement: Path = typer.Argument(..., help="The checkpoint's statement (checkpoint-N.txt)."),
    bundle: Path = typer.Argument(..., help="Its entry, as a Sigstore bundle (.sigstore.json)."),
    log_key: Path = typer.Option(..., "--log-key", help="The log's public key (PEM, Ed25519)."),
    origin: str = typer.Option(..., "--origin", help="The log's name in its checkpoints."),
    key: Path | None = typer.Option(
        None, "--key", help="AgentGov's public key (PEM): the entry must be signed with it."
    ),
) -> None:
    """Check, offline, that a transparency log holds a checkpoint: the log signed the
    checkpoint the entry's proof leads to, and the entry is the statement, signed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from agentgov import transparency

    try:
        found = json.loads(bundle.read_text())
        [entry] = found["verificationMaterial"]["tlogEntries"]
        signer = None
        if key is not None:
            signer = serialization.load_pem_public_key(key.read_bytes())
            if not isinstance(signer, ec.EllipticCurvePublicKey):
                _fail(f"{key} isn't an ECDSA public key")
        checked = transparency.check(
            entry,
            statement.read_bytes(),
            log_key=transparency.load_log_key(log_key),
            origin=origin,
            signer=signer,
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        _fail(f"can't read them: {exc}")
    except transparency.TransparencyError as exc:
        _fail(f"not verified: {exc}")
    typer.echo(
        f"verified: entry {checked.index} of {checked.origin}, in its tree of "
        f"{checked.tree_size} (root {checked.root_hash})"
    )


@ledger_app.command("retention")
def ledger_retention(
    run: bool = typer.Option(False, "--run", help="Do now what the hourly round does."),
) -> None:
    """How long the ledger and operational records are kept, and where the chain starts."""
    if run:
        _print(_call("POST", "/v1/ledger/retention/run"))
        return
    _print(_call("GET", "/v1/ledger/retention"))


@ledger_app.command("tail")
def ledger_tail(
    limit: int = 20,
    type: str | None = typer.Option(None, help="Event type; * is a wildcard (decision.*)."),
    agent: str | None = typer.Option(None, help="Only this agent's entries."),
    user: str | None = typer.Option(None, help="Only what agents did for this person."),
    decision: str | None = typer.Option(
        None, help="allow, deny, require_approval, or monitored (let through in monitor mode)."
    ),
    traces: bool = typer.Option(False, "--traces", help="Add links to the trace viewer."),
) -> None:
    """Show the latest ledger entries, oldest first."""
    params: dict[str, Any] = {
        "limit": limit,
        **_given(type=type, agent=agent, user=user, decision=decision),
    }
    rows = list(reversed(_call("GET", "/v1/ledger", params=params)))
    columns = ["seq", "ts", "type", "agent_name", "on_behalf_of", "resource", "decision", "reason"]
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
    role: str = typer.Option(..., help="admin, approver, secops, auditor, registrar or service."),
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
    """Each source of platform agents, and each optional Microsoft connection."""
    view = _call("GET", "/v1/platforms")
    rows = []
    for src in view["sources"]:
        last = src["last_sync"] or {}
        if not src["configured"]:
            state = "not configured"
        elif src.get("turned_on") is False:
            state = "turned off in features"
        elif last:
            state = "ok" if last["ok"] else f"failed: {last['message']}"
        else:
            state = "never"
        rows.append({**src, "last_sync": last.get("at"), "state": state})
    _table(rows, ["source", "mode", "agents", "last_sync", "state"])
    typer.echo()
    links = []
    for c in view.get("connections", []):
        last = c.get("last_run") or {}
        note = ""
        if c["status"] == "missing_permission":
            note = f"grant {c['permission']}"
        elif c["status"] in ("off", "import"):
            note = "needs " + ", ".join(c["needs"])
        elif last and not last.get("ok"):
            note = last.get("message", "")
        links.append({**c, "last_run": last.get("at"), "note": note})
    _table(links, ["key", "status", "last_run", "note"])
    detection = view.get("threat_detection") or {}
    if detection.get("mode", "off") != "off":
        typer.echo(
            f"\nthreat detection ({detection['mode']}): {detection.get('calls') or 0} tool calls, "
            f"{detection.get('blocked') or 0} blocked, "
            f"{detection.get('would_block') or 0} would have been blocked"
        )


SYNC_SOURCES = (
    "microsoft-365",
    "copilot-studio",
    "entra-agent-id",
    "entra-users",
    "purview-audit",
    "defender",
)
# Platforms read by a connector of AgentGov's own (docs/other-platforms.md).
OTHER_PLATFORMS = ("aws", "google-cloud", "salesforce", "databricks", "microsoft-foundry")


def _sync_summary(source: str, c: dict[str, Any]) -> str:
    if source == "entra-agent-id":
        return f"{c['created']} new, {c['updated']} updated, {c['linked']} linked to agents"
    if source == "purview-audit":
        return (
            f"{c['interactions']} interactions, {c['maker_events']} maker changes, "
            f"{c['searching']} searches running"
        )
    if source == "defender":
        return f"{c['alerts']} agent alerts, {c['matched']} matched, {c['resolved']} resolved"
    if source == "entra-users":
        return f"{c['found']} people found, {c['not_found']} not users, {c['left']} left"
    summary = f"{c['created']} new, {c['updated']} updated, {c['skipped']} skipped"
    if source in OTHER_PLATFORMS:
        summary += f", {c['findings']} open findings"
        if c.get("failed"):
            summary += f"; {c['failed']} parts couldn't be read (see `agentgov platforms status`)"
    return summary


@platforms_app.command("sync")
def platforms_sync(
    source: str = typer.Argument(
        "all",
        help="all (every connection AgentGov's app may use), microsoft-365, entra-agent-id, "
        "entra-users, purview-audit, defender, copilot-studio (as you, after `agentgov login` "
        "through "
        "Microsoft Entra ID), or another platform: aws, google-cloud, salesforce, databricks, "
        "microsoft-foundry.",
    ),
) -> None:
    """Sync now (AgentGov's app connections and other platforms also sync on a schedule)."""
    if source == "all":
        results = _call("POST", "/v1/platforms/sync", timeout=LONG_TIMEOUT)
        failed = False
        for key, outcome in results.items():
            if "error" in outcome:
                failed = True
                _done("platform", key, f"failed: {outcome['error']}")
            elif "lacks_permission" in outcome:
                _done("platform", key, f"skipped (the app lacks {outcome['lacks_permission']})")
            else:
                _done("platform", key, f"synced ({_sync_summary(key, outcome)})")
        if failed:
            raise typer.Exit(1)
        return
    if source not in SYNC_SOURCES + OTHER_PLATFORMS:
        _fail(f"the source is all or one of {', '.join(SYNC_SOURCES + OTHER_PLATFORMS)}")
    counts = _call("POST", f"/v1/platforms/{source}/sync", timeout=LONG_TIMEOUT)
    if source in ("microsoft-365", "copilot-studio"):
        _synced(source, "synced", counts)
        _people_looked_up(counts.get("people"))
    else:
        _done("platform", source, f"synced ({_sync_summary(source, counts)})")


@platforms_app.command("connector-policy")
def platforms_connector_policy() -> None:
    """What pushing the connector allowlist into Power Platform would do (as you)."""
    view = _call("GET", "/v1/platforms/connector-policy", timeout=LONG_TIMEOUT)
    typer.echo(f"policy:    {view['policy_name']} ({view['policy_id'] or 'not created yet'})")
    typer.echo(f"allowlist: {', '.join(view['allowlist']) or '(empty: nothing can be pushed)'}")
    if view.get("out_of_date"):
        typer.echo(f"in Power Platform now: {', '.join(view['in_power_platform'] or [])}")
    typer.echo()
    rows = [
        {
            **t,
            "state": "applied"
            if t["applied"]
            else ("taken by " + ", ".join(t["other_policies"]) if t["other_policies"] else "free"),
        }
        for t in view["targets"]
    ]
    _table(rows, ["scope", "id", "name", "state"])
    for agent in view["agents_losing_connectors"]:
        typer.echo(f"agent/{agent['name']} would lose: {', '.join(agent['connectors'])}")


@platforms_app.command("push-connector-policy")
def platforms_push_connector_policy(
    group: list[str] | None = typer.Option(None, "--group", help="Environment group ID."),
    environment: list[str] | None = typer.Option(None, "--environment", help="Environment ID."),
    yes: bool = YES,
) -> None:
    """Make Power Platform allow only the approved connectors in these groups and
    environments, as you. Every other connector is blocked there, for apps and flows too."""
    targets = [{"scope": "group", "id": g} for g in _split(group)] + [
        {"scope": "environment", "id": e} for e in _split(environment)
    ]
    if not targets:
        _fail("name a --group or an --environment (see `agentgov platforms connector-policy`)")
    _confirm(
        "Power Platform will block every connector that isn't on the allowlist there, for apps "
        "and flows as well as agents. Push?",
        yes,
    )
    out = _call(
        "POST", "/v1/platforms/connector-policy", json={"targets": targets}, timeout=LONG_TIMEOUT
    )
    _done(
        "policy",
        out["policy_id"],
        f"allows {', '.join(out['connectors'])} in "
        + ", ".join(f"{t['scope']} {t['id']}" for t in out["targets"]),
    )


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
    _people_looked_up(counts.get("people"))


def _people_looked_up(outcome: dict[str, Any] | None) -> None:
    """What looking up the makers an import or sync named came to."""
    if outcome is None:
        return
    if "error" in outcome:
        typer.echo(f"makers not looked up: {outcome['error']}", err=True)
    else:
        typer.echo(f"makers looked up: {_sync_summary('entra-users', outcome)}")


@platforms_app.command("import-users")
def platforms_import_users(
    file: Path = typer.Argument(
        ...,
        help="The Microsoft Entra admin center's Users > Download users (CSV), or JSON with "
        "id and mail.",
    ),
) -> None:
    """Upload a list of users from Microsoft Entra ID, so that the people Copilot Studio
    names by Entra ID are known by name without Microsoft Graph."""
    try:
        text = file.read_text(encoding="utf-8-sig")
    except OSError as exc:
        _fail(f"cannot read {file}: {exc}")
    kind = "application/json" if text.lstrip().startswith(("[", "{")) else "text/csv"
    out = _call(
        "POST",
        "/v1/platforms/entra-users/import",
        content=text.encode(),
        headers={"content-type": kind},
        timeout=LONG_TIMEOUT,
    )
    makers = out["makers"]
    _done(
        "people",
        file.name,
        f"{out['people']} kept, {out['skipped']} without an object ID; "
        f"{makers['known']} of the {makers['named']} people platforms name are known",
    )


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


@platforms_app.command("entra-access")
def platforms_entra_access(
    agent: str | None = typer.Option(None, help="Only this agent's (with what it could hold)."),
) -> None:
    """The Microsoft Entra access packages agents' Entra identities hold, and until when."""
    if agent:
        view = _call("GET", f"/v1/agents/{quote(agent)}/entra-access-packages")
        rows = view["held"]
        for row in rows:
            row["agent"] = agent
        typer.echo(f"mode: {view['mode']}; Entra identity: {view['entra_agent_id'] or 'none'}")
    else:
        view = _call("GET", "/v1/platforms/entra-access-packages")
        names = view["agents"]
        rows = [{**row, "agent": names.get(agent_id, agent_id)}
                for agent_id, held in view["held"].items() for row in held]  # fmt: skip
        typer.echo(f"mode: {view['mode']}; {len(view['packages'])} packages agents can hold")
    _table(rows, ["agent", "package", "state", "expires_at", "id"])


@platforms_app.command("entra-assign")
def platforms_entra_assign(
    agent: str, package: str = typer.Argument(..., help="The package's ID or name.")
) -> None:
    """Ask Entra to assign an access package to the agent's Entra identity (manage mode)."""
    out = _call(
        "POST", f"/v1/agents/{quote(agent)}/entra-access-packages/assign", json={"package": package}
    )
    _done("entra-request", out["request_id"] or "?", out["state"] or "submitted")


@platforms_app.command("entra-remove")
def platforms_entra_remove(agent: str, assignment_id: str, yes: bool = YES) -> None:
    """Ask Entra to remove one of the agent identity's assignments (manage mode)."""
    _confirm(f"Ask Entra to remove {assignment_id} from {agent}?", yes)
    out = _call("DELETE", f"/v1/agents/{quote(agent)}/entra-access-packages/{quote(assignment_id)}")
    _done("entra-request", out["request_id"] or "?", out["state"] or "submitted")


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


# ------------------------------------------------------------------ features


@features_app.command("list")
def features_list() -> None:
    """Every feature, its mode, whether it can do what its mode says, and what it does or
    what stops it."""
    view = _call("GET", "/v1/features")
    rows = [
        {
            "feature": f["key"],
            "mode": f["mode"],
            # Its mode for some agents: how many exceptions (agentgov features get shows them).
            "exceptions": len(f.get("scopes") or []) or "",
            "status": f.get("status"),
            "set_by": f["set_by"],
            "does": (f.get("problems") or [f["effect"]])[0],
        }
        for f in view["features"]
    ]
    _table(rows, ["feature", "mode", "exceptions", "status", "set_by", "does"])


@app.command()
def components() -> None:
    """What the control plane reaches itself, and what each governance processor says it
    reaches: whether features can do what their modes say comes from these."""
    view = _call("GET", "/v1/components")
    rows = []

    def add(where: str, reported: str | None, checks: dict[str, Any]) -> None:
        for name, c in checks.items():
            state = ("reachable" if c["ok"] else "unreachable") if c["configured"] else "not set up"
            rows.append(
                {
                    "component": where,
                    "check": name,
                    "state": state,
                    "reported": reported,
                    "detail": c.get("detail") or "",
                }
            )

    add("control plane", "now", view["control_plane"])
    for p in view["processors"]:
        where = f"processor {p['instance']}" + ("" if p["fresh"] else " (out of touch)")
        add(where, p["reported_at"], p["checks"])
    if not view["processors"]:
        rows.append(
            {
                "component": "processor",
                "check": "",
                "state": "none has reported",
                "reported": "",
                "detail": "nothing is known to check calls through the gateway",
            }
        )
    _table(rows, ["component", "check", "state", "reported", "detail"])


@features_app.command("get")
def features_get(key: str) -> None:
    """One feature: its modes, what each does, and who chose the current one."""
    _print(_call("GET", f"/v1/features/{quote(key)}"))


@features_app.command("set")
def features_set(
    key: str,
    mode: str = typer.Argument(..., help="off, monitor or enforce (off or on for some)."),
    yes: bool = YES,
) -> None:
    """Choose how strictly a feature applies."""
    current = _call("GET", f"/v1/features/{quote(key)}")
    modes = current["modes"]
    if mode not in modes:
        _fail(f"{key} takes {', '.join(modes)} (got {mode!r})")
    if mode != current["mode"] and modes.index(mode) < modes.index(current["mode"]):
        _confirm(
            f"{current['title']}: {current['mode']} to {mode}? {current['effects'].get(mode, '')}",
            yes,
        )
    out = _call("PUT", f"/v1/features/{quote(key)}", json={"mode": mode})
    _done("feature", key, f"{out['mode']}: {out['effect']}")


# What listing a control's exceptions adds to each (registry.features.LISTED): not sent back.
LISTED = ("describe", "agents", "missing")


def _exception(e: dict[str, Any]) -> str:
    """An exception in words, with how many agents it applies to now."""
    missing = f"; there is no {', '.join(e['missing'])}" if e.get("missing") else ""
    reach = f" ({e['agents']} agent(s) now{missing})" if "agents" in e else ""
    return f"{e['mode']} for {e['describe']}{reach}"


@features_app.command("scope")
def features_scope(
    key: str,
    mode: str = typer.Argument(..., help="The control's mode for these agents."),
    blueprint: list[str] = typer.Option(None, "--blueprint", help="Repeatable."),
    team: list[str] = typer.Option(None, "--team", help="Repeatable."),
    environment: list[str] = typer.Option(None, "--environment", help="Repeatable."),
    platform: list[str] = typer.Option(
        None, "--platform", help="gateway, aws, microsoft-365, ... Repeatable."
    ),
    label: list[str] = typer.Option(None, "--label", help="key=value. Repeatable."),
    note: str | None = typer.Option(None, "--note", help="Why, for whoever reads it next."),
    yes: bool = YES,
) -> None:
    """Add an exception to a control: its mode for the agents in a scope (every option
    given must match). The first exception that matches an agent applies to it."""
    current = _call("GET", f"/v1/features/{quote(key)}")
    scope: dict[str, Any] = {
        k: _split(v)
        for k, v in (
            ("blueprints", blueprint),
            ("teams", team),
            ("environments", environment),
            ("platforms", platform),
        )
        if v
    }
    if label:
        scope["labels"] = _labels(label)
    if not scope:
        _fail("say which agents: --blueprint, --team, --environment, --platform or --label")
    entry: dict[str, Any] = {"mode": mode, "scope": scope}
    if note:
        entry["note"] = note
    modes = current["modes"]
    if mode in modes and modes.index(mode) < modes.index(current["mode"]):
        _confirm(f"{current['title']}: {mode} for these agents, {current['mode']} for others?", yes)
    scopes = [{k: v for k, v in e.items() if k not in LISTED} for e in current.get("scopes") or []]
    out = _call("PUT", f"/v1/features/{quote(key)}", json={"scopes": [*scopes, entry]})
    _done(
        "feature",
        key,
        f"{len(out['scopes'])} exception(s): " + "; ".join(_exception(e) for e in out["scopes"]),
    )


@features_app.command("unscope")
def features_unscope(
    key: str,
    number: int = typer.Argument(
        ..., help="Which exception, as agentgov features get lists them (1 is the first)."
    ),
    yes: bool = YES,
) -> None:
    """Remove one of a control's exceptions."""
    current = _call("GET", f"/v1/features/{quote(key)}")
    scopes = [{k: v for k, v in e.items() if k not in LISTED} for e in current.get("scopes") or []]
    if not 1 <= number <= len(scopes):
        _fail(f"{key} has {len(scopes)} exception(s)")
    gone = current["scopes"][number - 1]
    _confirm(f"{current['title']}: remove {gone['mode']} for {gone['describe']}?", yes)
    out = _call(
        "PUT", f"/v1/features/{quote(key)}", json={"scopes": scopes[: number - 1] + scopes[number:]}
    )
    _done("feature", key, f"{len(out['scopes'])} exception(s) left")


@features_app.command("presets")
def features_presets() -> None:
    """Starting points that set many modes at once, and what each would change now."""
    view = _call("GET", "/v1/feature-presets")
    rows: list[dict[str, Any]] = []
    for preset in view["presets"]:
        name = preset["preset"]
        rows += [
            {"preset": name, "feature": c["key"], "from": c["from"], "to": c["to"], "note": ""}
            for c in preset["changes"]
        ]
        rows += [
            {
                "preset": name,
                "feature": c["key"],
                "from": c["from"],
                "to": c["to"],
                "note": f"kept: {c['reason']}",
            }
            for c in preset["kept"]
        ]
        if not preset["changes"] and not preset["kept"]:
            rows.append({"preset": name, "note": "changes nothing now"})
    _table(rows, ["preset", "feature", "from", "to", "note"])
    if view.get("applied"):
        typer.echo(f"The deployment applied {view['applied']} (AGENTGOV_FEATURE_PRESET).")


@features_app.command("preset")
def features_preset(
    name: str = typer.Argument(..., help="monitor or inventory."), yes: bool = YES
) -> None:
    """Apply a starting point: set the modes it sets, but for features the deployment pins
    (agentgov features presets shows what it would change)."""
    view = _call("GET", "/v1/feature-presets")
    plan = next((p for p in view["presets"] if p["preset"] == name), None)
    if plan is None:
        _fail(f"no preset {name!r}; presets: {', '.join(p['preset'] for p in view['presets'])}")
    if not plan["changes"]:
        _done("preset", name, "nothing to change")
        return
    summary = "; ".join(f"{c['key']} {c['from']} to {c['to']}" for c in plan["changes"])
    _confirm(f"{plan['title']}: {summary}?", yes)
    out = _call("POST", f"/v1/feature-presets/{quote(name)}")
    count = len(out["changes"])
    _done("preset", name, f"{count} feature{'' if count == 1 else 's'} changed")


# ----------------------------------------------------------------------- mcp


@mcp_app.command("registry")
def mcp_registry() -> None:
    """What developers' MCP clients see in the MCP registry, and where they read it."""
    view = _call("GET", "/v1/mcp/registry")
    rows = []
    for entry in view["servers"]:
        server = entry["server"]
        where = [r["url"] for r in server.get("remotes") or []]
        where += [
            f"{p['registryType']}:{p['identifier']}"
            + (f"@{p['version']}" if p.get("version") else "")
            for p in server.get("packages") or []
        ]
        rows.append({**server, "where": ", ".join(where)})
    _table(rows, ["name", "version", "where"])
    state = "on" if view["enabled"] else "off (agentgov features set mcp-registry on)"
    typer.echo(f"registry: {view['url']} ({state})")


@mcp_app.command("managed-settings")
def mcp_managed_settings(
    output: Path | None = typer.Option(None, "--output", "-o", help="Write it to this file."),
) -> None:
    """The registry as GitHub Copilot's managed-settings.json allowlist."""
    text = json.dumps(_call("GET", "/v1/mcp/managed-settings"), indent=2) + "\n"
    if output is None:
        typer.echo(text, nl=False)
    else:
        output.write_text(text)
        typer.echo(f"wrote {output}")


@mcp_app.command("scan")
def mcp_scan_command(
    directory: list[Path] | None = typer.Option(
        None, "--dir", help="A project to look in too (repeatable; default: this directory)."
    ),
    home: Path | None = typer.Option(None, help="Scan this home directory instead of yours."),
    report: bool = typer.Option(False, "--report", help="Send what was found to AgentGov."),
    as_json: bool = typer.Option(False, "--json", help="Print what was found as JSON."),
) -> None:
    """The MCP servers set up on this machine, in VS Code, Copilot, Claude, Cursor and
    other clients. Credentials are left out: environment variables and headers by name."""
    from agentgov import mcp_scan

    found = mcp_scan.scan(directory or [Path.cwd()], home=home)
    servers = [s.to_dict() for s in found]
    if as_json:
        _print(servers)
    else:
        rows = [{**s, "where": s["url"] or " ".join(s["command"])} for s in servers]
        _table(rows, ["name", "client", "scope", "transport", "where"])
    if report:
        here = mcp_scan.machine()
        # Which file a server came from stays here: it names the person's home directory.
        sent = [{k: v for k, v in s.items() if k != "file"} for s in servers]
        outcome = _call(
            "POST",
            "/v1/mcp/sightings",
            json={"machine": here["machine"], "user": here["user"], "servers": sent},
        )
        typer.echo(
            f"reported {outcome['servers']} servers: {outcome['approved']} approved, "
            f"{outcome['unapproved']} not approved, {outcome['bypass']} past the gateway, "
            f"{outcome['blocked']} blocked"
        )


@mcp_app.command("sightings")
def mcp_sightings() -> None:
    """The MCP servers developers reported, and whether each is approved."""
    rows = [
        {
            **g,
            "names": ", ".join(g["names"]),
            "clients": ", ".join(g["clients"]),
            "server": g["server"] or "",
        }
        for g in _call("GET", "/v1/mcp/sightings")
    ]
    _table(rows, ["status", "server", "identity", "names", "clients", "machines", "users"])


# -------------------------------------------------------------------- models


def _prices(values: list[str] | None) -> dict[str, dict[str, float]]:
    """Prices written as ``model-glob=input,output`` in USD per million tokens."""
    prices = {}
    for value in values or []:
        model, sep, amounts = value.partition("=")
        parts = [p.strip() for p in amounts.split(",")]
        try:
            input_usd, output_usd = (float(p) for p in parts)
        except ValueError:
            _fail(f"prices look like model=input,output in USD per million tokens (got {value!r})")
        if not sep or not model.strip():
            _fail(f"prices look like model=input,output in USD per million tokens (got {value!r})")
        prices[model.strip()] = {"input": input_usd, "output": output_usd}
    return prices


def _provider_fields(
    *,
    kind: str | None,
    description: str | None,
    base_url: str | None,
    key_file: str | None,
    trust: str | None,
    price: list[str] | None,
    label: list[str] | None,
) -> dict[str, Any]:
    body = _given(kind=kind, description=description, trust_level=trust)
    for key, value in (("base_url", base_url), ("key_file", key_file)):
        if value is not None:
            body[key] = value or None
    if price is not None:
        body["prices"] = _prices(price)
    if label is not None:
        body["labels"] = _labels(label)
    return body


PROVIDER_KIND = typer.Option(None, help="openai, anthropic, gemini or openai-compatible.")
BASE_URL = typer.Option(
    None, help="An openai-compatible server's OpenAI API base, e.g. http://vllm:8000/v1."
)
KEY_FILE = typer.Option(
    None, help="Where the gateway reads its API key (default /model-keys/<name>)."
)
TRUST = typer.Option(None, "--trust", help="verified: personal data may be sent to it.")
PRICE = typer.Option(
    None, "--price", help="model=input,output in USD per million tokens (repeatable)."
)


@models_app.command("list")
def models_list() -> None:
    """Model providers, and where agents call them."""
    rows = [
        {**p, "trust": p["trust_level"], "gateway_path": p["route"]}
        for p in _call("GET", "/v1/models/providers")
    ]
    _table(rows, ["name", "kind", "status", "trust", "gateway_path", "key_file"])


@models_app.command("get")
def models_get(name: str) -> None:
    """A model provider, as JSON."""
    _print(_call("GET", f"/v1/models/providers/{quote(name)}"))


@models_app.command("create")
def models_create(
    name: str,
    kind: str = typer.Option(..., help="openai, anthropic, gemini or openai-compatible."),
    description: str | None = DESCRIPTION,
    base_url: str | None = BASE_URL,
    key_file: str | None = KEY_FILE,
    trust: str | None = TRUST,
    price: list[str] | None = PRICE,
    label: list[str] | None = LABEL,
) -> None:
    """Approve a model provider. Put its API key where the gateway reads it."""
    body = _provider_fields(
        kind=kind,
        description=description,
        base_url=base_url,
        key_file=key_file,
        trust=trust,
        price=price,
        label=label,
    )
    out = _call("POST", "/v1/models/providers", json={"name": name, **body})
    _done("model-provider", out["name"], f"approved; agents call it at {out['route']}")


@models_app.command("update")
def models_update(
    name: str,
    kind: str | None = PROVIDER_KIND,
    description: str | None = DESCRIPTION,
    base_url: str | None = BASE_URL,
    key_file: str | None = KEY_FILE,
    trust: str | None = TRUST,
    price: list[str] | None = typer.Option(
        None, "--price", help="Prices model=input,output (replace them)."
    ),
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change a model provider."""
    body = _provider_fields(
        kind=kind,
        description=description,
        base_url=base_url,
        key_file=key_file,
        trust=trust,
        price=price,
        label=label,
    )
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    out = _call(
        "PATCH", f"/v1/models/providers/{quote(name)}", json=body, **_if_version(if_version)
    )
    _done("model-provider", out["name"], "updated")


@models_app.command("block")
def models_block(name: str) -> None:
    """Stop every call to a model provider."""
    out = _call("POST", f"/v1/models/providers/{quote(name)}/block")
    _done("model-provider", out["name"], out["status"])


@models_app.command("unblock")
def models_unblock(name: str) -> None:
    """Allow calls to a blocked model provider again."""
    out = _call("POST", f"/v1/models/providers/{quote(name)}/unblock")
    _done("model-provider", out["name"], out["status"])


@models_app.command("delete")
def models_delete(name: str, yes: bool = YES) -> None:
    """Remove a model provider: its route goes from the gateway."""
    _confirm(f"Delete model provider {name}?", yes)
    _call("DELETE", f"/v1/models/providers/{quote(name)}")
    _done("model-provider", name, "deleted")


# ------------------------------------------------------------------- issuers

ISSUER_URL = typer.Option(
    None, "--issuer", help="As its tokens name it: a URL, or spiffe://<trust domain>."
)
KEYS_URL = typer.Option(
    None,
    help="Where its keys are: a Kubernetes issuer discovery URL, a JWKS URL (oidc, found "
    "from the issuer otherwise) or a SPIFFE bundle endpoint ('' to clear).",
)
AUDIENCE = typer.Option(
    None,
    help="oidc: the audience its tokens carry when it can't be Keycloak's realm, such as "
    "api://agentgov for Microsoft Entra ID ('' to clear).",
)
ALLOW_REUSE = typer.Option(
    None,
    "--allow-reuse/--no-reuse",
    help="oidc: whether a token may authenticate more than once (needed for tokens without a "
    "jti claim, such as Microsoft Entra ID's).",
)


def _issuer_fields(**fields: Any) -> dict[str, Any]:
    body = _given(**{k: v for k, v in fields.items() if k != "label"})
    for key in ("keys_url", "audience"):
        if body.get(key) == "":
            body[key] = None
    if fields.get("label") is not None:
        body["labels"] = _labels(fields["label"])
    return body


@issuers_app.command("list")
def issuers_list() -> None:
    """List identity issuers, with the agents that authenticate with each."""
    rows = _call("GET", "/v1/identity-issuers")
    for r in rows:
        r["sync"] = r["sync"]["error"] or ("synced" if r["sync"]["synced_at"] else "waiting")
    _table(rows, ["name", "kind", "status", "agents", "issuer", "sync"])


@issuers_app.command("get")
def issuers_get(name: str) -> None:
    """Show an identity issuer."""
    _print(_call("GET", f"/v1/identity-issuers/{quote(name)}"))


@issuers_app.command("create")
def issuers_create(
    name: str,
    kind: str = typer.Option(..., help="kubernetes, spiffe or oidc."),
    issuer: str = typer.Option(
        ..., "--issuer", help="As its tokens name it: a URL, or spiffe://<trust domain>."
    ),
    keys_url: str | None = KEYS_URL,
    audience: str | None = AUDIENCE,
    allow_reuse: bool | None = ALLOW_REUSE,
    description: str | None = DESCRIPTION,
    label: list[str] | None = LABEL,
) -> None:
    """Trust an identity issuer: agents then authenticate with its tokens."""
    body = _issuer_fields(
        kind=kind,
        issuer=issuer,
        keys_url=keys_url,
        audience=audience,
        allow_reuse=allow_reuse,
        description=description,
        label=label,
    )
    out = _call("POST", "/v1/identity-issuers", json={"name": name, **body})
    _done("identity-issuer", out["name"], out["status"])


@issuers_app.command("update")
def issuers_update(
    name: str,
    issuer: str | None = ISSUER_URL,
    keys_url: str | None = KEYS_URL,
    audience: str | None = AUDIENCE,
    allow_reuse: bool | None = ALLOW_REUSE,
    description: str | None = DESCRIPTION,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change an identity issuer."""
    body = _issuer_fields(
        issuer=issuer,
        keys_url=keys_url,
        audience=audience,
        allow_reuse=allow_reuse,
        description=description,
        label=label,
    )
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    out = _call(
        "PATCH", f"/v1/identity-issuers/{quote(name)}", json=body, **_if_version(if_version)
    )
    _done("identity-issuer", out["name"], "updated")


@issuers_app.command("block")
def issuers_block(name: str) -> None:
    """Stop every agent authenticating with the issuer's tokens."""
    out = _call("POST", f"/v1/identity-issuers/{quote(name)}/block")
    _done("identity-issuer", out["name"], f"{out['status']} ({out['agents']} agents)")


@issuers_app.command("unblock")
def issuers_unblock(name: str) -> None:
    """Trust a blocked identity issuer again."""
    out = _call("POST", f"/v1/identity-issuers/{quote(name)}/unblock")
    _done("identity-issuer", out["name"], out["status"])


@issuers_app.command("delete")
def issuers_delete(name: str, yes: bool = YES) -> None:
    """Stop trusting an identity issuer no agent uses."""
    _confirm(f"Delete identity issuer {name}?", yes)
    _call("DELETE", f"/v1/identity-issuers/{quote(name)}")
    _done("identity-issuer", name, "deleted")


# ------------------------------------------------------------ security operations

HANDOFF = "security-operations"


@secops_app.command("status")
def secops_status() -> None:
    """The hand-off level, what it lets the secops role do, and where things go."""
    view = _call("GET", "/v1/secops")
    may = "; ".join(view["secops_may"]) or "read"
    typer.echo(f"hand-off: {view['level']} (the secops role may: {may})")
    if not view["sending"]:
        typer.echo("nothing is sent (agentgov secops level inform turns it on)")
    _destination_table(view["destinations"])


@secops_app.command("level")
def secops_level(
    level: str = typer.Argument(..., help="off, inform, triage, contain or decide."),
    yes: bool = YES,
) -> None:
    """Choose how much is handed to the security team's tools (administrators)."""
    features_set(HANDOFF, level, yes)


@secops_app.command("events")
def secops_events(
    after: int = typer.Option(0, help="From after this ledger entry (0: the start)."),
    limit: int = typer.Option(200, help="Events per request (up to 1000)."),
    events: str | None = typer.Option(
        None, help="decisions, approvals, findings, access, changes (comma-separated)."
    ),
    min_severity: str = typer.Option("info", help="info, low, medium, high or critical."),
    follow: bool = typer.Option(False, "--follow", "-f", help="Keep waiting for new ones."),
    every: float = typer.Option(5.0, help="With --follow: seconds between polls."),
) -> None:
    """The ledger as OCSF events, one JSON object per line (for a SIEM's agent to collect).
    Where to go on from (--after) goes to standard error."""
    import time

    while True:
        params = {"after": after, "limit": limit, "min_severity": min_severity}
        page = _call("GET", "/v1/secops/events", params={**params, **_given(events=events)})
        for event in page["events"]:
            typer.echo(json.dumps(event, separators=(",", ":")))
        after = page["next"]
        if page["more"]:
            continue
        if not follow:
            typer.echo(f"next: --after {after}", err=True)
            return
        time.sleep(every)


def _destination_table(rows: list[dict[str, Any]]) -> None:
    out = []
    for d in rows:
        delivery = d["delivery"]
        state = delivery["last_error"] or (
            f"{delivery['behind']} behind" if delivery["behind"] else "up to date"
        )
        secret = d["secret"]
        if not secret["present"] and secret["need"] == "required":
            state = f"no secret file {secret['file']}"
        out.append(
            {
                **d,
                "events": ",".join(d["events"]),
                "sent": delivery["delivered"],
                "state": state,
            }
        )
    _table(out, ["name", "kind", "status", "events", "min_severity", "sent", "state"])


DEST_URL = typer.Option(
    None, "--url", help="The SIEM's endpoint (OTLP/HTTP, HTTP input or Splunk HEC)."
)
DEST_EVENTS = typer.Option(
    None,
    "--events",
    help="SIEMs: decisions, approvals, findings, access, changes. Chats: findings, approvals, "
    "blocks. Comma-separated; all by default.",
)
DEST_SEVERITY = typer.Option(
    None, "--min-severity", help="info, low, medium, high or critical (chats: high by default)."
)
DEST_FORMAT = typer.Option(None, "--format", help="Webhooks: json (an array) or ndjson.")


def _destination_fields(**fields: Any) -> dict[str, Any]:
    body = _given(**{k: v for k, v in fields.items() if k not in ("label", "events")})
    if body.get("url") == "":
        body["url"] = None
    if fields.get("events") is not None:
        body["events"] = _split([fields["events"]])
    if fields.get("label") is not None:
        body["labels"] = _labels(fields["label"])
    return body


@destinations_app.command("list")
def destinations_list() -> None:
    """List destinations, with how far each has got."""
    _destination_table(_call("GET", "/v1/destinations"))


@destinations_app.command("get")
def destinations_get(name: str) -> None:
    """Show a destination (never its credential)."""
    _print(_call("GET", f"/v1/destinations/{quote(name)}"))


@destinations_app.command("create")
def destinations_create(
    name: str,
    kind: str = typer.Option(..., help="otlp, webhook, splunk-hec, slack or teams."),
    url: str | None = DEST_URL,
    events: str | None = DEST_EVENTS,
    min_severity: str | None = DEST_SEVERITY,
    format: str | None = DEST_FORMAT,
    backfill: bool = typer.Option(
        False, "--backfill", help="SIEMs: send the ledger from its start, not from now."
    ),
    paused: bool = typer.Option(False, "--paused", help="Add it paused."),
    description: str | None = DESCRIPTION,
    label: list[str] | None = LABEL,
) -> None:
    """Send a SIEM the ledger, or a chat alerts. Its credential goes in its secret file."""
    body = _destination_fields(
        kind=kind,
        url=url,
        events=events,
        min_severity=min_severity,
        format=format,
        description=description,
        label=label,
    )
    if backfill:
        body["backfill"] = True
    if paused:
        body["status"] = "paused"
    out = _call("POST", "/v1/destinations", json={"name": name, **body})
    _done("destination", out["name"], out["status"])
    secret = out["secret"]
    if not secret["present"]:
        need = "needs" if secret["need"] == "required" else "may have"
        typer.echo(f"it {need} a secret file: {secret['file']} (see docs/secops.md)")


@destinations_app.command("update")
def destinations_update(
    name: str,
    url: str | None = DEST_URL,
    events: str | None = DEST_EVENTS,
    min_severity: str | None = DEST_SEVERITY,
    format: str | None = DEST_FORMAT,
    description: str | None = DESCRIPTION,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change a destination."""
    body = _destination_fields(
        url=url,
        events=events,
        min_severity=min_severity,
        format=format,
        description=description,
        label=label,
    )
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    out = _call("PATCH", f"/v1/destinations/{quote(name)}", json=body, **_if_version(if_version))
    _done("destination", out["name"], "updated")


@destinations_app.command("pause")
def destinations_pause(name: str) -> None:
    """Stop sending to a destination; it keeps its place in the ledger."""
    out = _call("POST", f"/v1/destinations/{quote(name)}/pause")
    _done("destination", out["name"], out["status"])


@destinations_app.command("resume")
def destinations_resume(name: str) -> None:
    """Send to a paused destination again, from where it stopped."""
    out = _call("POST", f"/v1/destinations/{quote(name)}/resume")
    _done("destination", out["name"], out["status"])


@destinations_app.command("replay")
def destinations_replay(
    name: str,
    after: int = typer.Option(0, help="From after this ledger entry (0: the start)."),
    yes: bool = YES,
) -> None:
    """Send a SIEM the ledger again (it drops what it already has by metadata.uid)."""
    _confirm(f"Send {name} the ledger again from after entry {after}?", yes)
    out = _call("POST", f"/v1/destinations/{quote(name)}/replay", json={"after": after})
    _done("destination", out["name"], f"from after entry {out['delivery']['cursor']}")


@destinations_app.command("test")
def destinations_test(name: str) -> None:
    """Send a test event (SIEMs) or message (chats) now."""
    out = _call("POST", f"/v1/destinations/{quote(name)}/test")
    if not out["ok"]:
        _fail(f"destination/{name}: {out['error']}")
    _done("destination", name, "test sent")


@destinations_app.command("delete")
def destinations_delete(name: str, yes: bool = YES) -> None:
    """Stop sending to a destination, for good."""
    _confirm(f"Delete destination {name}?", yes)
    _call("DELETE", f"/v1/destinations/{quote(name)}")
    _done("destination", name, "deleted")


# ------------------------------------------------------------- access packages

PKG_GRANT = typer.Option(None, "--grant", help="Tool grant server:tool,tool (repeatable).")
PKG_MODEL = typer.Option(
    None, "--model-access", help="Models it grants, provider:model,model (repeatable)."
)
PKG_AGENTS = typer.Option(
    None, "--agent-access", help="Agents it lets call, by name or pattern (repeatable)."
)
PKG_BLUEPRINTS = typer.Option(
    None, "--blueprint", help="Only agents on these blueprints may hold it (repeatable)."
)
PKG_DAYS = typer.Option(None, "--days", help="How many days it lasts at most (1 to 365).")
PKG_REVIEW = typer.Option(None, "--review-days", help="Review who holds it every N days.")
PKG_APPROVAL = typer.Option(
    None, "--approval/--no-approval", help="Whether an approver decides requests."
)


def _package_fields(
    description: str | None,
    grant: list[str] | None,
    model_access: list[str] | None,
    agent_access: list[str] | None,
    blueprint: list[str] | None,
    days: int | None,
    review_days: int | None,
    no_review: bool,
    approval: bool | None,
) -> dict[str, Any]:
    body = _given(description=description, duration_days=days, approval=approval)
    if grant is not None:
        body["permissions"] = _grants(grant)
    if model_access is not None:
        body["model_access"] = _model_access(model_access)
    if agent_access is not None:
        body["agent_access"] = _split(agent_access)
    if blueprint is not None:
        body["blueprints"] = _split(blueprint)
    if no_review:
        body["review_days"] = None
    elif review_days is not None:
        body["review_days"] = review_days
    return body


def _grant_summary(p: dict[str, Any]) -> str:
    parts = [f"{g['server']}:{','.join(g['tools'])}" for g in p["permissions"]]
    parts += [f"{m['provider']}:{','.join(m['models'])}" for m in p["model_access"]]
    if p["agent_access"]:
        parts.append(f"agents:{','.join(p['agent_access'])}")
    return "; ".join(parts)


@packages_app.command("list")
def packages_list() -> None:
    """List access packages, and how many agents hold each."""
    rows = _call("GET", "/v1/access-packages")
    for row in rows:
        row["grants"] = _grant_summary(row)
        row["days"] = row["duration_days"]
        row["held"] = row["assignments"]["active"] + row["assignments"]["expired"]
        row["waiting"] = row["assignments"]["requested"]
    _table(rows, ["name", "days", "grants", "held", "waiting"])


@packages_app.command("get")
def packages_get(name: str) -> None:
    """Show an access package."""
    _print(_call("GET", f"/v1/access-packages/{quote(name)}"))


@packages_app.command("create")
def packages_create(
    name: str,
    description: str | None = DESCRIPTION,
    grant: list[str] | None = PKG_GRANT,
    model_access: list[str] | None = PKG_MODEL,
    agent_access: list[str] | None = PKG_AGENTS,
    blueprint: list[str] | None = PKG_BLUEPRINTS,
    days: int | None = PKG_DAYS,
    review_days: int | None = PKG_REVIEW,
    approval: bool | None = PKG_APPROVAL,
) -> None:
    """Add an access package: what it grants, to which agents, for how long."""
    body = _package_fields(
        description,
        grant,
        model_access,
        agent_access,
        blueprint,
        days,
        review_days,
        False,
        approval,
    )
    out = _call("POST", "/v1/access-packages", json={"name": name, **body})
    _done("access-package", out["name"], "created")


@packages_app.command("update")
def packages_update(
    name: str,
    description: str | None = DESCRIPTION,
    grant: list[str] | None = typer.Option(
        None, "--grant", help="Tool grants server:tool,tool (replace them; repeatable)."
    ),
    model_access: list[str] | None = typer.Option(
        None, "--model-access", help="Models it grants (replace them; repeatable)."
    ),
    agent_access: list[str] | None = typer.Option(
        None, "--agent-access", help="Agents it lets call (replace them; repeatable)."
    ),
    blueprint: list[str] | None = typer.Option(
        None, "--blueprint", help="The blueprints whose agents may hold it (replace them)."
    ),
    days: int | None = PKG_DAYS,
    review_days: int | None = PKG_REVIEW,
    no_review: bool = typer.Option(False, "--no-review", help="No periodic reviews."),
    approval: bool | None = PKG_APPROVAL,
    if_version: int | None = IF_VERSION,
) -> None:
    """Change an access package: every agent that holds it gets the change."""
    body = _package_fields(
        description, grant, model_access, agent_access, blueprint, days, review_days, no_review,
        approval,
    )  # fmt: skip
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    out = _call("PATCH", f"/v1/access-packages/{quote(name)}", json=body, **_if_version(if_version))
    _done("access-package", out["name"], "updated")


@packages_app.command("delete")
def packages_delete(name: str, yes: bool = YES) -> None:
    """Delete an access package no agent holds or asks for."""
    _confirm(f"Delete access package {name}?", yes)
    _call("DELETE", f"/v1/access-packages/{quote(name)}")
    _done("access-package", name, "deleted")


@packages_app.command("request")
def packages_request(
    agent: str,
    package: str,
    reason: str = typer.Option(..., help="Why the agent needs it."),
    days: int | None = typer.Option(None, help="For how many days (the package's most)."),
    approve: bool = typer.Option(
        False, "--approve", help="Assign it at once (administrators only)."
    ),
) -> None:
    """Ask for an access package for an agent; asked again while it holds one, it renews."""
    body: dict[str, Any] = {"agent": agent, "package": package, "reason": reason}
    if days is not None:
        body["days"] = days
    if approve:
        body["approve"] = True
    out = _call("POST", "/v1/access-assignments", json=body)
    until = f" until {out['expires_at']}" if out["expires_at"] else ""
    _done("access", out["id"], f"{out['status']}{until}")


@packages_app.command("assignments")
def packages_assignments(
    status: str | None = typer.Option(
        None, help="requested, active, expired, denied, revoked, renewed or all."
    ),
    agent: str | None = typer.Option(None, help="Only this agent's."),
    package: str | None = typer.Option(None, help="Only this package's."),
) -> None:
    """List who holds and asks for access packages."""
    params = _given(status=status, agent=agent, package=package)
    rows = _call("GET", "/v1/access-assignments", params=params)
    _table(rows, ["id", "agent_name", "package", "status", "expires_at", "requested_by", "reason"])


def _assignment_action(assignment_id: str, action: str, body: dict[str, Any]) -> None:
    out = _call("POST", f"/v1/access-assignments/{quote(assignment_id)}/{action}", json=body)
    _done("access", out["id"], out["status"])


@packages_app.command("approve")
def packages_approve(assignment_id: str, note: str | None = None) -> None:
    """Approve a request (someone other than who asked)."""
    _assignment_action(assignment_id, "approve", _given(note=note))


@packages_app.command("deny")
def packages_deny(assignment_id: str, note: str | None = None) -> None:
    """Deny a request."""
    _assignment_action(assignment_id, "deny", _given(note=note))


@packages_app.command("revoke")
def packages_revoke(assignment_id: str, reason: str | None = None, yes: bool = YES) -> None:
    """Take an access package away from an agent, now."""
    _confirm(f"Revoke {assignment_id}?", yes)
    _assignment_action(assignment_id, "revoke", _given(reason=reason))


@packages_app.command("review")
def packages_review(
    assignment_id: str,
    keep: bool = typer.Option(
        ..., "--keep/--remove", help="Whether the agent still needs it (remove revokes it)."
    ),
    note: str | None = None,
) -> None:
    """Review an agent's access package: keep it, or remove it."""
    _assignment_action(assignment_id, "review", {"keep": keep, **_given(note=note)})


# ---------------------------------------------------------------------- teams

MEMBER = typer.Option(
    None,
    "--member",
    help="Someone in it, by email address or user name: they see its issues in AgentGov "
    "(repeatable or comma-separated).",
)
EMAIL = typer.Option(
    None,
    "--email",
    help="Where its issues are emailed, such as a list's address (repeatable or "
    "comma-separated); without any, its members' addresses.",
)
CHANNEL = typer.Option(
    None,
    "--channel",
    help="A Teams or Slack destination its issues are posted to (repeatable or comma-separated).",
)


def _team_fields(
    description: str | None,
    member: list[str] | None,
    email: list[str] | None,
    channel: list[str] | None,
    default: bool | None,
) -> dict[str, Any]:
    body = _given(description=description, default=default)
    for key, values in (("members", member), ("emails", email), ("destinations", channel)):
        if values is not None:
            body[key] = _split(values)
    return body


@teams_app.command("list")
def teams_list() -> None:
    """List teams."""
    rows = _call("GET", "/v1/teams")
    for row in rows:
        row["members"] = len(row["members"])
        row["emails"] = ", ".join(row["emails"])
        row["channels"] = ", ".join(row["destinations"])
        row["default"] = "yes" if row["default"] else ""
    _table(rows, ["name", "default", "members", "emails", "channels"])


@teams_app.command("get")
def teams_get(name: str) -> None:
    """Show a team, and the blueprints and agents that name it."""
    _print(_call("GET", f"/v1/teams/{quote(name)}"))


@teams_app.command("create")
def teams_create(
    name: str,
    description: str | None = DESCRIPTION,
    member: list[str] | None = MEMBER,
    email: list[str] | None = EMAIL,
    channel: list[str] | None = CHANNEL,
    default: bool = typer.Option(
        False, "--default", help="Issues without a team of their own go to it."
    ),
) -> None:
    """Add a team that agents' owners, sponsors and blueprints can name."""
    body = _team_fields(description, member, email, channel, default or None)
    out = _call("POST", "/v1/teams", json={"name": name, **body})
    _done("team", out["name"], "created (the default team)" if out["default"] else "created")


@teams_app.command("update")
def teams_update(
    name: str,
    description: str | None = DESCRIPTION,
    member: list[str] | None = typer.Option(
        None, "--member", help="Its members (replace them; repeatable)."
    ),
    email: list[str] | None = typer.Option(
        None, "--email", help="Where its issues are emailed (replace them; repeatable)."
    ),
    channel: list[str] | None = typer.Option(
        None, "--channel", help="Its Teams and Slack destinations (replace them; repeatable)."
    ),
    default: bool | None = typer.Option(
        None, "--default/--not-default", help="Whether issues without a team go to it."
    ),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change a team. Only the options you pass are changed."""
    body = _team_fields(description, member, email, channel, default)
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    out = _call("PATCH", f"/v1/teams/{quote(name)}", json=body, **_if_version(if_version))
    _done("team", out["name"], "updated")


@teams_app.command("delete")
def teams_delete(name: str, yes: bool = YES) -> None:
    """Delete a team that no blueprint or agent names."""
    _confirm(f"Delete team {name}?", yes)
    _call("DELETE", f"/v1/teams/{quote(name)}")
    _done("team", name, "deleted")


@models_app.command("usage")
def models_usage(
    days: int = typer.Option(7, help="How many days back, today included."),
    agent: str | None = typer.Option(None, help="Only this agent."),
    provider: str | None = typer.Option(None, help="Only this provider."),
    by: str | None = typer.Option(
        None, help="Add it up per owner or sponsor of the agents instead."
    ),
) -> None:
    """Calls, tokens and cost per agent, day, provider and model; and budgets today."""
    if by not in (None, "owner", "sponsor"):
        _fail(f"--by takes owner or sponsor (got {by!r})")
    params = {"days": days, **_given(agent=agent, provider=provider)}
    view = _call("GET", "/v1/models/usage", params=params)
    if by:
        groups = [
            {
                **g,
                by: g[by] or f"(no {by})",
                "tokens_in": g["input_tokens"],
                "tokens_out": g["output_tokens"],
                "cost_usd": f"{g['cost_usd']:.4f}",
            }
            for g in view[f"by_{by}"]
        ]
        _table(groups, [by, "agents", "calls", "tokens_in", "tokens_out", "cost_usd"])
        return
    rows = [
        {
            **r,
            "agent": r["agent_name"] or "(unidentified)",
            "tokens_in": r["input_tokens"],
            "tokens_out": r["output_tokens"],
            "cost_usd": f"{r['cost_usd']:.4f}",
        }
        for r in view["rows"]
    ]
    _table(rows, ["day", "agent", "provider", "model", "calls", "refused", "tokens_in",
                  "tokens_out", "cost_usd"])  # fmt: skip
    for b in view["today"]:
        if b["daily_token_budget"] is not None:
            state = "over budget" if b["over_budget"] else "within budget"
            typer.echo(
                f"agent/{b['agent_name']}: {b['used_today']} of {b['daily_token_budget']} "
                f"tokens today ({state})"
            )


# --------------------------------------------------------------- management rules

RULE_ACTION = typer.Option(
    None, help="issue, assign_owner, block, delete or revoke_access (issue by default)."
)
RULE_OWNER = typer.Option(None, "--owner", help="assign_owner: the team or email to make owner.")
RULE_AFTER = typer.Option(
    None, "--after-days", help="Days an agent matches before the action (14 by default)."
)
RULE_SEVERITY = typer.Option(None, help="Its issues' severity: low, medium, high or critical.")
RULE_MAX = typer.Option(None, "--max-actions", help="Agents it acts on at once, at most.")
RULE_MODE = typer.Option(None, help="off, monitor (the default) or enforce.")
INACTIVE_DAYS = typer.Option(None, "--inactive-days", help="Condition: no activity for N days.")
MISSING = typer.Option(
    None,
    "--missing",
    help="Condition: lacks owner, sponsors, team, blueprint or workload_identity (repeatable).",
)
OVERDUE = typer.Option(
    None, "--attestation-overdue-days", help="Condition: attestation overdue for N days."
)
FINDING = typer.Option(
    None, "--finding", help="Condition: an open finding of this type, * allowed (repeatable)."
)
FINDING_SEVERITY = typer.Option(
    None, "--finding-severity", help="Condition: the finding is at least this severe."
)
RISK_LEVEL = typer.Option(None, "--risk-level", help="Condition: at least this risk level.")
STATUS = typer.Option(
    None, "--status", help="Condition: pending, active, blocked or discovered (repeatable)."
)
IN_BLUEPRINT = typer.Option(None, "--blueprint", help="Scope: agents on these blueprints.")
IN_TEAM = typer.Option(None, "--team", help="Scope: agents of these teams.")
IN_ENVIRONMENT = typer.Option(None, "--environment", help="Scope: agents in these environments.")
IN_PLATFORM = typer.Option(
    None, "--platform", help="Scope: gateway, microsoft-365 or copilot-studio (repeatable)."
)
IN_LABEL = typer.Option(None, "--scope-label", help="Scope: agents with this label, key=value.")


def _rule_fields(
    *,
    description: str | None,
    inactive_days: int | None,
    missing: list[str] | None,
    attestation_overdue_days: int | None,
    finding: list[str] | None,
    finding_severity: str | None,
    risk_level: str | None,
    status: list[str] | None,
    blueprint: list[str] | None,
    team: list[str] | None,
    environment: list[str] | None,
    platform: list[str] | None,
    scope_label: list[str] | None,
    action: str | None,
    owner: str | None,
    after_days: int | None,
    severity: str | None,
    max_actions: int | None,
    mode: str | None,
    label: list[str] | None,
) -> dict[str, Any]:
    """A rule's fields from the options passed. Conditions, and scope, are replaced as a
    whole when any of theirs is passed."""
    conditions = _given(
        inactive_days=inactive_days,
        missing=_split(missing) or None,
        attestation_overdue_days=attestation_overdue_days,
        findings=_split(finding) or None,
        finding_severity=finding_severity,
        risk_level=risk_level,
        status=_split(status) or None,
    )
    scope = _given(
        blueprints=_split(blueprint) or None,
        teams=_split(team) or None,
        environments=_split(environment) or None,
        platforms=_split(platform) or None,
        labels=_labels(scope_label) or None,
    )
    body = _given(
        description=description,
        action=action,
        after_days=after_days,
        severity=severity,
        max_actions=max_actions,
        mode=mode,
    )
    if conditions:
        body["conditions"] = conditions
    if scope:
        body["scope"] = scope
    if owner is not None:
        body["params"] = {"owner": owner}
    if label is not None:
        body["labels"] = _labels(label)
    return body


def _conditions_text(conditions: dict[str, Any]) -> str:
    return "; ".join(
        f"{k}={','.join(v) if isinstance(v, list) else v}" for k, v in conditions.items()
    )


@rules_app.command("list")
def rules_list() -> None:
    """List management rules: what each looks for, does, and how many agents it matches."""
    rows = _call("GET", "/v1/rules")
    for row in rows:
        row["when"] = _conditions_text(row["conditions"])
        row["after"] = f"{row['after_days']}d"
        row["mode"] = (
            row["mode"]
            if row["effective_mode"] == row["mode"]
            else f"{row['mode']} ({row['effective_mode']})"
        )
        row["matching"] = row["matches"]["matching"]
    _table(rows, ["name", "mode", "action", "after", "when", "matching"])


@rules_app.command("get")
def rules_get(name: str) -> None:
    """Show a management rule."""
    _print(_call("GET", f"/v1/rules/{quote(name)}"))


def _show_preview(view: dict[str, Any]) -> None:
    head = f"{view['matching']} agent(s) match, {view['due']} due now ({view['mode']})"
    if view["held_back"]:
        head += f": more than {view['max_actions']} at once, so it would act on none"
    if not view["running"]:
        head += f"; not running: {view['why_not']}"
    typer.echo(head)
    rows = [{**e, "why": "; ".join(e["reasons"])} for e in view["agents"]]
    if rows:
        _table(rows, ["agent", "state", "detail", "why"])
    for u in view["unknown"]:
        typer.echo(f"agent/{u['agent']}: can't tell: {u['why']}")


@rules_app.command("create")
def rules_create(
    name: str,
    description: str | None = DESCRIPTION,
    inactive_days: int | None = INACTIVE_DAYS,
    missing: list[str] | None = MISSING,
    attestation_overdue_days: int | None = OVERDUE,
    finding: list[str] | None = FINDING,
    finding_severity: str | None = FINDING_SEVERITY,
    risk_level: str | None = RISK_LEVEL,
    status: list[str] | None = STATUS,
    blueprint: list[str] | None = IN_BLUEPRINT,
    team: list[str] | None = IN_TEAM,
    environment: list[str] | None = IN_ENVIRONMENT,
    platform: list[str] | None = IN_PLATFORM,
    scope_label: list[str] | None = IN_LABEL,
    action: str | None = RULE_ACTION,
    owner: str | None = RULE_OWNER,
    after_days: int | None = RULE_AFTER,
    severity: str | None = RULE_SEVERITY,
    max_actions: int | None = RULE_MAX,
    mode: str | None = RULE_MODE,
    label: list[str] | None = LABEL,
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what it would match and do, without saving it."
    ),
) -> None:
    """Add a management rule: conditions, the agents it looks at, and what it does."""
    body = _rule_fields(
        description=description, inactive_days=inactive_days, missing=missing,
        attestation_overdue_days=attestation_overdue_days, finding=finding,
        finding_severity=finding_severity, risk_level=risk_level, status=status,
        blueprint=blueprint, team=team, environment=environment, platform=platform,
        scope_label=scope_label, action=action, owner=owner, after_days=after_days,
        severity=severity, max_actions=max_actions, mode=mode, label=label,
    )  # fmt: skip
    if dry_run:
        _show_preview(_call("POST", "/v1/rules/preview", json={"name": name, **body}))
        return
    out = _call("POST", "/v1/rules", json={"name": name, **body})
    _done("rule", out["name"], f"created ({out['effective_mode']})")


@rules_app.command("update")
def rules_update(
    name: str,
    description: str | None = DESCRIPTION,
    inactive_days: int | None = INACTIVE_DAYS,
    missing: list[str] | None = MISSING,
    attestation_overdue_days: int | None = OVERDUE,
    finding: list[str] | None = FINDING,
    finding_severity: str | None = FINDING_SEVERITY,
    risk_level: str | None = RISK_LEVEL,
    status: list[str] | None = STATUS,
    blueprint: list[str] | None = IN_BLUEPRINT,
    team: list[str] | None = IN_TEAM,
    environment: list[str] | None = IN_ENVIRONMENT,
    platform: list[str] | None = IN_PLATFORM,
    scope_label: list[str] | None = IN_LABEL,
    action: str | None = RULE_ACTION,
    owner: str | None = RULE_OWNER,
    after_days: int | None = RULE_AFTER,
    severity: str | None = RULE_SEVERITY,
    max_actions: int | None = RULE_MAX,
    mode: str | None = RULE_MODE,
    label: list[str] | None = typer.Option(None, "--label", help="Labels (replace them)."),
    if_version: int | None = IF_VERSION,
) -> None:
    """Change a management rule. Passing any condition replaces its conditions, and any
    scope option its scope."""
    body = _rule_fields(
        description=description, inactive_days=inactive_days, missing=missing,
        attestation_overdue_days=attestation_overdue_days, finding=finding,
        finding_severity=finding_severity, risk_level=risk_level, status=status,
        blueprint=blueprint, team=team, environment=environment, platform=platform,
        scope_label=scope_label, action=action, owner=owner, after_days=after_days,
        severity=severity, max_actions=max_actions, mode=mode, label=label,
    )  # fmt: skip
    if not body:
        _fail("nothing to change: pass at least one option (see --help)")
    out = _call("PATCH", f"/v1/rules/{quote(name)}", json=body, **_if_version(if_version))
    _done("rule", out["name"], f"updated ({out['effective_mode']})")


@rules_app.command("delete")
def rules_delete(name: str, yes: bool = YES) -> None:
    """Delete a management rule: its issues are resolved; what it did stays done."""
    _confirm(f"Delete management rule {name}?", yes)
    _call("DELETE", f"/v1/rules/{quote(name)}")
    _done("rule", name, "deleted")


@rules_app.command("preview")
def rules_preview(name: str) -> None:
    """The agents a rule matches now, since when, and what it will do to each."""
    _show_preview(_call("GET", f"/v1/rules/{quote(name)}/preview"))


@rules_app.command("evaluate")
def rules_evaluate() -> None:
    """Run the rules now, instead of after the next posture scan."""
    out = _call("POST", "/v1/rules/evaluate")
    if out.get("off"):
        typer.echo(f"management rules are off: {out['resolved']} issue(s) resolved")
        return
    for name, counts in out.items():
        typer.echo(
            f"rule/{name}: {counts['matching']} matching, {counts['acted']} acted on, "
            f"{counts['would_act']} would have been, {counts['held_back']} held back"
        )


@rules_app.command("agent")
def rules_agent(agent: str) -> None:
    """The rules that match an agent, and what each will do or did."""
    rows = _call("GET", f"/v1/agents/{quote(agent)}/rules")
    _table(rows, ["rule", "action", "mode", "since", "state", "detail"])


# ------------------------------------------------------------------ evidence

EVIDENCE_DAYS = typer.Option(90, "--days", help="The period: the last N days.")
STATUS_NAMES = {
    "in_place": "in place",
    "partly": "partly",
    "configured": "configured, not observed",
    "not_set_up": "not set up",
    "attention": "NEEDS ATTENTION",
    "outside": "outside AgentGov",
}


@evidence_app.command("report")
def evidence_report(
    framework: str = typer.Option(
        "eu-ai-act", "--framework", help="eu-ai-act, iso-42001 or nist-ai-rmf."
    ),
    days: int = EVIDENCE_DAYS,
    as_json: bool = typer.Option(False, "--json", help="The whole report, as JSON."),
) -> None:
    """What AgentGov does towards a framework's controls, how far that is set up, and the
    evidence. It doesn't say that the organisation complies."""
    report = _call("GET", "/v1/evidence/report", params={"framework": framework, "days": days})
    if as_json:
        _print(report)
        return
    typer.echo(f"{report['framework']['title']}, the last {report['period']['days']} days")
    c = report["coverage"]
    typer.echo(
        f"What AgentGov saw of the {c['agents']} agent{'' if c['agents'] == 1 else 's'}: "
        f"{c['calls_checked']} had their calls checked, {c['activity_only']} were seen at "
        f"work only, {c['inventory_only']} only in their platform's inventory, "
        f"{c['not_seen']} not at all."
    )
    if c["platforms_not_read"]:
        typer.echo(f"Not read in the period: {', '.join(c['platforms_not_read'])}.")
    rows = []
    for c in report["controls"]:
        evidence = "; ".join(f"{e['label']}: {e['value']}" for e in c["evidence"][:3])
        rows.append({"control": c["id"], "status": STATUS_NAMES[c["status"]], "evidence": evidence})
    _table(rows, ["control", "status", "evidence"])
    for c in report["controls"]:
        for gap in c["gaps"]:
            typer.echo(f"{c['id']}: {gap}")


@evidence_app.command("pack")
def evidence_pack(
    days: int = EVIDENCE_DAYS,
    out: Path | None = typer.Option(None, "--out", "-o", help="The zip file to write."),
) -> None:
    """The reports, the ledger for the period, the checkpoints and their time-stamps, the
    inventory and the registry as code, in one zip, for whoever assesses compliance."""
    with (
        _client() as client,
        client.stream("GET", "/v1/evidence/pack", params={"days": days}) as resp,
    ):
        if resp.status_code >= 400:
            resp.read()
            _fail(resp.text)
        name = resp.headers.get("content-disposition", "").partition('filename="')[2].rstrip('"')
        target = out or Path(name or "agentgov-evidence.zip")
        with target.open("wb") as file:
            for chunk in resp.iter_bytes():
                file.write(chunk)
    typer.echo(f"wrote {target} ({target.stat().st_size} bytes)")


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

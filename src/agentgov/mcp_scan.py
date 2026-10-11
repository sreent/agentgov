"""The MCP servers configured on a developer's machine, for AgentGov's inventory.

Developers add MCP servers to their editors and assistants: VS Code and GitHub
Copilot, Claude Desktop and Claude Code, Cursor, Windsurf, Gemini CLI, Codex.
``agentgov mcp scan`` reads those clients' configuration files, user-wide and in
the projects it is pointed at, and lists each server: its transport and URL, or
the command that starts it. With ``--report`` it sends the list to AgentGov,
which compares it with the approved tool servers and raises findings for the
rest.

Configuration files hold credentials (API keys in environment variables, tokens
in headers or arguments). Nothing of them leaves the machine: environment
variables and headers are reported by name only, URLs without their query and
user information, and arguments that look like credentials are replaced.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
import tomllib
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from agentgov.processor import detectors

REDACTED = "<redacted>"
MAX_FILE_BYTES = 2_000_000

# Flags whose value is a credential: --token X, --api-key=X.
# Options whose value is a credential (--token X, --api-key=X, --auth-header X): any word
# of the option's name is one of these, or contains token, secret or password.
_SECRET_WORDS = {"key", "apikey", "pass", "pwd", "auth", "authorization", "bearer", "cookie",
                 "credential", "credentials"}  # fmt: skip
_SECRET_IN_WORD = ("token", "secret", "passw")
# Options whose value is an HTTP header, "Name: value" (mcp-remote's --header).
_HEADER_FLAGS = {"--header", "--headers", "--http-header", "-H"}
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+\S+")


def _secret_flag(arg: str) -> bool:
    if not arg.startswith("-"):
        return False
    words = re.split(r"[-_.]+", arg.lstrip("-").split("=", 1)[0].lower())
    return any(w in _SECRET_WORDS or any(s in w for s in _SECRET_IN_WORD) for w in words if w)


@dataclass
class Source:
    """A configuration file one client reads."""

    client: str
    scope: str  # "user" or "project"
    path: Path
    key: str  # where the servers are: "servers" (VS Code) or "mcpServers"
    format: str = "json"


@dataclass
class Sighting:
    """One MCP server in one client's configuration, as reported."""

    name: str
    client: str
    scope: str
    transport: str  # "stdio", "http" or "sse"
    url: str | None = None
    command: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    file: str = ""
    # How AgentGov recognises the same server elsewhere: "url:<url>", "npm:<package>",
    # "pypi:<package>", "oci:<image>" or "command:<command>".
    identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _app_data(home: Path, env: dict[str, str]) -> Path:
    if sys.platform == "win32":
        return Path(env.get("APPDATA") or home / "AppData" / "Roaming")
    if sys.platform == "darwin":
        return home / "Library" / "Application Support"
    return Path(env.get("XDG_CONFIG_HOME") or home / ".config")


def user_sources(home: Path | None = None) -> list[Source]:
    """The user-wide configuration files of the clients AgentGov knows: this user's, or
    those in ``home`` (another person's home directory, where this process's environment
    doesn't apply)."""
    env = dict(os.environ) if home is None else {}
    home = home or Path.home()
    app = _app_data(home, env)
    copilot = Path(env.get("COPILOT_HOME") or home / ".copilot")
    return [
        Source("vscode", "user", app / "Code" / "User" / "mcp.json", "servers"),
        Source("vscode-insiders", "user", app / "Code - Insiders" / "User" / "mcp.json", "servers"),
        Source("copilot-cli", "user", copilot / "mcp-config.json", "mcpServers"),
        Source(
            "claude-desktop", "user", app / "Claude" / "claude_desktop_config.json", "mcpServers"
        ),
        Source("claude-code", "user", home / ".claude.json", "mcpServers"),
        Source("cursor", "user", home / ".cursor" / "mcp.json", "mcpServers"),
        Source(
            "windsurf", "user", home / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers"
        ),
        Source("gemini-cli", "user", home / ".gemini" / "settings.json", "mcpServers"),
        Source("codex", "user", home / ".codex" / "config.toml", "mcp_servers", "toml"),
    ]


def project_sources(directory: Path) -> list[Source]:
    """The configuration files a project can carry."""
    return [
        Source("vscode", "project", directory / ".vscode" / "mcp.json", "servers"),
        Source("claude-code", "project", directory / ".mcp.json", "mcpServers"),
        Source("cursor", "project", directory / ".cursor" / "mcp.json", "mcpServers"),
        Source("gemini-cli", "project", directory / ".gemini" / "settings.json", "mcpServers"),
    ]


# ------------------------------------------------------------------ parsing

_JSONC = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', re.S)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def loads_jsonc(text: str) -> Any:
    """JSON with comments and trailing commas, as VS Code writes it."""
    stripped = _JSONC.sub(lambda m: m.group(0) if m.group(0).startswith('"') else "", text)
    return json.loads(_TRAILING_COMMA.sub(r"\1", stripped))


def _read(source: Source) -> Any:
    if not source.path.is_file() or source.path.stat().st_size > MAX_FILE_BYTES:
        return None
    text = source.path.read_text(encoding="utf-8", errors="replace")
    try:
        return tomllib.loads(text) if source.format == "toml" else loads_jsonc(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return None


def _servers(source: Source, data: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    if not isinstance(data, dict):
        return
    blocks = [data.get(source.key)]
    if source.client == "claude-code" and source.scope == "user":
        # ~/.claude.json also keeps servers per project.
        blocks += [
            p.get(source.key) for p in (data.get("projects") or {}).values() if isinstance(p, dict)
        ]
    for block in blocks:
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, dict):
                    yield str(name), spec


# ------------------------------------------------------------- sanitising


def clean_url(url: str) -> str:
    """The URL without its user information, query or fragment, which can hold secrets."""
    parts = urlsplit(url.strip())
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), host.lower(), parts.path, "", ""))


def _header(value: str) -> str:
    """A header with its value left out: "Authorization: <redacted>"."""
    name, sep, _ = value.partition(":")
    return f"{name.strip()}: {REDACTED}" if sep else REDACTED


def clean_args(args: list[Any]) -> list[str]:
    """Command-line arguments without the credentials in them."""
    out: list[str] = []
    expect: str | None = None  # what the previous option says this argument is
    for raw in args:
        arg = str(raw)
        if expect == "secret":
            out.append(REDACTED)
            expect = None
            continue
        if expect == "header":
            out.append(_header(arg))
            expect = None
            continue
        option = arg.split("=", 1)[0]
        if option in _HEADER_FLAGS or option.lower() in _HEADER_FLAGS:
            if "=" in arg:
                out.append(f"{arg.split('=', 1)[0]}={_header(arg.split('=', 1)[1])}")
            else:
                out.append(arg)
                expect = "header"
            continue
        if _secret_flag(arg):
            if "=" in arg:
                out.append(arg.split("=", 1)[0] + "=" + REDACTED)
            else:
                out.append(arg)
                expect = "secret"
            continue
        if _BEARER.search(arg):
            out.append(_BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", arg))
            continue
        if (
            detectors.find_secrets((), arg)
            or urlsplit(arg).password
            or ("://" in arg and urlsplit(arg).query)
        ):
            out.append(
                clean_url(arg) if "://" in arg and not detectors.find_secrets((), arg) else REDACTED
            )
            continue
        out.append(arg)
    return out


_LAUNCHERS = {"npx": "npm", "pnpx": "npm", "bunx": "npm", "uvx": "pypi", "pipx": "pypi"}
# Package specs carry a version: "@scope/name@1.2.3", "name==1.2.3".
_PACKAGE = re.compile(r"^(@?[^@=\s]+)(?:@[^@\s]*|==\S*)?$")
# Options of `docker run` that take a value, so the image is the first other word.
_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "--network", "--net",
    "-p", "--publish", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform",
    "-l", "--label", "--add-host", "--cap-add", "--cap-drop", "-h", "--hostname", "-m",
    "--memory", "--cpus", "--pull", "--runtime", "--security-opt", "--tmpfs", "--ulimit",
}  # fmt: skip


def _program(path: str) -> str:
    name = re.split(r"[\\/]", path)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        name = name.removesuffix(suffix)
    return name


def _image(args: list[str]) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in _DOCKER_VALUE_FLAGS:
            skip = True
        elif not arg.startswith("-"):
            return arg
    return None


def identity_of(url: str | None, command: list[str]) -> str:
    """How AgentGov recognises the same server on another machine, or in the registry:
    ``url:<url>``, ``npm:<package>``, ``pypi:<package>``, ``oci:<image>`` or
    ``command:<command line>``."""
    if url:
        return f"url:{url.rstrip('/')}"
    if not command:
        return ""
    program, args = _program(command[0]), command[1:]
    if program == "pipx" and args[:1] == ["run"]:
        args = args[1:]
    if program in _LAUNCHERS:
        package = next((a for a in args if not a.startswith("-") and a != REDACTED), None)
        if package:
            match = _PACKAGE.match(package)
            return f"{_LAUNCHERS[program]}:{match.group(1) if match else package}"
    if program in ("docker", "podman") and "run" in args:
        image = _image(args[args.index("run") + 1 :])
        if image:
            # Without the tag or digest: "mcp/postgres:1.2" is "mcp/postgres".
            base = image.split("@", 1)[0]
            name, _, tag = base.rpartition(":")
            return f"oci:{name if name and '/' not in tag else base}"
    return "command:" + " ".join([program, *args])[:300]


def sighting(source: Source, name: str, spec: dict[str, Any]) -> Sighting:
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    kind = str(spec.get("type") or spec.get("transport") or "").lower()
    if url:
        transport = "sse" if kind == "sse" or str(url).rstrip("/").endswith("/sse") else "http"
        url = clean_url(str(url))
        command: list[str] = []
    else:
        transport = "stdio"
        program = spec.get("command")
        args = spec.get("args") or []
        command = clean_args([program, *args]) if program else []
    return Sighting(
        name=name,
        client=source.client,
        scope=source.scope,
        transport=transport,
        url=url,
        command=command,
        env=sorted(str(k) for k in (spec.get("env") or {})),
        headers=sorted(str(k) for k in (spec.get("headers") or spec.get("http_headers") or {})),
        file=str(source.path),
        identity=identity_of(url, command),
    )


def scan(directories: list[Path] | None = None, home: Path | None = None) -> list[Sighting]:
    """The MCP servers configured on this machine, user-wide and in ``directories``."""
    sources = user_sources(home)
    for directory in directories or []:
        sources += project_sources(directory)
    found = []
    for source in sources:
        for name, spec in _servers(source, _read(source)):
            found.append(sighting(source, name, spec))
    return found


def machine() -> dict[str, str]:
    return {
        "machine": platform.node() or "unknown",
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "",
    }

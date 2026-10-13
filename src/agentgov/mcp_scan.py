"""The MCP servers configured on a developer's machine, for AgentGov's inventory.

Developers add MCP servers to their editors and assistants: VS Code and GitHub
Copilot, Claude Desktop and Claude Code, Cursor, Windsurf, Gemini CLI, Codex.
``agentgov mcp scan`` reads those clients' configuration files, user-wide and in
the projects it is pointed at, and lists each server: its transport and URL, or
the command that starts it. With ``--report`` it sends the list to AgentGov,
which compares it with the approved tool servers and raises findings for the
rest.

Configuration files hold credentials (API keys in environment variables, tokens
in headers, arguments or a URL's path). None of them is reported: environment
variables and headers by name only; a server's address by its scheme, host and
port, with a short hash of its path, where some services put the credential;
and in arguments, URLs without their user information, query or fragment, the
values of options that take a credential, a header or an environment variable
(``-e NAME=value``), and whatever looks like a key or a token, as <redacted>.
AgentGov sanitises a report again with these rules before it keeps it.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import platform
import re
import sys
import tomllib
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

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
# Options whose value is an environment variable, NAME=value (docker run's -e).
_ENV_FLAGS = {"-e", "--env"}
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+\S+")
# What reads as a key or a token rather than a word, a path or a version: a UUID, or a run
# of letters and digits at least 20 long that switches between them often, with at least
# 3 bits of entropy a character.
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
_RUN = re.compile(r"[A-Za-z0-9]{20,}")
_SWITCHES = 4
_BITS = 3.0
# What an address keeps of a path: a short hash.
_PATH_HASH = re.compile(r"^[0-9a-f]{12}$")


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


def _host(parts: SplitResult) -> str:
    """A URL's host and port, without its user information."""
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"  # an IPv6 address
    try:
        port = parts.port
    except ValueError:
        port = None  # not a port
    return f"{host}:{port}" if port else host


def _random(run: str) -> bool:
    switches = sum(a.isdigit() != b.isdigit() for a, b in itertools.pairwise(run))
    if switches < _SWITCHES:
        return False
    bits = -sum(n / len(run) * math.log2(n / len(run)) for n in Counter(run).values())
    return bits >= _BITS


def redact_random(text: str) -> str:
    """``text`` with what reads as a key or a token in it as <redacted>."""
    text = _UUID.sub(REDACTED, text)
    return _RUN.sub(lambda m: REDACTED if _random(m.group()) else m.group(), text)


def address(url: str) -> str:
    """A server's address, as reported: its scheme, host and port, and a short hash of its
    path (``https://mcp.example.com#3f2a1b9c4d5e``), so that two servers on one host stay
    apart while what the path holds stays on the machine. An address is its own address."""
    parts = urlsplit(url.strip())
    base = urlunsplit((parts.scheme.lower(), _host(parts), "", "", ""))
    path = parts.path.rstrip("/")
    if path:
        return f"{base}#{hashlib.sha256(path.encode()).hexdigest()[:12]}"
    if not parts.query and _PATH_HASH.match(parts.fragment):
        return f"{base}#{parts.fragment}"
    return base


def clean_url(url: str) -> str:
    """A URL in an argument: without its user information, query or fragment, which can
    hold secrets, and with what reads as a key or a token in its path redacted."""
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme.lower(), _host(parts), redact_random(parts.path), "", ""))


def _header(value: str) -> str:
    """A header with its value left out: "Authorization: <redacted>"."""
    name, sep, _ = value.partition(":")
    return f"{name.strip()}: {REDACTED}" if sep else REDACTED


def _env(value: str) -> str:
    """An environment variable with its value left out: "NAME=<redacted>"."""
    name, sep, _ = value.partition("=")
    return f"{name}={REDACTED}" if sep else value


def _clean_word(arg: str) -> str:
    if detectors.find_secrets((), arg):
        return REDACTED
    return clean_url(arg) if "://" in arg else redact_random(arg)


def clean_args(args: list[Any]) -> list[str]:
    """Command-line arguments without the credentials in them. Cleaning them again changes
    nothing."""
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
        if expect == "env":
            out.append(_env(arg))
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
        if option in _ENV_FLAGS:
            if "=" in arg:
                out.append(f"{option}={_env(arg.split('=', 1)[1])}")
            else:
                out.append(arg)
                expect = "env"
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
        out.append(_clean_word(arg))
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
    ``url:<address>``, ``npm:<package>``, ``pypi:<package>``, ``oci:<image>`` or
    ``command:<command line>``, from its address (see :func:`address`) or its cleaned
    command line."""
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


def clean_identity(identity: str) -> str:
    """An identity as reported, sanitised as :func:`identity_of` makes one."""
    kind, _, value = identity.partition(":")
    if kind == "url":
        return f"url:{address(value)}"
    if kind == "command":
        return "command:" + " ".join(clean_args(value.split(" ")))[:300]
    return identity


def sighting(source: Source, name: str, spec: dict[str, Any]) -> Sighting:
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    kind = str(spec.get("type") or spec.get("transport") or "").lower()
    if url:
        transport = "sse" if kind == "sse" or str(url).rstrip("/").endswith("/sse") else "http"
        url = address(str(url))
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

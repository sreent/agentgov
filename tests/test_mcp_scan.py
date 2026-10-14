"""Reading the MCP servers set up on a developer's machine (agentgov.mcp_scan)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentgov import mcp_scan


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A home directory and a project with MCP clients set up, as a developer's are."""
    home, project = tmp_path / "home", tmp_path / "project"
    # Another person's home: this process's environment doesn't apply to it.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "elsewhere"))
    monkeypatch.setattr(mcp_scan.sys, "platform", "linux")
    files = {
        home / ".config/Code/User/mcp.json": """{
          // VS Code writes comments and trailing commas
          "servers": {
            "crm": {"type": "http", "url": "https://gateway.example.com/mcp/crm",
                    "headers": {"Authorization": "Bearer ${input:token}"}},
            "github": {"type": "http", "url": "https://u:p@api.githubcopilot.com/mcp/?token=abc"},
            "playwright": {"command": "npx", "args": ["-y", "@playwright/mcp@0.0.41"]},
          },
        }""",
        home / ".cursor/mcp.json": json.dumps({"mcpServers": {
            "postgres": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "PGPASSWORD",
                         "mcp/postgres:1.2", "postgresql://admin:s3cret@db:5432/app"],
                         "env": {"PGPASSWORD": "hunter2"}},
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7", "--api-key",
                      "sk-live-123456789012345678901234"]},
        }}),
        home / ".claude.json": json.dumps({"projects": {"/src/app": {"mcpServers": {
            "notes": {"command": "/usr/bin/python3", "args": ["notes_server.py"]}}}}}),
        home / ".codex/config.toml": '[mcp_servers.files]\ncommand = "npx"\nargs = '
                                     '["-y", "@modelcontextprotocol/server-filesystem", "/"]\n',
        project / ".vscode/mcp.json": json.dumps({"servers": {
            "crm-direct": {"type": "http", "url": "http://crm-mcp:9000/mcp"}}}),
        project / ".mcp.json": "not json",
    }  # fmt: skip
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return home, project


def test_servers_are_found_in_every_client(machine) -> None:
    home, project = machine
    found = {s.name: s for s in mcp_scan.scan([project], home=home)}
    assert set(found) == {
        "crm", "github", "playwright", "postgres", "fetch", "notes", "files", "crm-direct",
    }  # fmt: skip
    assert (found["crm"].client, found["crm"].scope) == ("vscode", "user")
    assert (found["crm-direct"].client, found["crm-direct"].scope) == ("vscode", "project")
    assert found["notes"].client == "claude-code" and found["files"].client == "codex"


def test_identities(machine) -> None:
    home, project = machine
    found = {s.name: s.identity for s in mcp_scan.scan([project], home=home)}
    assert found == {
        "crm": f"url:https://gateway.example.com#{digest('/mcp/crm')}",
        "github": f"url:https://api.githubcopilot.com#{digest('/mcp')}",
        "playwright": "npm:@playwright/mcp",
        "postgres": "oci:mcp/postgres",
        "fetch": "pypi:mcp-server-fetch",
        "notes": "command:python3 notes_server.py",
        "files": "npm:@modelcontextprotocol/server-filesystem",
        "crm-direct": f"url:http://crm-mcp:9000#{digest('/mcp')}",
    }


def test_credentials_never_leave_the_machine(machine) -> None:
    home, project = machine
    report = json.dumps([s.to_dict() for s in mcp_scan.scan([project], home=home)])
    for secret in ("hunter2", "s3cret", "sk-live", "token=abc", "u:p@", "${input:token}"):
        assert secret not in report
    found = {s.name: s for s in mcp_scan.scan([project], home=home)}
    assert found["postgres"].env == ["PGPASSWORD"]
    assert found["crm"].headers == ["Authorization"]
    assert found["fetch"].command == [
        "uvx",
        "mcp-server-fetch==2025.4.7",
        "--api-key",
        "<redacted>",
    ]
    assert found["github"].url == f"https://api.githubcopilot.com#{digest('/mcp')}"


@pytest.mark.parametrize(
    ("command", "identity"),
    [
        (["C:\\Program Files\\nodejs\\npx.cmd", "-y", "@playwright/mcp@latest"],
         "npm:@playwright/mcp"),
        (["docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server:v1@sha256:ab"],
         "oci:ghcr.io/github/github-mcp-server"),
        (["docker", "run", "localhost:5000/mcp/x"], "oci:localhost:5000/mcp/x"),
        (["pipx", "run", "mcp-server-git"], "pypi:mcp-server-git"),
        (["python", "server.py", "--port", "3000"], "command:python server.py --port 3000"),
    ],
)  # fmt: skip
def test_identity_of_commands(command: list[str], identity: str) -> None:
    assert mcp_scan.identity_of(None, command) == identity


@pytest.mark.parametrize(
    ("args", "cleaned"),
    [
        (["mcp-remote", "https://x.example/mcp", "--header", "Authorization: Bearer abc123"],
         ["mcp-remote", "https://x.example/mcp", "--header", "Authorization: <redacted>"]),
        (["mcp-remote", "-H", "X-Api-Key: zzz"], ["mcp-remote", "-H", "X-Api-Key: <redacted>"]),
        (["server", "--header=X-Api-Key: zzz"], ["server", "--header=X-Api-Key: <redacted>"]),
        (["server", "--auth-header", "xyz"], ["server", "--auth-header", "<redacted>"]),
        (["server", "--password=hunter2"], ["server", "--password=<redacted>"]),
        (["server", "Bearer abc.def.ghi"], ["server", "Bearer <redacted>"]),
        (["server", "https://u:p@db.example/x"], ["server", "<redacted>"]),
        (["server", "https://api.example/x?key=1"], ["server", "https://api.example/x"]),
        (["server", "-h", "localhost", "--port", "3000"],
         ["server", "-h", "localhost", "--port", "3000"]),
    ],
)  # fmt: skip
def test_arguments_lose_their_credentials(args: list[str], cleaned: list[str]) -> None:
    assert mcp_scan.clean_args(args) == cleaned


ZAPIER = "https://actions.zapier.com/mcp/sk-ak-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c/sse"
ZAPIER_KEY = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
ZAPIER_SERVER = "ODg5YzQ1ZTAtNGQ4Mi00ZjI5LWI2NDgtM2E3ZGU5YjFjMmQ0OjEyMzQ1Njc4OTA"
COMPOSIO = "2b1f7c0e-9a4d-4c55-8a51-6d0d8f3e2a11"


def digest(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()[:12]


def test_what_paths_and_options_hold_stays_on_the_machine(tmp_path: Path) -> None:
    """Some services put the credential in the URL's path; docker takes one as -e NAME=value."""
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor/mcp.json").write_text(json.dumps({"mcpServers": {
        "zapier": {"url": ZAPIER},
        "zapier-remote": {"command": "npx", "args": [
            "-y", "mcp-remote", f"https://mcp.zapier.com/api/mcp/s/{ZAPIER_SERVER}=/mcp"]},
        "composio": {"url": f"https://mcp.composio.dev/composio/server/{COMPOSIO}/mcp"},
        "postgres": {"command": "docker", "args": [
            "run", "-i", "--rm", "-e", "POSTGRES_PASSWORD=Sup3rS3cretPw!", "--env=API=abc",
            "-e", "PGHOST", "mcp/postgres"]},
        "git": {"command": "uvx", "args": [
            "mcp-server-git==2025.4.7", "--repository", "/src/app",
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"]},
    }}))  # fmt: skip
    found = {s.name: s for s in mcp_scan.scan([], home=home)}
    report = json.dumps([s.to_dict() for s in found.values()])
    for secret in (ZAPIER_KEY, ZAPIER_SERVER, COMPOSIO, "Sup3rS3cretPw!", "=abc", "9c1185a5"):
        assert secret not in report
    path = f"/mcp/sk-ak-{ZAPIER_KEY}/sse"
    assert found["zapier"].url == f"https://actions.zapier.com#{digest(path)}"
    assert found["zapier"].identity == f"url:{found['zapier'].url}"
    assert found["composio"].url.startswith("https://mcp.composio.dev#")
    assert found["zapier-remote"].command == [
        "npx", "-y", "mcp-remote", "https://mcp.zapier.com/api/mcp/s/<redacted>=/mcp",
    ]  # fmt: skip
    assert found["zapier-remote"].identity == "npm:mcp-remote"
    assert found["postgres"].command == [
        "docker", "run", "-i", "--rm", "-e", "POSTGRES_PASSWORD=<redacted>",
        "--env=API=<redacted>", "-e", "PGHOST", "mcp/postgres",
    ]  # fmt: skip
    assert found["postgres"].identity == "oci:mcp/postgres"
    assert found["git"].command == [
        "uvx", "mcp-server-git==2025.4.7", "--repository", "/src/app", "<redacted>",
    ]  # fmt: skip
    assert found["git"].identity == "pypi:mcp-server-git"


@pytest.mark.parametrize(
    "arg",
    [
        "@modelcontextprotocol/server-filesystem", "mcp-server-fetch==2025.4.7",
        "@playwright/mcp@0.0.41", "/home/alice/projects/notes_server.py", "x86_64-linux-gnu",
        "2024-01-01T00:00:00Z", "C:\\Program Files\\nodejs\\npx.cmd", "--port=3000",
        "https://api.githubcopilot.com/mcp/", "server.smithery.ai/@smithery-ai/github",
    ],
)  # fmt: skip
def test_words_paths_and_versions_stay(arg: str) -> None:
    assert mcp_scan.clean_args(["server", arg]) == ["server", arg]


def test_a_digest_keeps_its_image() -> None:
    pinned = (
        "ghcr.io/github/github-mcp-server:v1"
        "@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )
    cleaned = mcp_scan.clean_args(["docker", "run", "-i", "--rm", pinned])
    assert cleaned[-1] == "ghcr.io/github/github-mcp-server:v1@sha256:<redacted>"
    assert mcp_scan.identity_of(None, cleaned) == "oci:ghcr.io/github/github-mcp-server"


@pytest.mark.parametrize(
    "url",
    [ZAPIER, "https://u:p@api.githubcopilot.com/mcp/?token=abc", "http://[::1]:9000/mcp",
     "https://mcp.example.com/", "https://mcp.example.com"],
)  # fmt: skip
def test_sanitising_again_changes_nothing(url: str) -> None:
    assert mcp_scan.address(mcp_scan.address(url)) == mcp_scan.address(url)
    args = ["npx", "mcp-remote", url, "-e", "A=b", "--token", "t", "--header", "X: y"]
    assert mcp_scan.clean_args(mcp_scan.clean_args(args)) == mcp_scan.clean_args(args)
    for identity in (f"url:{url}", "command:mcp-remote -H X-Api-Key: <redacted>"):
        once = mcp_scan.clean_identity(identity)
        assert mcp_scan.clean_identity(once) == once

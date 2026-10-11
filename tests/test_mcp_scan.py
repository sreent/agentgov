"""Reading the MCP servers set up on a developer's machine (agentgov.mcp_scan)."""

from __future__ import annotations

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
        "crm": "url:https://gateway.example.com/mcp/crm",
        "github": "url:https://api.githubcopilot.com/mcp",
        "playwright": "npm:@playwright/mcp",
        "postgres": "oci:mcp/postgres",
        "fetch": "pypi:mcp-server-fetch",
        "notes": "command:python3 notes_server.py",
        "files": "npm:@modelcontextprotocol/server-filesystem",
        "crm-direct": "url:http://crm-mcp:9000/mcp",
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
    assert found["github"].url == "https://api.githubcopilot.com/mcp/"


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

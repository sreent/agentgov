"""AgentGov on one server (docs/deploy/server.md): the realm made for an installation, and a
control plane others reach that holds a secret everybody knows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentgov import cli
from agentgov.config import Settings
from agentgov.identity import realm

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[1]
REALM = ROOT / "deploy" / "compose" / "keycloak" / "agentgov-realm.json"


def people(made: dict) -> list[str]:  # type: ignore[type-arg]
    return [u["username"] for u in made["users"] if "serviceAccountClientId" not in u]


def test_the_realm_for_an_installation() -> None:
    source = json.loads(REALM.read_text())
    assert people(source) and "http://localhost:8000" in json.dumps(source)
    made = realm.for_installation(
        source, public_url="https://agentgov.example.com/", demo_users=False
    )
    text = json.dumps(made)
    assert "localhost:8000" not in text
    admin = next(c for c in made["clients"] if c["clientId"] == "agentgov-admin")
    assert admin["redirectUris"] == ["https://agentgov.example.com/auth/callback"]
    assert people(made) == []
    # The control plane's service account stays: it provisions agents' clients with it.
    assert [u["username"] for u in made["users"]] == ["service-account-agentgov-control-plane"]
    assert realm.DEMO_APP not in [c["clientId"] for c in made["clients"]]
    # The rest is as it came: secrets stay placeholders Keycloak fills in from its settings.
    assert "${AGENTGOV_KEYCLOAK_CLIENT_SECRET}" in text
    assert source == json.loads(REALM.read_text())


def test_as_the_chart_makes_it() -> None:
    """The chart does the same to its copy (templates/keycloak.yaml), which CI keeps equal."""
    chart = ROOT / "deploy" / "helm" / "agentgov" / "templates" / "keycloak.yaml"
    template = chart.read_text()
    assert '"http://localhost:8000"' in template and "serviceAccountClientId" in template
    assert f'"{realm.DEMO_APP}"' in template


@pytest.mark.parametrize(
    "url", ["agentgov.example.com", "https://agentgov.example.com/agentgov", "ftp://x"]
)
def test_an_address_that_isnt_one(url: str) -> None:
    with pytest.raises(ValueError, match="isn't the control plane's address"):
        realm.for_installation({}, public_url=url)


def test_the_cli(tmp_path: Path) -> None:
    out = tmp_path / "import" / "agentgov-realm.json"
    result = runner.invoke(
        cli.app,
        [
            "keycloak-realm",
            str(REALM),
            "--public-url=https://agentgov.example.com",
            "--no-demo-users",
            f"--output={out}",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "no demo people" in result.output
    assert people(json.loads(out.read_text())) == []
    shown = runner.invoke(cli.app, ["keycloak-realm", str(REALM)])
    assert shown.exit_code == 0 and "alice" in people(json.loads(shown.output))
    missing = runner.invoke(cli.app, ["keycloak-realm", str(tmp_path / "nothing.json")])
    assert missing.exit_code == 2 and "can't read" in missing.output


def test_well_known_secrets() -> None:
    settings = Settings(admin_token="dev-admin-token", service_token="change-me")
    assert settings.well_known_secrets() == ["AGENTGOV_ADMIN_TOKEN", "AGENTGOV_SERVICE_TOKEN"]
    assert Settings(admin_token="3f1c0e9d").well_known_secrets() == []
    for url, here in [
        ("http://localhost:8000", True),
        ("https://agentgov.localhost", True),
        ("http://127.0.0.1:8000", True),
        ("https://agentgov.example.com", False),
        ("http://10.0.0.7:8000", False),
    ]:
        assert Settings(public_url=url).only_this_machine() is here, url


def test_a_control_plane_others_reach_wont_start_with_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    started: list[str] = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: started.append("run"))
    monkeypatch.delenv("AGENTGOV_TLS_DIR", raising=False)
    monkeypatch.setenv("AGENTGOV_PUBLIC_URL", "https://agentgov.example.com")
    monkeypatch.setenv("AGENTGOV_ADMIN_TOKEN", "dev-admin-token")
    refused = runner.invoke(cli.app, ["server"])
    assert refused.exit_code == 2 and not started
    assert "AGENTGOV_ADMIN_TOKEN holds a value from AgentGov's examples" in refused.output
    monkeypatch.setenv("AGENTGOV_ADMIN_TOKEN", "3f1c0e9d5b7a")
    assert runner.invoke(cli.app, ["server"]).exit_code == 0 and started == ["run"]
    # On this machine only, the stacks' defaults are fine.
    monkeypatch.setenv("AGENTGOV_PUBLIC_URL", "http://localhost:8000")
    monkeypatch.setenv("AGENTGOV_ADMIN_TOKEN", "dev-admin-token")
    assert runner.invoke(cli.app, ["server"]).exit_code == 0

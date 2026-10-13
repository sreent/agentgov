from __future__ import annotations

import pytest

from agentgov.config import Settings


def test_environment_values_are_typed() -> None:
    settings = Settings.from_env(
        {
            "AGENTGOV_DATABASE_URL": "sqlite:///x.db",
            "AGENTGOV_AUTO_BLOCK_RISK_SCORE": "80",
            "AGENTGOV_PROMPT_INJECTION_THRESHOLD": "0.5",
            "AGENTGOV_DEV_MODE": "true",
            "AGENTGOV_KEYCLOAK_URL": "",
        }
    )
    assert settings.database_url == "sqlite:///x.db"
    assert settings.auto_block_risk_score == 80
    assert settings.prompt_injection_threshold == 0.5
    assert settings.dev_mode is True
    assert settings.keycloak_url is None
    assert settings.keycloak_enabled is False


def test_kubernetes_service_links_are_not_settings() -> None:
    # A Service named agentgov-gateway gives every pod in its namespace this variable.
    links = Settings.from_env({"AGENTGOV_GATEWAY_PORT": "tcp://10.96.191.160:8080"})
    assert links.gateway_port == 8080
    assert Settings.from_env({"AGENTGOV_GATEWAY_PORT": "9090"}).gateway_port == 9090
    with pytest.raises(ValueError, match="AGENTGOV_GATEWAY_PORT must be an integer"):
        Settings.from_env({"AGENTGOV_GATEWAY_PORT": "lots"})


def test_overrides_win() -> None:
    assert Settings.from_env({}, admin_token="x").admin_token == "x"


def test_pii_thresholds() -> None:
    settings = Settings(pii_entities="EMAIL_ADDRESS:0.5, phone_number:0.4 ,PERSON")
    assert settings.pii_thresholds() == {"EMAIL_ADDRESS": 0.5, "PHONE_NUMBER": 0.4, "PERSON": 0.5}


@pytest.mark.parametrize(
    "env",
    [
        {"AGENTGOV_PROMPT_INJECTION_THRESHOLD": "1.5"},
        {"AGENTGOV_PRESIDIO_FAILURE_MODE": "maybe"},
        {"AGENTGOV_PII_ENTITIES": "EMAIL_ADDRESS:high"},
        {"AGENTGOV_FEATURES": "least-privilege=sometimes"},
        {"AGENTGOV_FEATURES": "teleportation=on"},
        {"AGENTGOV_FEATURES": "discovery"},
        {"AGENTGOV_TLS_RELOAD_SECONDS": "-1"},
        {"AGENTGOV_IDENTITY_FULL_SYNC_SECONDS": "-1"},
        {"AGENTGOV_PLATFORM_SYNC_INTERVAL_SECONDS": "-1"},
    ],
)
def test_invalid_values(env) -> None:
    with pytest.raises(ValueError):
        Settings.from_env(env)


def test_feature_pins() -> None:
    settings = Settings.from_env({"AGENTGOV_FEATURES": " least-privilege=monitor, discovery=off "})
    assert settings.feature_pins() == {"least-privilege": "monitor", "discovery": "off"}


def test_settings_that_became_features_are_refused_with_directions() -> None:
    with pytest.raises(ValueError, match="AGENTGOV_FEATURES=unknown-callers=<mode>"):
        Settings.from_env({"AGENTGOV_UNKNOWN_AGENT_MODE": "monitor"})


def test_one_certificate_watcher_per_directory(tmp_path) -> None:
    """Every Settings.tls() of a component gives the same identity, which alone looks after
    its renewals."""
    from agentgov import tls

    tls.issue(tls.make_authority(tmp_path / "ca"), tmp_path / "me", "agentgov-me", ["me"])
    env = {"AGENTGOV_TLS_DIR": str(tmp_path / "me"), "AGENTGOV_TLS_RELOAD_SECONDS": "0"}
    settings = Settings.from_env(env)
    assert settings.tls() is settings.tls() is Settings.from_env(dict(env)).tls()
    assert Settings.from_env({}).tls() is None


def test_the_hosts_credentials_may_go_to() -> None:
    listed = Settings(
        credential_hosts=" Splunk.Example.com., *.service-now.com, 10.0.0.5, ::1, vllm"
    )
    assert listed.credential_host_list() == [
        "splunk.example.com", "*.service-now.com", "10.0.0.5", "::1", "vllm",
    ]  # fmt: skip
    for url in (
        "https://SPLUNK.example.com:8088/services/collector",
        "https://acme.service-now.com/api",
        "http://10.0.0.5:4318",
        "http://[::1]:8080/x",
        "http://vllm:8000/v1",
    ):
        assert listed.credentials_may_go_to(url), url
    for url in (
        "https://service-now.com/",  # *. is the hosts under it, not the domain itself
        "https://acme.service-now.com.evil.example/",
        "https://evil-service-now.com/",
        "https://splunk.example.com@evil.example/",
        "not a url",
        None,
    ):
        assert not listed.credentials_may_go_to(url), url
    assert Settings().credentials_may_go_to("https://anything.example")
    for bad in ("https://splunk.example.com", "*", "*.", "a b"):
        with pytest.raises(ValueError, match="AGENTGOV_CREDENTIAL_HOSTS"):
            Settings(credential_hosts=bad).credential_host_list()

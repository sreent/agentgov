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


def test_overrides_win() -> None:
    assert Settings.from_env({}, admin_token="x").admin_token == "x"


def test_pii_thresholds() -> None:
    settings = Settings(pii_entities="EMAIL_ADDRESS:0.5, phone_number:0.4 ,PERSON")
    assert settings.pii_thresholds() == {"EMAIL_ADDRESS": 0.5, "PHONE_NUMBER": 0.4, "PERSON": 0.5}


@pytest.mark.parametrize(
    "env",
    [
        {"AGENTGOV_UNKNOWN_AGENT_MODE": "allow-all"},
        {"AGENTGOV_PROMPT_INJECTION_THRESHOLD": "1.5"},
        {"AGENTGOV_PRESIDIO_FAILURE_MODE": "maybe"},
        {"AGENTGOV_PII_ENTITIES": "EMAIL_ADDRESS:high"},
    ],
)
def test_invalid_values(env) -> None:
    with pytest.raises(ValueError):
        Settings.from_env(env)

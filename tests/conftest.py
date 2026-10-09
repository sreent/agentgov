from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.runtime import Runtime

ADMIN = {"Authorization": "Bearer test-admin"}
SERVICE = {"Authorization": "Bearer test-service"}


def opa_available() -> bool:
    return shutil.which("opa") is not None


requires_opa = pytest.mark.skipif(not opa_available(), reason="opa binary not installed")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'agentgov.db'}",
        admin_token="test-admin",
        service_token="test-service",
        posture_interval_seconds=0,
    )


@pytest.fixture
def rt(settings: Settings) -> Iterator[Runtime]:
    runtime = Runtime(settings)
    runtime.init_db()
    yield runtime
    runtime.db.dispose()


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings, background=False)
    with TestClient(app) as test_client:
        yield test_client


def seed(client: TestClient, *, sponsors: list[str] | None = None) -> dict[str, Any]:
    """A blueprint, an approved CRM server and an active agent."""
    client.post(
        "/v1/blueprints",
        json={
            "name": "support",
            "risk_tier": "medium",
            "permissions": [{"server": "crm", "tools": ["get_*", "delete_customer"]}],
        },
        headers=ADMIN,
    ).raise_for_status()
    client.post(
        "/v1/toolservers",
        json={"name": "crm", "url": "http://crm:9000/mcp", "trust_level": "verified"},
        headers=ADMIN,
    ).raise_for_status()
    resp = client.post(
        "/v1/agents",
        json={
            "name": "support-bot",
            "blueprint": "support",
            "owner": "cx",
            "sponsors": sponsors if sponsors is not None else ["alice@example.com"],
            "approve": True,
        },
        headers=ADMIN,
    )
    resp.raise_for_status()
    return resp.json()

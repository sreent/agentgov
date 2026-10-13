from __future__ import annotations

import os
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, make_url
from sqlalchemy.pool import NullPool

from agentgov import migrations
from agentgov.api.app import create_app
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.runtime import Runtime

ADMIN = {"Authorization": "Bearer test-admin"}
SERVICE = {"Authorization": "Bearer test-service"}
# Single sign-on, for settings whose tests sign people in (signed_in).
SSO = {"oidc_issuer": "https://idp.test/realms/agentgov", "oidc_client_secret": "test-oidc-secret"}


def opa_available() -> bool:
    return shutil.which("opa") is not None


requires_opa = pytest.mark.skipif(not opa_available(), reason="opa binary not installed")


# With a PostgreSQL server here (an SQLAlchemy URL to any database on it, such as
# postgresql+psycopg://postgres:secret@127.0.0.1:5432/postgres), every test that takes the
# `settings` fixture runs on a database of its own there instead of SQLite.
POSTGRES = os.environ.get("AGENTGOV_TEST_POSTGRES_URL")
TEMPLATE = "agentgov_test_template"


def postgres_admin() -> Engine:
    assert POSTGRES
    return create_engine(POSTGRES, isolation_level="AUTOCOMMIT", poolclass=NullPool)


@pytest.fixture(scope="session")
def migrated_database(tmp_path_factory: pytest.TempPathFactory) -> Path | str:
    """A database built by the migrations once, copied for each test (tests/test_migrations.py
    covers the migrations themselves): a file, or a template database on PostgreSQL."""
    if POSTGRES:
        admin = postgres_admin()
        with admin.connect() as connection:
            connection.exec_driver_sql(f"DROP DATABASE IF EXISTS {TEMPLATE} WITH (FORCE)")
            connection.exec_driver_sql(f"CREATE DATABASE {TEMPLATE}")
        db = Database(make_url(POSTGRES).set(database=TEMPLATE).render_as_string(False))
        migrations.upgrade(db.engine)
        db.dispose()
        admin.dispose()
        return TEMPLATE
    path = tmp_path_factory.mktemp("schema") / "agentgov.db"
    db = Database(f"sqlite:///{path}")
    migrations.upgrade(db.engine)
    with db.engine.connect() as connection:
        # Everything into the main file before it is copied (outside a transaction).
        connection.connection.dbapi_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.dispose()
    return path


@pytest.fixture
def database_url(tmp_path: Path, migrated_database: Path | str) -> Iterator[str]:
    """A fresh copy of the migrated database, for one test."""
    if isinstance(migrated_database, Path):
        shutil.copyfile(migrated_database, tmp_path / "agentgov.db")
        yield f"sqlite:///{tmp_path / 'agentgov.db'}"
        return
    name = f"agentgov_test_{uuid.uuid4().hex[:16]}"
    admin = postgres_admin()
    with admin.connect() as connection:
        connection.exec_driver_sql(f"CREATE DATABASE {name} TEMPLATE {migrated_database}")
    try:
        yield make_url(POSTGRES).set(database=name).render_as_string(False)
    finally:
        with admin.connect() as connection:
            connection.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


@pytest.fixture
def settings(database_url: str) -> Settings:
    return Settings(
        database_url=database_url,
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


def signed_in(client: TestClient, email: str, *roles: str) -> dict[str, str]:
    """A person signed in through single sign-on as ``email``, which their provider vouches
    for, with ``roles`` (none: someone without a role): the session a sign-in starts
    (tests/test_sso.py signs in through a provider). The client's settings need SSO."""
    from agentgov.identity import sso

    rt = client.app.state.rt  # type: ignore[attr-defined]
    who = sso.Identity(subject=email, name=email, roles=list(roles), id_token="", email=email)
    with rt.db.session() as s:
        token, _ = sso.start_session(s, rt.settings, who)
    return {"Authorization": f"Bearer {token}"}

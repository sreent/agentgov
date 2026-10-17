from __future__ import annotations

import os
import shutil
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

from agentgov import db as database
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


# With a PostgreSQL server here (the URL of any database on it, such as
# postgresql+psycopg://postgres:secret@127.0.0.1:5432/postgres), every test that takes the
# `settings` fixture runs on a database of its own there instead of SQLite.
POSTGRES = os.environ.get("AGENTGOV_TEST_POSTGRES_URL")
TEMPLATE = "agentgov_test_template"


def postgres_admin() -> Any:
    """A connection to the tests' PostgreSQL server, in autocommit: to make databases and
    drop them. Its caller closes it."""
    assert POSTGRES
    server = Database(POSTGRES)
    try:
        return server.connect()
    finally:
        server.dispose()


def postgres_url(name: str) -> str:
    """The URL of database ``name`` on the tests' PostgreSQL server."""
    assert POSTGRES
    return urlsplit(POSTGRES)._replace(path=f"/{name}").geturl()


@pytest.fixture(autouse=True)
def _disposed() -> Iterator[None]:
    """Every database a test opened is closed after it: its connections, and on PostgreSQL
    psycopg's pool, whose threads would otherwise outlive it."""
    yield
    for db in database.live():
        db.dispose()


@pytest.fixture(scope="session")
def migrated_database(tmp_path_factory: pytest.TempPathFactory) -> Path | str:
    """A database built by the migrations once, copied for each test (tests/test_migrations.py
    covers the migrations themselves): a file, or a template database on PostgreSQL."""
    if POSTGRES:
        with postgres_admin() as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {TEMPLATE} WITH (FORCE)")
            admin.execute(f"CREATE DATABASE {TEMPLATE}")
        db = Database(postgres_url(TEMPLATE))
        migrations.upgrade(db)
        db.dispose()
        return TEMPLATE
    path = tmp_path_factory.mktemp("schema") / "agentgov.db"
    db = Database(f"sqlite:///{path}")
    migrations.upgrade(db)
    db.dispose()
    checkpoint(path)
    return path


def checkpoint(path: Path) -> None:
    """Everything in an SQLite database's write-ahead log into its file, before the file is
    copied."""
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


@pytest.fixture
def database_url(tmp_path: Path, migrated_database: Path | str) -> Iterator[str]:
    """A fresh copy of the migrated database, for one test."""
    if isinstance(migrated_database, Path):
        shutil.copyfile(migrated_database, tmp_path / "agentgov.db")
        yield f"sqlite:///{tmp_path / 'agentgov.db'}"
        return
    name = f"agentgov_test_{uuid.uuid4().hex[:16]}"
    with postgres_admin() as admin:
        admin.execute(f"CREATE DATABASE {name} TEMPLATE {migrated_database}")
    try:
        yield postgres_url(name)
    finally:
        for db in database.live():
            db.dispose()
        with postgres_admin() as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


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
    with rt.db.transaction() as tx:
        token, _ = sso.start_session(tx, rt.settings, who)
    return {"Authorization": f"Bearer {token}"}

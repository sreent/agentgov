"""The database schema's migrations: they build the models' schema, adopt databases
created before migrations, and refuse schemas this version doesn't know."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text
from typer.testing import CliRunner

from agentgov import cli, migrations, models
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.db.models import Agent, Blueprint, ToolServer
from agentgov.runtime import Runtime

runner = CliRunner()


def _urls(tmp_path: Path) -> list[str]:
    urls = [f"sqlite:///{tmp_path / 'schema.db'}"]
    # Also check a real PostgreSQL when one is offered (it must be empty).
    if os.environ.get("AGENTGOV_TEST_POSTGRES_URL"):
        urls.append(os.environ["AGENTGOV_TEST_POSTGRES_URL"])
    return urls


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(f"sqlite:///{tmp_path / 'agentgov.db'}")
    yield database
    database.dispose()


def test_the_migrations_build_the_models_schema(tmp_path: Path) -> None:
    for url in _urls(tmp_path):
        database = Database(url)
        try:
            migrations.upgrade(database.engine)
            with database.engine.connect() as connection:
                context = MigrationContext.configure(connection, opts={"compare_type": True})
                differences = compare_metadata(context, models.Base.metadata)
            # A model changed without a migration: add one to agentgov/migrations/versions.
            assert differences == [], differences
        finally:
            if url.startswith("postgresql"):
                with database.engine.begin() as connection:
                    connection.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
            database.dispose()


def test_one_line_of_history() -> None:
    assert len(migrations.scripts().get_heads()) == 1, "merge the migration branches"
    assert migrations.scripts().get_revision(migrations.BASELINE).down_revision is None


def test_status_check_and_upgrade(db: Database) -> None:
    every = [s.revision for s in reversed(list(migrations.scripts().walk_revisions()))]
    state = migrations.status(db.engine)
    assert (state.current, state.pending, state.up_to_date) == (None, every, False)
    with pytest.raises(migrations.SchemaError, match="agentgov db upgrade"):
        migrations.check(db.engine)

    assert migrations.upgrade(db.engine) == every
    state = migrations.status(db.engine)
    assert (state.current, state.pending, state.up_to_date) == (migrations.head(), [], True)
    migrations.check(db.engine)
    assert migrations.upgrade(db.engine) == []  # nothing left to do


def _before_migrations(db: Database, *, lacking: str | None = None) -> None:
    """A database as create_all left it before migrations: the baseline's tables (less
    one a still older version didn't have yet), and no record of a revision."""
    with db.engine.begin() as connection:
        command.upgrade(migrations._config(connection), migrations.BASELINE)
        connection.execute(text("DROP TABLE alembic_version"))
        if lacking:
            connection.execute(text(f"DROP TABLE {lacking}"))


def test_a_database_from_before_migrations_is_adopted(db: Database) -> None:
    _before_migrations(db, lacking="integration_state")
    with db.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO blueprints (id, name, description, risk_tier, permissions, "
                "require_sponsor, labels, created_at, updated_at) VALUES ('bp_1', 'support', "
                "'', 'medium', '[]', 1, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
    assert migrations.status(db.engine).unversioned

    migrations.upgrade(db.engine)

    assert migrations.status(db.engine).up_to_date
    assert "integration_state" in inspect(db.engine).get_table_names()
    with db.transaction():
        assert Blueprint.objects.get(pk="bp_1").name == "support"  # data kept


def test_a_schema_from_a_newer_version_is_refused(db: Database) -> None:
    migrations.upgrade(db.engine)
    with db.engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num = '9999'"))
    for attempt in (migrations.status, migrations.check, migrations.upgrade):
        with pytest.raises(migrations.SchemaError, match="newer version"):
            attempt(db.engine)


def test_the_control_plane_can_leave_migrating_to_a_job(settings: Settings, tmp_path: Path) -> None:
    rt = Runtime(
        settings.with_overrides(
            database_url=f"sqlite:///{tmp_path / 'empty.db'}", database_auto_migrate=False
        )
    )
    try:
        with pytest.raises(migrations.SchemaError, match="agentgov db upgrade"):
            rt.init_db()
        migrations.upgrade(rt.db.engine)  # what the job does
        rt.init_db()
    finally:
        rt.db.dispose()


def test_what_was_blocked_before_is_read_from_the_ledger(db: Database, settings: Settings) -> None:
    """Agents and tool servers blocked before AgentGov kept what they were (0032) are given it
    from their blocks' ledger entries: unblocked, a pending one waits for approval again."""
    from agentgov.registry import agents, toolservers

    migrations.upgrade(db.engine)
    with db.transaction() as tx:
        made = agents.register(tx, settings, {"name": "new-bot", "sponsors": ["a"]}, actor="t")
        agents.transition(tx, settings, made, "block", actor="t")
        ts = toolservers.create(
            tx, {"name": "byo", "url": "http://byo/mcp"}, actor="t", approve=False
        )
        toolservers.set_status(tx, ts, "block", actor="t")
    with migrations._migrating(db.engine) as connection:
        command.downgrade(migrations._config(connection), "0031")
    assert "blocked_from" not in {c["name"] for c in inspect(db.engine).get_columns("agents")}
    migrations.upgrade(db.engine)
    with db.transaction() as tx:
        assert Agent.objects.get(pk=made.id).blocked_from == "pending"
        assert ToolServer.objects.get(pk=ts.id).blocked_from == "pending"


def test_foreign_keys_are_enforced_again_after_migrating(db: Database) -> None:
    migrations.upgrade(db.engine)
    with db.engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


class TestCli:
    @pytest.fixture
    def env(self, tmp_path: Path) -> dict[str, str]:
        return {"AGENTGOV_DATABASE_URL": f"sqlite:///{tmp_path / 'cli.db'}"}

    def test_status_then_upgrade(self, env: dict[str, str]) -> None:
        before = runner.invoke(cli.app, ["db", "status"], env=env)
        assert before.exit_code == 1 and f"pending: {migrations.BASELINE}" in before.output

        sql = runner.invoke(cli.app, ["db", "upgrade", "--sql"], env=env)
        assert sql.exit_code == 0 and "CREATE TABLE agents" in sql.output

        done = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert done.exit_code == 0, done.output
        assert f"database/{migrations.head()}: migrated" in done.output

        after = runner.invoke(cli.app, ["db", "status"], env=env)
        assert after.exit_code == 0 and "the schema is up to date" in after.output
        again = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert "already up to date" in again.output

    def test_adopting_from_the_cli(self, env: dict[str, str]) -> None:
        database = Database(env["AGENTGOV_DATABASE_URL"])
        _before_migrations(database)
        database.dispose()
        status = runner.invoke(cli.app, ["db", "status"], env=env)
        assert "created before migrations" in status.output
        done = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert done.exit_code == 0, done.output
        assert f"database/{migrations.BASELINE}: adopted" in done.output

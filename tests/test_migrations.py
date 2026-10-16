"""The database schema's migrations: Alembic's, then Django's (docs/adr/0007-django.md). They
build the models' schema, adopt databases created before migrations and databases Alembic's
alone migrated, and refuse schemas this version doesn't know."""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from django.core.management import call_command
from django.db import connections
from django.db.migrations.loader import MigrationLoader
from django.test import override_settings
from sqlalchemy import inspect, text
from typer.testing import CliRunner

from agentgov import cli, migrations
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.db.models import Agent, Blueprint, ToolServer
from agentgov.runtime import Runtime
from tests.test_django_models import database_tables

runner = CliRunner()
POSTGRES = os.environ.get("AGENTGOV_TEST_POSTGRES_URL")


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(f"sqlite:///{tmp_path / 'agentgov.db'}")
    yield database
    database.dispose()


@pytest.fixture(params=["sqlite", "postgresql"])
def empty(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[list[Database]]:
    """Empty databases on SQLite, and on PostgreSQL when the tests have one."""
    if request.param == "sqlite":
        yield [Database(f"sqlite:///{tmp_path / f'{n}.db'}") for n in range(2)]
        return
    if not POSTGRES:
        pytest.skip("needs AGENTGOV_TEST_POSTGRES_URL")
    from sqlalchemy import make_url

    from tests.conftest import postgres_admin

    names = [f"agentgov_empty_{uuid.uuid4().hex[:12]}" for _ in range(2)]
    admin = postgres_admin()
    with admin.connect() as connection:
        for name in names:
            connection.exec_driver_sql(f"CREATE DATABASE {name}")
    try:
        yield [
            Database(make_url(POSTGRES).set(database=name).render_as_string(False))
            for name in names
        ]
    finally:
        from agentgov import db as database

        for opened in database.live():
            opened.dispose()
        with admin.connect() as connection:
            for name in names:
                connection.exec_driver_sql(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        admin.dispose()


def _alembic_only(db: Database, revision: str = "head") -> None:
    """Alembic's migrations, up to ``revision``, as the versions before Django's ran them."""
    with migrations._migrating(db.engine) as connection:
        command.upgrade(migrations._config(connection), revision)


def _recorded(db: Database) -> list[str]:
    """Django's migrations the database has recorded as applied."""
    try:
        with connections[db.alias].cursor() as cursor:
            cursor.execute("SELECT name FROM django_migrations WHERE app = 'agentgov' ORDER BY id")
            return [name for (name,) in cursor.fetchall()]
    finally:
        connections[db.alias].close()


def test_djangos_first_migration_builds_the_schema_alembics_last_leaves(
    empty: list[Database],
) -> None:
    by_alembic, by_django = empty
    _alembic_only(by_alembic)
    try:
        call_command("migrate", migrations.APP, database=by_django.alias, verbosity=0)
    finally:
        connections[by_django.alias].close()
    built, made = database_tables(by_alembic), database_tables(by_django)
    assert sorted(built) == sorted(made)
    for table in sorted(built):
        for part in ("columns", "primary key", "unique", "indexes", "foreign keys", "defaults"):
            assert made[table][part] == built[table][part], (table, part)


def test_the_migrations_have_every_change_to_the_models() -> None:
    # The models against the migrations' files alone: with the routers, makemigrations would
    # also read every database open in this process (or left registered, and dropped since).
    try:
        with override_settings(DATABASE_ROUTERS=[]):
            call_command("makemigrations", migrations.APP, check=True, dry_run=True, verbosity=0)
    except SystemExit as exc:  # a model changed without a migration
        pytest.fail(f"a model changed without a migration: run scripts/new-migration.sh ({exc})")


def test_one_line_of_history() -> None:
    assert len(migrations.scripts().get_heads()) == 1, "merge the migration branches"
    assert migrations.scripts().get_revision(migrations.BASELINE).down_revision is None
    leaves = MigrationLoader(None, ignore_no_migrations=True).graph.leaf_nodes(migrations.APP)
    assert len(leaves) == 1, "merge Django's migrations (makemigrations --merge)"


def test_status_check_and_upgrade(db: Database) -> None:
    alembic = [s.revision for s in reversed(list(migrations.scripts().walk_revisions()))]
    every = alembic + migrations.django_migrations()
    state = migrations.status(db)
    assert (state.current, state.pending, state.up_to_date) == (None, every, False)
    with pytest.raises(migrations.SchemaError, match="agentgov db upgrade"):
        migrations.check(db)

    assert migrations.upgrade(db) == every
    state = migrations.status(db)
    assert (state.current, state.pending, state.up_to_date) == (migrations.head(), [], True)
    migrations.check(db)
    assert migrations.upgrade(db) == []  # nothing left to do
    assert _recorded(db) == migrations.django_migrations()


def test_a_database_alembic_migrated_takes_djangos_first_migration_as_applied(
    db: Database,
) -> None:
    """A database the versions before Django's migrations migrated: Alembic's last revision,
    and the tables Django's first migration would make, so it is recorded, not run."""
    _alembic_only(db)
    with db.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO blueprints (id, name, description, risk_tier, permissions, "
                "require_sponsor, labels, created_at, updated_at) VALUES ('bp_1', 'support', "
                "'', 'medium', '[]', 1, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
    state = migrations.status(db)
    assert (state.current, state.pending) == (migrations.alembic_head(), ["0001_initial"])
    sql = migrations.upgrade_sql(db)
    assert "CREATE TABLE agents" not in sql
    assert "INSERT INTO django_migrations" in sql and "'0001_initial'" in sql

    assert migrations.upgrade(db) == ["0001_initial"]
    assert migrations.status(db).up_to_date
    assert _recorded(db) == ["0001_initial"]
    with db.transaction():
        assert Blueprint.objects.get(pk="bp_1").name == "support"  # data kept


def test_replicas_starting_together_migrate_one_at_a_time(empty: list[Database]) -> None:
    """Two upgrades of one database at once: one migrates, then the other finds nothing to
    do, and Django's first migration is recorded once. (Several replicas need PostgreSQL;
    on SQLite there is one control plane.)"""
    first = empty[0]
    if first.sqlite:
        pytest.skip("several replicas need PostgreSQL")
    other = Database(first.url)
    done: list[list[str]] = []
    failed: list[BaseException] = []

    def migrate(db: Database) -> None:
        try:
            done.append(migrations.upgrade(db))
        except BaseException as exc:  # reported below
            failed.append(exc)

    threads = [threading.Thread(target=migrate, args=(db,)) for db in (first, other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    assert failed == []
    every = [s.revision for s in reversed(list(migrations.scripts().walk_revisions()))]
    assert sorted(done) == [[], every + migrations.django_migrations()]
    assert migrations.status(first).up_to_date
    assert _recorded(first) == migrations.django_migrations()


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
    assert migrations.status(db).unversioned

    migrations.upgrade(db)

    assert migrations.status(db).up_to_date
    assert "integration_state" in inspect(db.engine).get_table_names()
    with db.transaction():
        assert Blueprint.objects.get(pk="bp_1").name == "support"  # data kept


def test_a_schema_from_a_newer_version_is_refused(db: Database) -> None:
    migrations.upgrade(db)
    with db.engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num = '9999'"))
    for attempt in (migrations.status, migrations.check, migrations.upgrade):
        with pytest.raises(migrations.SchemaError, match="newer version"):
            attempt(db)


def test_a_django_migration_from_a_newer_version_is_refused(db: Database) -> None:
    migrations.upgrade(db)
    with db.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO django_migrations (app, name, applied) "
                "VALUES ('agentgov', '0002_from_the_future', CURRENT_TIMESTAMP)"
            )
        )
    for attempt in (migrations.status, migrations.check, migrations.upgrade):
        with pytest.raises(migrations.SchemaError, match="'0002_from_the_future'"):
            attempt(db)


def test_the_control_plane_can_leave_migrating_to_a_job(settings: Settings, tmp_path: Path) -> None:
    rt = Runtime(
        settings.with_overrides(
            database_url=f"sqlite:///{tmp_path / 'empty.db'}", database_auto_migrate=False
        )
    )
    try:
        with pytest.raises(migrations.SchemaError, match="agentgov db upgrade"):
            rt.init_db()
        migrations.upgrade(rt.db)  # what the job does
        rt.init_db()
    finally:
        rt.db.dispose()


def test_what_was_blocked_before_is_read_from_the_ledger(db: Database, settings: Settings) -> None:
    """Agents and tool servers blocked before AgentGov kept what they were (0032) are given it
    from their blocks' ledger entries: unblocked, a pending one waits for approval again."""
    from agentgov.registry import agents, toolservers

    migrations.upgrade(db)
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
    migrations.upgrade(db)
    with db.transaction():
        assert Agent.objects.get(pk=made.id).blocked_from == "pending"
        assert ToolServer.objects.get(pk=ts.id).blocked_from == "pending"


def test_foreign_keys_are_enforced_again_after_migrating(db: Database) -> None:
    migrations.upgrade(db)
    with db.engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


class TestCli:
    @pytest.fixture
    def env(self, tmp_path: Path) -> dict[str, str]:
        return {"AGENTGOV_DATABASE_URL": f"sqlite:///{tmp_path / 'cli.db'}"}

    def test_status_then_upgrade(self, env: dict[str, str]) -> None:
        before = runner.invoke(cli.app, ["db", "status"], env=env)
        assert before.exit_code == 1 and f"pending: {migrations.BASELINE}" in before.output
        assert before.output.rstrip().endswith(migrations.head())

        sql = runner.invoke(cli.app, ["db", "upgrade", "--sql"], env=env)
        assert sql.exit_code == 0 and "CREATE TABLE agents" in sql.output
        assert "INSERT INTO django_migrations" in sql.output

        done = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert done.exit_code == 0, done.output
        assert f"database/{migrations.head()}: migrated" in done.output

        after = runner.invoke(cli.app, ["db", "status"], env=env)
        assert after.exit_code == 0 and "the schema is up to date" in after.output
        assert f"current: {migrations.head()}" in after.output
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

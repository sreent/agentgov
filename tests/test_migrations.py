"""The database schema's migrations: Django's (docs/adr/0007-django.md). They build the
models' schema, take over databases Alembic's migrations took to their last revision, and
refuse schemas this version doesn't know."""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from django.core.management import call_command
from django.db import connections
from django.db.migrations.loader import MigrationLoader
from django.test import override_settings
from typer.testing import CliRunner

from agentgov import cli, migrations
from agentgov.config import Settings
from agentgov.db import Database
from agentgov.db.models import Blueprint
from agentgov.runtime import Runtime

runner = CliRunner()
POSTGRES = os.environ.get("AGENTGOV_TEST_POSTGRES_URL")


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(f"sqlite:///{tmp_path / 'agentgov.db'}")
    yield database
    database.dispose()


@pytest.fixture(params=["sqlite", "postgresql"])
def empty(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Database]:
    """An empty database on SQLite, and on PostgreSQL when the tests have one."""
    if request.param == "sqlite":
        yield Database(f"sqlite:///{tmp_path / 'empty.db'}")
        return
    if not POSTGRES:
        pytest.skip("needs AGENTGOV_TEST_POSTGRES_URL")
    from tests.conftest import postgres_admin, postgres_url

    name = f"agentgov_empty_{uuid.uuid4().hex[:12]}"
    with postgres_admin() as admin:
        admin.execute(f"CREATE DATABASE {name}")
    try:
        yield Database(postgres_url(name))
    finally:
        from agentgov import db as database

        for opened in database.live():
            opened.dispose()
        with postgres_admin() as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def _as_alembic_left_it(db: Database, revision: str = migrations.ALEMBIC_LAST) -> None:
    """A database as the versions before Django's migrations left it: the schema of Alembic's
    last revision, which Django's first migration builds (the version that ran both checked
    that it does), and Alembic's record of a revision rather than Django's."""
    try:
        call_command("migrate", migrations.APP, database=db.alias, verbosity=0)
    finally:
        connections[db.alias].close()
    with db.transaction() as tx:
        tx.execute("DROP TABLE django_migrations")
        tx.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)")
        tx.execute("INSERT INTO alembic_version (version_num) VALUES (%s)", [revision])


def _recorded(db: Database) -> list[str]:
    """Django's migrations the database has recorded as applied."""
    with db.transaction() as tx:
        rows = tx.execute("SELECT name FROM django_migrations WHERE app = 'agentgov' ORDER BY id")
    return [name for (name,) in rows]


def test_the_migrations_have_every_change_to_the_models() -> None:
    # The models against the migrations' files alone: with the routers, makemigrations would
    # also read every database open in this process (or left registered, and dropped since).
    try:
        with override_settings(DATABASE_ROUTERS=[]):
            call_command("makemigrations", migrations.APP, check=True, dry_run=True, verbosity=0)
    except SystemExit as exc:  # a model changed without a migration
        pytest.fail(f"a model changed without a migration: run scripts/new-migration.sh ({exc})")


def test_one_line_of_history() -> None:
    leaves = MigrationLoader(None, ignore_no_migrations=True).graph.leaf_nodes(migrations.APP)
    assert len(leaves) == 1, "merge Django's migrations (makemigrations --merge)"


def test_status_check_and_upgrade(empty: Database) -> None:
    every = migrations.django_migrations()
    state = migrations.status(empty)
    assert (state.current, state.pending, state.up_to_date) == (None, every, False)
    with pytest.raises(migrations.SchemaError, match="agentgov db upgrade"):
        migrations.check(empty)

    assert migrations.upgrade(empty) == every
    state = migrations.status(empty)
    assert (state.current, state.pending, state.up_to_date) == (migrations.head(), [], True)
    migrations.check(empty)
    assert migrations.upgrade(empty) == []  # nothing left to do
    assert _recorded(empty) == every


def test_a_database_alembics_migrations_left_is_taken_over(empty: Database) -> None:
    """At Alembic's last revision, with the tables Django's first migration would make: it is
    recorded as applied, not run, and the data stays."""
    _as_alembic_left_it(empty)
    with empty.transaction():
        Blueprint.objects.create(id="bp_1", name="support")
    state = migrations.status(empty)
    assert state.from_alembic
    assert (state.current, state.pending) == (migrations.ALEMBIC_LAST, ["0001_initial"])
    sql = migrations.upgrade_sql(empty)
    assert 'CREATE TABLE "agents"' not in sql
    assert "INSERT INTO django_migrations" in sql and "'0001_initial'" in sql

    assert migrations.upgrade(empty) == ["0001_initial"]
    assert migrations.status(empty).up_to_date
    assert _recorded(empty) == ["0001_initial"]
    with empty.transaction() as tx:
        assert Blueprint.objects.get(pk="bp_1").name == "support"
        # Alembic's record stays, for the version before, should it run on the database again.
        assert tx.execute("SELECT version_num FROM alembic_version") == [("0032",)]


def test_a_database_at_an_earlier_alembic_revision_is_refused(empty: Database) -> None:
    """The last version that ran Alembic's migrations brings it to their last revision
    first; then it is taken over."""
    _as_alembic_left_it(empty, "0031")
    for attempt in (
        migrations.status,
        migrations.check,
        migrations.upgrade,
        migrations.upgrade_sql,
    ):
        with pytest.raises(
            migrations.SchemaError,
            match=f"Alembic's revision 0031.*commit {migrations.LAST_WITH_ALEMBIC}",
        ):
            attempt(empty)
    with empty.transaction() as tx:  # what that version does
        tx.execute("UPDATE alembic_version SET version_num = %s", [migrations.ALEMBIC_LAST])
    assert migrations.upgrade(empty) == ["0001_initial"]


def test_a_database_from_before_migrations_is_refused(empty: Database) -> None:
    """Made by create_all before AgentGov had migrations: its tables, and neither Alembic's
    record of a revision nor Django's."""
    _as_alembic_left_it(empty)
    with empty.transaction() as tx:
        tx.execute("DROP TABLE alembic_version")
    for attempt in (migrations.status, migrations.upgrade):
        with pytest.raises(
            migrations.SchemaError,
            match=f"before AgentGov had migrations.*commit {migrations.LAST_WITH_ALEMBIC}",
        ):
            attempt(empty)


def test_replicas_starting_together_migrate_one_at_a_time(empty: Database) -> None:
    """Two upgrades of one database at once: one migrates, then the other finds nothing to
    do, and each migration is recorded once. (Several replicas need PostgreSQL; on SQLite
    there is one control plane.)"""
    if empty.sqlite:
        pytest.skip("several replicas need PostgreSQL")
    other = Database(empty.url)
    done: list[list[str]] = []
    failed: list[BaseException] = []

    def migrate(db: Database) -> None:
        try:
            done.append(migrations.upgrade(db))
        except BaseException as exc:  # reported below
            failed.append(exc)

    threads = [threading.Thread(target=migrate, args=(db,)) for db in (empty, other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    assert failed == []
    assert sorted(done) == [[], migrations.django_migrations()]
    assert migrations.status(empty).up_to_date
    assert _recorded(empty) == migrations.django_migrations()


def test_a_django_migration_from_a_newer_version_is_refused(db: Database) -> None:
    migrations.upgrade(db)
    with db.transaction() as tx:
        tx.execute(
            "INSERT INTO django_migrations (app, name, applied) "
            "VALUES ('agentgov', '0002_from_the_future', CURRENT_TIMESTAMP)"
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


def test_foreign_keys_are_enforced_after_migrating(db: Database) -> None:
    """Django's migrations turn SQLite's foreign keys off while they alter tables; the
    connections the transactions take after have them on."""
    migrations.upgrade(db)
    with db.transaction() as tx:
        assert tx.execute("PRAGMA foreign_keys") == [(1,)]


class TestCli:
    @pytest.fixture
    def env(self, tmp_path: Path) -> dict[str, str]:
        return {"AGENTGOV_DATABASE_URL": f"sqlite:///{tmp_path / 'cli.db'}"}

    def test_status_then_upgrade(self, env: dict[str, str]) -> None:
        first = migrations.django_migrations()[0]
        before = runner.invoke(cli.app, ["db", "status"], env=env)
        assert before.exit_code == 1 and f"pending: {first}" in before.output
        assert before.output.rstrip().endswith(migrations.head())

        sql = runner.invoke(cli.app, ["db", "upgrade", "--sql"], env=env)
        assert sql.exit_code == 0 and 'CREATE TABLE "agents"' in sql.output
        assert "INSERT INTO django_migrations" in sql.output

        done = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert done.exit_code == 0, done.output
        assert f"database/{migrations.head()}: migrated" in done.output

        after = runner.invoke(cli.app, ["db", "status"], env=env)
        assert after.exit_code == 0 and "the schema is up to date" in after.output
        assert f"current: {migrations.head()}" in after.output
        again = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert "already up to date" in again.output

    def test_taking_over_from_alembic(self, env: dict[str, str]) -> None:
        database = Database(env["AGENTGOV_DATABASE_URL"])
        _as_alembic_left_it(database)
        database.dispose()
        status = runner.invoke(cli.app, ["db", "status"], env=env)
        assert status.exit_code == 1
        assert f"current: {migrations.ALEMBIC_LAST}, Alembic's last revision" in status.output
        done = runner.invoke(cli.app, ["db", "upgrade"], env=env)
        assert done.exit_code == 0, done.output
        first = migrations.django_migrations()[0]
        assert f"database/{first}: taken over from Alembic's migrations" in done.output
        assert "already up to date" not in done.output

    def test_an_older_database_is_refused(self, env: dict[str, str]) -> None:
        database = Database(env["AGENTGOV_DATABASE_URL"])
        _as_alembic_left_it(database, "0030")
        database.dispose()
        for command in (["db", "status"], ["db", "upgrade"], ["db", "upgrade", "--sql"]):
            refused = runner.invoke(cli.app, command, env=env)
            assert refused.exit_code == 2, command  # an error
            assert f"commit {migrations.LAST_WITH_ALEMBIC}" in refused.output, command

"""The Django models (agentgov.db.models) against the database the migrations build: the
same tables, columns, keys, constraints, indexes and defaults; and the values as the
databases hold them (docs/adr/0007-django.md)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from django.apps import apps
from django.core import checks
from django.db import connections
from django.db.models import Field, UniqueConstraint, Value

from agentgov.db import Database
from agentgov.db import models as django_models

# --------------------------------------------------------------------------- the schema


def django_kind(field: Field) -> str:
    if field.is_relation:
        return django_kind(field.target_field)  # type: ignore[attr-defined]
    kind = field.get_internal_type()
    if kind == "AutoField":
        return "integer"
    if kind == "CharField":
        return f"varchar({field.max_length})"
    return {
        "TextField": "text",
        "IntegerField": "integer",
        "BigIntegerField": "bigint",
        "BooleanField": "boolean",
        "FloatField": "float",
        "JSONField": "json",
        "DateTimeField": "timestamp",
    }[kind]


# A column's type as each database names it, and as the models do.
KINDS = {
    "text": "text",
    "integer": "integer",
    "bigint": "bigint",
    "bool": "boolean",
    "boolean": "boolean",
    "real": "float",
    "double precision": "float",
    "json": "json",
    "datetime": "timestamp",
    "timestamp without time zone": "timestamp",
}


def database_kind(declared: str) -> str:
    declared = declared.lower()
    if length := re.fullmatch(r"(?:varchar|character varying)\((\d+)\)", declared):
        return f"varchar({length[1]})"
    if declared not in KINDS:
        raise AssertionError(f"a column of type {declared!r}")
    return KINDS[declared]


def django_default(field: Field) -> str:
    value = field.db_default
    if isinstance(value, Value):
        value = value.value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | dict):
        return json.dumps(value)
    return str(value)


def database_default(text: str, kind: str) -> str:
    # As each database writes it: '[]'::json, 'either'::character varying, false, 0.
    text = re.sub(r"::[a-z ]+$", "", text.strip()).strip("()")
    text = text.removeprefix("'").removesuffix("'")
    if kind == "boolean":
        return {"0": "false", "1": "true"}.get(text, text)
    return text


def django_tables() -> dict[str, dict[str, Any]]:
    tables = {}
    for model in apps.get_app_config("agentgov").get_models():
        meta = model._meta
        fields = meta.local_concrete_fields
        column = {f.name: f.column for f in fields}
        tables[meta.db_table] = {
            "columns": {f.column: (django_kind(f), f.null) for f in fields},
            "primary key": sorted(f.column for f in meta.pk_fields),
            "unique": {
                c.name: sorted(column[name] for name in c.fields)
                for c in meta.constraints
                if isinstance(c, UniqueConstraint)
            },
            "indexes": {i.name: sorted(column[name] for name in i.fields) for i in meta.indexes},
            "foreign keys": {
                f.column: (f.related_model._meta.db_table, f.target_field.column)
                for f in fields
                if f.is_relation
            },
            "defaults": {f.column: django_default(f) for f in fields if f.has_db_default()},
        }
    return tables


def database_columns(db: Database, cursor: Any, table: str) -> list[tuple[str, str, bool, Any]]:
    """Each column of ``table``: its name, its type as the database declares it, whether it
    takes null, and its default as the database writes it."""
    if db.sqlite:
        cursor.execute(f'PRAGMA table_info("{table}")')
        return [(name, kind, not notnull, default) for _, name, kind, notnull, default, _ in cursor]
    cursor.execute(
        "SELECT column_name, data_type, character_maximum_length, is_nullable = 'YES', "
        "column_default FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = %s",
        [table],
    )
    return [
        (name, f"{kind}({length})" if length else kind, null, default)
        for name, kind, length, null, default in cursor
    ]


def database_tables(db: Database) -> dict[str, dict[str, Any]]:
    """The tables as the database has them, read by Django's introspection and from the
    database's own catalogue."""
    connection = connections[db.alias]
    look = connection.introspection
    tables = {}
    try:
        with connection.cursor() as cursor:
            for name in look.table_names(cursor):
                if name in ("alembic_version", "django_migrations"):
                    continue  # each tool's record of what it applied
                unique, indexes, foreign_keys = {}, {}, {}
                for constraint, about in look.get_constraints(cursor, name).items():
                    if about["primary_key"] or about["check"]:
                        continue
                    if about["foreign_key"]:
                        foreign_keys[about["columns"][0]] = tuple(about["foreign_key"])
                    elif about["unique"]:
                        unique[constraint] = sorted(about["columns"])
                    elif about["index"]:
                        indexes[constraint] = sorted(about["columns"])
                columns = database_columns(db, cursor, name)
                kinds = {column: database_kind(kind) for column, kind, _, _ in columns}
                tables[name] = {
                    "columns": {column: (kinds[column], null) for column, _, null, _ in columns},
                    "primary key": sorted(look.get_primary_key_columns(cursor, name) or []),
                    "unique": unique,
                    "indexes": indexes,
                    "foreign keys": foreign_keys,
                    "defaults": {
                        column: database_default(default, kinds[column])
                        for column, _, _, default in columns
                        if default is not None
                    },
                }
    finally:
        connection.close()
    return tables


def test_the_models_name_the_tables_the_migrations_build(database_url: str) -> None:
    db = Database(database_url)
    built, named = database_tables(db), django_tables()
    assert sorted(named) == sorted(built)
    for table in sorted(built):
        for part in ("columns", "primary key", "unique", "indexes", "foreign keys", "defaults"):
            assert named[table][part] == built[table][part], (table, part)


def test_django_finds_nothing_wrong_with_the_models() -> None:
    found = checks.run_checks(app_configs=[apps.get_app_config("agentgov")])
    assert [str(issue) for issue in found if not issue.is_silenced()] == []


# ------------------------------------------------------------------ the values stored


WHEN = datetime(2026, 10, 15, 8, 30, tzinfo=UTC)  # no microseconds: the format's edge case


def test_values_as_the_databases_hold_them(database_url: str) -> None:
    """What AgentGov has always written: times in UTC without a zone (on SQLite, text that
    always has microseconds, so that times compare as text), and JSON as text. The rows
    there read as they should, and what is written now is stored the same way."""
    db = Database(database_url)
    teams = django_models.Team.objects
    with db.transaction() as tx:
        tx.execute(
            "INSERT INTO teams (id, name, description, members, emails, destinations, "
            "created_at, updated_at) VALUES ('team_a', 'written-before', '', "
            "'[\"a@example.com\"]', '[]', '[]', '2026-10-15 08:30:00.000000', "
            "'2026-10-15 08:30:00.000000')"
        )
        team = teams.get(pk="team_a")
        # The last two, the database's defaults.
        assert (team.members, team.emails, team.is_default, team.version) == (
            ["a@example.com"],
            [],
            False,
            1,
        )
        assert team.created_at == WHEN
        assert team.created_at.tzinfo is not None
        teams.create(
            id="team_b",
            name="written-now",
            members=[{"nested": True}],
            # Without a zone: taken as UTC.
            created_at=datetime(2026, 10, 15, 8, 30, 0, 1),
        )
        [(created, members)] = tx.execute(
            "SELECT created_at, members FROM teams WHERE id = 'team_b'"
        )
        if db.sqlite:
            assert created == "2026-10-15 08:30:00.000001"
            members = json.loads(members)
        else:
            assert created == datetime(2026, 10, 15, 8, 30, 0, 1)
        assert members == [{"nested": True}]
        # Times compare in the database as they should.
        names = teams.order_by("created_at").values_list("name", flat=True)
        assert list(names) == ["written-before", "written-now"]
        later = teams.filter(created_at__gt=WHEN).values_list("name", flat=True)
        assert list(later) == ["written-now"]
        assert teams.get(pk="team_b").created_at == WHEN + timedelta(microseconds=1)


def test_keys_of_several_columns_and_foreign_keys(database_url: str) -> None:
    db = Database(database_url)
    with db.transaction():
        django_models.Blueprint.objects.create(id="bp_1", name="support")
        django_models.Agent.objects.create(id="agt_1", name="bot", blueprint_id="bp_1")
    with db.transaction():
        assert django_models.Agent.objects.get(pk="agt_1").blueprint.name == "support"
        django_models.ModelUsage.objects.create(
            agent_id="agt_1",
            day="2026-10-15",
            provider="openai",
            model="gpt",
            input_tokens=5,
        )
    with db.transaction():
        usage = django_models.ModelUsage.objects.get(pk=("agt_1", "2026-10-15", "openai", "gpt"))
        assert usage.input_tokens == 5


# --------------------------------------------------------------------------- saving


def test_a_save_writes_the_fields_that_changed(database_url: str) -> None:
    """As SQLAlchemy did: two transactions that change different fields of one row keep
    both changes, a save that changed nothing writes nothing, and the time the row was
    updated moves with a change."""
    db = Database(database_url)
    teams = django_models.Team.objects
    with db.transaction():
        teams.create(id="tm_1", name="support")
    with db.transaction():
        first = teams.get(pk="tm_1")
    with db.transaction():
        second = teams.get(pk="tm_1")
    made = first.updated_at
    with db.transaction():
        first.description = "first-line support"
        first.save()
    with db.transaction():
        second.members = ["alice@example.com"]
        second.save()
    with db.transaction():
        team = teams.get(pk="tm_1")
        assert (team.description, team.members) == ("first-line support", ["alice@example.com"])
        assert team.updated_at > made
        updated = team.updated_at
        team.save()
        team.name = "support"  # what it was
        team.save()
    with db.transaction():
        assert teams.get(pk="tm_1").updated_at == updated


def test_a_row_read_in_part_or_again_writes_what_changed(database_url: str) -> None:
    db = Database(database_url)
    teams = django_models.Team.objects
    with db.transaction():
        teams.create(id="tm_1", name="support", description="before")
    with db.transaction():
        team = teams.only("id", "name").get(pk="tm_1")
        team.description = "set without reading it"
        team.save()
    with db.transaction():
        team = teams.get(pk="tm_1")
        assert team.description == "set without reading it"
        teams.filter(pk="tm_1").update(name="renamed meanwhile")
        team.refresh_from_db()
        assert team.name == "renamed meanwhile" and team.changed() == []

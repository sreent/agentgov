"""The Django models (agentgov.db.models) against the database the migrations build: the
same tables, columns, keys, constraints, indexes and defaults; and what SQLAlchemy's models
write, Django's read, and the other way round (docs/adr/0007-django.md)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from django.apps import apps
from django.core import checks
from django.db.models import Field, UniqueConstraint, Value
from sqlalchemy import inspect, select
from sqlalchemy import types as sa

from agentgov import models
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


def database_kind(type_: Any) -> str:
    if isinstance(type_, sa.Text):
        return "text"
    if isinstance(type_, sa.String):
        return f"varchar({type_.length})"
    if isinstance(type_, sa.BigInteger):
        return "bigint"
    if isinstance(type_, sa.Integer):
        return "integer"
    if isinstance(type_, sa.Boolean):
        return "boolean"
    if isinstance(type_, sa.Float):
        return "float"
    if isinstance(type_, sa.JSON):
        return "json"
    if isinstance(type_, sa.DateTime):
        return "timestamp"
    raise AssertionError(f"a column of type {type_!r}")


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


def database_tables(db: Database) -> dict[str, dict[str, Any]]:
    look = inspect(db.engine)
    tables = {}
    for name in look.get_table_names():
        if name == "alembic_version":
            continue
        columns = look.get_columns(name)
        unique = {u["name"]: sorted(u["column_names"]) for u in look.get_unique_constraints(name)}
        indexes = {}
        for index in look.get_indexes(name):
            if index.get("duplicates_constraint"):
                continue
            target = unique if index["unique"] else indexes
            target[index["name"]] = sorted(index["column_names"])
        kinds = {c["name"]: database_kind(c["type"]) for c in columns}
        tables[name] = {
            "columns": {c["name"]: (kinds[c["name"]], c["nullable"]) for c in columns},
            "primary key": sorted(look.get_pk_constraint(name)["constrained_columns"]),
            "unique": unique,
            "indexes": indexes,
            "foreign keys": {
                fk["constrained_columns"][0]: (fk["referred_table"], fk["referred_columns"][0])
                for fk in look.get_foreign_keys(name)
            },
            # A key the database numbers itself (AutoField) has no default of Django's.
            "defaults": {
                c["name"]: database_default(c["default"], kinds[c["name"]])
                for c in columns
                if c["default"] is not None and not c["default"].startswith("nextval(")
            },
        }
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


# ------------------------------------------------------------- the values, both ways


WHEN = datetime(2026, 10, 15, 8, 30, tzinfo=UTC)  # no microseconds: the format's edge case


def test_each_reads_what_the_other_writes(database_url: str) -> None:
    db = Database(database_url)
    with db.session() as s:
        s.add(
            models.Team(
                id="team_a",
                name="written-by-sqlalchemy",
                members=["a@example.com"],
                created_at=WHEN,
            )
        )
    with db.transaction():
        team = django_models.Team.objects.get(pk="team_a")
        assert (team.members, team.emails, team.is_default, team.version) == (
            ["a@example.com"],
            [],
            False,
            1,
        )
        assert team.created_at == WHEN
        assert team.created_at.tzinfo is not None
        django_models.Team.objects.create(
            id="team_b",
            name="written-by-django",
            members=[{"nested": True}],
            created_at=WHEN + timedelta(microseconds=1),
            # Without a zone: taken as UTC, as SQLAlchemy's models take it.
            updated_at=datetime(2026, 10, 15, 9, 0),
        )
    with db.session() as s:
        team = s.get(models.Team, "team_b")
        assert team is not None
        assert team.members == [{"nested": True}]
        assert team.created_at == WHEN + timedelta(microseconds=1)
        assert team.updated_at.tzinfo is not None
        assert team.is_default is False and team.version == 1  # the database's defaults
        # Times written by either compare in the database as they should.
        names = s.scalars(select(models.Team.name).order_by(models.Team.created_at)).all()
        assert names == ["written-by-sqlalchemy", "written-by-django"]
        later = s.scalars(select(models.Team.name).where(models.Team.created_at > WHEN)).all()
        assert later == ["written-by-django"]


def test_keys_of_several_columns_and_foreign_keys(database_url: str) -> None:
    db = Database(database_url)
    with db.session() as s:
        s.add(models.Blueprint(id="bp_1", name="support"))
        s.add(models.Agent(id="agt_1", name="bot", blueprint_id="bp_1"))
    with db.transaction():
        agent = django_models.Agent.objects.select_related("blueprint").get(pk="agt_1")
        assert agent.blueprint.name == "support"
        django_models.ModelUsage.objects.create(
            agent_id="agt_1",
            day="2026-10-15",
            provider="openai",
            model="gpt",
            input_tokens=5,
        )
    with db.session() as s:
        usage = s.get(models.ModelUsage, ("agt_1", "2026-10-15", "openai", "gpt"))
        assert usage is not None and usage.input_tokens == 5

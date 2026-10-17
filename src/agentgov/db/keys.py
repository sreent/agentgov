"""Foreign keys as AgentGov's database keeps them, which isn't as Django 5.2 makes them
(docs/adr/0007-django.md):

* Checked as each statement writes them, as Alembic's schema had them, rather than at commit,
  as Django makes them. Checked at commit, a key would lock the row it names after the ledger's
  head, which a transaction locks last (agentgov.ledger), and two transactions could each wait
  for the other.
* With the database's own rule on delete where Django's is to set the key to null
  (``on_delete=SET_NULL``): the database sets it to null too (``ON DELETE SET NULL``), whoever
  deletes the row, as AgentGov's schema did before Django's migrations built it. Django 6's
  ``DB_SET_NULL`` can replace this, once AgentGov runs on it.

AgentGov's schema editors make keys so (``KeyRules``: agentgov.db.postgresql,
agentgov.db.sqlite3), and ``RemakeKeys`` makes a database's keys again where they are
otherwise.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, NamedTuple

from django.db.migrations.operations.base import Operation
from django.db.models import SET_NULL

if TYPE_CHECKING:
    from django.db.backends.base.schema import BaseDatabaseSchemaEditor as _Editor
else:
    _Editor = object

# When the database checks a key: as each statement writes it. Deferrable all the same, as
# Django's own SQL for keys expects (it sets one IMMEDIATE before dropping it).
CHECKED = " DEFERRABLE INITIALLY IMMEDIATE"
# The database's rule for a key, by Django's: setting it to null only, which leaves a row
# deleted outside Django as Django would. Rows deleted with the one they name (CASCADE) are
# left to Django, so that none goes without AgentGov's code knowing.
RULES = {SET_NULL: "SET NULL"}
# What a key without a rule does, as the databases name it: refuse to be left dangling.
NO_RULE = "NO ACTION"
# PostgreSQL's names for the rules (pg_constraint.confdeltype).
_PG_RULES = {"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}


class Key(NamedTuple):
    # What the database does to the key when the row it names is deleted.
    rule: str
    # Whether the database checks it at commit, rather than as each statement writes it.
    deferred: bool


def is_key(field: Any) -> bool:
    """Whether ``field`` is a foreign key the database keeps (a constraint)."""
    return (
        field.remote_field is not None
        and not field.many_to_many
        and getattr(field, "db_constraint", False)
    )


def rule(field: Any) -> str:
    """What the database does to ``field``, a foreign key, when the row it names is deleted."""
    return RULES.get(field.remote_field.on_delete, NO_RULE)


def made(field: Any) -> Key:
    """``field``'s key as AgentGov's schema editors make it."""
    return Key(rule(field), deferred="INITIALLY DEFERRED" in CHECKED)


def keyed(clause: str, field: Any) -> str:
    """``clause``, the SQL Django writes for ``field``'s key or its template, as AgentGov makes
    the key: with its rule, and checked as each statement writes it."""
    ruled = "" if rule(field) == NO_RULE else f" ON DELETE {rule(field)}"
    for deferred in ("%(deferrable)s", " DEFERRABLE INITIALLY DEFERRED"):
        if deferred in clause:
            return clause.replace(deferred, ruled + CHECKED, 1)
    raise ValueError(f"Django wrote a key that says nothing of when it is checked: {clause!r}")


def in_database(connection: Any, table: str) -> dict[str, Key]:
    """``table``'s foreign keys as the database has them, by column; none for a table it
    doesn't have."""
    with connection.cursor() as cursor:
        if connection.vendor != "sqlite":
            cursor.execute(
                "SELECT a.attname, c.confdeltype, c.condeferred FROM pg_constraint c "
                "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] "
                "WHERE c.contype = 'f' AND c.conrelid = to_regclass(%s)",
                [table],
            )
            return {name: Key(_PG_RULES[kind], deferred) for name, kind, deferred in cursor}
        cursor.execute(f"PRAGMA foreign_key_list({connection.ops.quote_name(table)})")
        # id, seq, table, from, to, on_update, on_delete, match
        rules = {row[3]: row[6] for row in cursor.fetchall()}
        if not rules:
            return {}
        cursor.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = %s", [table])
        deferred = _deferred(cursor.fetchone()[0])
        return {column: Key(rules[column], column in deferred) for column in rules}


def _deferred(sql: str) -> set[str]:
    """The columns whose keys SQLite checks at commit, as a table's CREATE TABLE statement
    declares them: in a column's definition, or after the columns (FOREIGN KEY (...))."""
    body = sql[sql.index("(") + 1 : sql.rindex(")")]
    parts, depth, quoted, start = [], 0, False, 0
    for at, char in enumerate(body):
        if char == "'":
            quoted = not quoted
        elif not quoted and char in "()":
            depth += 1 if char == "(" else -1
        elif not quoted and char == "," and depth == 0:
            parts.append(body[start:at])
            start = at + 1
    parts.append(body[start:])
    columns = set()
    for part in (part.strip() for part in parts):
        if "INITIALLY DEFERRED" not in part.upper():
            continue
        after = re.match(r"(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(\s*[\"`\[]?(\w+)", part, re.I)
        columns.add(after[1] if after else part.split()[0].strip('"`[]'))
    return columns


class KeyRules(_Editor):
    """For AgentGov's schema editors: each foreign key they make as AgentGov keeps it
    (``keyed``), and one whose rule changes made again."""

    def _create_fk_sql(self, model: Any, field: Any, suffix: str) -> Any:
        # A key made after its table or column (PostgreSQL's).
        statement = super()._create_fk_sql(model, field, suffix)
        statement.template = keyed(statement.template, field)
        return statement

    def add_field(self, model: Any, field: Any) -> None:
        if not is_key(field) or not self.sql_create_column_inline_fk:
            super().add_field(model, field)
            return
        # A key written with its column.
        self.sql_create_column_inline_fk = keyed(type(self).sql_create_column_inline_fk, field)
        try:
            super().add_field(model, field)
        finally:
            del self.sql_create_column_inline_fk

    def _field_should_be_altered(self, old_field: Any, new_field: Any, ignore: Any = None) -> bool:
        # Django takes on_delete for something the database doesn't keep.
        if super()._field_should_be_altered(old_field, new_field, ignore):
            return True
        return is_key(old_field) and is_key(new_field) and rule(old_field) != rule(new_field)


class RemakeKeys(Operation):
    """A migration's step: ``model_name``'s foreign keys made again where the database has them
    otherwise than AgentGov's schema editors make them (``made``), as on a database Django's
    migrations built before the editors made keys so. A key made so, and a table not made yet,
    are left as they are; going back leaves the keys."""

    reduces_to_sql = True
    reversible = True

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name

    def state_forwards(self, app_label: str, state: Any) -> None:
        pass

    def database_forwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        model = to_state.apps.get_model(app_label, self.model_name)
        connection = schema_editor.connection
        if not self.allow_migrate_model(connection.alias, model):
            return
        have = in_database(connection, model._meta.db_table)
        otherwise = [
            field
            for field in model._meta.local_fields
            if is_key(field) and field.column in have and have[field.column] != made(field)
        ]
        if not otherwise:
            return
        if connection.vendor == "sqlite":
            # SQLite changes a table's keys only by making the table again.
            schema_editor._remake_table(model)
            return
        for field in otherwise:
            for name in schema_editor._constraint_names(model, [field.column], foreign_key=True):
                schema_editor.execute(schema_editor._delete_fk_sql(model, name))
            schema_editor.execute(
                schema_editor._create_fk_sql(model, field, "_fk_%(to_table)s_%(to_column)s")
            )

    def database_backwards(
        self, app_label: str, schema_editor: Any, from_state: Any, to_state: Any
    ) -> None:
        pass

    def describe(self) -> str:
        return f"Make {self.model_name}'s foreign keys again as AgentGov keeps them"


# Migration 0002's name for it, when it gave keys their rules on delete alone.
AddRulesOnDelete = RemakeKeys

"""What the database does to a foreign key when the row it names is deleted: what Django does.
A key Django sets to null when its row goes (``on_delete=SET_NULL``) the database sets to null
too (``ON DELETE SET NULL``), whoever deletes the row, as AgentGov's schema did before Django's
migrations built it (docs/adr/0007-django.md).

Django 5.2 writes no such rule into the database, so AgentGov's schema editors do
(``KeyRules``: agentgov.db.postgresql, agentgov.db.sqlite3), and a migration gives it to the
keys a database has without it (``AddRulesOnDelete``). Django 6's ``DB_SET_NULL`` replaces
them, once AgentGov runs on it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db.migrations.operations.base import Operation
from django.db.models import SET_NULL

if TYPE_CHECKING:
    from django.db.backends.base.schema import BaseDatabaseSchemaEditor as _Editor
else:
    _Editor = object

# The database's rule for a key, by Django's: setting it to null only, which leaves a row
# deleted outside Django as Django would. Rows deleted with the one they name (CASCADE) are
# left to Django, so that none goes without AgentGov's code knowing.
RULES = {SET_NULL: "SET NULL"}
# What a key without a rule does, as the databases name it: refuse to be left dangling.
NO_RULE = "NO ACTION"


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


def rule_sql(field: Any) -> str:
    """The clause that gives ``field``'s constraint its rule; none for a field without one."""
    if not is_key(field) or rule(field) == NO_RULE:
        return ""
    return f" ON DELETE {rule(field)}"


def with_rule(clause: str, ruled: str) -> str:
    """``clause``, a key's SQL or its template, with ``ruled`` where SQL takes it: after the
    column the key names, before when it is checked."""
    for checked in ("%(deferrable)s", " DEFERRABLE"):
        if checked in clause:
            return clause.replace(checked, ruled + checked, 1)
    return clause + ruled


def in_database(connection: Any, table: str) -> dict[str, str]:
    """What the database does to each of ``table``'s foreign keys, by column, when the row it
    names is deleted; nothing for a table it doesn't have."""
    with connection.cursor() as cursor:
        if connection.vendor == "sqlite":
            cursor.execute(f"PRAGMA foreign_key_list({connection.ops.quote_name(table)})")
            # id, seq, table, from, to, on_update, on_delete, match
            return {row[3]: row[6] for row in cursor.fetchall()}
        cursor.execute(
            "SELECT kcu.column_name, rc.delete_rule "
            "FROM information_schema.referential_constraints rc "
            "JOIN information_schema.key_column_usage kcu "
            "ON kcu.constraint_schema = rc.constraint_schema "
            "AND kcu.constraint_name = rc.constraint_name "
            "WHERE kcu.table_schema = current_schema() AND kcu.table_name = %s",
            [table],
        )
        return dict(cursor.fetchall())


class KeyRules(_Editor):
    """For AgentGov's schema editors: each foreign key they make has its rule (``rule``), and
    one whose rule changes is made again."""

    def _create_fk_sql(self, model: Any, field: Any, suffix: str) -> Any:
        # A key made after its table or column (PostgreSQL's).
        statement = super()._create_fk_sql(model, field, suffix)
        statement.template = with_rule(statement.template, rule_sql(field))
        return statement

    def add_field(self, model: Any, field: Any) -> None:
        ruled = rule_sql(field)
        if not ruled or not self.sql_create_column_inline_fk:
            super().add_field(model, field)
            return
        # The key written with its column, and its rule with it.
        self.sql_create_column_inline_fk = with_rule(type(self).sql_create_column_inline_fk, ruled)
        try:
            super().add_field(model, field)
        finally:
            del self.sql_create_column_inline_fk

    def _field_should_be_altered(self, old_field: Any, new_field: Any, ignore: Any = None) -> bool:
        # Django takes on_delete for something the database doesn't keep.
        changed = super()._field_should_be_altered(old_field, new_field, ignore)
        return changed or rule_sql(old_field) != rule_sql(new_field)


class AddRulesOnDelete(Operation):
    """A migration's step: ``model_name``'s foreign keys given, in the database, the rules
    they lack, on a database Django's migrations built before AgentGov's schema editors wrote
    them. A key with its rule, and a table not made yet, are left as they are; going back
    leaves the rules."""

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
        lacking = [
            field
            for field in model._meta.local_fields
            if is_key(field) and field.column in have and have[field.column] != rule(field)
        ]
        if not lacking:
            return
        if connection.vendor == "sqlite":
            # SQLite changes a table's keys only by making the table again.
            schema_editor._remake_table(model)
            return
        for field in lacking:
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
        return f"Give {self.model_name}'s foreign keys their rules on delete in the database"

"""Django fields for the columns as the migrations make them, holding what AgentGov has
always written: times in UTC without a zone, and JSON in ``json`` columns (Django's own
JSONField has ``jsonb``)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from django.db import models
from django.utils.dateparse import parse_datetime


class UTCDateTimeField(models.DateTimeField):
    """A time, stored in UTC without a zone (``TIMESTAMP`` on PostgreSQL; text on SQLite,
    always with microseconds) and read back in UTC. One given without a zone is taken as
    UTC, not as some local time."""

    def db_type(self, connection: Any) -> str:
        return "TIMESTAMP WITHOUT TIME ZONE" if connection.vendor == "postgresql" else "DATETIME"

    def get_prep_value(self, value: Any) -> Any:
        value = self.to_python(value)
        if isinstance(value, datetime):
            return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return value

    def get_db_prep_value(self, value: Any, connection: Any, prepared: bool = False) -> Any:
        if not prepared:
            value = self.get_prep_value(value)
        if value is None or hasattr(value, "resolve_expression"):
            return value
        value = value.astimezone(UTC).replace(tzinfo=None)
        if connection.vendor == "sqlite":
            # Always with microseconds, as the rows there have them: times compare as text.
            return value.isoformat(" ", timespec="microseconds")
        return value

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, str):
            parsed = parse_datetime(value)
            if parsed is None:
                raise ValueError(f"not a time: {value!r}")
            value = parsed
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class JSONField(models.JSONField):
    """JSON in a ``json`` column (text on SQLite), written as text (``jsonb`` would reorder
    it), and read as psycopg gives it from PostgreSQL, decoded."""

    def db_type(self, connection: Any) -> str:
        return "JSON"

    def get_db_prep_value(self, value: Any, connection: Any, prepared: bool = False) -> Any:
        if not prepared:
            value = self.get_prep_value(value)
        if value is None or hasattr(value, "resolve_expression"):
            return value
        return json.dumps(value, cls=self.encoder)

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value  # SQL's NULL, or a json column's value psycopg decoded
        return super().from_db_value(value, expression, connection)

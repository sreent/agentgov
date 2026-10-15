from django.apps import AppConfig


class Database(AppConfig):
    """The database's tables, as Django models (agentgov.db.models)."""

    name = "agentgov.db"
    label = "agentgov"

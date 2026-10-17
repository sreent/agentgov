"""An agent's blueprint set to null by the database when the blueprint is deleted, as Django
sets it (agentgov.db.keys), on a database Django's first migration built before AgentGov's
schema editors wrote that rule. Databases Alembic's migrations built have it, and those built
since get it with their tables."""

from django.db import migrations

import agentgov.db.keys


class Migration(migrations.Migration):
    dependencies = [("agentgov", "0001_initial")]

    operations = [agentgov.db.keys.AddRulesOnDelete("agent")]

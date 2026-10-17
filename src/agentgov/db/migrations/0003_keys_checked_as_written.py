"""Foreign keys checked as each statement writes them, as Alembic's schema had them, rather
than at commit, as Django's first migrations made them (agentgov.db.keys): checked at commit, a
key locks the row it names after the ledger's head, and two transactions can each wait for the
other. Databases Alembic's migrations built have them so, and those built since get them so
with their tables."""

from django.db import migrations

import agentgov.db.keys


class Migration(migrations.Migration):
    dependencies = [("agentgov", "0002_rules_on_delete")]

    operations = [agentgov.db.keys.RemakeKeys("agent")]

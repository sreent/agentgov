#!/usr/bin/env bash
# Write the migration for a change to the models (src/agentgov/models.py):
#
#   scripts/new-migration.sh "Add model grants to blueprints"
#
# Alembic compares a database built by the existing migrations with the models
# and writes the difference as the next numbered revision in
# src/agentgov/migrations/versions. Read it before committing: Alembic cannot
# tell a rename from a drop and an add, and data migrations are written by hand.
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 \"what changed\"" >&2; exit 2; }
cd "$(dirname "$0")/.."
PYTHON=${PYTHON:-.venv/bin/python}

"$PYTHON" - "$1" <<'EOF'
import sys
import tempfile

from alembic import command

from agentgov import migrations
from agentgov.db import Database

with tempfile.TemporaryDirectory() as tmp:
    db = Database(f"sqlite:///{tmp}/schema.db")
    migrations.upgrade(db.engine)
    with db.engine.connect() as connection:
        script = command.revision(
            migrations._config(connection, skip_empty=True),
            message=sys.argv[1],
            autogenerate=True,
            rev_id=f"{int(migrations.head()) + 1:04d}",
        )
    db.dispose()
if not script:
    sys.exit("the models match the migrations: nothing to write")
print(script.path)
EOF
"${PYTHON%/python}/ruff" format --quiet src/agentgov/migrations/versions

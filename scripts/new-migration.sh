#!/usr/bin/env bash
# Write the migration for a change to the models (src/agentgov/db/models.py):
#
#   scripts/new-migration.sh add_model_grants_to_blueprints
#
# Django compares the models with its migrations and writes the difference as the next
# numbered migration in src/agentgov/db/migrations. Read it before committing: Django
# asks whether a field was renamed when it can't tell, and moving data between columns
# is yours to write (a RunPython or RunSQL operation).
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 what_changed" >&2; exit 2; }
cd "$(dirname "$0")/.."
PYTHON=${PYTHON:-.venv/bin/python}

"$PYTHON" - "$1" <<'PY'
import sys

from django.core.management import call_command

from agentgov import migrations, web

web.configure()
call_command("makemigrations", migrations.APP, name=sys.argv[1])
PY
"${PYTHON%/python}/ruff" check --fix --quiet --select I src/agentgov/db/migrations
"${PYTHON%/python}/ruff" format --quiet src/agentgov/db/migrations

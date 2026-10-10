#!/bin/bash
# Prepares a Claude Code cloud session to run this repository's checks
# (scripts/ci.sh): Python dependencies in .venv and the opa binary. Docker is
# started on demand by scripts/ci.sh when an image or end-to-end check needs it.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"
scripts/ci.sh --setup

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "export PATH=\"$PWD/.venv/bin:\$PATH\"" >>"$CLAUDE_ENV_FILE"
fi
echo "Run the checks with scripts/ci.sh (add --e2e for the full stack); GitHub Actions runs the same script."

#!/usr/bin/env bash
# Thin wrapper: "cd <Project> && ./scripts/venv_run.sh" — no need to name the project.
# From All_Scripts: ./run.sh <Project> [script] [-- args...]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ALL_SCRIPTS_ROOT="$(cd "$PROJECT_DIR/.." && pwd)"
PROJECT_NAME="$(basename "$PROJECT_DIR")"
exec "$ALL_SCRIPTS_ROOT/scripts/venv_run.sh" "$PROJECT_NAME" "$@"

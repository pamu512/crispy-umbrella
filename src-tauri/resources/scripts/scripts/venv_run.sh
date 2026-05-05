#!/usr/bin/env bash
# Run a Python app in a per-project venv. Safe to re-run: creates venv and pip-installs as needed.
# Discovered projects:  ../run.sh   (from the All_Scripts root). For “cd into project” use that project’s scripts/venv_run.sh wrapper.
# Usage (from workspace root, one level above **scripts/**):
#   ./scripts/venv_run.sh <project_subdir> [entry_script] [ -- extra args to Python ...]
# Example:
#   ./scripts/venv_run.sh CVE_Project_NVD
#   ./scripts/venv_run.sh Intelx_Crawler    other.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJ_RELP="${1:-}"
if [[ -z "$PROJ_RELP" || "$PROJ_RELP" == -* ]]; then
  echo "usage: $(basename "$0") <project_subdir> [entry_script] [-- python_args...]" >&2
  exit 1
fi
shift
PROJ_DIR="$WS_ROOT/$PROJ_RELP"
if [[ ! -d "$PROJ_DIR" ]]; then
  echo "not a directory: $PROJ_DIR" >&2
  exit 1
fi
cd "$PROJ_DIR"
if [[ ! -f requirements.txt ]]; then
  echo "error: $PROJ_RELP/requirements.txt not found (run from a folder that has one)." >&2
  exit 1
fi
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# Idempotent: fast when already satisfied; upgrades when requirements change.
.venv/bin/pip install -q -r requirements.txt
ENTRY=main.py
if [[ -n "${1:-}" && "$1" != "--" ]]; then
  if [[ -f "$1" ]]; then
    ENTRY="$1"
    shift
  fi
fi
if [[ "${1:-}" == "--" ]]; then shift; fi
exec .venv/bin/python3 "$ENTRY" "$@"

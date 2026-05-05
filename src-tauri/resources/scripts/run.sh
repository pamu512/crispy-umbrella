#!/usr/bin/env bash
# Friendly launcher: runs any project’s venv + Python entrypoint. Run from the All_Scripts directory.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
RUNNER="$ROOT/scripts/venv_run.sh"

list_projects() {
  local found=0
  for d in "$ROOT"/*; do
    [[ -d "$d" ]] || continue
    if [[ -f "$d/requirements.txt" ]]; then
      printf "  %s\n" "$(basename "$d")"
      found=1
    fi
  done
  if [[ $found -eq 0 ]]; then
    echo "  (no projects with requirements.txt found)" >&2
  fi
}

if [[ $# -eq 0 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<EOF
CTI All_Scripts — run a project in its own venv (creates .venv and pip installs on first use).

  From this folder:
    ./run.sh <project>                 # run main.py
    ./run.sh <project> other.py        # run a different entry script
    ./run.sh <project> main.py -- -a  # pass args to Python (after --)

  From inside a project folder (no need to name the project):
    ./scripts/venv_run.sh
    ./scripts/venv_run.sh my_script.py

Projects:
EOF
  list_projects
  echo
  echo "See README.txt for paths and the smoke test."
  exit 0
fi

exec "$RUNNER" "$@"

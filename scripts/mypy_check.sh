#!/usr/bin/env bash
# Strict static typing for configured Python paths (see repo-root pyproject.toml [tool.mypy]).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ ! -x .venv/bin/mypy ]]; then
  echo "Create .venv and install dev typing deps, e.g.:" >&2
  echo "  python3 -m venv .venv && .venv/bin/pip install mypy '>=1.8' pydantic pandas-stubs types-requests" >&2
  exit 1
fi
exec .venv/bin/mypy "$@"

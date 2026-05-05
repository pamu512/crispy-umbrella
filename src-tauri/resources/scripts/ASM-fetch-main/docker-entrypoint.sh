#!/usr/bin/env bash
set -e

# Run alembic migrations if alembic is available
if command -v alembic >/dev/null 2>&1; then
  echo "Running alembic upgrade head..."
  alembic upgrade head || true
else
  echo "alembic not installed in image; skipping migrations"
fi

# Start the uvicorn app
exec uvicorn main:app --host 0.0.0.0 --port 8000

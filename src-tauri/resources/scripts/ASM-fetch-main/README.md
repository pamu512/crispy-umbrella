# eASM Platform (External Attack Surface Management)

## Overview

eASM is a lightweight, containerized platform for automated external attack surface discovery. It scans domains (A records, MX hosts, TLS, Shodan/FOFA/Pentest-Tools integrations), stores structured findings, and provides export endpoints for analysis. The stack uses FastAPI (HTTP API), Celery (background task execution), PostgreSQL (storage), and Redis (task broker).

This README provides a professional, step-by-step guide to run the project, use the API, and configure a custom database.

## Quick start (development)

Prerequisites: Docker and Docker Compose.

1. Build and start the full stack:

```bash
docker compose up --build
```

1. The API is available at [http://localhost:8000](http://localhost:8000). Interactive API docs are at [http://localhost:8000/docs](http://localhost:8000/docs).
2. Stop and remove containers, anonymous volumes and orphans:

```bash
docker compose down --volumes --remove-orphans
```

## Default Postgres (bundled)

- The project includes a Postgres container named `db`. On first startup the database `asm_db` and the default user are created by the container's init scripts.
- If you'd rather use an external Postgres:
  1. Provision or choose a Postgres instance reachable from the host or containers.
  2. Create a database (for example `asm_db`) and a user with appropriate privileges.
  3. Configure environment variables (in `.env` or your orchestration) to point to your DB:

```text
DB_HOST=<your-db-host>
DB_PORT=5432
DB_USER=<your-db-user>
DB_PASSWORD=<your-db-password>
DB_NAME=asm_db
DATABASE_URL=postgresql+psycopg2://<DB_USER>:<DB_PASSWORD>@<DB_HOST>:<DB_PORT>/<DB_NAME>
```

1. Rebuild and restart the stack. Alembic migrations will execute on startup to prepare the schema.

## API reference with examples

All examples assume the server is at `http://localhost:8000`.

1. Subscriptions

- POST /subscriptions/
 Request
 Response (200)
- GET /subscriptions/
 Request
 Response (200)
- PUT /subscriptions/{domain_id}?frequency={frequency}
 Request
 Response (200) — the updated domain

1. Scans

- POST /scans/instant
 Launch a one-off scan. Provide either `domain` (string) or `domain_id`.
 Request
 Response (200)
 Notes:
  - Instant scans are marked `priority` and are scheduled ahead of pending subscription scans.
  - Scans may take anywhere from a few seconds to several minutes depending on how many subdomains and services are discovered; please be patient while results are collected and processed.
- GET /scans/{scan_id}/status
 Request
 Response (200)
- POST /scans/{scan_id}/terminate
 Request
 Response (200) — updated ScanOut with status `terminated`.
- GET /scans/
 List all scans or filter by domain_id: `GET /scans/?domain_id=17`
- GET /scans/queue
 Returns scans currently `scanning` first, then `pending` ordered by `priority` (desc) and `id` (asc).

1. Results & Exports

- GET /results/{scan_id}/json — Return scan results in structured JSON.
- GET /export/{scan_id}/csv — Download CSV file.
- GET /export/{scan_id}/xlsx — Download XLSX file.

> 🚨 Important — Use JSON for AI/Automation  
> The JSON export contains the complete, raw and highly-detailed scan data (JSONB fields, lists of findings, service fingerprints, and other raw attributes). The CSV and XLSX exports are simplified, human-friendly overviews intended for quick inspection, reporting, or spreadsheet workflows. If you plan to feed results into automation or AI tools for advanced analysis, use the JSON output — it preserves the full structure required for best results.

Download examples (curl):

```bash
curl -X GET "http://localhost:8000/results/1/json" -o result.json
curl -X GET "http://localhost:8000/export/1/csv" -o result.csv
curl -X GET "http://localhost:8000/export/1/xlsx" -o result.xlsx
```

## Operational details

- Scheduling: Celery Beat runs scheduled tasks for daily (00:00), weekly (Monday 00:00) and monthly (day 1, 00:00). These expressions are configured in `src/tasks/scan_tasks.py`.
- Concurrency: Controlled with `MAX_CONCURRENT_SCANS`. When capacity is full tasks are rescheduled with a small delay.
- Prioritization: Instant scans are marked priority and will be placed before non-priority pending scans.

## Running tests and local development

- Use the interactive API docs at `/docs` to explore request/response models.

## Troubleshooting

- ResponseValidationError: ensure your DB schema matches the Pydantic models and that migrations have been applied.
- Celery import errors: ensure `PYTHONPATH=/app` is set in the environment or your container configuration.

## Diagrams

UML sources are included in the `docs/` folder and reflect the current project state (priority scans, JSONB list fields, removed `logs`/`error_message`, and external integrations).

- `docs/database.puml` — database ERD (domains, scans with `priority`, subdomain_data with JSONB fields)
- `docs/workflow.puml` — architecture and task flow (FastAPI, Celery worker/beat, Redis, crt_sh/pentest_tools integrations)

Render locally with PlantUML (Java):

```bash
java -jar plantuml.jar docs/database.puml
java -jar plantuml.jar docs/workflow.puml
```

Or use Docker:

```bash
docker run --rm -v "$PWD":/workspace plantuml/plantuml:latest docs/database.puml
docker run --rm -v "$PWD":/workspace plantuml/plantuml:latest docs/workflow.puml
```

Rendered diagrams (served by plantuml.com):

Database diagram

Workflow diagram
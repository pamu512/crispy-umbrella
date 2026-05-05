# Social Media Search Tool

A social media search tool that uses Tor proxy service for anonymous searching with privacy protection features.

## Requirements

- **Docker** and **Docker Compose** installed

## Docker (default Tor)

The Compose file always defines a **`tor_docker`** service (`dperson/torproxy`). The **`main`** service **`depends_on`** it with **`condition: service_healthy`**, so any normal `docker compose up` or `docker compose run main …` (without `--no-deps`) brings Tor up on the same bridge network before searches run. Traffic uses the in-network SOCKS endpoint, not the host’s `127.0.0.1:9050`.

**`./docker-run.sh`** / **`docker-run.ps1`** also start **`tor_docker`** explicitly and wait for **healthy**, then run **`main`**—aligned with Compose defaults.

| Variable | Default in Compose | Meaning |
|----------|-------------------|---------|
| `TOR_SOCKS_HOST` | `tor_docker` | SOCKS hostname (`getSearchResult.py`; use `127.0.0.1` only if Tor runs on the host) |
| `TOR_SOCKS_PORT` | `9050` | SOCKS port |
| `TOR_CONTROL_PORT` | `9051` | Control port (optional; remote SOCKS path may not use control) |
| `TOR_DOCKER_CONTAINER` | `docker-tor` | Container name hint for Docker-socket flows |
| `TARGET_NAME` / `OUTPUT_PATH` | optional | Used by the default `command` in `docker-compose.yml` when set |

**Build / run**

```bash
cd Social_MediaV2
docker compose build
./docker-run.sh "YourTarget" ./output
# or: docker compose up   # uses compose command + env from file
```

**Playwright in the image**

The **Dockerfile** runs **`playwright install --with-deps chromium`** after **`pip install`**, with **`PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`**. If you change Playwright versions or trim the Dockerfile, run once inside the stack:

```bash
docker compose run --rm main playwright install --with-deps chromium
```

Using **`docker compose run --no-deps main …`** skips starting **`tor_docker`**; set **`TOR_SOCKS_HOST`** / **`TOR_SOCKS_PORT`** yourself if you still need Tor (e.g. host proxy).

## Quick Start (Docker)

This tool runs in a Docker container and automatically handles:

1. Searching social media platforms (Facebook, Twitter, Instagram, LinkedIn, TikTok, Pinterest)
2. Saving results to CSV
3. Taking screenshots of the results (using Playwright)

### Usage

**Linux / macOS:**

```bash
./docker-run.sh <target_name> [output_path] [num] [start_time] [end_time]
```

**Windows (PowerShell):**

```powershell
.\docker-run.ps1 <target_name> [output_path] [num] [start_time] [end_time]
```

### Parameters

- `target_name` (Required): The keyword or target to search for.
- `output_path` (Optional): Directory to save results (default: `./output`).
- `num` (Optional): Number of results per platform (default: `10`).
- `start_time` (Optional): Start date filter in `YYYY-MM-DD` format (default: none).
- `end_time` (Optional): End date filter in `YYYY-MM-DD` format (default: none).

### Examples

**Basic search (10 results):**

```bash
./docker-run.sh "Jack" ./output
```

**Search with custom count (20 results):**

```bash
./docker-run.sh "Jack" ./output 20
```

**Search with date filter:**

```bash
./docker-run.sh "Jack" ./output 20 "2025-01-01" "2025-12-31"
```

## Outputs

The tool generates two output directories relative to your specified output path:

1. **CSV Results**:
  `output/<target_name>/<target_name>_<platform>.csv`
2. **Screenshots**:
  `output_screenshot_<target_name>/<platform>/<row_index>.png`

*(Note: TikTok screenshots are skipped by default)*

---

## CTI Command Center (local Python + vault)

The desktop app can run **`main.py`** directly (project `.venv` / `python3`), with the same semantics as Docker:

- **Target** (required): search keyword (multi-word targets are supported; output folders strip wrapping quotes per `getSearchResult.py`).
- **Output root**: `Social_MediaV2/output` (absolute path passed as `-v2` so CSVs always land under the project tree).
- **Results per platform**: default **10** (override in the run dialog).
- **Start / end time** (optional): `YYYY-MM-DD`, passed as `--start-time` / `--end-time` when set.

CSV layout (per platform file):

- Path: `output/<target_folder>/<target_folder>_<platform>.csv`
- Columns: `title`, `url`, `abstract`, `date`

### Ingest into `cti_vault.db`

After a **successful** run from the Command Center, the app scans `Social_MediaV2/output/**/*.csv` and **upserts** rows into SQLite table **`social_media_results`**:

| Column | Meaning |
|--------|---------|
| `target_name` | Subdirectory name under `output/` (filesystem-safe target) |
| `platform` | Parsed from filename (`facebook`, `twitter`, …) |
| `title`, `url`, `abstract`, `result_date` | From CSV |
| `source_csv` | Relative path to the file under the workspace |
| `ingested_at` | UTC timestamp (RFC3339) |

Unique key: **`(url, platform)`** — re-running refreshes metadata for the same hit.

Example query in the Investigation Canvas / `query_db`:

```sql
SELECT target_name, platform, title, url, result_date
FROM social_media_results
ORDER BY ingested_at DESC
LIMIT 20;
```

**Requirements:** Tor + dependencies from `requirements.txt` in a **venv** at project root (see `SCRIPT_WORKFLOWS.md`); the README **Docker** path remains the fully tested environment for Playwright + Tor.
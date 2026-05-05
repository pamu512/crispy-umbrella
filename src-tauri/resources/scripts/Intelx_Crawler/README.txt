Native IntelX: `intelx_native_sync.py` uses **stdlib HTTP only** (`urllib` — no `pip install requests` required), calls
`https://2.intelx.io` (override with `INTELX_BASE_URL`), polls until the search finishes, then upserts each hit into
`ioc_records` (`intelx_search_hit`) via `shared_utils/db_manager.py`.
Stdin: four lines (target, start, end, limit). Required env: `INTELX_API_KEY` (forwarded from the host if set),
plus `CTI_DB_PATH` / `VAULT_PATH` injected by Tauri.

Legacy Docker Compose remains available only when `INTELX_LEGACY_DOCKER=1` and `docker-compose.yml` is present.

Bundle reminder: ensure `tauri.conf.json` maps bundled scripts, e.g.
`"resources/scripts/**/*": "scripts/"` under `bundle.resources` (already standard for this app).

#!/usr/bin/env python3
"""
Native IntelX sync: POST /intelligent/search, poll /intelligent/search/result, upsert hits into cti_vault.

Environment (set by the Tauri host or your shell):
  CTI_DB_PATH / VAULT_PATH — canonical SQLite vault (required)
  INTELX_API_KEY — Intelligence X API key, header x-key (required for live search)

Optional:
  INTELX_BASE_URL — default https://2.intelx.io

Input (either mode):
  • CLI: ``python3 intelx_native_sync.py <query> <start_date> <end_date> <limit>`` (dates YYYY-MM-DD).
  • Stdin: four lines — query, start_date, end_date, search_limit (when argv has only the script name).
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# Bundle layout: resources/scripts/Intelx_Crawler/this.py + resources/scripts/shared_utils/db_manager.py
# PyInstaller onefile: shared_utils is unpacked next to the binary under ``_MEIPASS``.
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    sys.path.insert(0, str(Path(sys._MEIPASS) / "shared_utils"))
else:
    _SCRIPTS_ROOT = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(_SCRIPTS_ROOT / "shared_utils"))
from circuit_breaker import circuit_protect  # noqa: E402
from db_manager import CTIVault  # noqa: E402

for _ex in Path(__file__).resolve().parents:
    if (_ex / "exceptions.py").is_file():
        if str(_ex) not in sys.path:
            sys.path.insert(0, str(_ex))
        break
from exceptions import DependencyUnavailableError  # noqa: E402

_SSL = ssl.create_default_context()


def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 120.0,
) -> tuple[int, str]:
    """Stdlib HTTP — no ``requests`` dependency (system python3 often lacks pip packages)."""

    def _impl() -> tuple[int, str]:
        req = Request(url, data=body, method=method.upper())
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            with urlopen(req, timeout=timeout, context=_SSL) as resp:
                code = resp.getcode()
                raw = resp.read()
        except HTTPError as e:
            code = e.code
            raw = e.read() if e.fp else b""
        except URLError as e:
            raise e
        text = raw.decode("utf-8", errors="replace")
        return int(code), text

    return circuit_protect("intelx_http", _impl)


def _post_json(url: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[int, Any]:
    data = json.dumps(payload).encode("utf-8")
    h = dict(headers)
    h.setdefault("Content-Type", "application/json")
    code, text = _http_request(url, method="POST", headers=h, body=data, timeout=120.0)
    try:
        return code, json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return code, text


def _get_json(url: str, headers: dict[str, str]) -> tuple[int, Any]:
    code, text = _http_request(url, method="GET", headers=headers, timeout=120.0)
    try:
        return code, json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        return code, text


def _read_stdin() -> tuple[str, str, str, str]:
    lines = sys.stdin.read().splitlines()
    while len(lines) < 4:
        lines.append("")
    return (lines[0].strip(), lines[1].strip(), lines[2].strip(), lines[3].strip())


def _poll_results(
    base: str,
    headers: dict[str, str],
    search_id: str,
    limit: int,
    poll_interval_s: float = 2.0,
    max_wait_s: int = 180,
) -> dict[str, Any]:
    """Poll IntelX until search completes (status != 0) or timeout."""
    qs = urlencode(
        {
            "id": search_id,
            "limit": str(limit),
            "statistics": "1",
            "previewlines": "8",
        }
    )
    url = f"{base}/intelligent/search/result?{qs}"
    deadline = time.monotonic() + max_wait_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        code, parsed = _get_json(url, headers)
        if code != 200:
            snippet = parsed if isinstance(parsed, str) else str(parsed)
            print(f"IntelX result HTTP {code}: {snippet[:500]}", flush=True)
            time.sleep(poll_interval_s)
            continue
        if not isinstance(parsed, dict):
            print("Invalid JSON from IntelX result (expected object).", flush=True)
            time.sleep(poll_interval_s)
            continue
        last = parsed

        status = last.get("status")
        records = last.get("records") or []
        # 0 = in progress, 1 = completed (may have 0 records), 2 = id invalid
        if status == 2:
            print("IntelX search id expired or invalid.", flush=True)
            return last
        if status == 0:
            print(f"IntelX search in progress… ({len(records)} partial records)", flush=True)
            time.sleep(poll_interval_s)
            continue
        return last

    print("Timed out waiting for IntelX search to finish.", flush=True)
    return last


def _upsert_records(
    vault: CTIVault,
    query: str,
    records: list[dict[str, Any]],
) -> int:
    n = 0
    for rec in records:
        systemid = str(rec.get("systemid") or "").strip()
        storageid = str(rec.get("storageid") or "").strip()
        name = str(rec.get("name") or "").strip()
        if not systemid and not storageid:
            continue
        ioc_value = f"intelx:{systemid}:{storageid}" if systemid or storageid else name[:512]
        meta = {
            "query": query,
            "record_name": name,
            "systemid": systemid,
            "storageid": storageid,
            "bucket": rec.get("bucket"),
            "date": rec.get("date"),
            "media": rec.get("media"),
            "added": rec.get("added"),
            "preview": rec.get("preview"),
        }
        vault.upsert_ioc(
            ioc_value,
            "intelx_search_hit",
            source_project="Intelx_Crawler",
            metadata=meta,
        )
        n += 1
    return n


def main() -> None:
    if len(sys.argv) >= 5:
        query = sys.argv[1].strip()
        start_d = sys.argv[2].strip()
        end_d = sys.argv[3].strip()
        limit_s = sys.argv[4].strip()
    elif len(sys.argv) <= 1:
        query, start_d, end_d, limit_s = _read_stdin()
    else:
        print(
            "Usage: intelx_native_sync.py <query> <start_date> <end_date> <limit>\n"
            "   or: pipe four lines on stdin (query, start, end, limit).",
            file=sys.stderr,
        )
        sys.exit(2)
    if not query:
        print("intelx_native_sync: first stdin line (query) is required.", file=sys.stderr)
        sys.exit(1)

    db = (os.environ.get("CTI_DB_PATH") or os.environ.get("VAULT_PATH") or "").strip()
    if not db:
        print("CTI_DB_PATH or VAULT_PATH must be set to the vault SQLite file.", file=sys.stderr)
        sys.exit(1)
    if not Path(db).is_file():
        print(f"Vault database is not a file: {db}", file=sys.stderr)
        sys.exit(1)

    api_key = (os.environ.get("INTELX_API_KEY") or "").strip()
    if not api_key:
        print(
            "INTELX_API_KEY is not set. Add your Intelligence X API key to the environment "
            "(e.g. export INTELX_API_KEY=… before launching the app, or set it in the IDE run configuration).",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        limit = int(limit_s) if limit_s.strip().isdigit() else 2000
    except ValueError:
        limit = 2000
    limit = max(1, min(limit, 10_000))

    for label, d in (("start", start_d), ("end", end_d)):
        try:
            datetime.strptime(d, "%Y-%m-%d")
        except ValueError:
            print(f"Invalid {label} date (use YYYY-MM-DD): {d!r}", file=sys.stderr)
            sys.exit(1)

    datefrom = f"{start_d} 00:00:00"
    dateto = f"{end_d} 23:59:59"
    base = (os.environ.get("INTELX_BASE_URL") or "https://2.intelx.io").rstrip("/")
    headers = {"x-key": api_key, "Content-Type": "application/json"}

    payload = {
        "term": query,
        "lookuplevel": 0,
        "maxresults": limit,
        "timeout": None,
        "datefrom": datefrom,
        "dateto": dateto,
        "sort": 2,
        "media": 0,
        "terminate": [],
    }

    print(
        f"IntelX native sync: query={query!r} window={start_d}..{end_d} limit={limit}",
        flush=True,
    )
    print(f"Using vault: {db}", flush=True)
    print(f"POST {base}/intelligent/search", flush=True)

    search_url = f"{base}/intelligent/search"
    try:
        code, start_body = _post_json(search_url, headers, payload)
    except DependencyUnavailableError as e:
        print(f"IntelX unavailable (circuit breaker): {e}", file=sys.stderr)
        sys.exit(3)
    except URLError as e:
        print(f"IntelX network error: {e}", file=sys.stderr)
        sys.exit(1)
    if code != 200:
        err_txt = start_body if isinstance(start_body, str) else json.dumps(start_body)[:800]
        print(f"IntelX search failed HTTP {code}: {err_txt}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(start_body, dict):
        print("IntelX search returned non-JSON object.", file=sys.stderr)
        sys.exit(1)

    search_id = start_body.get("id")
    if not search_id:
        print(f"No search id in response: {start_body!r}", file=sys.stderr)
        sys.exit(1)

    print(f"Search id: {search_id} — polling for results…", flush=True)
    try:
        result = _poll_results(base, headers, str(search_id), limit)
    except DependencyUnavailableError as e:
        print(f"IntelX unavailable (circuit breaker): {e}", file=sys.stderr)
        sys.exit(3)
    except URLError as e:
        print(f"IntelX network error during poll: {e}", file=sys.stderr)
        sys.exit(1)

    records = result.get("records") or []
    print(f"IntelX returned {len(records)} record(s).", flush=True)

    with CTIVault(db) as vault:
        written = _upsert_records(vault, query, records)

    print(f"Vault: upserted {written} IOC row(s) into ioc_records (source_project=Intelx_Crawler).", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()

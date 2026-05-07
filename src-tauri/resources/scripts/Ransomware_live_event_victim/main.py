#!/usr/bin/env python3
"""
Ransomware.live PRO → SQLite `ransomware_events` (native Tauri ingest).

Uses stdlib HTTP + sqlite3 only (no dotenv). Requires CTI_DB_PATH from the host.

CLI:
  python3 main.py --api-key KEY --start-date YYYY-MM-DD --end-date YYYY-MM-DD
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import ssl
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

_scripts = Path(__file__).resolve().parent.parent
if str(_scripts / "shared_utils") not in sys.path:
    sys.path.insert(0, str(_scripts / "shared_utils"))

for _root in Path(__file__).resolve().parents:
    if (_root / "exceptions.py").is_file():
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))
        break
else:
    raise ImportError("Could not locate repo root (exceptions.py).")

from circuit_breaker import circuit_protect
from exceptions import DependencyUnavailableError, NetworkError

DEFAULT_API_BASE = "https://api-pro.ransomware.live"
_SSL = ssl.create_default_context()

SOURCE_VICTIMS = "ransomware.live_victims"
SOURCE_PRESS = "ransomware.live_press"


def api_base() -> str:
    return (os.environ.get("RANSOMWARE_LIVE_API_BASE") or DEFAULT_API_BASE).strip().rstrip("/")


def parse_iso_date(raw: str) -> date | None:
    raw = raw.strip()
    if not raw:
        return None
    if "T" in raw:
        raw = raw.split("T", 1)[0]
    for fmt in ("%Y-%m-%d", "%Y.%m.%d"):
        try:
            return datetime.strptime(raw[:10], fmt).date()
        except ValueError:
            continue
    return None


def parse_calendar(s: str) -> date:
    return datetime.strptime(s.strip(), "%Y-%m-%d").date()


def iter_months_in_range(start: date, end: date):
    y, m = start.year, start.month
    ey, em = end.year, end.month
    while (y, m) <= (ey, em):
        yield y, m
        if m == 12:
            y += 1
            m = 1
        else:
            m += 1


def http_get_json(url: str, api_key: str) -> Any:
    def _do() -> Any:
        req = Request(
            url,
            headers={
                "accept": "application/json",
                "X-API-KEY": api_key.strip(),
                "User-Agent": "CTI-Command-Center/ransomware_native_sync",
            },
            method="GET",
        )
        try:
            with urlopen(req, timeout=120, context=_SSL) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise NetworkError(
                {"url": url, "http_status": e.code, "body_preview": body[:800]},
                message=f"HTTP {e.code}: {body[:800]}",
            ) from e
        except URLError as e:
            raise NetworkError(
                {"url": url, "reason": "url_error", "detail": str(e)},
                message=f"network error: {e}",
            ) from e

    return circuit_protect("ransomware_live_api", _do)


def extract_array(root: Any) -> list[Any]:
    if isinstance(root, list):
        return root
    if isinstance(root, dict):
        for key in ("victims", "data", "results", "items"):
            v = root.get(key)
            if isinstance(v, list):
                return v
    return []


def victim_attack_date(item: dict[str, Any]) -> date | None:
    raw = (item.get("attackdate") or item.get("attack_date") or "").strip()
    if not raw and item.get("discovered"):
        raw = str(item.get("discovered", "")).strip()
    return parse_iso_date(raw) if raw else None


def fetch_victims_month(base: str, api_key: str, year: int, month: int) -> list[dict[str, Any]]:
    qs = urlencode(
        {"year": str(year), "month": f"{month:02d}", "date": "attacked"}
    )
    url = f"{base}/victims/?{qs}"
    data = http_get_json(url, api_key)
    out: list[dict[str, Any]] = []
    for x in extract_array(data):
        if isinstance(x, dict):
            out.append(x)
    return out


def fetch_press_year(base: str, api_key: str, year: int) -> list[dict[str, Any]]:
    qs = urlencode({"year": str(year)})
    url = f"{base}/press/all?{qs}"
    data = http_get_json(url, api_key)
    out: list[dict[str, Any]] = []
    arr = data.get("results") if isinstance(data, dict) else None
    if isinstance(arr, list):
        for x in arr:
            if isinstance(x, dict):
                out.append(x)
    return out


def row_in_date_range(d: date | None, start: date, end: date) -> bool:
    if d is None:
        return False
    return start <= d <= end


def insert_event(
    conn: sqlite3.Connection,
    *,
    event_date: str | None,
    victim_name: str,
    attack_details: str,
    source: str,
) -> None:
    conn.execute(
        """
        INSERT INTO ransomware_events (event_date, victim_name, attack_details, source)
        VALUES (?, ?, ?, ?)
        """,
        (event_date, victim_name, attack_details, source),
    )


def ingest_victims(
    conn: sqlite3.Connection,
    base: str,
    api_key: str,
    start: date,
    end: date,
) -> int:
    n = 0
    for year, month in iter_months_in_range(start, end):
        try:
            rows = fetch_victims_month(base, api_key, year, month)
        except (DependencyUnavailableError, NetworkError) as e:
            print(f"⚠️ victims {year}-{month:02d}: {e}", flush=True)
            continue
        for item in rows:
            ad = victim_attack_date(item)
            if not row_in_date_range(ad, start, end):
                continue
            victim = (item.get("victim") or "").strip() or "(unknown)"
            ed = ad.isoformat() if ad else None
            meta = {
                "group": item.get("group"),
                "description": item.get("description"),
                "country": item.get("country"),
                "domain": item.get("domain"),
                "url": item.get("url") or item.get("post_url"),
                "activity": item.get("activity"),
                "discovered": item.get("discovered"),
                "attackdate": item.get("attackdate"),
            }
            insert_event(
                conn,
                event_date=ed,
                victim_name=victim,
                attack_details=json.dumps(meta, ensure_ascii=False),
                source=SOURCE_VICTIMS,
            )
            n += 1
        print(f"  victims API {year}-{month:02d}: processed ({len(rows)} raw rows)", flush=True)
    return n


def ingest_press(
    conn: sqlite3.Connection,
    base: str,
    api_key: str,
    start: date,
    end: date,
) -> int:
    n = 0
    years = range(start.year, end.year + 1)
    for year in years:
        try:
            rows = fetch_press_year(base, api_key, year)
        except (DependencyUnavailableError, NetworkError) as e:
            print(f"⚠️ press/{year}: {e}", flush=True)
            continue
        for item in rows:
            raw_d = item.get("date")
            if raw_d is None:
                continue
            d = parse_iso_date(str(raw_d))
            if not row_in_date_range(d, start, end):
                continue
            victim = (
                (item.get("victim") or item.get("title") or "").strip() or "(press)"
            )
            ed = d.isoformat() if d else None
            insert_event(
                conn,
                event_date=ed,
                victim_name=victim,
                attack_details=json.dumps(item, ensure_ascii=False, default=str),
                source=SOURCE_PRESS,
            )
            n += 1
        print(f"  press/{year}: matched rows in range ({len(rows)} raw)", flush=True)
    return n


def main() -> int:
    p = argparse.ArgumentParser(description="Ransomware.live → vault.ransomware_events")
    p.add_argument("--api-key", required=True, help="PRO API key (X-API-KEY)")
    p.add_argument("--start-date", required=True, help="YYYY-MM-DD inclusive")
    p.add_argument("--end-date", required=True, help="YYYY-MM-DD inclusive")
    args = p.parse_args()

    api_key = args.api_key.strip()
    if not api_key:
        print("--api-key must be non-empty.", file=sys.stderr)
        return 1

    try:
        start = parse_calendar(args.start_date)
        end = parse_calendar(args.end_date)
    except ValueError as e:
        print(f"Invalid date (use YYYY-MM-DD): {e}", file=sys.stderr)
        return 1

    if end < start:
        print("end-date must be >= start-date.", file=sys.stderr)
        return 1

    db_path = (os.environ.get("CTI_DB_PATH") or os.environ.get("VAULT_PATH") or "").strip()
    if not db_path:
        print("CTI_DB_PATH must be set.", file=sys.stderr)
        return 1

    base = api_base()
    print(f"API base: {base}", flush=True)
    print(f"Range: {start.isoformat()} … {end.isoformat()} (vault: {db_path})", flush=True)

    conn = sqlite3.connect(db_path)
    try:
        nv = ingest_victims(conn, base, api_key, start, end)
        np = ingest_press(conn, base, api_key, start, end)
        conn.commit()
        print(
            f"Done. Inserted {nv} victim-derived row(s), {np} press row(s) into ransomware_events.",
            flush=True,
        )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

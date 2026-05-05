#!/usr/bin/env python3
"""
Native MAC stealer (RUMARK) ingest: scrape onion logs and upsert into CTI vault `ioc_records`.

Requires:
  CTI_DB_PATH — SQLite vault path (set by Tauri when spawning the ingestion sidecar).
  Tor — RequestsTor / SOCKS for `.onion` (see requests_tor).

CLI:
  python3 main.py --cookie '…' --domains 'a.com,b.com'
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from bs4 import BeautifulSoup
from requests_tor import RequestsTor


SOURCE_PROJECT = "Compromised_user_Mac"
IOC_TYPE = "stealer_log"


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if not k:
            continue
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


def _merge_dotenv_into_environ() -> None:
    proj = Path(__file__).resolve().parent
    merged: dict[str, str] = {}
    merged.update(_parse_env_file(proj.parent / ".env"))
    merged.update(_parse_env_file(proj / ".env"))
    for k, v in merged.items():
        if k not in os.environ:
            os.environ[k] = v


def normalize_date_size(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    date = raw[:10]
    size = raw[10:]
    return date, size


# Headers for requests (onion host matches legacy script).
hds = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
    "Cookie": "",
    "Host": "rumarkstror5mvgzzodqizofkji3fna7lndfylmzeisj5tamqnwnr4ad.onion",
    "Priority": "u=0, i",
    "Referer": "http://rumarkstror5mvgzzodqizofkji3fna7lndfylmzeisj5tamqnwnr4ad.onion/logs",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": "1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0"
    ),
}

rt = RequestsTor()


def scrape_domain(target_domain: str) -> list[dict]:
    """Scrape one domain query; return rows ready for `ioc_records` (one row per target link)."""
    out: list[dict] = []
    if isinstance(target_domain, list):
        target_domain = ",".join(target_domain)
    url = (
        "http://rumarkstror5mvgzzodqizofkji3fna7lndfylmzeisj5tamqnwnr4ad.onion/logs?"
        "stealer=&system=&country=&state=&city=&zip=&page=1&perpage=100&isp=&outlook=&"
        f"links={target_domain}&withcookies=0&pricesort=&pricerange=4;15&vendor=&mask=&email=&cookies=&emaildom="
    )
    resp = rt.get(url, headers=hds)

    if resp.status_code != 200:
        print(f"⚠️ unable to get page. status code: {resp.status_code}", flush=True)
        return out

    doc = BeautifulSoup(resp.text, "lxml")
    logs_contents = doc.select("table tr")
    for logs_array in logs_contents[1:]:
        logs = logs_array.select("td")
        if len(logs) < 7:
            continue
        other_links: list[str] = []
        target_links: list[str] = []
        seen_target_links: set[str] = set()
        try:
            for link in logs[2].select("a, span a"):
                link_text = link.text.strip()
                if link_text and link_text != "Show more...":
                    if target_domain in link_text:
                        if link_text not in seen_target_links:
                            target_links.append(link_text)
                            seen_target_links.add(link_text)
                    else:
                        other_links.append(link_text)
        except Exception:
            print("✅ unable to parse row cells.", flush=True)
            continue

        if len(target_links) < 1:
            continue

        try:
            date, size = normalize_date_size(logs[6].text.strip())
        except (IndexError, Exception):
            continue

        stealer = logs[0].text.strip()
        for tl in target_links:
            out.append(
                {
                    "stealer": stealer,
                    "target_link": tl,
                    "other_links": other_links,
                    "date": date,
                    "size": size,
                }
            )
    return out


def upsert_ioc_rows(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """Match Rust `insert_mac_rows` ON CONFLICT behavior (vault must already contain `ioc_records`)."""
    if not rows:
        return 0
    n = 0
    cur = conn.cursor()
    sql = """
            INSERT INTO ioc_records (ioc_value, ioc_type, first_seen, last_seen, source_project, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET
              last_seen = excluded.last_seen,
              metadata = COALESCE(excluded.metadata, ioc_records.metadata),
              source_project = CASE
                WHEN excluded.source_project IS NOT NULL AND TRIM(COALESCE(excluded.source_project, '')) != ''
                THEN excluded.source_project
                ELSE ioc_records.source_project
              END
            """
    for row in rows:
        ioc_value = (row.get("target_link") or "").strip()
        if not ioc_value:
            continue
        first_seen = (row.get("date") or "").strip() or None
        last_seen = first_seen
        meta = json.dumps(
            {
                "stealer": row.get("stealer", ""),
                "target_link": ioc_value,
                "other_links": row.get("other_links") or [],
                "date": row.get("date", ""),
                "size": row.get("size", ""),
                "ingest": "mac_stealer",
            },
            ensure_ascii=False,
        )
        cur.execute(
            sql,
            (ioc_value, IOC_TYPE, first_seen, last_seen, SOURCE_PROJECT, meta),
        )
        n += 1
    return n


def main() -> int:
    parser = argparse.ArgumentParser(description="RUMARK MAC stealer → vault ioc_records")
    parser.add_argument("--cookie", required=True, help="Session cookie header value")
    parser.add_argument(
        "--domains",
        required=True,
        help="Comma-separated domains to query (e.g. example.com,foo.org)",
    )
    args = parser.parse_args()

    _merge_dotenv_into_environ()

    db_path = (os.environ.get("CTI_DB_PATH") or os.environ.get("VAULT_PATH") or "").strip()
    if not db_path:
        print("CTI_DB_PATH (or VAULT_PATH) must be set to the vault SQLite file.", file=sys.stderr)
        return 1
    if not Path(db_path).is_file():
        print(f"Vault database is not a file: {db_path}", file=sys.stderr)
        return 1

    cookie_value = args.cookie.strip()
    if not cookie_value:
        print("--cookie must be non-empty.", file=sys.stderr)
        return 1

    domains = [d.strip().lower() for d in args.domains.split(",") if d.strip()]
    if not domains:
        print("--domains must list at least one domain.", file=sys.stderr)
        return 1

    hds["Cookie"] = cookie_value

    print(f"Domains: {domains}", flush=True)
    print(f"Using vault: {db_path}", flush=True)

    conn = sqlite3.connect(db_path)
    try:
        total_upserts = 0
        for domain in domains:
            print(f"Scraping {domain!r}…", flush=True)
            rows = scrape_domain(domain)
            n = upsert_ioc_rows(conn, rows)
            total_upserts += n
            print(f"  → upserted {n} IOC row(s) for this domain.", flush=True)
        conn.commit()
        print(
            f"Done. Total IOC upserts (ioc_type={IOC_TYPE!r}, source={SOURCE_PROJECT!r}): {total_upserts}",
            flush=True,
        )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

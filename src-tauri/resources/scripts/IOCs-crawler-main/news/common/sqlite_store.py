"""
Persist crawler rows into the CTI vault SQLite `ioc_news` table (replaces RethinkDB BW_crawler.news).

Requires **CTI_DB_PATH** (absolute path to `cti_vault.db`).
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _db_path() -> Path:
    raw = (os.environ.get("CTI_DB_PATH") or os.environ.get("VAULT_PATH") or "").strip()
    if not raw:
        raise RuntimeError("CTI_DB_PATH (or VAULT_PATH) must be set to the vault SQLite file.")
    return Path(raw).expanduser().resolve()


def _ser_field(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, (list, tuple, dict)):
        return json.dumps(x, ensure_ascii=False)[:8000]
    return str(x)[:8000]


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ioc_news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT,
            source TEXT,
            article_ts INTEGER,
            iocs TEXT,
            mitre TEXT,
            content_preview TEXT,
            ingested_at TEXT NOT NULL,
            created_at TEXT
        );
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_ioc_news_url ON ioc_news(url)"
    )
    # Older vaults may lack created_at — best-effort add for search UI.
    cur = conn.execute("PRAGMA table_info(ioc_news)")
    cols = {row[1] for row in cur.fetchall()}
    if "created_at" not in cols:
        conn.execute("ALTER TABLE ioc_news ADD COLUMN created_at TEXT")


def upsert_news_article(data: dict) -> None:
    """Upsert one article document (same shape as legacy Rethink `news` rows)."""
    url = (data.get("url") or "").strip()
    if not url:
        return

    db_path = _db_path()
    title = (data.get("title") or "")[:2000]
    src = (data.get("source") or "")[:500]
    tm = data.get("tm")
    try:
        article_ts = int(tm) if tm is not None else None
    except (TypeError, ValueError):
        article_ts = None
    content = data.get("content") or ""
    preview = str(content)[:4000]
    iocs_s = _ser_field(data.get("IOCs"))
    mitre_s = _ser_field(data.get("MITRE"))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = sqlite3.connect(str(db_path))
    try:
        _ensure_schema(conn)
        conn.execute(
            """
            INSERT INTO ioc_news (url, title, source, article_ts, iocs, mitre, content_preview, ingested_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(url) DO UPDATE SET
              title = excluded.title,
              source = excluded.source,
              article_ts = excluded.article_ts,
              iocs = excluded.iocs,
              mitre = excluded.mitre,
              content_preview = excluded.content_preview,
              ingested_at = excluded.ingested_at,
              created_at = excluded.created_at
            """,
            (url, title, src, article_ts, iocs_s, mitre_s, preview, now, now),
        )
        conn.commit()
    finally:
        conn.close()

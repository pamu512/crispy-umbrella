"""
CTI SQLite vault: path resolution, WAL pragmas on connect, upserts, and agent-friendly reads.

Schema creation and migrations are implemented only in Rust (``src-tauri/src/vault_db.rs``).
Open the vault through the Tauri host or any code path that calls ``initialize_vault`` / ``open_vault``
before using this module against a new database file.

Resolution order for the database file (never uses the repo/dev tree unless you pass an explicit path):
1. ``CTI_DB_PATH`` — absolute path to ``cti_vault.db`` (set by the Tauri host for child processes).
2. ``CTI_WRITABLE_ROOT`` / ``CTI_APP_DATA_ROOT`` — directory containing ``cti_vault.db`` or the ``cti-app`` folder.
3. Default: ``<Tauri app_data_dir>/<identifier>/cti-app/cti_vault.db`` (same layout as Rust ``writable_cti_root``).

Override the bundle id with ``CTI_APP_IDENTIFIER`` (default matches ``tauri.conf.json`` ``identifier``).
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_cvss_base_score(s: str) -> float | None:
    """Extract a leading decimal from CVSS-like strings (mirrors Rust ``vault_db::parse_cvss_base_score``)."""
    t = s.strip()
    num = "".join(c for c in t if c.isascii() and (c.isdigit() or c == "."))
    if not num:
        return None
    try:
        return float(num)
    except ValueError:
        return None


def _tauri_app_data_dir(identifier: str) -> Path:
    """Mirror Tauri ``app_data_dir()`` + join ``cti-app`` in Rust."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", "").strip()
        if base:
            return Path(base) / identifier
        return Path.home() / "AppData" / "Roaming" / identifier
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / identifier
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return Path(xdg) / identifier
    return Path.home() / ".local" / "share" / identifier


def resolve_vault_db_path(explicit: Path | str | None = None) -> Path:
    """
    Resolve ``cti_vault.db`` to the user's application data area, not the current working tree.

    ``explicit`` wins when provided. Otherwise env vars, then Tauri-style AppData.
    """
    if explicit is not None:
        p = Path(explicit).expanduser().resolve()
        if p.is_dir():
            return (p / "cti_vault.db").resolve()
        return p.resolve()

    raw = (os.environ.get("CTI_DB_PATH") or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()

    root = (os.environ.get("CTI_WRITABLE_ROOT") or os.environ.get("CTI_APP_DATA_ROOT") or "").strip()
    if root:
        r = Path(root).expanduser().resolve()
        if r.suffix.lower() == ".db":
            return r.resolve()
        if r.name == "cti-app":
            return (r / "cti_vault.db").resolve()
        return (r / "cti-app" / "cti_vault.db").resolve()

    ident = (os.environ.get("CTI_APP_IDENTIFIER") or "com.pamu512.crispyumbrella").strip()
    return (_tauri_app_data_dir(ident) / "cti-app" / "cti_vault.db").resolve()


_SELECT_ONLY = re.compile(r"^\s*select\s", re.IGNORECASE | re.DOTALL)


def _assert_select_only(sql: str) -> None:
    s = sql.strip()
    if not s:
        raise ValueError("Empty query")
    if ";" in s.rstrip(";"):
        raise ValueError("Multiple statements are not allowed")
    if not _SELECT_ONLY.match(s):
        raise ValueError("query_vault only allows a single SELECT statement")
    forbidden = (
        " insert ",
        " update ",
        " delete ",
        " drop ",
        " alter ",
        " create ",
        " attach ",
        " detach ",
        " pragma ",
    )
    lower = f" {s.lower()} "
    for tok in forbidden:
        if tok in lower:
            raise ValueError(f"Disallowed token in read-only query: {tok.strip()}")


class CTIVault:
    """SQLite CTI vault: WAL + upserts + read helpers.

    DDL and migrations are owned by Rust (``vault_db::initialize_vault``). Open the database from
    the Tauri host (or any path that runs those migrations) before ingesting; this class does not
    create tables.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = resolve_vault_db_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA busy_timeout=30000;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> CTIVault:
        _ = self.connection
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def upsert_cve(
        self,
        cve_id: str,
        *,
        severity_score: float | None = None,
        published_date: str | None = None,
        updated_at: str | None = None,
        metadata: Mapping[str, Any] | str | None = None,
    ) -> None:
        """Insert or replace one CVE row (canonical ``cve_data`` schema)."""
        cid = cve_id.strip()
        if not cid:
            raise ValueError("cve_id is required")
        meta_str: str | None
        if metadata is None:
            meta_str = None
        elif isinstance(metadata, str):
            meta_str = metadata
        else:
            meta_str = json.dumps(metadata, ensure_ascii=False)
        now = _utc_iso()
        pub = (published_date or "").strip()
        upd = (updated_at or now).strip() or now
        c = self.connection
        c.execute(
            """
            INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                severity_score = COALESCE(excluded.severity_score, cve_data.severity_score),
                published_date = CASE
                    WHEN excluded.published_date IS NOT NULL AND TRIM(excluded.published_date) != ''
                    THEN excluded.published_date
                    ELSE cve_data.published_date
                END,
                updated_at = excluded.updated_at,
                metadata = COALESCE(excluded.metadata, cve_data.metadata)
            """,
            (cid, severity_score, pub, upd, meta_str),
        )
        c.commit()

    def upsert_asm(
        self,
        asset_target: str,
        *,
        asset_type: str | None = None,
        last_scan_at: str | None = None,
        status: str | None = None,
        metadata: Mapping[str, Any] | str | None = None,
    ) -> None:
        """Insert or update one ASM row."""
        at = asset_target.strip()
        if not at:
            raise ValueError("asset_target is required")
        meta_str: str | None
        if metadata is None:
            meta_str = None
        elif isinstance(metadata, str):
            meta_str = metadata
        else:
            meta_str = json.dumps(metadata, ensure_ascii=False)
        ls = (last_scan_at or _utc_iso()).strip() or _utc_iso()
        st = (status or "active").strip() or "active"
        typ = (asset_type or "unknown").strip() or "unknown"
        c = self.connection
        c.execute(
            """
            INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(asset_target) DO UPDATE SET
                asset_type = COALESCE(NULLIF(TRIM(excluded.asset_type), ''), asm_assets.asset_type),
                last_scan_at = excluded.last_scan_at,
                status = COALESCE(NULLIF(TRIM(excluded.status), ''), asm_assets.status),
                metadata = COALESCE(excluded.metadata, asm_assets.metadata)
            """,
            (at, typ, ls, st, meta_str),
        )
        c.commit()

    def upsert_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        *,
        first_seen: str | None = None,
        last_seen: str | None = None,
        source_project: str | None = None,
        metadata: Mapping[str, Any] | str | None = None,
    ) -> None:
        """
        Insert or update one IOC row.

        On conflict: ``first_seen`` is preserved; ``last_seen`` and ``metadata`` are updated.
        ``source_project`` is updated when the caller supplies a non-empty value.
        """
        v = ioc_value.strip()
        t = ioc_type.strip()
        if not v or not t:
            raise ValueError("ioc_value and ioc_type are required")

        now = _utc_iso()
        fs = (first_seen or now).strip() or now
        ls = (last_seen or now).strip() or now
        meta_str: str | None
        if metadata is None:
            meta_str = None
        elif isinstance(metadata, str):
            meta_str = metadata
        else:
            meta_str = json.dumps(metadata, ensure_ascii=False)

        c = self.connection
        c.execute(
            """
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
            """,
            (v, t, fs, ls, source_project, meta_str),
        )
        c.commit()

    def batch_upsert_iocs(
        self,
        rows: list[tuple[str, str, str, str, str | None, str | None]],
    ) -> None:
        """
        Insert or update many IOC rows in one transaction (``executemany``).

        Each tuple: ``(ioc_value, ioc_type, first_seen, last_seen, source_project, metadata_json)``.
        """
        if not rows:
            return
        now = _utc_iso()
        cleaned: list[tuple[str, str, str, str, str | None, str | None]] = []
        for tup in rows:
            v, t, fs, ls, sp, meta = tup
            v2 = (v or "").strip()
            t2 = (t or "").strip()
            if not v2 or not t2:
                continue
            fs2 = ((fs or "").strip() or now)
            ls2 = ((ls or "").strip() or now)
            cleaned.append((v2, t2, fs2, ls2, sp, meta))
        if not cleaned:
            return
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
        c = self.connection
        c.execute("BEGIN IMMEDIATE")
        try:
            c.executemany(sql, cleaned)
            c.commit()
        except Exception:
            c.rollback()
            raise

    def batch_upsert_cves(
        self,
        rows: list[tuple[str, float | None, str, str, str | None]],
    ) -> None:
        """
        Each tuple: ``(cve_id, severity_score, published_date, updated_at, metadata_json)``.
        """
        if not rows:
            return
        now = _utc_iso()
        cleaned: list[tuple[str, float | None, str, str, str | None]] = []
        for tup in rows:
            cid, sev, pub, upd, meta = tup
            c2 = (cid or "").strip()
            if not c2:
                continue
            pub2 = (pub or "").strip()
            upd2 = (upd or "").strip() or now
            cleaned.append((c2, sev, pub2, upd2, meta))
        if not cleaned:
            return
        sql = """
            INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                severity_score = COALESCE(excluded.severity_score, cve_data.severity_score),
                published_date = CASE
                    WHEN excluded.published_date IS NOT NULL AND TRIM(excluded.published_date) != ''
                    THEN excluded.published_date
                    ELSE cve_data.published_date
                END,
                updated_at = excluded.updated_at,
                metadata = COALESCE(excluded.metadata, cve_data.metadata)
            """
        c = self.connection
        c.execute("BEGIN IMMEDIATE")
        try:
            c.executemany(sql, cleaned)
            c.commit()
        except Exception:
            c.rollback()
            raise

    def batch_upsert_asm_assets(
        self,
        rows: list[tuple[str, str, str, str, str | None]],
    ) -> None:
        """
        Each tuple: ``(asset_target, asset_type, last_scan_at, status, metadata_json)``.
        """
        if not rows:
            return
        now = _utc_iso()
        cleaned: list[tuple[str, str, str, str, str | None]] = []
        for tup in rows:
            at, typ, ls, st, meta = tup
            a2 = (at or "").strip()
            if not a2:
                continue
            typ2 = ((typ or "").strip() or "unknown")
            ls2 = ((ls or "").strip() or now)
            st2 = ((st or "").strip() or "active")
            cleaned.append((a2, typ2, ls2, st2, meta))
        if not cleaned:
            return
        sql = """
            INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(asset_target) DO UPDATE SET
                asset_type = COALESCE(NULLIF(TRIM(excluded.asset_type), ''), asm_assets.asset_type),
                last_scan_at = excluded.last_scan_at,
                status = COALESCE(NULLIF(TRIM(excluded.status), ''), asm_assets.status),
                metadata = COALESCE(excluded.metadata, asm_assets.metadata)
            """
        c = self.connection
        c.execute("BEGIN IMMEDIATE")
        try:
            c.executemany(sql, cleaned)
            c.commit()
        except Exception:
            c.rollback()
            raise

    def query_vault(self, query_string: str) -> list[dict[str, Any]]:
        """Run a single read-only ``SELECT``; returns list of row dicts."""
        _assert_select_only(query_string)
        cur = self.connection.execute(query_string)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def get_recent_intelligence(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Newest activity across ``cve_data``, ``ioc_records``, and ``asm_assets`` for Threat Pulse-style UIs.

        Each row: ``feed_type``, ``headline``, ``sort_ts``, ``payload`` (metadata JSON string or null).
        """
        lim = max(1, min(int(limit), 500))
        sql = f"""
        SELECT * FROM (
            SELECT
                'cve' AS feed_type,
                cve_id AS headline,
                COALESCE(
                    NULLIF(TRIM(updated_at), ''),
                    NULLIF(TRIM(published_date), ''),
                    '1970-01-01T00:00:00Z'
                ) AS sort_ts,
                metadata AS payload
            FROM cve_data
            UNION ALL
            SELECT
                'ioc' AS feed_type,
                ioc_value AS headline,
                COALESCE(
                    NULLIF(TRIM(last_seen), ''),
                    NULLIF(TRIM(first_seen), ''),
                    '1970-01-01T00:00:00Z'
                ) AS sort_ts,
                metadata AS payload
            FROM ioc_records
            UNION ALL
            SELECT
                'asm' AS feed_type,
                asset_target AS headline,
                COALESCE(
                    NULLIF(TRIM(last_scan_at), ''),
                    '1970-01-01T00:00:00Z'
                ) AS sort_ts,
                metadata AS payload
            FROM asm_assets
        )
        ORDER BY sort_ts DESC
        LIMIT {lim}
        """
        return self.query_vault(sql)

    def get_vault_meta(self, key: str) -> str | None:
        cur = self.connection.execute(
            "SELECT value FROM vault_meta WHERE key = ? LIMIT 1", (key,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return str(row[0])

    def set_vault_meta(self, key: str, value: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value)
        )
        self.connection.commit()


def open_cti_vault() -> sqlite3.Connection:
    """Open resolved path with the same PRAGMAs as ``CTIVault.connection`` (no DDL)."""
    v = CTIVault()
    _ = v.connection
    return v.connection

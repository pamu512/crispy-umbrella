#!/usr/bin/env python3
"""
Push ASM subdomain findings from the ASM Postgres DB into the Command Center vault
(`asm_assets` in ``cti_vault.db``) using the **canonical** schema:

``asset_target``, ``asset_type``, ``last_scan_at``, ``status``, ``metadata`` (JSON).

Environment (same as Command Center / ingestor):

- ``CTI_DB_PATH`` — absolute path to ``cti_vault.db`` (preferred when the host sets it).
- ``CTI_WORKSPACE_PATH`` — workspace root; vault is resolved as
  ``<workspace>/cti-app/cti_vault.db`` if present, else ``<workspace>/cti_vault.db``.

Postgres: ``DATABASE_URL`` / ``DB_*`` from ``.env``. Postgres must be reachable.

Stdout: prints ``INGESTED:<n>`` for the last run row count.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(ts) -> str:
    if ts is None:
        return _utc_iso()
    if hasattr(ts, "isoformat"):
        t = ts
        if getattr(t, "tzinfo", None) is None:
            t = t.replace(tzinfo=timezone.utc)
        return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(ts)


def resolve_cti_vault_path() -> Path:
    raw = (os.environ.get("CTI_DB_PATH") or "").strip()
    if raw:
        p = Path(raw).expanduser().resolve()
        if p.is_dir():
            return (p / "cti_vault.db").resolve()
        return p
    wp = (os.environ.get("CTI_WORKSPACE_PATH") or "").strip()
    if not wp:
        raise SystemExit(
            "ERROR: Set CTI_DB_PATH or CTI_WORKSPACE_PATH (workspace root used by Command Center)."
        )
    root = Path(wp).expanduser().resolve()
    for candidate in (root / "cti-app" / "cti_vault.db", root / "cti_vault.db"):
        if candidate.is_file():
            return candidate.resolve()
    # Default layout matches Tauri writable root
    out = root / "cti-app" / "cti_vault.db"
    out.parent.mkdir(parents=True, exist_ok=True)
    return out.resolve()


def _ensure_asm_schema(cur: sqlite3.Cursor) -> None:
    """
    Idempotent DDL aligned with Command Center ``db_manager.CTIVault``.

    The vault primary key is ``asset_target`` (not a legacy ``asset`` column). Any old
    local script that created ``asm_assets(asset, ...)`` conflicts with this schema;
    use this exporter only against a vault created by the app or after aligning DDL.
    """
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS asm_assets (
            asset_target TEXT PRIMARY KEY NOT NULL,
            asset_type TEXT,
            last_scan_at TEXT,
            status TEXT,
            metadata TEXT
        );
        """
    )


def main() -> int:
    try:
        vault = resolve_cti_vault_path()
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 1

    try:
        from sqlalchemy.orm import Session

        from src.database.models import Domain, Scan, ScanStatus, SubdomainData
        from src.database.session import SessionLocal
    except Exception as e:
        print(f"ERROR: ASM imports failed: {e}", file=sys.stderr)
        return 1

    session: Session = SessionLocal()
    try:
        rows = (
            session.query(SubdomainData, Scan, Domain)
            .join(Scan, SubdomainData.scan_id == Scan.id)
            .join(Domain, Scan.domain_id == Domain.id)
            .filter(Scan.status == ScanStatus.completed)
            .order_by(SubdomainData.id.desc())
            .limit(12_000)
            .all()
        )
    except Exception as e:
        print(
            f"ERROR: Postgres query failed (is the DB up? Try DB_HOST=127.0.0.1 if using Docker port mapping): {e}",
            file=sys.stderr,
        )
        session.close()
        return 1

    n = 0
    batch: list[tuple[str, str, str, str, str]] = []

    try:
        for sd, scan, dom in rows:
            asset_target = f"{dom.domain_name} → {sd.host}"
            parts = [
                f"record={sd.type}",
                f"ip={sd.ip or 'N/A'}",
            ]
            if getattr(sd, "asn", None) and sd.asn not in (None, "", "N/A"):
                parts.append(f"asn={sd.asn}")
            up = sd.unusual_ports
            if isinstance(up, list) and up:
                parts.append("unusual_ports=" + ",".join(str(x) for x in up)[:180])
            elif up not in (None, "", "N/A"):
                parts.append(f"unusual_ports={str(up)[:180]}")
            ss = sd.sensitive_subdomains
            if isinstance(ss, list) and ss:
                parts.append("sensitive=" + ",".join(str(x) for x in ss)[:120])
            elif ss not in (None, "", "N/A"):
                parts.append(f"sensitive={str(ss)[:120]}")
            cv = sd.cve
            if isinstance(cv, list) and cv:
                parts.append("cve=" + ",".join(str(x) for x in cv)[:160])
            summary = " | ".join(parts)[:920]
            last_scan = _iso(sd.created_at or scan.scan_timestamp)
            asset_type = (str(getattr(sd, "type", None) or "subdomain").strip() or "subdomain")
            meta = {
                "domain": dom.domain_name,
                "host": sd.host,
                "ip": sd.ip,
                "summary": summary,
                "source": "ASM-fetch export_asm_to_cti_vault",
            }
            meta_str = json.dumps(meta, ensure_ascii=False)
            batch.append((asset_target, asset_type, last_scan, "active", meta_str))

        sql = """
            INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(asset_target) DO UPDATE SET
                asset_type = COALESCE(NULLIF(TRIM(excluded.asset_type), ''), asm_assets.asset_type),
                last_scan_at = excluded.last_scan_at,
                status = COALESCE(NULLIF(TRIM(excluded.status), ''), asm_assets.status),
                metadata = COALESCE(excluded.metadata, asm_assets.metadata)
            """

        con = sqlite3.connect(str(vault), timeout=30.0)
        try:
            cur = con.cursor()
            con.execute("PRAGMA journal_mode=WAL;")
            con.execute("PRAGMA synchronous=NORMAL;")
            con.execute("PRAGMA busy_timeout=5000;")
            _ensure_asm_schema(cur)
            con.commit()
            if batch:
                con.execute("BEGIN IMMEDIATE")
                cur.executemany(sql, batch)
                con.commit()
                n = len(batch)
        finally:
            con.close()
    except sqlite3.Error as e:
        print(f"ERROR: SQLite vault failed ({vault}): {e}", file=sys.stderr)
        return 1
    finally:
        session.close()

    print(f"INGESTED:{n}")
    if n == 0:
        print(
            "NOTE: No rows from completed scans. Run scans via the API "
            "(POST /scans/instant) while Postgres has data, then re-run this export.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

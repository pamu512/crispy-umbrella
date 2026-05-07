"""
Idempotency: repeating the same write/update with identical payloads must not drift state.

- ``CTIVault.batch_upsert_*`` return ``None``; the observable contract is unchanged DB rows.
- ``CSVIngestor.ingest_csv`` returns a row count; repeating on the same file must yield the same
  count and an identical persisted snapshot.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from db_manager import CTIVault
from ingestor import CSVIngestor


def _create_minimal_ioc_vault(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_records (
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                source_project TEXT,
                metadata TEXT,
                PRIMARY KEY (ioc_value, ioc_type)
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def _create_minimal_cve_vault(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_data (
                cve_id TEXT PRIMARY KEY,
                severity_score REAL,
                published_date TEXT,
                updated_at TEXT,
                metadata TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def _create_minimal_asm_vault(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS asm_assets (
                asset_target TEXT PRIMARY KEY,
                asset_type TEXT,
                last_scan_at TEXT,
                status TEXT,
                metadata TEXT
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def _ioc_rows_snapshot(db_path: Path) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            """
            SELECT ioc_value, ioc_type, first_seen, last_seen, source_project, metadata
            FROM ioc_records
            ORDER BY ioc_value, ioc_type
            """
        )
        return [tuple(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _cve_rows_snapshot(db_path: Path) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            """
            SELECT cve_id, severity_score, published_date, updated_at, metadata
            FROM cve_data
            ORDER BY cve_id
            """
        )
        return [tuple(r) for r in cur.fetchall()]
    finally:
        conn.close()


def _asm_rows_snapshot(db_path: Path) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            """
            SELECT asset_target, asset_type, last_scan_at, status, metadata
            FROM asm_assets
            ORDER BY asset_target
            """
        )
        return [tuple(r) for r in cur.fetchall()]
    finally:
        conn.close()


@pytest.mark.integration
def test_batch_upsert_iocs_twice_identical_payload_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    _create_minimal_ioc_vault(db_path)
    rows = [
        (
            "203.0.113.5",
            "ipv4",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
            "IOC_Test",
            '{"source_csv": "a.csv", "k": "v"}',
        ),
    ]

    vault = CTIVault(db_path)
    out1 = vault.batch_upsert_iocs(rows)
    snap1 = _ioc_rows_snapshot(db_path)

    out2 = vault.batch_upsert_iocs(rows)
    snap2 = _ioc_rows_snapshot(db_path)

    assert out1 is out2 is None
    assert snap1 == snap2


@pytest.mark.integration
def test_batch_upsert_cves_twice_identical_payload_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    _create_minimal_cve_vault(db_path)
    rows = [
        ("CVE-2026-0001", 9.8, "2026-01-01", "2026-01-02", '{"note": "x"}'),
    ]

    vault = CTIVault(db_path)
    out1 = vault.batch_upsert_cves(rows)
    snap1 = _cve_rows_snapshot(db_path)

    out2 = vault.batch_upsert_cves(rows)
    snap2 = _cve_rows_snapshot(db_path)

    assert out1 is out2 is None
    assert snap1 == snap2


@pytest.mark.integration
def test_batch_upsert_asm_twice_identical_payload_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    _create_minimal_asm_vault(db_path)
    rows = [
        (
            "203.0.113.10",
            "host_ip",
            "2026-01-01T00:00:00Z",
            "active",
            '{"source_csv": "asm.csv"}',
        ),
    ]

    vault = CTIVault(db_path)
    out1 = vault.batch_upsert_asm_assets(rows)
    snap1 = _asm_rows_snapshot(db_path)

    out2 = vault.batch_upsert_asm_assets(rows)
    snap2 = _asm_rows_snapshot(db_path)

    assert out1 is out2 is None
    assert snap1 == snap2


@pytest.mark.integration
def test_ingest_csv_twice_same_file_idempotent(tmp_path: Path) -> None:
    """End-to-end ingest: second pass matches first row count and persisted IOC rows."""
    db_path = tmp_path / "vault.db"
    _create_minimal_ioc_vault(db_path)

    # Single CSV under tmp (no ``workspace_root``): avoids post-ingest move to
    # ``<project>/output/archived_logs/``, which would remove the path before the second call.
    csv_path = tmp_path / "ioc_batch.csv"
    csv_path.write_text(
        "indicator,ioc_type,first_seen,last_seen\n"
        "203.0.113.7,ipv4,2026-01-01T00:00:00Z,2026-01-02T00:00:00Z\n",
        encoding="utf-8",
    )

    vault = CTIVault(db_path)
    ingestor = CSVIngestor(vault)

    n1 = ingestor.ingest_csv(csv_path, project_folder="IOCs-crawler-main")
    snap1 = _ioc_rows_snapshot(db_path)

    n2 = ingestor.ingest_csv(csv_path, project_folder="IOCs-crawler-main")
    snap2 = _ioc_rows_snapshot(db_path)

    assert n1 == n2
    assert snap1 == snap2

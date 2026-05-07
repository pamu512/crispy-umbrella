"""
Integration tests: interrupted state transitions must not leave the vault wedged.

Simulates abrupt failure at ``_commit_batch_transaction`` (e.g. power loss) for
``CTIVault`` multi-row batch upserts. This targets the same hook as production
(``db_manager._commit_batch_transaction``) because ``sqlite3.Connection.commit``
is not patchable on Python 3.14+.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

import db_manager
from db_manager import CTIVault


def _make_flaky_batch_commit() -> Callable[[sqlite3.Connection], None]:
    real = db_manager._commit_batch_transaction
    state = {"n": 0}

    def _flaky(conn: sqlite3.Connection) -> None:
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("simulated commit failure (power loss)")
        real(conn)

    return _flaky


def _create_minimal_ioc_vault(db_path: Path) -> None:
    """Minimal schema aligned with Rust ``ensure_ioc_records`` (vault_db.rs)."""
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


def _ioc_count(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM ioc_records").fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


@pytest.mark.integration
def test_batch_ioc_upsert_survives_commit_interrupt_no_partial_rows_not_locked(
    tmp_path: Path,
) -> None:
    """
    If the batch commit step fails after ``executemany`` (simulated power loss),
    ``rollback`` must leave **no** partial rows, and a later batch must succeed
    (connection not left locked in a half-finished transaction).
    """
    db_path = tmp_path / "cti_vault.db"
    _create_minimal_ioc_vault(db_path)

    vault = CTIVault(db_path)
    rows = [
        (
            "192.0.2.10",
            "ipv4",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "test_proj",
            None,
        ),
        (
            "evil.example",
            "domain",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            "test_proj",
            None,
        ),
    ]

    with patch.object(db_manager, "_commit_batch_transaction", _make_flaky_batch_commit()):
        with pytest.raises(OSError, match="simulated commit"):
            vault.batch_upsert_iocs(rows)

    assert _ioc_count(db_path) == 0, "partial rows must not persist after rollback"

    conn = vault.connection
    if hasattr(conn, "in_transaction"):
        assert not conn.in_transaction, "connection must not be stuck mid-transaction"

    vault.batch_upsert_iocs(rows)
    assert _ioc_count(db_path) == 2, "vault must accept work after interrupted batch"


@pytest.mark.integration
def test_batch_cve_upsert_survives_commit_interrupt_no_partial_rows(
    tmp_path: Path,
) -> None:
    """Same contract for ``batch_upsert_cves`` (CVE batch transaction)."""
    db_path = tmp_path / "cve_vault.db"
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

    vault = CTIVault(db_path)
    rows = [
        ("CVE-2026-0001", 9.8, "2026-01-01", "2026-01-02", None),
        ("CVE-2026-0002", 7.2, "2026-01-03", "2026-01-04", None),
    ]

    with patch.object(db_manager, "_commit_batch_transaction", _make_flaky_batch_commit()):
        with pytest.raises(OSError):
            vault.batch_upsert_cves(rows)

    conn = sqlite3.connect(db_path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM cve_data").fetchone()[0]
    finally:
        conn.close()

    assert n == 0

    vault.batch_upsert_cves(rows)
    conn = sqlite3.connect(db_path)
    try:
        n2 = conn.execute("SELECT COUNT(*) FROM cve_data").fetchone()[0]
    finally:
        conn.close()
    assert n2 == 2

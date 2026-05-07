"""
Concurrency: ``circuit_breaker`` is the primary shared_utils module that guards shared state with
locks:

- ``_registry_lock`` protects the process-wide ``get_breaker`` name → instance map.
- Each ``CircuitBreaker._lock`` protects ``_fail_times`` / ``_open_until`` (internal counters).

These tests fire the same primary API (**``circuit_protect``** / **``get_breaker``**) **10** times in
parallel via :mod:`threading` and :func:`asyncio.gather` (:func:`asyncio.to_thread`), then assert
singleton registry behavior, identical successful returns, and consistent internal counter state — no
lost updates from data races.

An integration case uses **10** threads + a ``threading.Barrier`` to upsert into the same on-disk
vault file (engine-level locking).

(Local-file writers such as ``ingestor._append_ingest_log`` do not use an explicit Python ``Lock``.)
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import uuid
from pathlib import Path

import circuit_breaker as cb
import pytest
from circuit_breaker import circuit_protect, get_breaker
from db_manager import CTIVault
from exceptions import DependencyUnavailableError


def _cleanup_registry(name: str) -> None:
    with cb._registry_lock:
        cb._registry.pop(name, None)


def test_threading_ten_parallel_get_breaker_returns_same_instance() -> None:
    """Ten threads must observe one shared ``CircuitBreaker`` per logical name (registry lock)."""
    name = f"reg-{uuid.uuid4().hex}"
    try:
        seen: list[int] = []
        guard = threading.Lock()

        def worker() -> None:
            b = get_breaker(name)
            with guard:
                seen.append(id(b))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        assert len(seen) == 10
        assert len(set(seen)) == 1
    finally:
        _cleanup_registry(name)


def test_threading_ten_parallel_protect_success_same_return_and_clean_counters() -> None:
    """Successful ``protect`` runs clear failure state under ``_lock``; no torn updates."""
    name = f"ok-{uuid.uuid4().hex}"
    try:
        results: list[str] = []
        guard = threading.Lock()

        def worker() -> None:
            out = circuit_protect(name, lambda: "payload")
            with guard:
                results.append(out)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        assert results == ["payload"] * 10
        br = get_breaker(name)
        with br._lock:
            assert len(br._fail_times) == 0
            assert br._open_until is None
    finally:
        _cleanup_registry(name)


def test_threading_ten_parallel_protect_failures_consistent_open_state() -> None:
    """
    Ten concurrent failing calls: failure accounting stays coherent (no corrupted list length /
    threshold logic). After the storm, the breaker is either open with bounded failure history or
    callers see ``DependencyUnavailableError``.
    """
    name = f"fail-{uuid.uuid4().hex}"
    try:
        err = RuntimeError("dependency down")

        def boom() -> None:
            raise err

        caught: list[type[BaseException]] = []
        guard = threading.Lock()

        def worker() -> None:
            try:
                circuit_protect(name, boom)
            except BaseException as e:
                with guard:
                    caught.append(type(e))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        assert len(caught) == 10
        assert all(
            t in (RuntimeError, DependencyUnavailableError) for t in caught
        ), caught

        br = get_breaker(name)
        with br._lock:
            assert br.failure_threshold == 5
            assert len(br._fail_times) <= br.failure_threshold
            if br._open_until is not None:
                assert len(br._fail_times) >= br.failure_threshold
    finally:
        _cleanup_registry(name)


def test_asyncio_gather_ten_to_thread_same_return_values() -> None:
    """``asyncio.gather`` + ``to_thread`` exercises the same lock-protected path off the event loop."""
    name = f"async-{uuid.uuid4().hex}"
    try:

        async def run_one() -> int:
            return await asyncio.to_thread(circuit_protect, name, lambda: 42)

        async def main() -> list[int]:
            return await asyncio.gather(*[run_one() for _ in range(10)])

        out = asyncio.run(main())
        assert out == [42] * 10

        br = get_breaker(name)
        with br._lock:
            assert len(br._fail_times) == 0
            assert br._open_until is None
    finally:
        _cleanup_registry(name)


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


def _ioc_count(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0])
    finally:
        conn.close()


@pytest.mark.integration
def test_threading_ten_parallel_sqlite_upserts_same_file_no_lost_rows(
    tmp_path: Path,
) -> None:
    """
    Ten threads write distinct IOC rows to the same ``cti_vault.db`` path (WAL on).

    ``CTIVault`` has no process-wide :class:`threading.Lock`; cross-thread safety for the
    on-disk file is provided by :mod:`sqlite3` and the engine. We assert 10 committed rows
    (no cross-thread update races visible as lost commits).
    """
    db_path = tmp_path / "cti_vault.db"
    _create_minimal_ioc_vault(db_path)
    barrier = threading.Barrier(10)
    excs: list[BaseException] = []
    elock = threading.Lock()

    def work(idx: int) -> None:
        try:
            barrier.wait(timeout=30.0)
            with CTIVault(db_path) as v:
                v.batch_upsert_iocs(
                    [
                        (
                            f"2001:db8::{idx:04d}",
                            "ipv6",
                            "2026-01-01T00:00:00Z",
                            "2026-01-01T00:00:00Z",
                            "concurrent",
                            None,
                        )
                    ]
                )
        except BaseException as e:  # noqa: BLE001 — surface any DB error
            with elock:
                excs.append(e)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60.0)

    assert not excs, excs
    assert _ioc_count(db_path) == 10

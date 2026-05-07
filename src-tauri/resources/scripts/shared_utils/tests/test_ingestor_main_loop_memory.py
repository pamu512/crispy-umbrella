"""
Stress the ingestor **main mapping loop** (``CSVIngestor._ingest_mapped``): FieldMapper,
batch tuple assembly, and vault batch dispatch — the hot path used by ``ingest_csv`` /
``sync_project_outputs``.

Runs **1,000** iterations in **one process**. Compares working-set RSS before vs after;
if growth exceeds **5%**, fails and prints a **tracemalloc** diff (likely leak sites).

SQLite is stubbed (no-op vault) so allocator noise from ``sqlite3`` does not dominate RSS.
"""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import tracemalloc
from typing import Any

import pytest

from ingestor import CSVIngestor

_ITERATIONS = 1000
_MAX_RELATIVE_GROWTH = 0.05


class _NoopVault:
    """Minimal duck type: ``_ingest_mapped`` only calls batch upserts."""

    def batch_upsert_iocs(
        self,
        rows: list[tuple[str, str, str, str, str | None, str | None]],
    ) -> None:
        del rows

    def batch_upsert_cves(
        self,
        rows: list[tuple[str, float | None, str, str, str | None]],
    ) -> None:
        del rows

    def batch_upsert_asm_assets(
        self,
        rows: list[tuple[str, str, str, str, str | None]],
    ) -> None:
        del rows


def _working_set_bytes() -> int:
    """Best-effort resident / working-set size for this process (platform-specific)."""
    if sys.platform.startswith("linux"):
        with open("/proc/self/statm", encoding="ascii") as f:  # noqa: PTH123
            resident_pages = int(f.read().split()[1])
        return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))

    if sys.platform == "darwin":
        out = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(os.getpid())],
            capture_output=True,
            text=True,
            check=True,
        )
        rss_kb = int(out.stdout.split()[0])
        return rss_kb * 1024

    if sys.platform == "win32":
        import ctypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        proc = ctypes.windll.kernel32.GetCurrentProcess()
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
            proc,
            ctypes.byref(counters),
            counters.cb,
        ):
            raise OSError(ctypes.get_last_error())
        return int(counters.WorkingSetSize)

    pytest.skip(f"RSS sampling not implemented for {sys.platform!r}")


def _warm_main_loop(
    ingestor: CSVIngestor,
    rows: list[dict[str, Any]],
    *,
    n: int = 24,
) -> None:
    for _ in range(n):
        ingestor._ingest_mapped(rows, "IOC_Generic", source_csv="sample.csv")


def _format_tracemalloc_diff(
    snap_before: tracemalloc.Snapshot,
    snap_after: tracemalloc.Snapshot,
    *,
    limit: int = 25,
) -> str:
    lines: list[str] = []
    for stat in snap_after.compare_to(snap_before, "lineno")[:limit]:
        lines.append(str(stat))
    return "\n".join(lines)


@pytest.mark.integration
def test_csv_ingestor_main_loop_memory_stable_1000_iterations() -> None:
    """
    Execute the ingest mapping loop (IOC_Generic profile) 1,000 times.

    Fails when RSS grows more than 5% vs baseline; includes tracemalloc lineno diff to
    pinpoint Python-side retention.
    """
    rows: list[dict[str, Any]] = [
        {
            "ioc_value": "203.0.113.5",
            "ioc_type": "ipv4",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-01T00:00:00Z",
            "source_project": "mem_test",
        },
        {
            "ioc_value": "evil.example",
            "ioc_type": "domain",
            "first_seen": "2026-01-02T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
        },
    ]

    ingestor = CSVIngestor(_NoopVault())

    _warm_main_loop(ingestor, rows)

    gc.collect()
    gc.collect()

    mem_before = _working_set_bytes()

    tracemalloc.start(25)
    snap_before = tracemalloc.take_snapshot()

    for _ in range(_ITERATIONS):
        ingestor._ingest_mapped(rows, "IOC_Generic", source_csv="sample.csv")

    snap_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    gc.collect()
    gc.collect()

    mem_after = _working_set_bytes()

    delta = mem_after - mem_before
    if mem_before <= 0:
        pytest.fail(f"invalid baseline RSS: {mem_before}")

    ratio = delta / mem_before
    if ratio <= _MAX_RELATIVE_GROWTH:
        return

    leak_hint = _format_tracemalloc_diff(snap_before, snap_after)
    pytest.fail(
        f"Ingest main-loop memory regression: RSS grew {ratio:.2%} "
        f"(before={mem_before} after={mem_after} delta={delta} bytes; "
        f"threshold={_MAX_RELATIVE_GROWTH:.0%}). "
        f"Likely Python-side retention — top tracemalloc growth (lineno):\n{leak_hint}"
    )

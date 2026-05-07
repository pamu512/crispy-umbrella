"""Tests for Python-side debug snapshot (circuit registry)."""

from __future__ import annotations

import pytest

from circuit_breaker import circuit_protect, circuit_registry_snapshot
from debug_status import collect_python_debug_snapshot, log_internal_status


def test_collect_python_debug_snapshot_includes_breakers_after_use() -> None:
    circuit_registry_snapshot()  # may be empty
    circuit_protect("test_status_breaker", lambda: "ok")
    snap = collect_python_debug_snapshot()
    assert "circuit_breakers" in snap
    assert "test_status_breaker" in snap["circuit_breakers"]


def test_log_internal_status_returns_payload(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("INFO"):
        out = log_internal_status()
    assert "circuit_breakers" in out
    assert any("cti.status" in r.message for r in caplog.records)

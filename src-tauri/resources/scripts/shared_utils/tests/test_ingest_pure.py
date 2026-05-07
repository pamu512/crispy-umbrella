"""
Unit tests for pure CSV/mapping helpers in ``ingestor`` — no temp files, no disk I/O.
"""

from __future__ import annotations

import json

import pytest

from ingestor import parse_csv_stdlib_text, rows_to_vault_upsert_batches


def test_parse_csv_stdlib_text_normalizes_headers_and_rows() -> None:
    text = "IOC Value,Type\n203.0.113.5,ipv4\n"
    cols, rows = parse_csv_stdlib_text(text)
    assert cols == ["ioc_value", "type"]
    assert rows == [
        {"ioc_value": "203.0.113.5", "type": "ipv4"},
    ]


def test_parse_csv_stdlib_text_header_only_yields_columns() -> None:
    text = "a,b,c\n"
    cols, rows = parse_csv_stdlib_text(text)
    assert cols == ["a", "b", "c"]
    assert rows == []


def test_rows_to_vault_upsert_batches_ioc_generic_builds_ioc_tuple() -> None:
    rows_in = [
        {
            "ioc_value": "evil.example",
            "ioc_type": "domain",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
        },
    ]
    ioc_b, cve_b, asm_b, skips = rows_to_vault_upsert_batches(
        rows_in,
        "IOC_Generic",
        source_csv="indicators.csv",
    )
    assert cve_b == []
    assert asm_b == []
    assert skips == []
    assert len(ioc_b) == 1
    val, typ, fs, ls, proj, meta_json = ioc_b[0]
    assert val == "evil.example"
    assert typ == "domain"
    assert fs == "2026-01-01T00:00:00Z"
    assert ls == "2026-01-02T00:00:00Z"
    assert proj == "csv_ingest"
    assert meta_json is not None
    meta = json.loads(meta_json)
    assert meta.get("source_csv") == "indicators.csv"


def test_rows_to_vault_upsert_batches_skip_populates_skip_logs() -> None:
    rows_in = [{"ioc_type": "ipv4"}]  # missing IOC value
    ioc_b, _, _, skips = rows_to_vault_upsert_batches(
        rows_in,
        "IOC_Generic",
        source_csv="bad.csv",
    )
    assert ioc_b == []
    assert len(skips) == 1
    assert skips[0].startswith("bad.csv:")


def test_rows_to_vault_upsert_batches_nvd_row() -> None:
    rows_in = [
        {
            "cve_id": "CVE-2024-0001",
            "score": "7.5",
            "published": "2024-06-01",
            "updated_at": "2024-06-15T00:00:00Z",
        },
    ]
    _, cve_b, _, skips = rows_to_vault_upsert_batches(
        rows_in,
        "NVD",
        source_csv="nvd.csv",
    )
    assert skips == []
    assert len(cve_b) == 1
    cid, sev, pub, upd, meta_json = cve_b[0]
    assert cid == "CVE-2024-0001"
    assert sev == 7.5
    assert pub == "2024-06-01T00:00:00Z"
    assert upd == "2024-06-15T00:00:00Z"
    assert meta_json is not None


@pytest.mark.parametrize("fallback", ["2026-03-01T12:00:00Z", None])
def test_rows_to_vault_upsert_batches_asm_uses_fallback_or_default(
    fallback: str | None,
) -> None:
    rows_in = [
        {
            "host": "a.example",
            "last_scan": "",
            "type": "host",
        },
    ]
    _, _, asm_b, skips = rows_to_vault_upsert_batches(
        rows_in,
        "ASM",
        source_csv="asm.csv",
        fallback_scan_iso=fallback,
    )
    assert skips == []
    assert len(asm_b) == 1
    target, asset_type, scan_at, status, _meta = asm_b[0]
    assert target == "a.example"
    assert asset_type == "host"
    assert status == "active"
    if fallback:
        assert scan_at == "2026-03-01T12:00:00Z"
    else:
        # Pure helper defaulted scan time (wall clock) — only assert shape
        assert len(scan_at) >= 10

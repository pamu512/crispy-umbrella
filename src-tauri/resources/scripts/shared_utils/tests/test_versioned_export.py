"""Tests for :mod:`versioned_export` JSON/CSV migration and writers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from versioned_export import (
    CTI_CSV_FORMAT_VERSION,
    CTI_EXPORT_FORMAT_VERSION,
    CTI_EXPORT_VERSION_KEY,
    dump_export_json,
    load_migrated_export_json,
    migrate_export_json,
    read_versioned_csv,
    with_export_version,
    write_versioned_csv,
)


def test_with_export_version_stamps_current() -> None:
    d = with_export_version({"a": 1})
    assert d[CTI_EXPORT_VERSION_KEY] == CTI_EXPORT_FORMAT_VERSION
    assert d["a"] == 1


def test_migrate_v1_json_adds_version() -> None:
    legacy = {"root": "/tmp/ws", "files": [], "rows": 0, "shutdown": False}
    m = migrate_export_json(legacy)
    assert m[CTI_EXPORT_VERSION_KEY] == CTI_EXPORT_FORMAT_VERSION
    assert m["root"] == "/tmp/ws"
    assert m["shutdown"] is False


def test_migrate_v2_idempotent() -> None:
    v2 = {CTI_EXPORT_VERSION_KEY: 2, "x": 1}
    m = migrate_export_json(v2)
    assert m[CTI_EXPORT_VERSION_KEY] == CTI_EXPORT_FORMAT_VERSION
    assert m["x"] == 1


def test_migrate_rejects_newer_export_version() -> None:
    future = {CTI_EXPORT_VERSION_KEY: CTI_EXPORT_FORMAT_VERSION + 10}
    with pytest.raises(ValueError, match="newer"):
        migrate_export_json(future)


def test_migrate_rejects_non_object_root() -> None:
    with pytest.raises(TypeError):
        migrate_export_json([1, 2])


def test_dump_and_load_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    dump_export_json(path, {"hello": "world"})
    loaded = load_migrated_export_json(path)
    assert loaded["hello"] == "world"
    assert loaded[CTI_EXPORT_VERSION_KEY] == CTI_EXPORT_FORMAT_VERSION


def test_csv_write_read_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "t.csv"
    write_versioned_csv(path, ["col"], [{"col": "v"}])
    ver, fields, rows = read_versioned_csv(path)
    assert ver == CTI_CSV_FORMAT_VERSION
    assert fields == ["col"]
    assert rows == [{"col": "v"}]
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# cti_csv_format_version=")


def test_csv_v1_header_only_migrates(tmp_path: Path) -> None:
    path = tmp_path / "legacy.csv"
    path.write_text("name,val\nfoo,1\n", encoding="utf-8")
    ver, fields, rows = read_versioned_csv(path)
    assert ver == CTI_CSV_FORMAT_VERSION
    assert fields == ["name", "val"]
    assert rows == [{"name": "foo", "val": "1"}]


def test_csv_version_number_in_comment(tmp_path: Path) -> None:
    path = tmp_path / "v2.csv"
    path.write_text(
        "# cti_csv_format_version=2\n"
        "a,b\n"
        "1,2\n",
        encoding="utf-8",
    )
    ver, fields, rows = read_versioned_csv(path)
    assert ver == CTI_CSV_FORMAT_VERSION
    assert rows == [{"a": "1", "b": "2"}]


def test_json_dump_indent_none(tmp_path: Path) -> None:
    path = tmp_path / "compact.json"
    dump_export_json(path, {"k": "v"}, indent=None)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw[CTI_EXPORT_VERSION_KEY] == CTI_EXPORT_FORMAT_VERSION

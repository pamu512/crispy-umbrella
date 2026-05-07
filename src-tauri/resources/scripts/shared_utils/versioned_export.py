"""
Versioned JSON/CSV exports for sidecar CLIs and saved artifacts.

* **Version 1** — legacy documents with no format key (or version ``1``).
* **Version 2** — includes ``cti_export_format_version: 2`` (JSON) or a leading
  ``# cti_csv_format_version=2`` line (CSV).

Use :func:`with_export_version` when writing; :func:`migrate_export_json` /
:func:`read_versioned_csv` when reading files that may be older.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from io import StringIO
from pathlib import Path
from typing import Any, TextIO

CTI_EXPORT_FORMAT_VERSION: int = 2
CTI_EXPORT_VERSION_KEY: str = "cti_export_format_version"

CTI_CSV_VERSION_LINE_RE = re.compile(
    r"^#\s*cti_csv_format_version\s*=\s*(?P<v>\d+)\s*$",
    re.IGNORECASE,
)


def with_export_version(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``payload`` stamped with the current JSON export version."""
    out: dict[str, Any] = dict(payload)
    out[CTI_EXPORT_VERSION_KEY] = CTI_EXPORT_FORMAT_VERSION
    return out


def parse_embedded_export_version(obj: Any) -> int:
    """
    Read the export version from a parsed JSON object.

    Missing or invalid version values are treated as **1** (legacy).
    """
    if not isinstance(obj, dict):
        return 1
    raw = obj.get(CTI_EXPORT_VERSION_KEY)
    if raw is None:
        return 1
    if isinstance(raw, bool):
        return 1
    if isinstance(raw, int):
        return raw if raw >= 1 else 1
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return 1


def migrate_export_json(obj: Any) -> dict[str, Any]:
    """
    Normalize a parsed JSON export to **Version 2** shape.

    Accepts Version 1 (no ``cti_export_format_version``) and Version 2.
    Future schema changes: add branches for intermediate versions, then set
    ``cti_export_format_version`` to :data:`CTI_EXPORT_FORMAT_VERSION`.
    """
    if not isinstance(obj, dict):
        raise TypeError(f"export root must be a JSON object, got {type(obj).__name__}")
    v = parse_embedded_export_version(obj)
    if v > CTI_EXPORT_FORMAT_VERSION:
        raise ValueError(
            f"export version {v} is newer than this code ({CTI_EXPORT_FORMAT_VERSION}); upgrade the client"
        )
    out: dict[str, Any] = dict(obj)
    if v == 1:
        # Version 1 → 2: schema unchanged today; add future field renames here when bumping.
        pass
    out[CTI_EXPORT_VERSION_KEY] = CTI_EXPORT_FORMAT_VERSION
    return out


def load_migrated_export_json(path: Path | str) -> dict[str, Any]:
    """Load a JSON file and migrate it to the current export version."""
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    return migrate_export_json(raw)


def dump_export_json(
    path: Path | str,
    payload: Mapping[str, Any],
    *,
    indent: int | None = 2,
) -> None:
    """Write JSON with the current export version key."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = with_export_version(dict(payload))
    p.write_text(json.dumps(body, indent=indent, ensure_ascii=False) + "\n", encoding="utf-8")


# --- CSV (leading comment line) ---

CTI_CSV_FORMAT_VERSION: int = 2


def _parse_csv_version_line(first_line: str) -> tuple[int, bool]:
    """
    If ``first_line`` is a version comment, return ``(version, True)``.
    Otherwise return ``(1, False)`` (legacy file with header first).
    """
    m = CTI_CSV_VERSION_LINE_RE.match(first_line.strip())
    if not m:
        return 1, False
    try:
        return int(m.group("v")), True
    except ValueError:
        return 1, False


def write_versioned_csv(
    dest: Path | str | TextIO,
    fieldnames: Sequence[str],
    rows: Iterable[Mapping[str, Any]],
    *,
    version: int = CTI_CSV_FORMAT_VERSION,
) -> None:
    """
    Write UTF-8 CSV with a format version comment as the first line.

    Version 1 legacy files had **no** comment line (header first).
    """
    header_line = f"# cti_csv_format_version={version}\n"

    def _write_stream(fp: TextIO) -> None:
        fp.write(header_line)
        w = csv.DictWriter(fp, fieldnames=list(fieldnames), lineterminator="\n")
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fieldnames})

    if hasattr(dest, "write"):
        _write_stream(dest)
        return
    p = Path(dest)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as fp:
        _write_stream(fp)


def read_versioned_csv(path: Path | str) -> tuple[int, list[str], list[dict[str, str]]]:
    """
    Read a CSV written by :func:`write_versioned_csv` or a Version 1 header-only file.

    Returns ``(version, fieldnames, rows)`` with rows as string dicts (``csv`` module style).
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        return 1, [], []

    ver, consumed = _parse_csv_version_line(lines[0])
    rest_idx = 1 if consumed else 0
    body = "\n".join(lines[rest_idx:])
    r = csv.DictReader(StringIO(body))
    fn = list(r.fieldnames or [])
    data_rows: list[dict[str, str]] = []
    for raw in r:
        data_rows.append({k: (raw.get(k) or "") for k in fn})
    if ver > CTI_CSV_FORMAT_VERSION:
        raise ValueError(
            f"CSV format version {ver} is newer than this code ({CTI_CSV_FORMAT_VERSION})"
        )
    if ver < CTI_CSV_FORMAT_VERSION:
        data_rows = _migrate_csv_rows_v1_to_v2(fn, data_rows)
    return CTI_CSV_FORMAT_VERSION, fn, data_rows


def _migrate_csv_rows_v1_to_v2(
    fieldnames: list[str],
    rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Placeholder: V1 and V2 share the same row shape today."""
    del fieldnames
    return list(rows)

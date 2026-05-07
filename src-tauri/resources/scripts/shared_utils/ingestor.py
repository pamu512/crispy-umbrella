"""
CSV → SQLite vault bridge: per-project column maps into ``cve_data``, ``ioc_records``, ``asm_assets``.

Run from the Tauri host (``CTI_DB_PATH``, ``CTI_WORKSPACE_PATH`` set)::

    python3 ingestor.py sync [WORKSPACE_DIR]
    python3 ingestor.py ingest-file PATH [--type CVE|IOC|ASM] [--project Intelx_Crawler]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import re
from io import StringIO
import shutil
import sys
import time
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import TextIO, cast

from constants import (
    BUNDLED_PROJECT_FOLDER_NAMES,
    ENV_CTI_LOGS_DIR,
    ENV_CTI_WORKSPACE_PATH,
    HOME_DOT_VAULT8_LOG_PARTS,
    INGEST_LOG_FILENAME,
    WINDOWS_LOCALAPPDATA_VAULT8_LOG_PARTS,
)
from db_manager import CTIVault, parse_cvss_base_score
from exceptions import JsonValue
from graceful_shutdown import install_handlers, shutdown_requested
from input_validation import (
    ValidationError,
    validate_csv_file_path,
    validate_optional_project_folder,
    validate_optional_project_type,
    validate_optional_workspace_directory,
    validate_workspace_path_required,
)
from logger import audit_state_change
from retry_backoff import with_exponential_backoff
from time_execution import time_execution
from versioned_export import with_export_version

_LOG = logging.getLogger(__name__)

try:
    import pandas as _pandas_mod

    pd: ModuleType | None = _pandas_mod
    _HAS_PANDAS = True
except ImportError:
    pd = None
    _HAS_PANDAS = False

# Same eight features as Rust ``validate_features_bundle`` — canonical names in ``constants``.
PROJECT_FOLDERS = BUNDLED_PROJECT_FOLDER_NAMES

_EXTRA_OUTPUT_GLOBS = (
    "final_report",
    "csv_output",
    "output_result",
    "output",
)


def _gather_project_output_csvs(project_base: Path) -> list[Path]:
    candidates: list[Path] = []
    for sub in _EXTRA_OUTPUT_GLOBS:
        d = project_base / sub
        if d.is_dir():
            candidates.extend(d.rglob("*.csv"))
    return sorted(set(candidates))


def _sync_shutdown_payload(
    root: Path,
    files_summary: list[dict[str, object]],
    rows_total: int,
) -> dict[str, object]:
    return with_export_version(
        {
            "root": str(root),
            "files": files_summary,
            "rows": rows_total,
            "shutdown": True,
        }
    )

# Maps bundled folder names to FieldMapper profile keys (8 project types).
FOLDER_TO_PROFILE: dict[str, str] = {
    "Intelx_Crawler": "Intelx",
    "CVE_Project_NVD": "NVD",
    "ASM-fetch-main": "ASM",
    "Ransomware_live_event_victim": "Ransomware",
    "IOCs-crawler-main": "IOC_Crawler",
    "Phishing_and_Social_Media_All-in-one": "Phishing",
    "Social_MediaV2": "Social",
    "Compromised_user_Mac": "Mac_Audit",
}


def _norm_header(h: str) -> str:
    return h.strip().strip("\ufeff").lower().replace(" ", "_")


def _cell_str(v: object) -> str:
    if v is None:
        return ""
    if _HAS_PANDAS and isinstance(v, float) and pd is not None and pd.isna(v):
        return ""
    if isinstance(v, float) and math.isnan(v):
        return ""
    return str(v).strip()


_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y",
    "%d/%m/%Y",
)


def _normalize_date_pandas(value: object) -> str | None:
    assert pd is not None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    ts = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(ts):
        return None
    out: str = cast(str, ts.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return out


def _parse_date_string_formats(s: str) -> str | None:
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(s.replace("Z", ""), fmt.replace("Z", ""))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


def normalize_date(value: object) -> str | None:
    """Normalize CSV date-like values to UTC ISO8601 ``...Z`` strings."""
    if value is None or value == "":
        return None
    if _HAS_PANDAS and pd is not None:
        return _normalize_date_pandas(value)
    s = str(value).strip()
    if not s or s.lower() in ("nan", "none", "n/a", "nat"):
        return None
    return _parse_date_string_formats(s)


def _default_date_iso() -> str:
    """Missing date columns default to ``datetime.now().isoformat()`` (naive local)."""
    return datetime.now().isoformat()


def _ingest_log_path() -> Path:
    """Prefer ``CTI_LOGS_DIR``; else Windows ``%LOCALAPPDATA%/Vault8/logs``; else ``~/.vault8/logs``."""
    ld = (os.environ.get(ENV_CTI_LOGS_DIR) or "").strip()
    if ld:
        return Path(ld).expanduser() / INGEST_LOG_FILENAME
    if sys.platform == "win32":
        la = (os.environ.get("LOCALAPPDATA") or "").strip()
        if la:
            return Path(la).joinpath(*WINDOWS_LOCALAPPDATA_VAULT8_LOG_PARTS) / INGEST_LOG_FILENAME
    return Path.home().joinpath(*HOME_DOT_VAULT8_LOG_PARTS) / INGEST_LOG_FILENAME


def _append_ingest_log(message: str) -> None:
    def _write() -> None:
        p = _ingest_log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{ts} {message}\n")

    try:
        with_exponential_backoff(_write, max_retries=3, base_delay_s=0.25, retry_on=(OSError,))
    except OSError:
        pass


def _pack_metadata(
    row: dict[str, str],
    consumed: set[str],
    *,
    source_csv: str,
    extras: dict[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Columns not mapped to top-level vault fields go into ``metadata`` (plus ``source_csv``)."""
    meta: dict[str, JsonValue] = {"source_csv": source_csv}
    if extras:
        for k, v in extras.items():
            if v is not None and v != "":
                meta[k] = v
    for k, v in row.items():
        if k in consumed:
            continue
        if v is None or v == "":
            continue
        meta[k] = v
    return meta


def _csv_in_project_tree(csv_path: Path, workspace: Path, project_folder: str) -> bool:
    try:
        csv_path.resolve().relative_to((workspace.expanduser().resolve() / project_folder).resolve())
        return True
    except ValueError:
        return False


def _archive_ingested_csv(csv_path: Path, workspace: Path, project_folder: str) -> Path | None:
    """Move CSV to ``<project>/output/archived_logs/`` (no delete)."""
    dest_dir = workspace.expanduser().resolve() / project_folder / "output" / "archived_logs"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / csv_path.name
        if dest.exists():
            dest = dest_dir / f"{csv_path.stem}_{int(time.time())}{csv_path.suffix}"
        shutil.move(str(csv_path.resolve()), str(dest))
        return dest
    except OSError:
        return None


class FieldMapper:
    """
    Project-specific CSV → vault row mapping (8 profiles + ``IOC_Generic`` for path-only ingest).

    Normalization: trim strings; ``ioc_type`` lowercase; missing dates → ``datetime.now().isoformat()``.
    """

    @staticmethod
    def map_fields(
        profile: str,
        row: Mapping[str, object],
        *,
        source_csv: str,
        fallback_scan_iso: str | None = None,
    ) -> tuple[dict[str, JsonValue] | None, str | None]:
        """
        Return ``(mapped, None)`` on success. ``mapped`` includes ``table`` in
        ``{"ioc"|"cve"|"asm"}`` plus keys matching batch upsert tuples.

        On skip (missing critical primary), return ``(None, reason)``.
        """
        from field_mapper_profiles import dispatch_field_profile

        norm: dict[str, str] = {_norm_header(str(k)): _cell_str(v) for k, v in row.items()}
        return dispatch_field_profile(
            profile,
            norm,
            source_csv=source_csv,
            fallback_scan_iso=fallback_scan_iso,
        )


def parse_csv_stdlib_file(stream: TextIO) -> tuple[list[str], list[dict[str, object]]]:
    """
    Parse CSV from a **text stream** (stdlib only): iterate rows without loading the whole file.

    Open paths with ``newline=''`` so quoted fields containing line breaks parse correctly
    (see :mod:`csv` documentation).
    """
    r = csv.DictReader(stream)
    if not r.fieldnames:
        return [], []
    columns = [_norm_header(str(h)) for h in r.fieldnames if h]
    rows: list[dict[str, object]] = []
    for raw in r:
        rows.append({_norm_header(k): v for k, v in raw.items() if k})
    return columns, rows


def parse_csv_stdlib_text(text: str) -> tuple[list[str], list[dict[str, object]]]:
    """Parse CSV from an in-memory string (wrapper around :func:`parse_csv_stdlib_file`)."""
    return parse_csv_stdlib_file(StringIO(text))


def _mapped_row_to_batches(
    m: dict[str, JsonValue],
    ioc_batch: list[tuple[str, str, str, str, str | None, str | None]],
    cve_batch: list[tuple[str, float | None, str, str, str | None]],
    asm_batch: list[tuple[str, str, str, str, str | None]],
) -> None:
    t = str(m["table"])
    meta = cast(dict[str, JsonValue], m.get("metadata") or {})
    meta_str = json.dumps(meta, ensure_ascii=False) if meta else None
    if t == "ioc":
        ioc_batch.append(
            (
                cast(str, m["ioc_value"]),
                cast(str, m["ioc_type"]),
                cast(str, m["first_seen"]),
                cast(str, m["last_seen"]),
                cast(str | None, m.get("source_project")),
                meta_str,
            )
        )
        return
    if t == "cve":
        cve_batch.append(
            (
                cast(str, m["cve_id"]),
                cast(float | None, m["severity_score"]),
                cast(str, m["published_date"]),
                cast(str, m["updated_at"]),
                meta_str,
            )
        )
        return
    if t == "asm":
        asm_batch.append(
            (
                cast(str, m["asset_target"]),
                cast(str, m["asset_type"]),
                cast(str, m["last_scan_at"]),
                cast(str, m["status"]),
                meta_str,
            )
        )


def rows_to_vault_upsert_batches(
    rows: list[dict[str, object]],
    profile: str,
    *,
    source_csv: str,
    fallback_scan_iso: str | None = None,
) -> tuple[
    list[tuple[str, str, str, str, str | None, str | None]],
    list[tuple[str, float | None, str, str, str | None]],
    list[tuple[str, str, str, str, str | None]],
    list[str],
]:
    """
    Pure data path: map normalized CSV rows to vault ``executemany`` tuples + skip log lines.

    No disk, no SQLite, no append-only log I/O. Callers own IO and persistence.
    If ``profile == \"ASM\"`` and ``fallback_scan_iso`` is missing, uses :func:`_default_date_iso`.
    """
    if profile == "ASM" and not fallback_scan_iso:
        fallback_scan_iso = _default_date_iso()
    ioc_batch: list[tuple[str, str, str, str, str | None, str | None]] = []
    cve_batch: list[tuple[str, float | None, str, str, str | None]] = []
    asm_batch: list[tuple[str, str, str, str, str | None]] = []
    skip_logs: list[str] = []

    for raw in rows:
        mapped, err = FieldMapper.map_fields(
            profile,
            raw,
            source_csv=source_csv,
            fallback_scan_iso=fallback_scan_iso,
        )
        if err:
            skip_logs.append(f"{source_csv}: {err}")
            continue
        assert mapped is not None
        _mapped_row_to_batches(mapped, ioc_batch, cve_batch, asm_batch)

    return ioc_batch, cve_batch, asm_batch, skip_logs


_PANDAS_CHUNK_ROWS = 65_536


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, object]]]:
    """
    IO + parsing on disk without ``Path.read_text()`` / full-buffer reads.

    - **Stdlib:** ``csv.DictReader`` over ``open(..., newline=\"\")`` — line-oriented iteration.
    - **Pandas:** chunked ``read_csv(iterator=True)`` — bounded in-memory frames per chunk (final
      ``rows`` list still scales with row count, same as before).
    """
    if _HAS_PANDAS:
        assert pd is not None
        columns: list[str] = []
        rows: list[dict[str, object]] = []
        try:
            reader = pd.read_csv(
                path,
                dtype=str,
                keep_default_na=False,
                chunksize=_PANDAS_CHUNK_ROWS,
                iterator=True,
            )
        except pd.errors.EmptyDataError:
            return [], []
        seen_columns = False
        for chunk in reader:
            chunk.columns = [_norm_header(str(c)) for c in chunk.columns]
            if not seen_columns:
                columns = list(chunk.columns)
                seen_columns = True
            rows.extend(chunk.to_dict(orient="records"))
        return columns, rows
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return parse_csv_stdlib_file(f)


def _project_folder_from_path(path: Path) -> str | None:
    """Return which bundled project folder this file lives under, if any."""
    parts = path.parts
    for p in PROJECT_FOLDERS:
        if p in parts:
            return p
    return None


def _intelx_type_to_ioc_type(raw: str) -> str:
    """Map IntelX ``type`` column (Email/Domain/…) to a stable ``ioc_type``."""
    t = raw.strip().lower()
    if not t:
        return "unknown"
    if "email" in t:
        return "email"
    if "domain" in t:
        return "domain"
    if "url" in t or "uri" in t:
        return "url"
    return t.replace(" ", "_")[:64]


def _infer_asm_from_path_and_columns(path: Path, p: str, colset: set[str]) -> bool:
    if "asm-fetch" in p or "asm_fetch" in p or path.name.endswith("_subdomains.csv"):
        return "hosts" in colset or "host" in colset
    return "hosts" in colset and ("ips" in colset or "ip" in colset)


def _infer_cve_from_path_and_columns(p: str, colset: set[str]) -> bool:
    if "cve_project_nvd" in p or "cve_id" in colset:
        return True
    return any(c.startswith("cvss") for c in colset) and (
        "description" in colset or "cve_id" in colset
    )


def detect_project_type(path: Path, columns: Iterable[str]) -> str:
    """Infer ``CVE`` | ``IOC`` | ``ASM`` when path is not under a known project folder."""
    p = str(path).lower()
    colset = {str(c).lower() for c in columns}

    if _infer_asm_from_path_and_columns(path, p, colset):
        return "ASM"
    if _infer_cve_from_path_and_columns(p, colset):
        return "CVE"
    return "IOC"


def _mtime_fallback_iso(path: Path) -> str:
    return normalize_date(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)) or _default_date_iso()


def _resolve_workspace_root_for_ingest(
    workspace_root: Path | str | None,
) -> Path | None:
    """Resolve and validate ``workspace_root`` for ingest (raises ``ValidationError`` on bad paths)."""
    if workspace_root is None:
        return None
    if isinstance(workspace_root, Path):
        try:
            ws = workspace_root.expanduser().resolve()
        except OSError as e:
            raise ValidationError(
                {
                    "field": "workspace_root",
                    "path": str(workspace_root),
                    "reason": "path_resolve",
                    "detail": str(e),
                },
                message="workspace_root could not be resolved",
            ) from e
        if not ws.is_dir():
            raise ValidationError(
                {"field": "workspace_root", "path": str(ws), "reason": "not_a_directory"},
                message="workspace_root must be an existing directory when set",
            )
        return ws
    return validate_optional_workspace_directory(
        str(workspace_root),
        field="workspace_root",
    )


class CSVIngestor:
    """Bridge CSV outputs (pandas when available) into a ``CTIVault``."""

    def __init__(self, vault: CTIVault) -> None:
        self.vault = vault

    def map_fields(
        self,
        project_profile: str,
        row: Mapping[str, object],
        *,
        source_csv: str = "",
        fallback_scan_iso: str | None = None,
    ) -> tuple[dict[str, JsonValue] | None, str | None]:
        """Delegate to ``FieldMapper`` (trim, ``ioc_type`` lower, metadata packing)."""
        return FieldMapper.map_fields(
            project_profile,
            row,
            source_csv=source_csv,
            fallback_scan_iso=fallback_scan_iso,
        )

    def _ingest_mapped(
        self,
        rows: list[dict[str, object]],
        profile: str,
        *,
        source_csv: str,
        fallback_scan_iso: str | None = None,
    ) -> int:
        """
        IO orchestration: pure mapping via :func:`rows_to_vault_upsert_batches`, then vault writes.

        ``source_csv`` is the logical filename (not necessarily an on-disk path).
        """
        ioc_batch, cve_batch, asm_batch, skip_logs = rows_to_vault_upsert_batches(
            rows,
            profile,
            source_csv=source_csv,
            fallback_scan_iso=fallback_scan_iso,
        )
        for msg in skip_logs:
            _append_ingest_log(msg)

        n = 0
        if ioc_batch:
            self.vault.batch_upsert_iocs(ioc_batch)
            n += len(ioc_batch)
        if cve_batch:
            self.vault.batch_upsert_cves(cve_batch)
            n += len(cve_batch)
        if asm_batch:
            self.vault.batch_upsert_asm_assets(asm_batch)
            n += len(asm_batch)
        return n

    def _maybe_archive_csv(
        self,
        csv_path: Path,
        workspace_root: Path | str | None,
        project_folder: str | None,
    ) -> None:
        if not workspace_root or not project_folder:
            return
        wr = Path(workspace_root).expanduser().resolve()
        if not csv_path.is_file():
            return
        if not _csv_in_project_tree(csv_path, wr, project_folder):
            return
        _archive_ingested_csv(csv_path, wr, project_folder)

    def ingest_csv(
        self,
        file_path: Path | str,
        project_type: str | None = None,
        *,
        project_folder: str | None = None,
        workspace_root: Path | str | None = None,
    ) -> int:
        path = validate_csv_file_path(file_path)

        columns, rows = _read_csv(path)
        if not rows:
            return 0

        validated_folder = (
            validate_optional_project_folder(project_folder)
            if project_folder is not None
            else None
        )
        validated_type = (
            validate_optional_project_type(project_type)
            if project_type is not None
            else None
        )

        folder = validated_folder or _project_folder_from_path(path)

        ws = _resolve_workspace_root_for_ingest(workspace_root)

        if folder in FOLDER_TO_PROFILE:
            return self._ingest_bundled_folder_csv(rows, path, folder, ws)

        return self._ingest_inferred_project_csv(
            rows,
            path,
            columns,
            validated_type,
            ws,
            folder,
        )

    def _ingest_bundled_folder_csv(
        self,
        rows: list[dict[str, object]],
        path: Path,
        folder: str,
        ws: Path | None,
    ) -> int:
        prof = FOLDER_TO_PROFILE[folder]
        fb = _mtime_fallback_iso(path) if prof == "ASM" else None
        n = self._ingest_mapped(
            rows,
            prof,
            source_csv=path.name,
            fallback_scan_iso=fb,
        )
        self._maybe_archive_csv(path, ws, folder)
        return n

    def _ingest_inferred_project_csv(
        self,
        rows: list[dict[str, object]],
        path: Path,
        columns: list[str],
        validated_type: str | None,
        ws: Path | None,
        folder: str | None,
    ) -> int:
        pt = validated_type or detect_project_type(path, columns)
        if pt == "CVE":
            n = self._ingest_mapped(rows, "NVD", source_csv=path.name)
            self._maybe_archive_csv(path, ws, folder)
            return n
        if pt == "ASM":
            n = self._ingest_mapped(
                rows,
                "ASM",
                source_csv=path.name,
                fallback_scan_iso=_mtime_fallback_iso(path),
            )
            self._maybe_archive_csv(path, ws, folder)
            return n
        if pt == "IOC":
            n = self._ingest_mapped(rows, "IOC_Generic", source_csv=path.name)
            self._maybe_archive_csv(path, ws, folder)
            return n
        raise ValidationError(
            {"field": "project_type", "resolved": pt},
            message=f"Unknown project_type after inference: {pt}",
        )

    def _ingest_key(self, path: Path) -> str:
        return f"csv_ingest_mtime_ns:{path.resolve()}"

    def _should_skip(self, path: Path) -> bool:
        try:
            st = path.stat()
        except OSError:
            return True
        key = self._ingest_key(path)
        prev = self.vault.get_vault_meta(key)
        return prev == str(st.st_mtime_ns)

    def _mark_done(self, path: Path) -> None:
        try:
            st = path.stat()
        except OSError:
            return
        self.vault.set_vault_meta(self._ingest_key(path), str(st.st_mtime_ns))

    def _ingest_csv_in_sync(
        self,
        path: Path,
        proj: str,
        root: Path,
        files_summary: list[dict[str, object]],
    ) -> int:
        """Ingest one CSV during workspace sync; append outcome to ``files_summary``."""
        try:
            n = self.ingest_csv(path, project_folder=proj, workspace_root=root)
            if path.is_file():
                self._mark_done(path)
            files_summary.append(
                {"path": str(path), "status": "ok", "rows": n, "project_folder": proj}
            )
            audit_state_change(
                _LOG,
                component="ingestor.CSVIngestor",
                previous_state="eligible",
                new_state="ingested",
                detail=f"path={path};rows={n};project_folder={proj}",
            )
            return n
        except Exception as e:  # noqa: BLE001
            _LOG.exception("ingest failed for %s", path)
            audit_state_change(
                _LOG,
                component="ingestor.CSVIngestor",
                previous_state="eligible",
                new_state="ingest_failed",
                detail=f"path={path};error={e!s}",
            )
            files_summary.append({"path": str(path), "status": "error", "error": str(e)})
            return 0

    def sync_project_outputs(self, base_dir: Path | str) -> dict[str, object]:
        """
        Walk the eight project trees under ``base_dir``, ingest CSVs under common output dirs.

        Skips files whose mtime matches the last successful ingest (stored in ``vault_meta``).
        CSVs under ``archived_logs`` are ignored. After a successful ingest, files are moved to
        ``<project>/output/archived_logs/`` when they live under the workspace tree.
        """
        root = Path(base_dir).expanduser().resolve()
        if not root.is_dir():
            raise NotADirectoryError(root)
        files_summary: list[dict[str, object]] = []
        rows_total = 0

        with time_execution(_LOG, label="ingestor.CSVIngestor.sync_project_outputs"):
            for proj in PROJECT_FOLDERS:
                if shutdown_requested():
                    audit_state_change(
                        _LOG,
                        component="ingestor.CSVIngestor",
                        previous_state="syncing",
                        new_state="shutdown_sig",
                        detail="SIGINT/SIGTERM: stopped before next project folder",
                    )
                    return _sync_shutdown_payload(root, files_summary, rows_total)
                base = root / proj
                if not base.is_dir():
                    continue
                for path in _gather_project_output_csvs(base):
                    if shutdown_requested():
                        audit_state_change(
                            _LOG,
                            component="ingestor.CSVIngestor",
                            previous_state="syncing",
                            new_state="shutdown_sig",
                            detail="SIGINT/SIGTERM: stopped before next CSV file",
                        )
                        return _sync_shutdown_payload(root, files_summary, rows_total)
                    if not path.is_file():
                        continue
                    if "archived_logs" in path.parts:
                        continue
                    if self._should_skip(path):
                        audit_state_change(
                            _LOG,
                            component="ingestor.CSVIngestor",
                            previous_state="eligible",
                            new_state="skipped_idempotent",
                            detail=str(path),
                        )
                        files_summary.append({"path": str(path), "status": "skipped", "rows": 0})
                        continue
                    rows_total += self._ingest_csv_in_sync(path, proj, root, files_summary)
        return with_export_version(
            {"root": str(root), "files": files_summary, "rows": rows_total, "shutdown": False}
        )


def run_sync(vault: CTIVault, workspace: str | None = None) -> dict[str, object]:
    raw = workspace if workspace is not None else os.environ.get(ENV_CTI_WORKSPACE_PATH)
    root_path = validate_workspace_path_required(raw, field="workspace")
    ing = CSVIngestor(vault)
    return ing.sync_project_outputs(root_path)


def run_ingest_file(
    vault: CTIVault,
    path: str,
    project_type: str | None,
    project_folder: str | None,
) -> dict[str, object]:
    ws = validate_optional_workspace_directory(os.environ.get(ENV_CTI_WORKSPACE_PATH))
    with time_execution(_LOG, label="ingestor.run_ingest_file"):
        ing = CSVIngestor(vault)
        n = ing.ingest_csv(
            path,
            project_type,
            project_folder=project_folder,
            workspace_root=ws,
        )
        audit_state_change(
            _LOG,
            component="ingestor.run_ingest_file",
            previous_state="eligible",
            new_state="ingested",
            detail=f"path={path};rows={n}",
        )
        return with_export_version({"path": path, "rows": n})


def _cli_run_sync(args: argparse.Namespace) -> int:
    try:
        with CTIVault() as vault:
            with time_execution(_LOG, label="ingestor.main.sync"):
                out = run_sync(vault, args.workspace or None)
    except ValidationError as e:
        print(json.dumps({"error": str(e), "context": e.context}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2))
    if out.get("shutdown"):
        return 0
    files_out = cast(list[dict[str, object]], out["files"])
    errors = [f for f in files_out if f.get("status") == "error"]
    return 1 if errors else 0


def _cli_run_ingest_file(args: argparse.Namespace) -> int:
    try:
        with CTIVault() as vault:
            with time_execution(_LOG, label="ingestor.main.ingest_file"):
                out = run_ingest_file(vault, args.file, args.type, args.project)
    except ValidationError as e:
        print(json.dumps({"error": str(e), "context": e.context}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    install_handlers()

    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="CTI CSV vault ingestor")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_sync = sub.add_parser("sync", help="Ingest all known project output CSVs under workspace")
    p_sync.add_argument(
        "workspace",
        nargs="?",
        default=os.environ.get(ENV_CTI_WORKSPACE_PATH, ""),
        help=f"Writable workspace root (default: {ENV_CTI_WORKSPACE_PATH})",
    )

    p_one = sub.add_parser("ingest-file", help="Ingest a single CSV")
    p_one.add_argument("file")
    p_one.add_argument("--type", choices=("CVE", "IOC", "ASM"), default=None)
    p_one.add_argument(
        "--project",
        choices=PROJECT_FOLDERS,
        default=None,
        help="Force project profile (folder name) for column mapping",
    )

    args = p.parse_args(argv)
    if args.cmd == "sync":
        return _cli_run_sync(args)
    if args.cmd == "ingest-file":
        return _cli_run_ingest_file(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

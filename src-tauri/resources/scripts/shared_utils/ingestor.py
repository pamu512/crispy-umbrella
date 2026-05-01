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
import math
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import pandas as pd

    _HAS_PANDAS = True
except ImportError:
    pd = None  # type: ignore[assignment]
    _HAS_PANDAS = False

from db_manager import CTIVault, parse_cvss_base_score

# Same eight features as Rust ``validate_features_bundle``.
PROJECT_FOLDERS = (
    "Intelx_Crawler",
    "CVE_Project_NVD",
    "ASM-fetch-main",
    "Ransomware_live_event_victim",
    "Phishing_and_Social_Media_All-in-one",
    "Social_MediaV2",
    "IOCs-crawler-main",
    "Compromised_user_Mac",
)

_EXTRA_OUTPUT_GLOBS = (
    "final_report",
    "csv_output",
    "output_result",
    "output",
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


def _cell_str(v: Any) -> str:
    if v is None:
        return ""
    if _HAS_PANDAS and isinstance(v, float) and pd is not None and pd.isna(v):
        return ""
    if isinstance(v, float) and math.isnan(v):
        return ""
    return str(v).strip()


def normalize_date(value: Any) -> str | None:
    """Normalize CSV date-like values to UTC ISO8601 ``...Z`` strings."""
    if value is None or value == "":
        return None
    if _HAS_PANDAS and pd is not None:
        try:
            if pd.isna(value):
                return None
        except (TypeError, ValueError):
            pass
        ts = pd.to_datetime(value, errors="coerce", utc=True)
        if pd.isna(ts):
            return None
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(value).strip()
    if not s or s.lower() in ("nan", "none", "n/a", "nat"):
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%d/%m/%Y",
    ):
        try:
            dt = datetime.strptime(s.replace("Z", ""), fmt.replace("Z", ""))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


def _default_date_iso() -> str:
    """Missing date columns default to ``datetime.now().isoformat()`` (naive local)."""
    return datetime.now().isoformat()


def _ingest_log_path() -> Path:
    """Prefer ``CTI_LOGS_DIR``; else Windows ``%LOCALAPPDATA%/Vault8/logs``; else ``~/.vault8/logs``."""
    ld = (os.environ.get("CTI_LOGS_DIR") or "").strip()
    if ld:
        return Path(ld).expanduser() / "ingest.log"
    if sys.platform == "win32":
        la = (os.environ.get("LOCALAPPDATA") or "").strip()
        if la:
            return Path(la) / "Vault8" / "logs" / "ingest.log"
    return Path.home() / ".vault8" / "logs" / "ingest.log"


def _append_ingest_log(message: str) -> None:
    p = _ingest_log_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{ts} {message}\n")
    except OSError:
        pass


def _pack_metadata(
    row: dict[str, str],
    consumed: set[str],
    *,
    source_csv: str,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Columns not mapped to top-level vault fields go into ``metadata`` (plus ``source_csv``)."""
    meta: dict[str, Any] = {"source_csv": source_csv}
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
        row: dict[str, Any],
        *,
        source_csv: str,
        fallback_scan_iso: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Return ``(mapped, None)`` on success. ``mapped`` includes ``table`` in
        ``{"ioc"|"cve"|"asm"}`` plus keys matching batch upsert tuples.

        On skip (missing critical primary), return ``(None, reason)``.
        """
        norm: dict[str, str] = {_norm_header(str(k)): _cell_str(v) for k, v in row.items()}

        if profile == "Intelx":
            consumed = {
                "selector",
                "query",
                "type",
                "date",
                "timestamp",
                "description",
                "summary",
            }
            selector = norm.get("selector") or norm.get("query") or ""
            if not selector:
                return None, "Intelx row missing IOC value (selector/query empty)"
            raw_type = norm.get("type") or ""
            ioc_type = _intelx_type_to_ioc_type(raw_type).lower()
            dt = normalize_date(norm.get("date") or norm.get("timestamp")) or _default_date_iso()
            meta = _pack_metadata(norm, consumed, source_csv=source_csv)
            return {
                "table": "ioc",
                "ioc_value": selector,
                "ioc_type": ioc_type,
                "first_seen": dt,
                "last_seen": dt,
                "source_project": "Intelx_Crawler",
                "metadata": meta,
            }, None

        if profile == "NVD":
            consumed = {
                "cve_id",
                "score",
                "severity_score",
                "published",
                "published_date",
                "updated_at",
                "lastmodified",
                "summary",
                "description",
                "cvss_v3.1",
                "cvss_v4.0",
            }
            cve_id = norm.get("cve_id") or ""
            if not cve_id.startswith("CVE-"):
                return None, f"NVD row missing or invalid cve_id: {cve_id!r}"
            score_raw = (
                norm.get("score")
                or norm.get("severity_score")
                or norm.get("cvss_v3.1")
                or norm.get("cvss_v4.0")
                or ""
            )
            sev: float | None
            try:
                sev = float(score_raw) if score_raw else None
            except ValueError:
                sev = parse_cvss_base_score(score_raw) if score_raw else None
            pub_raw = normalize_date(norm.get("published") or norm.get("published_date"))
            pub = (pub_raw or "").strip()
            upd = normalize_date(norm.get("updated_at") or norm.get("lastmodified")) or _default_date_iso()
            meta = _pack_metadata(norm, consumed, source_csv=source_csv)
            return {
                "table": "cve",
                "cve_id": cve_id,
                "severity_score": sev,
                "published_date": pub,
                "updated_at": upd,
                "metadata": meta,
            }, None

        if profile == "ASM":
            consumed = {
                "host",
                "hosts",
                "ip",
                "ips",
                "port",
                "ports",
                "opened_ports",
                "service",
                "services",
                "last_scan",
                "last_scan_at",
                "type",
                "unusual_ports",
            }
            host = norm.get("host") or norm.get("hosts") or ""
            ip = norm.get("ip") or norm.get("ips") or ""
            if not host and not ip:
                return None, "ASM row missing asset_target (host/ip empty)"
            if host and ip and ip.upper() != "N/A":
                asset_target = f"{host}|{ip}"
            elif host:
                asset_target = host
            else:
                asset_target = ip
            port = norm.get("port") or norm.get("ports") or norm.get("opened_ports") or ""
            service = norm.get("service") or norm.get("services") or ""
            scan_fb = fallback_scan_iso or _default_date_iso()
            last_scan = normalize_date(norm.get("last_scan") or norm.get("last_scan_at")) or scan_fb
            asset_type = (
                (norm.get("type") or "").strip()
                or ("service" if service else ("host_ip" if ip else "host"))
            )
            status = (norm.get("status") or "active").strip() or "active"
            extras: dict[str, Any] = {}
            if port:
                extras["port"] = port[:400]
            if service:
                extras["service"] = service[:400]
            if host and ip:
                extras["host"] = host
                extras["ip"] = ip
            meta = _pack_metadata(norm, consumed, source_csv=source_csv, extras=extras)
            return {
                "table": "asm",
                "asset_target": asset_target,
                "asset_type": asset_type,
                "last_scan_at": last_scan,
                "status": status,
                "metadata": meta,
            }, None

        if profile == "Ransomware":
            consumed = {
                "website",
                "url",
                "site",
                "date",
                "event_date",
                "victim_name",
                "company",
                "victim",
                "group",
                "group_name",
            }
            website = norm.get("website") or norm.get("url") or norm.get("site") or ""
            if not website:
                return None, "Ransomware row missing IOC value (website/url/site empty)"
            dt = normalize_date(norm.get("date") or norm.get("event_date")) or _default_date_iso()
            victim = norm.get("victim_name") or norm.get("company") or norm.get("victim") or ""
            group = norm.get("group") or norm.get("group_name") or ""
            meta = _pack_metadata(
                norm,
                consumed,
                source_csv=source_csv,
                extras={"victim_name": victim, "group": group},
            )
            return {
                "table": "ioc",
                "ioc_value": website,
                "ioc_type": "url",
                "first_seen": dt,
                "last_seen": dt,
                "source_project": "Ransomware_live_event_victim",
                "metadata": meta,
            }, None

        if profile == "IOC_Crawler":
            consumed = {
                "indicator",
                "ioc_value",
                "type",
                "ioc_type",
                "source",
                "source_project",
                "tags",
                "tag",
                "first_seen",
                "last_seen",
            }
            indicator = norm.get("indicator") or norm.get("ioc_value") or ""
            if not indicator:
                return None, "IOC_Crawler row missing IOC value (indicator/ioc_value empty)"
            ioc_type = (norm.get("type") or norm.get("ioc_type") or "unknown").lower() or "unknown"
            origin = norm.get("source") or norm.get("source_project") or "IOCs-crawler-main"
            tags = norm.get("tags") or norm.get("tag") or ""
            fs = normalize_date(norm.get("first_seen")) or _default_date_iso()
            ls = normalize_date(norm.get("last_seen")) or _default_date_iso()
            meta = _pack_metadata(norm, consumed, source_csv=source_csv, extras={"tags": tags})
            return {
                "table": "ioc",
                "ioc_value": indicator,
                "ioc_type": ioc_type,
                "first_seen": fs,
                "last_seen": ls,
                "source_project": origin or "IOCs-crawler-main",
                "metadata": meta,
            }, None

        if profile == "Phishing":
            consumed = {
                "phish_url",
                "url",
                "phishing_url",
                "target_brand",
                "brand",
                "target",
                "status",
                "first_seen",
                "last_seen",
            }
            url = norm.get("phish_url") or norm.get("url") or norm.get("phishing_url") or ""
            if not url:
                return None, "Phishing row missing IOC value (phish_url/url empty)"
            brand = norm.get("target_brand") or norm.get("brand") or norm.get("target") or ""
            status = norm.get("status") or ""
            fs = normalize_date(norm.get("first_seen")) or _default_date_iso()
            ls = normalize_date(norm.get("last_seen")) or _default_date_iso()
            meta = _pack_metadata(
                norm,
                consumed,
                source_csv=source_csv,
                extras={"target_brand": brand, "status": status},
            )
            return {
                "table": "ioc",
                "ioc_value": url,
                "ioc_type": "phishing_url",
                "first_seen": fs,
                "last_seen": ls,
                "source_project": "Phishing_and_Social_Media_All-in-one",
                "metadata": meta,
            }, None

        if profile == "Social":
            consumed = {
                "profile_link",
                "url",
                "link",
                "handle",
                "username",
                "user",
                "platform",
                "first_seen",
                "last_seen",
            }
            link = norm.get("profile_link") or norm.get("url") or norm.get("link") or ""
            if not link:
                return None, "Social row missing IOC value (profile_link/url empty)"
            handle = norm.get("handle") or norm.get("username") or norm.get("user") or ""
            platform = norm.get("platform") or ""
            fs = normalize_date(norm.get("first_seen")) or _default_date_iso()
            ls = normalize_date(norm.get("last_seen")) or _default_date_iso()
            meta = _pack_metadata(
                norm,
                consumed,
                source_csv=source_csv,
                extras={"handle": handle, "platform": platform},
            )
            return {
                "table": "ioc",
                "ioc_value": link,
                "ioc_type": "social",
                "first_seen": fs,
                "last_seen": ls,
                "source_project": "Social_MediaV2",
                "metadata": meta,
            }, None

        if profile == "Mac_Audit":
            consumed = {
                "hash",
                "sha256",
                "ioc_value",
                "file_path",
                "path",
                "filepath",
                "detection_name",
                "detection",
                "name",
                "first_seen",
                "last_seen",
            }
            h = norm.get("hash") or norm.get("sha256") or norm.get("ioc_value") or ""
            if not h or len(h) < 32 or not all(c in "0123456789abcdefABCDEF" for c in h):
                return None, "Mac_Audit row missing or invalid hash (ioc_value)"
            fpath = norm.get("file_path") or norm.get("path") or norm.get("filepath") or ""
            det = norm.get("detection_name") or norm.get("detection") or norm.get("name") or ""
            fs = normalize_date(norm.get("first_seen")) or _default_date_iso()
            ls = normalize_date(norm.get("last_seen")) or _default_date_iso()
            meta = _pack_metadata(
                norm,
                consumed,
                source_csv=source_csv,
                extras={"file_path": fpath, "detection_name": det},
            )
            return {
                "table": "ioc",
                "ioc_value": h.lower(),
                "ioc_type": "sha256",
                "first_seen": fs,
                "last_seen": ls,
                "source_project": "Compromised_user_Mac",
                "metadata": meta,
            }, None

        if profile == "IOC_Generic":
            consumed = {
                "ioc_value",
                "value",
                "url",
                "email",
                "indicator",
                "ioc_type",
                "type",
                "first_seen",
                "firstseen",
                "last_seen",
                "lastseen",
                "source_project",
                "project",
            }
            val = (
                norm.get("ioc_value")
                or norm.get("value")
                or norm.get("url")
                or norm.get("email")
                or norm.get("indicator")
                or ""
            )
            if not val:
                return None, "IOC row missing IOC value"
            ioc_type = (norm.get("ioc_type") or norm.get("type") or "unknown").lower() or "unknown"
            fs = normalize_date(norm.get("first_seen") or norm.get("firstseen")) or _default_date_iso()
            ls = normalize_date(norm.get("last_seen") or norm.get("lastseen")) or _default_date_iso()
            proj = norm.get("source_project") or norm.get("project") or "csv_ingest"
            meta = _pack_metadata(norm, consumed, source_csv=source_csv)
            return {
                "table": "ioc",
                "ioc_value": val,
                "ioc_type": ioc_type,
                "first_seen": fs,
                "last_seen": ls,
                "source_project": proj or "csv_ingest",
                "metadata": meta,
            }, None

        return None, f"Unknown FieldMapper profile: {profile!r}"


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    """Return (normalized_headers, rows_as_dicts)."""
    if _HAS_PANDAS:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        df.columns = [_norm_header(str(c)) for c in df.columns]
        rows = df.to_dict(orient="records")
        return list(df.columns), rows
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        if not r.fieldnames:
            return [], []
        rows = []
        for raw in r:
            rows.append({_norm_header(k): v for k, v in raw.items() if k})
        return list(rows[0].keys()) if rows else [], rows


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


def detect_project_type(path: Path, columns: Iterable[str]) -> str:
    """Infer ``CVE`` | ``IOC`` | ``ASM`` when path is not under a known project folder."""
    p = str(path).lower()
    colset = {str(c).lower() for c in columns}

    if "asm-fetch" in p or "asm_fetch" in p or path.name.endswith("_subdomains.csv"):
        if "hosts" in colset or "host" in colset:
            return "ASM"
    if "hosts" in colset and ("ips" in colset or "ip" in colset):
        return "ASM"

    if "cve_project_nvd" in p or "cve_id" in colset:
        return "CVE"
    if any(c.startswith("cvss") for c in colset) and ("description" in colset or "cve_id" in colset):
        return "CVE"

    if (
        "ioc_value" in colset
        or "ioc_type" in colset
        or ("intelx_crawler" in p and ("url" in colset or "email" in colset))
        or ("type" in colset and "value" in colset)
    ):
        return "IOC"

    if "intelx" in p or "csv_output" in p or "final_report" in p:
        return "IOC"

    return "IOC"


class CSVIngestor:
    """Bridge CSV outputs (pandas when available) into a ``CTIVault``."""

    def __init__(self, vault: CTIVault) -> None:
        self.vault = vault

    def map_fields(
        self,
        project_profile: str,
        row: dict[str, Any],
        *,
        source_csv: str = "",
        fallback_scan_iso: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Delegate to ``FieldMapper`` (trim, ``ioc_type`` lower, metadata packing)."""
        return FieldMapper.map_fields(
            project_profile,
            row,
            source_csv=source_csv,
            fallback_scan_iso=fallback_scan_iso,
        )

    def _ingest_mapped(
        self,
        rows: list[dict[str, Any]],
        source: Path,
        profile: str,
        *,
        fallback_scan_iso: str | None = None,
    ) -> int:
        if profile == "ASM" and not fallback_scan_iso:
            fallback_scan_iso = (
                normalize_date(datetime.fromtimestamp(source.stat().st_mtime, tz=timezone.utc))
                or _default_date_iso()
            )
        ioc_batch: list[tuple[str, str, str, str, str | None, str | None]] = []
        cve_batch: list[tuple[str, float | None, str, str, str | None]] = []
        asm_batch: list[tuple[str, str, str, str, str | None]] = []

        for raw in rows:
            mapped, err = FieldMapper.map_fields(
                profile,
                raw,
                source_csv=source.name,
                fallback_scan_iso=fallback_scan_iso,
            )
            if err:
                _append_ingest_log(f"{source}: {err}")
                continue
            t = mapped["table"]
            if t == "ioc":
                meta = mapped.get("metadata") or {}
                meta_str = json.dumps(meta, ensure_ascii=False) if meta else None
                ioc_batch.append(
                    (
                        mapped["ioc_value"],
                        mapped["ioc_type"],
                        mapped["first_seen"],
                        mapped["last_seen"],
                        mapped.get("source_project"),
                        meta_str,
                    )
                )
            elif t == "cve":
                meta = mapped.get("metadata") or {}
                meta_str = json.dumps(meta, ensure_ascii=False) if meta else None
                cve_batch.append(
                    (
                        mapped["cve_id"],
                        mapped["severity_score"],
                        mapped["published_date"],
                        mapped["updated_at"],
                        meta_str,
                    )
                )
            elif t == "asm":
                meta = mapped.get("metadata") or {}
                meta_str = json.dumps(meta, ensure_ascii=False) if meta else None
                asm_batch.append(
                    (
                        mapped["asset_target"],
                        mapped["asset_type"],
                        mapped["last_scan_at"],
                        mapped["status"],
                        meta_str,
                    )
                )

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
        path = Path(file_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(path)

        columns, rows = _read_csv(path)
        if not rows:
            return 0

        folder = (project_folder or "").strip() or _project_folder_from_path(path)
        ws = Path(workspace_root).expanduser().resolve() if workspace_root else None

        if folder in FOLDER_TO_PROFILE:
            prof = FOLDER_TO_PROFILE[folder]
            fb = (
                normalize_date(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc))
                or _default_date_iso()
                if prof == "ASM"
                else None
            )
            n = self._ingest_mapped(rows, path, prof, fallback_scan_iso=fb)
            self._maybe_archive_csv(path, ws, folder)
            return n

        pt = (project_type or detect_project_type(path, columns)).upper()
        if pt == "CVE":
            n = self._ingest_mapped(rows, path, "NVD")
            self._maybe_archive_csv(path, ws, folder)
            return n
        if pt == "ASM":
            fb = normalize_date(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)) or _default_date_iso()
            n = self._ingest_mapped(rows, path, "ASM", fallback_scan_iso=fb)
            self._maybe_archive_csv(path, ws, folder)
            return n
        if pt == "IOC":
            n = self._ingest_mapped(rows, path, "IOC_Generic")
            self._maybe_archive_csv(path, ws, folder)
            return n
        raise ValueError(f"Unknown project_type: {pt}")

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

    def sync_project_outputs(self, base_dir: Path | str) -> dict[str, Any]:
        """
        Walk the eight project trees under ``base_dir``, ingest CSVs under common output dirs.

        Skips files whose mtime matches the last successful ingest (stored in ``vault_meta``).
        CSVs under ``archived_logs`` are ignored. After a successful ingest, files are moved to
        ``<project>/output/archived_logs/`` when they live under the workspace tree.
        """
        root = Path(base_dir).expanduser().resolve()
        summary: dict[str, Any] = {"root": str(root), "files": [], "rows": 0}
        if not root.is_dir():
            raise NotADirectoryError(root)

        for proj in PROJECT_FOLDERS:
            base = root / proj
            if not base.is_dir():
                continue
            candidates: list[Path] = []
            for sub in _EXTRA_OUTPUT_GLOBS:
                d = base / sub
                if d.is_dir():
                    candidates.extend(d.rglob("*.csv"))
            for path in sorted(set(candidates)):
                if not path.is_file():
                    continue
                if "archived_logs" in path.parts:
                    continue
                if self._should_skip(path):
                    summary["files"].append({"path": str(path), "status": "skipped", "rows": 0})
                    continue
                try:
                    n = self.ingest_csv(path, project_folder=proj, workspace_root=root)
                    if path.is_file():
                        self._mark_done(path)
                    summary["rows"] += n
                    summary["files"].append(
                        {"path": str(path), "status": "ok", "rows": n, "project_folder": proj}
                    )
                except Exception as e:  # noqa: BLE001
                    summary["files"].append({"path": str(path), "status": "error", "error": str(e)})
        return summary


def run_sync(workspace: str | None = None) -> dict[str, Any]:
    ws = (workspace or os.environ.get("CTI_WORKSPACE_PATH") or "").strip()
    if not ws:
        raise SystemExit("WORKSPACE path required (arg or CTI_WORKSPACE_PATH)")
    with CTIVault() as vault:
        ing = CSVIngestor(vault)
        return ing.sync_project_outputs(ws)


def run_ingest_file(path: str, project_type: str | None, project_folder: str | None) -> dict[str, Any]:
    ws = (os.environ.get("CTI_WORKSPACE_PATH") or "").strip()
    with CTIVault() as vault:
        ing = CSVIngestor(vault)
        n = ing.ingest_csv(
            path,
            project_type,
            project_folder=project_folder,
            workspace_root=ws or None,
        )
        return {"path": path, "rows": n}


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(description="CTI CSV vault ingestor")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_sync = sub.add_parser("sync", help="Ingest all known project output CSVs under workspace")
    p_sync.add_argument(
        "workspace",
        nargs="?",
        default=os.environ.get("CTI_WORKSPACE_PATH", ""),
        help="Writable workspace root (default: CTI_WORKSPACE_PATH)",
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
        out = run_sync(args.workspace or None)
        print(json.dumps(out, indent=2))
        errors = [f for f in out["files"] if f.get("status") == "error"]
        return 1 if errors else 0
    if args.cmd == "ingest-file":
        out = run_ingest_file(args.file, args.type, args.project)
        print(json.dumps(out, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

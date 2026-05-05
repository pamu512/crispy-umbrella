"""
CVE_Project_NVD — non-interactive CLI for download, update, and search pipelines.

Search results are written to output_result/merged_cve_result.csv, then upserted into
the vault table cve_data using CTI_DB_PATH (same as the Rust CVE sidecar host).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

from NVD_CVE.SearchCVE import Search_NVD_CVE
from NVD_CVE.update_nvd_feeds import Update_NVD
from NVD_CVE.download_nvd_feeds import download_nvd_feeds

from Expolited_POC import Expolited_POC_start

from filter_cve import start_filter_cvss

from CVE_Project_CVE.SearchCVE import Search_CVE_Project_CVE
from CVE_Project_CVE.download_update_CVE_Project import download_update_CVEsP_feeds

from OT_Vulnerability.SearchCVE import Search_OT_CVE

from combine_CP_NVD import combine_CP_NVD
from combine_CP_NVD_OT import combine_cp_nvd_ot

from verify_cve_date import start_verify_cve_date


def _nvd_json_feeds_present() -> bool:
    d = Path(__file__).resolve().parent / "NVD_CVE" / "JSON"
    if not d.is_dir():
        return False
    return any(d.glob("nvdcve-2.0-*.json"))


def run_cti_auto_feeds() -> None:
    """
    First run (no marker, no NVD year JSON yet): full download like interactive 'download'.
    Later runs: incremental NVD + CVE Project update like interactive 'update'.

    Used when the project is launched from the toolbox with CTI_NON_INTERACTIVE and no CLI args.
    """
    root = Path(__file__).resolve().parent
    marker = root / ".cti_feeds_bootstrapped"

    if marker.exists() or _nvd_json_feeds_present():
        if not marker.exists() and _nvd_json_feeds_present():
            print(
                "CTI auto: existing NVD JSON feeds found — treating as already bootstrapped; "
                "using update mode. (Marker written.)"
            )
            marker.write_text("migrated\n", encoding="utf-8")
        print("CTI auto: follow-up run → updating NVD + CVE Project feeds…")
        Update()
        return

    print("CTI auto: first run → downloading NVD + CVE Project feeds (one-time bootstrap)…")
    download_nvd_feeds()
    download_update_CVEsP_feeds()
    marker.write_text("ok\n", encoding="utf-8")
    print("CTI auto: bootstrap complete. Next runs will use update mode.")


def Update():
    print("Updating NVD feeds...")
    Update_NVD()

    print("Updating CVE Project data...")
    download_update_CVEsP_feeds()


def Search(start_date, end_date, target_sources, CVSS_info=None):
    if CVSS_info is None:
        CVSS_info = {}
    output_dir = Path("output_result")
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"Search CVEs from {start_date} to {end_date} for target sources: "
        f"{target_sources if target_sources else 'All Sources'}"
    )
    target_sources = {s.lower() for s in target_sources}

    Search_NVD_CVE(start_date, end_date, target_sources)

    Search_CVE_Project_CVE(start_date, end_date, target_sources)

    combine_CP_NVD()

    Search_OT_CVE(start_date, end_date, target_sources)

    combine_cp_nvd_ot()

    start_filter_cvss(CVSS_info)

    start_verify_cve_date()

    Expolited_POC_start()


def parse_cvss_score(cell: Optional[str]) -> Optional[float]:
    if cell is None:
        return None
    s = str(cell).strip()
    if not s or s == "N/A":
        return None
    m = re.search(r"(\d+\.?\d*)", s)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _metadata_from_row(row: Dict[str, str]) -> str:
    desc = (row.get("Description") or "").strip()
    payload: Dict[str, Any] = {
        "description": desc or None,
        "vendor": (row.get("Vendor") or "").strip() or None,
        "title": (row.get("Title") or "").strip() or None,
        "weaknesses": (row.get("Weaknesses") or "").strip() or None,
        "references": (row.get("References") or "").strip() or None,
        "source_identifier": (row.get("Source Identifier") or "").strip() or None,
        "types_of_vulnerability": (row.get("Types of Vulnerability") or "").strip() or None,
        "cvss_v31_cell": (row.get("CVSS v3.1") or "").strip() or None,
        "cvss_v40_cell": (row.get("CVSS v4.0") or "").strip() or None,
        "database": (row.get("DataBase") or "").strip() or None,
        "ingested_via": "cve_project_nvd_search",
    }
    if row.get("Source"):
        payload["source"] = (row.get("Source") or "").strip() or None
    return json.dumps(payload, ensure_ascii=False)


def ingest_merged_csv_to_cve_data(db_path: Path, merged_csv: Path) -> int:
    if not merged_csv.is_file():
        raise FileNotFoundError(f"merged CSV not found: {merged_csv}")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        sql = """
            INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
              severity_score = excluded.severity_score,
              published_date = excluded.published_date,
              updated_at = excluded.updated_at,
              metadata = excluded.metadata
        """
        n = 0
        with merged_csv.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = (row.get("CVE ID") or "").strip()
                if not cve_id:
                    continue
                pub = (row.get("Published Date") or "").strip()
                last_mod = (row.get("Last Modified") or "").strip() or pub or now

                sev = parse_cvss_score(row.get("CVSS v3.1"))
                if sev is None:
                    sev = parse_cvss_score(row.get("CVSS v4.0"))

                meta = _metadata_from_row(row)
                cur.execute(sql, (cve_id, sev, pub, last_mod, meta))
                n += 1
        conn.commit()
        return n
    finally:
        conn.close()


def _parse_vendor_arg(vendor: str) -> Set[str]:
    v = vendor.strip()
    if not v:
        print("ERROR: --vendor must not be empty (use '*' for all sources).", file=sys.stderr)
        sys.exit(2)
    if v.lower() in ("*", "all"):
        return set()
    return {s.strip().lower() for s in v.split(",") if s.strip()}


def main_cli() -> None:
    parser = argparse.ArgumentParser(
        description="CVE_Project_NVD: download feeds, incremental update, or search + vault ingest."
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=("download", "update", "search"),
        help="download: NVD + CVE Project feeds; update: incremental; search: query window + upsert cve_data",
    )
    parser.add_argument("--start-date", dest="start_date", help="Search start (YYYY-MM-DD)")
    parser.add_argument("--end-date", dest="end_date", help="Search end (YYYY-MM-DD)")
    parser.add_argument(
        "--vendor",
        dest="vendor",
        help="Comma-separated vendors, or '*' / 'all' for any source",
    )
    args = parser.parse_args()

    if args.action == "search":
        if not args.start_date or not args.end_date or args.vendor is None:
            parser.error("search requires --start-date, --end-date, and --vendor")
        if not str(args.vendor).strip():
            parser.error("--vendor must not be empty (use '*' for all sources)")
        target_sources = _parse_vendor_arg(args.vendor)
        sd = args.start_date.strip()
        ed = args.end_date.strip()
        if not sd or not ed:
            parser.error("start/end dates must be non-empty (YYYY-MM-DD)")
        Search(sd, ed, target_sources, {})
        db_env = os.environ.get("CTI_DB_PATH", "").strip()
        if not db_env:
            print("ERROR: CTI_DB_PATH is not set; cannot ingest into cve_data.", file=sys.stderr)
            sys.exit(1)
        root = Path(__file__).resolve().parent
        merged = root / "output_result" / "merged_cve_result.csv"
        try:
            inserted = ingest_merged_csv_to_cve_data(Path(db_env), merged)
        except Exception as e:
            print(f"ERROR: vault ingest failed: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"✅ Upserted {inserted} row(s) into cve_data at {db_env}")
        return

    if args.action == "download":
        download_nvd_feeds()
        download_update_CVEsP_feeds()
        return

    if args.action == "update":
        Update()
        return


if __name__ == "__main__":
    # Toolbox / Armory: `python main.py` with CTI_NON_INTERACTIVE and no CLI args (legacy).
    if os.environ.get("CTI_NON_INTERACTIVE") == "1" and len(sys.argv) <= 1:
        run_cti_auto_feeds()
        sys.exit(0)

    main_cli()

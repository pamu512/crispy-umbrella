import os
import json
import csv
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

BASE_DIR = "CVE_Project_CVE/cves/cves"
OUTPUT_CSV = "output_result/CP_cve_search_result.csv"


# Extract single CVE JSON
def extract_fields(json_path: str):
    """Extract required fields from a CVE JSON file."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except:
        return None  # Skip unreadable files

    meta = data.get("cveMetadata", {})
    cna = data.get("containers", {}).get("cna", {})
    adp = data.get("containers", {}).get("adp", [])

    cve_id = meta.get("cveId", "")
    published = meta.get("datePublished", "")
    last_modified = meta.get("dateUpdated", "")

    # Vendor
    vendor_name = "N/A"
    for aff in cna.get("affected", []):
        v = aff.get("vendor", "")
        if v:
            vendor_name = v
            break

    # CVSS
    cvss_v31 = "N/A"
    cvss_v4 = "N/A"

    metrics = cna.get("metrics", [])
    for metric in metrics:
        if "cvssV3_1" in metric:
            score = metric["cvssV3_1"].get("baseScore", "")
            severity = metric["cvssV3_1"].get("baseSeverity", "")
            cvss_v31 = f"{score} ({severity})"
        if "cvssV4_0" in metric:
            score = metric["cvssV4_0"].get("baseScore", "")
            severity = metric["cvssV4_0"].get("baseSeverity", "")
            cvss_v4 = f"{score} ({severity})"

    # ADP metrics (override)
    for entry in adp:
        for metric in entry.get("metrics", []):
            if "cvssV3_1" in metric:
                score = metric["cvssV3_1"].get("baseScore", "")
                severity = metric["cvssV3_1"].get("baseSeverity", "")
                cvss_v31 = f"{score} ({severity})"
            if "cvssV4_0" in metric:
                score = metric["cvssV4_0"].get("baseScore", "")
                severity = metric["cvssV4_0"].get("baseSeverity", "")
                cvss_v4 = f"{score} ({severity})"

    # Weaknesses
    weaknesses = []
    problem_types = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            if desc.get("lang") in ("en", "en-US"):
                weaknesses.append(desc.get("cweId", ""))
                problem_types.append(desc.get("description", ""))
    weaknesses = "; ".join([w for w in weaknesses if w])
    problem_types = "; ".join([p for p in problem_types if p])

    # Description
    description = ""
    for desc in cna.get("descriptions", []):
        if desc.get("lang") in ("en", "en-US"):
            description = desc.get("value", "")
            break

    # References
    refs = []
    for ref in cna.get("references", []):
        if ref.get("url"):
            refs.append(ref["url"])
    refs = "; ".join(refs)

    # Title
    title = cna.get("title", "")
    if not title:
        if adp:
            title = adp[0].get("title", "")
        if not title:
            title = "N/A"

    return {
        "DataBase": "CVE_Project",
        "CVE ID": cve_id,
        "Vendor": vendor_name,
        "Published Date": published,
        "Last Modified": last_modified,
        "CVSS v3.1": cvss_v31,
        "CVSS v4.0": cvss_v4,
        "Weaknesses": weaknesses,
        "Description": description,
        "References": refs,
        "Source Identifier": "N/A",
        "Types of Vulnerability": problem_types,
        "Title": title
    }


# Parallel processing wrapper
def process_json_parallel(args):
    """Worker function for multiprocessing."""
    json_path, start, end, target_sources = args

    # Load JSON
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except:
        return None

    # Parse date
    meta = data.get("cveMetadata", {})
    published = meta.get("datePublished", None)
    if not published:
        return None

    try:
        pub_date = datetime.fromisoformat(published)
        if pub_date.tzinfo:
            pub_date = pub_date.replace(tzinfo=None)
    except:
        return None

    if not (start <= pub_date <= end):
        return None

    # Vendor filtering
    cna = data.get("containers", {}).get("cna", {})
    if target_sources:
        vendor_match = False
        for aff in cna.get("affected", []):
            v = aff.get("vendor", "").lower()
            if any(t in v for t in target_sources):
                vendor_match = True
                break
        if not vendor_match:
            return None

    return extract_fields(json_path)


# Main function with multiprocessing
def Search_CVE_Project_CVE(start_date, end_date, target_sources=set(), max_workers=8):
    start = datetime.fromisoformat(start_date)
    end = datetime.fromisoformat(end_date)

    start_year = start.year
    end_year = end.year
    years_to_scan = range(start_year, end_year + 1)

    json_files = []
    print("Start scanning CVE Project JSON files...")
    for year in years_to_scan:
        ydir = Path(BASE_DIR) / str(year)
        if not ydir.exists():
            continue
        for fp in ydir.rglob("CVE-*.json"):
            json_files.append(fp)

    print(f"Total JSON files to scan: {len(json_files)}")

    args_list = [
        (str(fp), start, end, [ts.lower() for ts in target_sources])
        for fp in json_files
    ]

    results = []
    with ProcessPoolExecutor(max_workers=max_workers) as exe:
        for result in tqdm(exe.map(process_json_parallel, args_list), total=len(args_list)):
            if result:
                results.append(result)

    # Write CSV
    Path("output_result").mkdir(exist_ok=True)

    fieldnames = [
        "DataBase", "CVE ID", "Vendor", "Published Date", "Last Modified",
        "CVSS v3.1", "CVSS v4.0", "Weaknesses",
        "Description", "References", "Source Identifier",
        "Types of Vulnerability", "Title"
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Done. Saved: {OUTPUT_CSV}")
    print(f"Total matches: {len(results)}")

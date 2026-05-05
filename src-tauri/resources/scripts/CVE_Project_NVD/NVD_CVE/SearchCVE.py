import json
import csv
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor
from tqdm import tqdm


JSON_DIR = Path("NVD_CVE/JSON")
OUTPUT_FILE = "output_result/NVD_cve_search_result.csv"


# Extract single CVE structure
def extract_cve_details(cve):
    cve_id = cve.get("id", "N/A")

    source = cve.get("sourceIdentifier", "N/A")
    if "@" in source:
        vendor = source.split("@")[1].split(".")[0].upper()
    else:
        vendor = "N/A"

    published = cve.get("published", "N/A")
    last_modified = cve.get("lastModified", "N/A")

    metrics = cve.get("metrics", {})

    # CVSS v3.1
    cvss3 = "N/A"
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss3 = f"{cvss.get('baseScore')} ({cvss.get('baseSeverity')})"

    # CVSS v4.0
    cvss4 = "N/A"
    if "cvssMetricV40" in metrics:
        cvss = metrics["cvssMetricV40"][0].get("cvssData", {})
        cvss4 = f"{cvss.get('baseScore')} ({cvss.get('baseSeverity')})"

    # Weaknesses
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                weaknesses.append(d.get("value"))
    weaknesses = "; ".join(weaknesses) if weaknesses else "N/A"

    # Description
    description = "N/A"
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value")
            break

    refs = [ref["url"] for ref in cve.get("references", []) if "url" in ref]
    refs = "; ".join(refs) if refs else "N/A"

    return {
        "DataBase": "NVD",
        "CVE ID": cve_id,
        "Vendor": vendor,
        "Published Date": published,
        "Last Modified": last_modified,
        "CVSS v3.1": cvss3,
        "CVSS v4.0": cvss4,
        "Weaknesses": weaknesses,
        "Description": description,
        "References": refs,
        "Source Identifier": source,
        "Types of Vulnerability": "N/A",
        "Title": "N/A"
    }


# Worker: Process a single NVD JSON file
def process_single_json(args):
    file_path, start, end, target_sources = args

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except:
        return []  # skip broken file

    vulns = data.get("vulnerabilities", [])
    res = []

    for item in vulns:
        cve = item.get("cve", {})
        pub = cve.get("published", None)
        if not pub:
            continue

        try:
            pub_date = datetime.fromisoformat(pub)
        except:
            continue

        if not (start <= pub_date <= end):
            continue

        # vendor filter
        if target_sources:
            src = cve.get("sourceIdentifier", "")
            if "@" in src:
                vendor = src.split("@")[1].split(".")[0].lower()
            else:
                vendor = ""

            if vendor not in target_sources:
                continue

        res.append(extract_cve_details(cve))

    return res


# Main: Multi-core execution
def Search_NVD_CVE(start_date, end_date, target_sources=set(), max_workers=8):

    start = datetime.fromisoformat(start_date)
    end = datetime.fromisoformat(end_date)

    start_year = start.year
    end_year = end.year

    # Only scan years between start_date & end_date
    json_files = []
    for year in range(start_year, end_year + 1):
        fp = JSON_DIR / f"nvdcve-2.0-{year}.json"
        if fp.exists():
            json_files.append(fp)

    print(f"Scanning NVD Database JSON files: {len(json_files)}")

    args = [
        (fp, start, end, {v.lower() for v in target_sources})
        for fp in json_files
    ]

    results = []

    with ProcessPoolExecutor(max_workers=max_workers) as exe:
        for part in tqdm(exe.map(process_single_json, args), total=len(args)):
            results.extend(part)

    # Save CSV
    Path("output_result").mkdir(exist_ok=True)

    df_fields = [
        "DataBase", "CVE ID", "Vendor",
        "Published Date", "Last Modified",
        "CVSS v3.1", "CVSS v4.0",
        "Weaknesses", "Description",
        "References", "Source Identifier",
        "Types of Vulnerability", "Title"
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=df_fields)
        writer.writeheader()
        writer.writerows(results)

    print(f"Done. Saved: {OUTPUT_FILE}")
    print(f"Matched records: {len(results)}")

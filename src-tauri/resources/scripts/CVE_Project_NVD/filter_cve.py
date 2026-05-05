import csv
import re

INPUT_FILE = "output_result/merged_cve_result.csv"
OUTPUT_FILE = "output_result/merged_cve_result.csv"

# Extract CVSS score "7.5 (HIGH)" → 7.5
# ===============================
def parse_score(val):
    if val in (None, "", "N/A"):
        return None
    try:
        # Extract float at beginning
        m = re.match(r"^\s*([0-9]+(\.[0-9]+)?)", val)
        if m:
            return float(m.group(1))
        return None
    except:
        return None


# CVSS Filtering Logic
# ===============================
def cvss_filter(row, CVSS_info):
    v3 = parse_score(row.get("CVSS v3.1"))
    v4 = parse_score(row.get("CVSS v4.0"))

    # Case 1: both missing → exclude
    if v3 is None and v4 is None:
        return False

    op3, th3 = CVSS_info.get("V3", (None, None))
    op4, th4 = CVSS_info.get("V4", (None, None))

    # If no threshold is set (None, None) → allow all CVEs that have any CVSS
    if op3 is None and th3 is None and op4 is None and th4 is None:
        return True

    # Case 2: V3 match
    if op3 and th3 is not None and v3 is not None:
        if op3 == '>' and v3 > th3: return True
        if op3 == '>=' and v3 >= th3: return True
        if op3 == '<' and v3 < th3: return True
        if op3 == '<=' and v3 <= th3: return True
        if op3 == '=' and v3 == th3: return True

    # Case 3: V4 match
    if op4 and th4 is not None and v4 is not None:
        if op4 == '>' and v4 > th4: return True
        if op4 == '>=' and v4 >= th4: return True
        if op4 == '<' and v4 < th4: return True
        if op4 == '<=' and v4 <= th4: return True
        if op4 == '=' and v4 == th4: return True

    return False


# Main: filter merged_cve_result.csv
# ===============================
def filter_merged_cve(CVSS_info):
    rows = []

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    filtered = [row for row in rows if cvss_filter(row, CVSS_info)]

    print("======================================")
    print(" Start filtering CVSS thresholds ")
    print(f"Total input CVEs: {len(rows)}")
    print(f"Total removed: {len(rows) - len(filtered)}")
    print(f"Total output CVEs: {len(filtered)}")
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys(), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(filtered)

    print(f"✅Finished output saved to: {OUTPUT_FILE}")


def start_filter_cvss(CVSS_info):
    filter_merged_cve(CVSS_info)

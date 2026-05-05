import csv
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import re




def extract_urls(ref_text: str) -> list[str]:
    """
    Extract URLs from a references field where URLs are typically separated by ';'.
    Also tolerates commas/newlines/extra text.
    Keeps order, removes duplicates.
    """
    if not ref_text or ref_text == "N/A":
        return []

    text = str(ref_text).strip()

    parts = re.split(r"\s*;\s*|\s*,\s*|\s*\n\s*", text)

    out: list[str] = []
    seen = set()

    for p in parts:
        p = p.strip()
        if not p:
            continue

        # Prefer token itself if it looks like a URL
        if p.startswith(("http://", "https://")):
            url = p
            if url not in seen:
                out.append(url)
                seen.add(url)
            continue

        # Fallback: find URLs inside the chunk
        for url in re.findall(r'https?://[^\s"\']+', p):
            if url not in seen:
                out.append(url)
                seen.add(url)

    return out

def merge_references(cp_ref: str | None, nvd_ref: str | None) -> str:
    """
    Merge CP + NVD references into one '; '-separated string, de-duplicate URLs.
    Order: CP first, then NVD.
    """
    cp_urls = extract_urls(cp_ref)
    nvd_urls = extract_urls(nvd_ref)

    merged: list[str] = []
    seen = set()

    for u in cp_urls + nvd_urls:
        if u and u not in seen:
            merged.append(u)
            seen.add(u)

    return "; ".join(merged) if merged else "N/A"



EXPECTED_HEADERS = [
    "DataBase", "CVE ID", "Vendor", "Published Date", "Last Modified", 
    "CVSS v3.1", "CVSS v4.0", "Weaknesses", "Description", "References", 
    "Source Identifier", "Types of Vulnerability", "Title"
]

def read_cve_data(path: str) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
    """
    Use csv.DictReader to read the CSV file and organize the data into a dictionary with 'CVE ID' as the key.
    It also returns the actual field headers for inspection.
    """
    data_map = {}
    actual_headers = []
    total_lines = 0  # Total number of rows counter
    
    try:
        with open(path, mode='r', newline='', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            try:
                actual_headers = next(reader)
                total_lines += 1 # Calculate header lines
            except StopIteration:
                print(f"⚠️ {path}  are empty file.")
                return {}, []

            f.seek(0)
            dict_reader = csv.DictReader(f)
            
            valid_cve_count = 0 # 新增：有效 CVE 計數器
            
            for row in dict_reader:
                total_lines += 1
                
            # Check if the number of fields is correct (this is a crucial step in resolving CSV misalignment issues)
            # Here, we use the number of keys in the row dictionary to determine this, because DictReader automatically handles skipping header rows.
            # Since DictReader reads rows that do not include header rows, and fields may be incorrectly parsed
            # Therefore, we conservatively require the number of fields to be approximately correct.    
                if len(row) < len(EXPECTED_HEADERS):
                    # print(f"⚠️ Skip the incorrect lines in {path} (line number {total_lines}), insufficient space.")
                    continue

                try:
                    cve_id = row['CVE ID']
                    cleaned_row = {k: v if v != 'N/A' else None for k, v in row.items()}
                    
                    if cve_id and cve_id not in data_map and len(cleaned_row) >= len(EXPECTED_HEADERS):
                        data_map[cve_id] = cleaned_row
                        valid_cve_count += 1
                except KeyError:
                    # print(f"⚠️ Skip the incorrect lines in {path} (line number {total_lines}), 'CVE ID' key is missing.")
                    continue
                except Exception:
                    continue

    except FileNotFoundError:
        print(f"❌ Error: File not found {path}。")
        return {}, []
    except Exception as e:
        print(f"❌ A serious error occurred while reading: {path} {e}")
        return {}, []
        
    # print(f"📊 {path} 檔案統計：")
    # print(f"   - 總行數 (含標頭)：{total_lines}")
    # print(f"   - 讀取到的有效 CVE 筆數：{valid_cve_count} (以 CVE ID 為基準)")
    return data_map, actual_headers


def combine_CP_NVD():
    print(" Begin reading and parsing CVE data...")
    
    cp_map, _ = read_cve_data("output_result/CP_cve_search_result.csv")
    nvd_map, _ = read_cve_data("output_result/NVD_cve_search_result.csv")

    if not cp_map and not nvd_map:
        print("The merge operation has been cancelled because the input files were either empty or failed to read.")
        return

    
    # Get all unique CVE IDs
    cp_keys = set(cp_map.keys())
    nvd_keys = set(nvd_map.keys())
    all_cve_ids = cp_keys | nvd_keys
    
    merged_data: List[Dict[str, Any]] = []
    
    # Statistical overlap and unique number of entries
    overlap_count = len(cp_keys & nvd_keys)
    cp_only_count = len(cp_keys - nvd_keys)
    nvd_only_count = len(nvd_keys - cp_keys)
    
    for cve_id in all_cve_ids:
        in_cp = cve_id in cp_map
        in_nvd = cve_id in nvd_map
        
        # Source
        source = ""
        if in_cp and in_nvd:
            source = "CP/NVD"
        elif in_cp:
            source = "CP"
        else:
            source = "NVD"
            
        base_row = cp_map.get(cve_id, {})
        nvd_row = nvd_map.get(cve_id, {})

        final_row = {'Source': source, 'CVE ID': cve_id}
        
        for header in EXPECTED_HEADERS:
            # Special case: merge References from CP + NVD
            if header == "References":
                final_row[header] = merge_references(
                    base_row.get("References"),
                    nvd_row.get("References")
                )
                continue

            # Default behavior: CP first, fallback to NVD
            value = base_row.get(header)
            if value is None or value == "":
                value = nvd_row.get(header)

            final_row[header] = value if value is not None else 'N/A'


        merged_data.append(final_row)

    
    output_filename = f"output_result/merged_cve_result.csv"
    output_headers = ["Source"] + EXPECTED_HEADERS
    
    #--- Output statistical information ---
    print(f"   - Total number of unique CVEs to be processed:{len(all_cve_ids)} records")
    print(f"   - CP file unique entries:{cp_only_count} records")
    print(f"   - NVD file unique entries:{nvd_only_count} records")
    print(f"   - Number of overlapping entries between the two files:{overlap_count} records")
    print("=====================================================")
    
    try:
        with open(output_filename, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(
                f, 
                fieldnames=output_headers, 
                quoting=csv.QUOTE_ALL
            )
            
            writer.writeheader()
            writer.writerows(merged_data)
            
        # print(f"✅ Merge complete! Final file {output_filename} ")
        print(f"   - Number of documents contained in the final file:{len(merged_data)} records")
    except Exception as e:
        print(f"❌ An error occurred while writing to the output file: {e}")

import csv
from datetime import datetime
from typing import List, Dict, Any, Tuple

# Expected column names for the final merged output
EXPECTED_HEADERS = [
    "Source", "DataBase", "CVE ID", "Vendor", "Published Date", "Last Modified", 
    "CVSS v3.1", "CVSS v4.0", "Weaknesses", "Description", "References", 
    "Source Identifier", "Types of Vulnerability", "Title"
]

def read_cve_data(path: str) -> Tuple[Dict[str, Dict[str, str]], int]:
    """
    Reads a CSV file using csv.DictReader and organizes the data into a dictionary
    keyed by 'CVE ID'. Returns the dictionary and the count of valid CVEs read.
    """
    data_map = {}
    total_lines = 0
    valid_cve_count = 0
    
    # Determine the minimum expected field count based on the file name.
    is_merged = 'output_result/merged_cve_result.csv' in path
    # The merged file has 'Source' (14 headers), OT file does not (13 headers)
    min_expected_fields = len(EXPECTED_HEADERS) if is_merged else len(EXPECTED_HEADERS) - 1

    try:
        # Use newline='' for cross-platform compatibility with line endings
        with open(path, mode='r', newline='', encoding='utf-8-sig') as f:
            # Read header line separately to get total_lines count
            reader = csv.reader(f)
            try:
                # headers = next(reader)
                next(reader) # Consume header line
                total_lines += 1
            except StopIteration:
                print(f"⚠️ {path} is an empty file.")
                return {}, 0
            
            f.seek(0)
            dict_reader = csv.DictReader(f)
            
            for row in dict_reader:
                total_lines += 1
                
                # Critical check for malformed lines: skip rows with insufficient fields
                if len(row) < min_expected_fields:
                    continue

                try:
                    cve_id = row['CVE ID']
                    # Convert 'N/A' and empty strings to None for proper merging logic
                    cleaned_row = {k: (v if v != 'N/A' and v != "" else None) for k, v in row.items()}
                    
                    if cve_id and cve_id not in data_map:
                        data_map[cve_id] = cleaned_row
                        valid_cve_count += 1
                except KeyError:
                    # 'CVE ID' key missing (parsing error)
                    continue
                except Exception:
                    continue

    except FileNotFoundError:
        print(f"❌ ERROR: File not found at {path}.")
        return {}, 0
    except Exception as e:
        print(f"❌ CRITICAL ERROR during read of {path}: {e}")
        return {}, 0
        
    print(f"{path} File Statistics:")
    print(f"   - Total lines (incl. header): {total_lines}")
    print(f"   - Valid unique CVE records read: {valid_cve_count}")
    return data_map, valid_cve_count


def combine_cp_nvd_ot():
    """
    Merges merged_cve_result.csv (CP/NVD data) and OT_cve_search_result.csv (OT data).
    The merged file acts as the primary source, with OT data used for field supplementation.
    """
    print("=====================================================")
    print("Starting data read and merge process...")
    
    # Step 1: Read Data
    # merged_map is the primary file (CP/NVD result)
    merged_map, merged_count = read_cve_data("output_result/merged_cve_result.csv")
    # ot_map is the secondary file (OT data)
    ot_map, ot_count = read_cve_data("output_result/OT_cve_search_result.csv")

    if not merged_map and not ot_map:
        print("🛑 Merge cancelled as both input files are empty or failed to read.")
        return

    # Step 2: Execute Merging Logic
    
    # Get all unique CVE IDs
    merged_keys = set(merged_map.keys())
    ot_keys = set(ot_map.keys())
    all_cve_ids = merged_keys | ot_keys
    
    merged_data: List[Dict[str, Any]] = []
    
    # Calculate overlap statistics
    overlap_count = len(merged_keys & ot_keys)
    merged_only_count = len(merged_keys - ot_keys)
    ot_only_count = len(ot_keys - merged_keys)

    for cve_id in all_cve_ids:
        in_merged = cve_id in merged_map
        in_ot = cve_id in ot_map
        
        # Determine base row, prioritizing the merged file
        # Fallback to OT data if CVE only exists there
        final_row = merged_map.get(cve_id, ot_map.get(cve_id, {}))
        
        # Get supplementary data from OT file
        supplementary_row = ot_map.get(cve_id, {})

        # --- Handle Merging and Special Fields ---
        
        # 1. Perform combine_first logic (supplement None/NA fields)
        for header in EXPECTED_HEADERS:
            # If the field in final_row is None (was N/A or empty), supplement from OT
            if final_row.get(header) is None:
                final_row[header] = supplementary_row.get(header)
        
        # 2. Process DataBase and Source fields
        if in_merged and in_ot:
            # Both files have it: overwrite DataBase field
            final_row['DataBase'] = 'OT_CVE'
            # Source field remains 'CP/NVD' or similar (from original merged file)
        elif in_ot and not in_merged:
            # Only exists in OT file: set Source and DataBase explicitly
            final_row['Source'] = 'OT'
            final_row['DataBase'] = 'OT_CVE'

        # 3. Final Cleanup: Replace all remaining None with 'N/A'
        final_row['CVE ID'] = cve_id # Ensure CVE ID is present
        final_row = {k: v if v is not None else 'N/A' for k, v in final_row.items()}
            
        merged_data.append(final_row)

    # Step 3: Write Output File
    
    output_filename = f"output_result/merged_cve_result.csv"
    output_headers = EXPECTED_HEADERS
    
    # --- Output Statistics ---
    print("=====================================================")
    print("Data Merge Statistics:")
    print(f"   - Primary file (Merged) count: {merged_count} records")
    print(f"   - Secondary file (OT) count: {ot_count} records")
    print(f"   - Overlapping records: {overlap_count} records")
    print(f"   - Total unique CVE records processed: {len(all_cve_ids)} records")
    print("=====================================================")
    
    try:
        with open(output_filename, mode='w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(
                f, 
                fieldnames=output_headers, 
                quoting=csv.QUOTE_ALL # CRITICAL: Ensure all fields are quoted
            )
            
            writer.writeheader()
            writer.writerows(merged_data)
            
        print(f"✅ Merge complete! Final file {output_filename} successfully created.")
        print(f"   - Final output record count: {len(merged_data)} records")
    except Exception as e:
        print(f"❌ ERROR writing output file: {e}")

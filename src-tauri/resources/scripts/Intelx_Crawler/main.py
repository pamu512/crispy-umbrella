import requests
import json
import os
import sys
import re
import pandas as pd
import io
from datetime import datetime
from pii_reporter import process_csv_folder
from final_filter import extract_credentials_from_any_column
from extract_credential import extract_credentials_from_filtered

BASE_URL = os.environ.get("INTELX_BASE_URL", "https://2.intelx.io").rstrip("/")
API_KEY = (os.environ.get("INTELX_API_KEY") or "").strip()
if not API_KEY:
    print("Set INTELX_API_KEY in the environment before running this script.", file=sys.stderr)
    sys.exit(1)
headers = {"x-key": API_KEY, "Content-Type": "application/json"}

def validate_inputs(targets, start_date, end_date, search_limit):
    errors = []

    # 1. verify target_id format
    def is_valid_target(t):
        email = r"[^@]+@[^@]+\.[^@]+"
        ip = r"^\d{1,3}(\.\d{1,3}){3}$"
        domain = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
        cidr = r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"
        url = r"^https?://"
        return (
            re.match(email, t)
            or re.match(ip, t)
            or re.match(domain, t)
            or re.match(cidr, t)
            or re.match(url, t)
        )

    for t in targets:
        if not is_valid_target(t):
            errors.append(f"❌ Invalid target format: {t}")

    # 2. Validate date format
    try:
        datetime.strptime(start_date, "%Y-%m-%d")
    except ValueError:
        errors.append("❌ Invalid start date format (YYYY-MM-DD)")

    try:
        datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        errors.append("❌ Invalid end date format (YYYY-MM-DD)")

    # 3. Validate limit is a positive integer
    if not search_limit.isdigit() or int(search_limit) <= 0:
        errors.append("❌ Search limit must be a positive integer.")

    if errors:
        for err in errors:
            print(err)
        exit(1)  # Exit the program if there is an error
    else:
        print("✅ Input format valid.")


def sanitize_filename(filename):
    # Replace illegal characters, periods with underscores, and remove all whitespace characters
    filename = re.sub(r'[\/:*?"<>|\[\].]+', '_', filename)
    filename = re.sub(r'\s+', '', filename)
    return filename

def search_id(id, strat_date, end_date):
    payload = {
        "term": id,
        "lookuplevel": 0,
        "maxresults": 10000,
        "timeout": None,
        "datefrom": strat_date,
        "dateto": end_date,
        "sort": 2,
        "media": 0,
        "terminate": []
    }

    response = requests.post(
        url=f"{BASE_URL}/intelligent/search",
        headers=headers,
        data=json.dumps(payload)
    )

    if response.status_code == 200:
        try:
            result = response.json()
            return result['id']
        except Exception as e:
            print("回應不是有效的 JSON：", e)
    else:
        print(f"請求失敗，狀態碼：{response.status_code}")

def get_search_result(search_id, Search_limit):
    url = f"{BASE_URL}/intelligent/search/result?id={search_id}&limit={str(Search_limit)}&statistics=1&previewlines=8"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        try:
            return response.json()
        except Exception as e:
            print("回應不是有效的 JSON：", e)
    else:
        print(f"請求失敗，狀態碼：{response.status_code}")

def get_every_rawdata(records_id,target_id, output_dir):
    print(f"🔍 {len(records_id['records'])} records were found in total.")
    
    for idx, record in enumerate(records_id['records'], start=1): 
        print(f"Processing record {idx} of {len(records_id['records'])}")
        published_date = record['date'].split("T")[0]  # Keep only the date part
        published_date = datetime.strptime(published_date, "%Y-%m-%d")  # convert to  datetime

        systemid = record['systemid']
        storageid = record['storageid']
        record_name = record['name']
        bucket = record['bucket']
        if "https" and ".html" not in record_name:
            get_each_rawdata(storageid, published_date, systemid, bucket, record_name, output_dir)
            

def get_each_rawdata(storageid, published_date, systemid, bucket, record_name, output_dir):
    safe_name = sanitize_filename(record_name)
    url = f"{BASE_URL}/file/view?f=16&storageid={storageid}&bucket={bucket}&k={API_KEY}"
    response = requests.get(url, headers=headers)
    #see if the content is html
    content_type = (response.headers.get("Content-Type") or "").lower()
    body_head = response.text.lstrip().lower()[:200]
    is_html = ("text/html" in content_type) or body_head.startswith("<!doctype html") or body_head.startswith("<html")

    print(f"🔄 Processing {record_name} from {published_date} with systemid {systemid}")
    try:
        file_ext = record_name.lower()
        output_path = os.path.join(output_dir, f"{safe_name}.csv")
        
        raw_output_dir = output_dir.replace("csv_output/", "original_raw_data/", 1)
        os.makedirs(raw_output_dir, exist_ok=True)
        
        raw_txt_path = os.path.join(raw_output_dir, f"{safe_name}.txt")
        with open(raw_txt_path, "w", encoding="utf-8") as f:
            f.write(response.text)

        if ".csv" in file_ext:
            print("Is CSV file")
            csv_io = io.StringIO(response.text)
            df = pd.read_csv(csv_io, header=None, on_bad_lines='skip')
            df.insert(0, "published_date", published_date)  # Insert published_date into the first column
            df.insert(1, "file_systemid", systemid)            
            store_rawdata(record_name, df, output_path)

        elif ".txt" in file_ext:
            print("Is TXT file")
            lines = response.text.splitlines()
            df = pd.DataFrame(lines, columns=["raw_line"])
            df.insert(0, "published_date", published_date)  # Insert published_date into the first column
            df.insert(1, "file_systemid", systemid)           
            store_rawdata(record_name, df, output_path)

        elif ".sql" in file_ext:
            print("Is SQL file")
            lines = response.text.splitlines()
            parsed_data = []
            for line in lines:
                line = line.strip().strip("(),;")
                elements = [e.strip().strip("'") if e.strip().upper() != "NULL" else None for e in line.split(",")]
                parsed_data.append(elements)

            df = pd.DataFrame(parsed_data)
            df.insert(0, "published_date", published_date)  # Insert published_date into the first column
            df.insert(1, "file_systemid", systemid)     
            store_rawdata(record_name, df, output_path)
        
        elif is_html:
            print("Is HTML (URL-like record name). Saving as CSV lines")
            lines = response.text.splitlines()
            df = pd.DataFrame(lines, columns=["raw_line"])
            df.insert(0, "published_date", published_date)
            df.insert(1, "file_systemid", systemid)
            store_rawdata(record_name, df, output_path) 

        else:
            print("Unknown file type")
            print(f"🔺 record_name: {record_name}")
            print(f"🔺 Saved raw text file: {safe_name}.txt")
    

    except Exception as e:
        print(f"❌ Failed to process {record_name}: {e}")


def store_rawdata(record_name, df, output_path):
    
    '''store filtered raw data as CSV'''
    # Filter rows containing target_id and extra keywords
    keywords = [str(target_id)]
    extra_keywords = ['https', '@', 'password', 'account','pass','pwd','url','user','id']

    # Create a regex pattern for target_id (must match)
    target_pattern = "|".join(map(re.escape, keywords))
    # Create a regex pattern for extra_keywords (any one will do)
    extra_pattern = "|".join(map(re.escape, extra_keywords))
    # First convert all fields to lowercase strings
    df_str = df.astype(str).apply(lambda row: " ".join(cell.strip().lower() for cell in row), axis=1)
    # Condition 1: Contains target_id (required condition)
    mask_target = df_str.str.contains(target_pattern.strip().lower(), na=False)
    # Condition 2: Contains any of the extra_keywords (optional condition)
    mask_extra = df_str.str.contains(extra_pattern.strip().lower(), na=False)
    # Result: satisfies both target_id and at least one extra_keywords
    df_filtered = df[mask_target & mask_extra]

    if not df_filtered.empty:
        # Remove all NaN columns
        df_filtered = df_filtered.dropna(axis=1, how='all')
        # Remove fields that are all empty strings
        df_filtered = df_filtered.loc[:, ~df_filtered.apply(lambda col: col.astype(str).str.strip().eq('').all())]

        df_filtered.to_csv(output_path, index=False, encoding="utf-8-sig")
        print(f"✅ Saved filtered CSV (removed empty columns): {output_path}")
    else:
        print(f"❌ Skipped {record_name} — no matching rows.")



if __name__ == "__main__":
    target_id = input("Enter a domain, URL, Email, IP, CIDR, address, and more... eg. domain1, domain2 :").strip().lower()
    target_id_list = [target_id.strip() for target_id in target_id.split(',') if target_id.strip()]

    start_date = input("Enter start date (YYYY-MM-DD): ").strip()
    end_date = input("Enter end date (YYYY-MM-DD): ").strip()
    Search_limit = input("Enter search limit (default is 2000): ").strip() or "2000"

    validate_inputs(target_id_list, start_date, end_date, Search_limit)

    df = datetime.strptime(start_date, "%Y-%m-%d").strftime("%Y-%m-%d 00:00:00")
    dt = datetime.strptime(end_date, "%Y-%m-%d").strftime("%Y-%m-%d 23:59:59")
    target_folder = sanitize_filename(target_id)
    output_dir = "csv_output/"+str(target_folder) + "_" + str(start_date) + "_to_" + str(end_date)
    os.makedirs(output_dir, exist_ok=True)

    for target_id in target_id_list:
        search_result_id = search_id(target_id, df, dt)
        print(f"🔍 Search result ID: {search_result_id}")
        if search_result_id:
            all_records_id = get_search_result(search_result_id, Search_limit)
            if all_records_id:
                get_every_rawdata(all_records_id,target_id, output_dir)
        
        # extract all the csv files in the csv_output/ to final_report/
        pii_output_dir = str(target_folder) + "_" + str(start_date) + "_to_" + str(end_date)
        process_csv_folder(pii_output_dir)

        os.makedirs("filtered", exist_ok=True)
        input_csv = "final_report/" + pii_output_dir + ".csv"
        if not os.path.exists(input_csv):
            print(f"No final report generated (0 records or no csv processed): {input_csv}")
            continue  # skip credential extraction for this target_id

        output_csv = "filtered/" + (pii_output_dir + ".csv").replace(".csv", "_matched.csv")
        extract_credentials_from_any_column(input_csv, output_csv, target_id)
        if os.path.exists(output_csv):
            extract_credentials_from_filtered(pii_output_dir)
        else:
            print(f"❌ No matched credentials found for {target_id}.")
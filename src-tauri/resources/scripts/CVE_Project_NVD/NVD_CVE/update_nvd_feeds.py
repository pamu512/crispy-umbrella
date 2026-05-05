import os
import requests
import gzip
import shutil
from datetime import datetime

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

# Set the year range to track (past 5 years + modified + recent)
current_year = datetime.now().year
YEARS = list(range(current_year - 4, current_year + 1))  # ex: 2021~2025
FEEDS = [f"nvdcve-2.0-{y}" for y in YEARS] + ["nvdcve-2.0-modified", "nvdcve-2.0-recent"]

# Local storage folder
OUTPUT_DIR = "NVD_CVE/JSON"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def local_path(filename):
    """Add the NVD_CVE/JSON/ path to the file name"""
    return os.path.join(OUTPUT_DIR, filename)

def download_file(url, filename):
    r = requests.get(url, stream=True)
    r.raise_for_status()
    with open(filename, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)

def is_update_needed(feed):
    local_meta = local_path(f"{feed}.meta")
    meta_url = f"{BASE_URL}/{feed}.meta"

    if not os.path.exists(local_meta):
        download_file(meta_url, local_meta)
        return True

    download_file(meta_url, local_path("tmp.meta"))
    with open(local_meta, "r") as f1, open(local_path("tmp.meta"), "r") as f2:
        old_meta = f1.read()
        new_meta = f2.read()

    if old_meta != new_meta:
        shutil.move(local_path("tmp.meta"), local_meta)
        return True
    else:
        os.remove(local_path("tmp.meta"))
        return False

def update_feed(feed):
    print(f"[*] Updating {feed}...")
    json_gz = local_path(f"{feed}.json.gz")
    json_file = local_path(f"{feed}.json")


    download_file(f"{BASE_URL}/{feed}.json.gz", json_gz)

    with gzip.open(json_gz, "rb") as f_in:
        with open(json_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    print(f"[+] Updated {json_file}")

def Update_NVD():
    for feed in FEEDS:
        if is_update_needed(feed):
            update_feed(feed)
        else:
            print(f"[*] {feed} is up-to-date.")
    print("[*] All feeds are up-to-date.")


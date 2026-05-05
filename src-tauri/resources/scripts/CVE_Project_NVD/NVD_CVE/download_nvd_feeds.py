import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from zipfile import ZipFile
from pathlib import Path
import os
import time

BASE_URL = "https://nvd.nist.gov"
PAGE_URL = "https://nvd.nist.gov/vuln/data-feeds#divJson20Feeds"

headers = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


def get_all_feed_links():
    """Grab all JSON 2.0 .zip / .meta links from the NVD Data Feed page (excluding .gz)"""
    resp = requests.get(PAGE_URL, headers=headers)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    all_links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        # Only capture .zip and .meta, not .gz
        if (href.endswith(".json.zip") or href.endswith(".meta")) and "/feeds/json/cve/2.0/" in href:
            full_url = urljoin(BASE_URL, href)
            all_links.append(full_url)
    return all_links


def download_file(url, save_dir="NVD_CVE/JSON"):
    """Download the zip or meta archive, unzip it and delete it"""
    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)

    file_name = url.split("/")[-1]
    save_path = save_dir / file_name

    # If the file already exists, skip it
    if save_path.exists():
        print(f"{file_name} Already exists, skipping download.")
        return

    print(f"Downloading:{file_name}")
    resp = requests.get(url, headers=headers, stream=True)
    resp.raise_for_status()

    # Write to file
    with open(save_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)

    # If it is a ZIP file → Unzip → Delete ZIP
    if file_name.endswith(".zip"):
        try:
            with ZipFile(save_path, "r") as zf:
                for member in zf.namelist():
                    if member.endswith(".json"):
                        json_path = save_dir / member
                        print(f"📂 Decompression {member} → {json_path}")
                        with zf.open(member) as src, open(json_path, "wb") as dst:
                            dst.write(src.read())
                print(f"Complete decompression：{file_name}")
            os.remove(save_path)
            print(f"🗑️ Deleted ZIP:{file_name}\n")
        except Exception as e:
            print(f"⚠️ Decompression failed:{file_name} ({e})")
    else:
        print(f"✅ Downloaded:{file_name}\n")


def download_nvd_feeds():
    print("Fetching all JSON 2.0 feed links from NVD (keeping only .zip and .meta)...")
    links = get_all_feed_links()
    print(f"Found {len(links)} feed：")
    for l in links:
        print(" -", l)
    print("")

    for link in links:
        try:
            download_file(link)
            time.sleep(1)
        except Exception as e:
            print(f"❌ error ({link}): {e}")

    print("All done!")



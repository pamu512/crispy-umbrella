import requests
import zipfile
import io
import shutil
import json
import time
from pathlib import Path
from tqdm import tqdm

# === Configuration ===
ZIP_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
COMMIT_API = "https://api.github.com/repos/CVEProject/cvelistV5/commits/main"
META_FILE = Path("CVE_Project_CVE/.commit.json")
DEST_DIR = Path("CVE_Project_CVE/cves")
TEMP_DIR = Path("CVE_Project_CVE/temp_zip")
CHUNK_SIZE = 1024 * 1024  # 1 MB per download chunk


def get_latest_commit():
    """Fetch the latest commit SHA from GitHub"""
    resp = requests.get(COMMIT_API, timeout=30)
    resp.raise_for_status()
    return resp.json()["sha"]


def has_new_update():
    """Compare local commit with GitHub’s latest version"""
    latest = get_latest_commit()
    if META_FILE.exists():
        saved = json.load(open(META_FILE))
        if saved.get("sha") == latest:
            print("The local dataset is already up-to-date. Skipping download.")
            return False

    META_FILE.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"sha": latest}, open(META_FILE, "w"))
    print(f"New update detected: {latest[:10]} ... downloading full dataset.")
    return True


def download_zip(url: str):
    """Download the ZIP archive with a progress bar"""
    print("Downloading CVE Project ZIP archive (anonymous mode)...")
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()

    total = int(resp.headers.get("content-length", 0))
    data = io.BytesIO()
    with tqdm(total=total, unit="B", unit_scale=True, desc="Downloading", ncols=80) as bar:
        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                data.write(chunk)
                bar.update(len(chunk))
    print("✅ Download completed. Extracting contents ...")
    data.seek(0)
    return data


def extract_all(zip_data: io.BytesIO):
    """Extract ZIP file and move the entire cves directory"""
    # Remove old data if exists
    if DEST_DIR.exists():
        print("Cleaning up old cves directory ...")
        shutil.rmtree(DEST_DIR)
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_data) as z:
        z.extractall(TEMP_DIR)

    src = TEMP_DIR / "cvelistV5-main" / "cves"

    if not src.exists():
        raise FileNotFoundError("⚠️ The ZIP structure is invalid. 'cves/' directory not found.")

    shutil.move(str(src), str(DEST_DIR))
    shutil.rmtree(TEMP_DIR, ignore_errors=True)

    print(f"✅ Extraction completed! Final location: {DEST_DIR.resolve()}")


def show_progress(message, seconds=2):
    """Simple progress animation"""
    for _ in tqdm(range(seconds), desc=message, unit="sec", ncols=80):
        time.sleep(1)


def download_update_CVEsP_feeds():
    print("Starting CVE Project download/update (ZIP mode) ...")
    show_progress("Initializing", 2)

    if not has_new_update():
        print("No new updates. The dataset is current.")
        return

    zip_data = download_zip(ZIP_URL)
    extract_all(zip_data)

    print("\n Update completed successfully!")
    print(f"📂 Final path: {DEST_DIR.resolve()}")



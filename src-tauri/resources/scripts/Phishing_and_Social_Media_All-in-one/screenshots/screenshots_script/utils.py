import csv
import os
from dataclasses import dataclass
from urllib.parse import urlparse
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class BrowserConfig:
    headless: bool = True


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_csv_rows(csv_file: str) -> List[Dict[str, str]]:
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def iter_urls(rows: Iterable[Dict[str, str]]) -> Iterable[tuple[int, str]]:
    """
    Yield (row_num, url) where row_num matches the CSV row number in the file.
    Row 1 is the header, so first data row is 2.
    """
    for i, row in enumerate(rows):
        row_num = i + 2
        url = (row.get("url") or "").strip()
        yield row_num, url


def default_output_root(input_folder: str) -> str:
    parent = os.path.dirname(os.path.abspath(input_folder))
    base = os.path.basename(os.path.abspath(input_folder))
    return os.path.join(parent, f"{base}_output")


def list_csv_files(input_folder: str) -> List[str]:
    files: List[str] = []
    for name in sorted(os.listdir(input_folder)):
        if name.lower().endswith(".csv"):
            files.append(os.path.join(input_folder, name))
    return files


def detect_platform_from_filename(filename: str) -> Optional[str]:
    """
    Determine platform from CSV filename.
    Returns one of: facebook, instagram, linkedin, tiktok, twitter
    """
    n = os.path.basename(filename).lower()
    if "facebook" in n:
        return "facebook"
    if "instagram" in n:
        return "instagram"
    if "linkedin" in n or "linkin" in n:
        return "linkedin"
    if "tiktok" in n:
        return "tiktok"
    if "twitter" in n or "x.com" in n or "x_" in n or "_x_" in n:
        return "twitter"
    return None


def csv_stem(csv_file: str) -> str:
    """
    Base name of the CSV file without extension, used for per-CSV output subfolders.
    Example: /a/b/my_twitter_urls.csv -> my_twitter_urls
    """
    return os.path.splitext(os.path.basename(csv_file))[0]


def detect_platform_from_url(url: str) -> Optional[str]:
    """
    Determine platform from a URL.
    Returns one of: facebook, instagram, linkedin, tiktok, twitter
    """
    u = (url or "").strip()
    if not u:
        return None
    try:
        host = (urlparse(u).netloc or "").lower()
    except Exception:
        return None

    # Remove port if any
    host = host.split(":")[0]
    if host.endswith("tiktok.com"):
        return "tiktok"
    if host.endswith("twitter.com") or host == "x.com" or host.endswith(".x.com"):
        return "twitter"
    if host.endswith("instagram.com"):
        return "instagram"
    if host.endswith("facebook.com") or host.endswith("fb.com"):
        return "facebook"
    if host.endswith("linkedin.com"):
        return "linkedin"
    return None


def detect_platform_from_csv_content(csv_file: str) -> Optional[str]:
    """
    Determine platform by inspecting the first non-empty URL in the CSV.
    """
    try:
        rows = read_csv_rows(csv_file)
    except Exception:
        return None
    for _, url in iter_urls(rows):
        p = detect_platform_from_url(url)
        if p:
            return p
    return None

    return None


def sanitize_filename(url: str) -> str:
    """
    Sanitize a URL to be safe for use as a filename.
    Removes protocol, replaces slashes with underscores, and limits length.
    """
    if not url:
        return "unknown"
    
    # Remove protocol
    u = url.replace("https://", "").replace("http://", "")
    
    # Replace characters invalid in filenames
    safe = ""
    for c in u:
        if c.isalnum() or c in ('-', '_', '.'):
            safe += c
        else:
            safe += "_"
            
    # Limit length to avoid filesystem issues
    if len(safe) > 150:
        safe = safe[:150]
        
    return safe

import re
import sys
import requests
from pathlib import Path
from bs4 import BeautifulSoup

for _root in Path(__file__).resolve().parents:
    if (_root / "shared_utils" / "retry_backoff.py").is_file():
        sys.path.insert(0, str(_root / "shared_utils"))
        break
else:
    raise ImportError("shared_utils/retry_backoff.py not found from verify_cve_date.py")

from circuit_breaker import circuit_protect
from retry_backoff import with_exponential_backoff
from difflib import SequenceMatcher
from urllib.parse import urlparse
import json
from datetime import datetime, time
import csv

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Keywords (in both Chinese and English)
KEY_GROUPS = {
    "publish": [
        "published", "publication date", "date published",
        "initial release", "first published", "posted",
        "公告日期", "發佈日期", "發布日期", "刊登日期", "首次發布", "初版"
    ],
    "release": [
        "release date", "released", "release", "revision history",
        "版本歷史", "修訂紀錄", "修訂歷史", "版本紀錄", "發行日期", "釋出日期"
    ],
    "updated": [
        "updated", "last updated", "date updated", "last modified", "modified",
        "更新日期", "最後更新", "最後修改", "修訂日期"
    ],
}

MONTHS = r"(Jan|January|Feb|February|Mar|March|Apr|April|May|Jun|June|Jul|July|Aug|August|Sep|Sept|September|Oct|October|Nov|November|Dec|December)"
DATE_REGEXES = [
    re.compile(r"\b(\d{4}-\d{2}-\d{2})\b"),  # 2025-09-30
    re.compile(r"\b(\d{1,2}/\d{1,2}/\d{4})(?:\s+\d{1,2}:\d{2}\s*(AM|PM))?\b", re.I),  # 09/30/2025 11:18 AM
    re.compile(rf"\b(\d{{1,2}}\s+{MONTHS}\s+\d{{4}})\b", re.I),  # 30 September 2025
    re.compile(r"\b(\d{4}年\d{1,2}月\d{1,2}日)\b"),  # 2025年9月30日
]

# Thread-local Session (One session per thread to avoid issues caused by sharing sessions)
_thread_local = threading.local()

def get_session() -> requests.Session:
    if getattr(_thread_local, "session", None) is None:
        s = requests.Session()

        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=50,
            pool_maxsize=50,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)

        _thread_local.session = s
    return _thread_local.session


def iso_ms_to_dt(iso_ms: str) -> datetime | None:
    """
    Parse ISO ms like: 2025-10-01T03:15:37.250
    Also accept ISO without ms: 2025-10-01T03:15:37
    Return naive datetime (no timezone).
    """
    if not iso_ms:
        return None
    s = iso_ms.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def compare_pick_earlier(date_a_iso: str | None, date_b_iso: str | None) -> tuple[str | None, str]:
    """
    Compare two ISO-ish strings and return (earlier_iso, reason).
    If one is missing/unparseable, return the other.
    """
    a_dt = iso_ms_to_dt(date_a_iso)
    b_dt = iso_ms_to_dt(date_b_iso)

    if a_dt and b_dt:
        if a_dt <= b_dt:
            return date_a_iso, "best_guess_date_iso <= original_date"
        return date_b_iso, "original_date < best_guess_date_iso"

    if a_dt and not b_dt:
        return date_a_iso, "original_date missing/unparseable, used best_guess_date_iso"

    if b_dt and not a_dt:
        return date_b_iso, "best_guess_date_iso missing/unparseable, used original_date"

    return None, "both missing/unparseable"


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def normalize_lines(text: str):
    raw_lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in raw_lines if ln]
    return lines


def extract_dates_from_window(lines, center_idx, radius=12):
    start = max(0, center_idx - radius)
    end = min(len(lines), center_idx + radius + 1)
    window = "\n".join(lines[start:end])

    found = []
    for rgx in DATE_REGEXES:
        for m in rgx.finditer(window):
            found.append(m.group(1))

    seen = set()
    uniq = []
    for d in found:
        if d not in seen:
            uniq.append(d)
            seen.add(d)
    return uniq, window


def parse_any_date_to_iso_ms(date_str: str) -> str | None:
    """
    Convert various date formats into ISO8601: YYYY-MM-DDTHH:MM:SS.mmm
    If time is missing, default to 00:00:00.000
    If only a date is present (no timezone), we keep it naive (no 'Z').
    """
    if not date_str:
        return None

    s = date_str.strip()

    # Normalize Chinese date: September 30, 2025 -> 2025-09-30
    m = re.fullmatch(r"(\d{4})年(\d{1,2})月(\d{1,2})日", s)
    if m:
        y, mo, d = map(int, m.groups())
        dt = datetime(y, mo, d, 0, 0, 0, 0)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    formats = [
        "%Y-%m-%d",                 # 2025-09-30
        "%m/%d/%Y",                 # 09/30/2025
        "%m/%d/%Y %I:%M %p",        # 09/29/2025 11:18 AM
        "%m/%d/%Y %H:%M",           # 09/29/2025 23:18
        "%d %B %Y",                 # 30 September 2025
        "%d %b %Y",                 # 30 Sep 2025
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        except ValueError:
            pass

    m = re.search(r"(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2})\s*(AM|PM)", s, re.I)
    if m:
        dt = datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3).upper()}", "%m/%d/%Y %I:%M %p")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
    if m:
        dt = datetime.strptime(m.group(1), "%Y-%m-%d")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    return None


# Change fuzzy_find_date to use session.get (for connection reuse).
def fuzzy_find_date(session: requests.Session, url: str, timeout=20, top_hits=8):
    def _session_get() -> requests.Response:
        resp = session.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()
        return resp

    def _fetch() -> requests.Response:
        return circuit_protect("cve_reference_http", _session_get)

    r = with_exponential_backoff(
        _fetch,
        max_retries=3,
        base_delay_s=1.0,
        retry_on=(requests.RequestException,),
    )

    soup = BeautifulSoup(r.text, "html.parser")
    text = soup.get_text("\n", strip=True)
    lines = normalize_lines(text)

    hits = []  # (score, group, idx, line)
    for idx, line in enumerate(lines):
        ln = line[:300]
        for group, keys in KEY_GROUPS.items():
            best = 0.0
            best_key = None
            for k in keys:
                s = similarity(ln, k)
                if s > best:
                    best = s
                    best_key = k
            if best >= 0.60:
                hits.append((best, group, idx, ln, best_key))

    hits.sort(key=lambda x: x[0], reverse=True)
    hits = hits[:top_hits]

    results = {
        "url": url,
        "host": urlparse(url).hostname,
        "candidates": {"publish": [], "release": [], "updated": []},
        "debug_hits": [],
    }

    for score, group, idx, ln, best_key in hits:
        dates, _window = extract_dates_from_window(lines, idx, radius=12)
        if dates:
            for d in dates:
                results["candidates"][group].append({
                    "date": d,
                    "score": round(score, 3),
                    "matched_keyword": best_key,
                    "line": ln[:180]
                })
        results["debug_hits"].append({
            "group": group,
            "score": round(score, 3),
            "matched_keyword": best_key,
            "line": ln[:180]
        })

    best = None
    best_group = None
    for grp in ("publish", "release", "updated"):
        if results["candidates"][grp]:
            best = results["candidates"][grp][0]["date"]
            best_group = grp
            break

    results["best_guess_date"] = best
    results["best_guess_group"] = best_group
    results["best_guess_date_iso"] = parse_any_date_to_iso_ms(best) if best else None

    return results


def verify_cve_date(session: requests.Session, url, original_date: str):
    out = fuzzy_find_date(session, url)

    best_iso = out.get("best_guess_date_iso")  # e.g. 2025-09-30T00:00:00.000
    picked_iso, reason = compare_pick_earlier(best_iso, original_date)

    if out.get("best_guess_date"):
        return True, picked_iso
    else:
        return False, None


# update_references_with_verify` processes each column in parallel using a ThreadPool.
def update_references_with_verify(in_csv: str, out_csv: str, max_workers: int = 20):
    with open(in_csv, "r", newline="", encoding="utf-8-sig") as f_in:
        reader = csv.DictReader(f_in)
        fieldnames = reader.fieldnames
        rows = list(reader)

    def process_row(row: dict) -> dict:
        cve = (row.get("CVE ID") or "").strip()
        refs = (row.get("References") or "").strip()
        original_date = (row.get("Published Date") or "").strip()

        if refs and refs.upper() != "N/A":
            parts = [p.strip() for p in refs.split(";") if p.strip()]

            session = get_session()
            for url in parts:
                try:
                    should_update, picked_iso = verify_cve_date(session, url, original_date)
                        
                except Exception:
                    continue

                if should_update and picked_iso:
                    print(f"Updating {cve} Published Date to: {picked_iso}")
                    row["Published Date"] = picked_iso
                    break
        else:
            print(f"{cve} No references found.")

        return row

    updated_rows = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(process_row, r) for r in rows]
        for fu in as_completed(futures):
            updated_rows.append(fu.result())

    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(updated_rows)


def start_verify_cve_date():
    print("========================================")
    print("Starting CVE date verification and update...")
    update_references_with_verify(
        "output_result/merged_cve_result.csv",
        "output_result/merged_cve_result.csv",
        max_workers=20
    )

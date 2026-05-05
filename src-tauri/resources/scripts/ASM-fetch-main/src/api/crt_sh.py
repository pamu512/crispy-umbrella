"""crt.sh helper for extracting subdomains from certificate transparency JSON.

Provides get_crt_subdomains(domain) which queries https://crt.sh/json?q={domain}
and returns a deduplicated list of hostnames that end with the given domain.

If the network request fails and a local file '{domain}.json' exists in the repo
root, it will be used as a fallback (useful for offline testing with sample responses).
"""
import json
import logging
import re
from pathlib import Path
from typing import List

import requests

logger = logging.getLogger(__name__)


def _clean_name(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    # crt.sh may return entries with wildcard prefixes
    if s.startswith("*."):
        s = s[2:]
    # remove any URI scheme or path if present
    s = re.sub(r'^https?://', '', s, flags=re.IGNORECASE)
    s = s.split('/')[0]
    return s


def _is_ip(s: str) -> bool:
    return re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s) is not None


def get_crt_subdomains(domain: str, timeout: int = 15, use_local_fallback: bool = True) -> List[str]:
    """Query crt.sh and return a deduplicated list of subdomains for `domain`.

    Returns a list of hostnames (strings). On error, returns an empty list.
    """
    url = f"https://crt.sh/json?q={domain}"
    hosts = set()
    try:
        r = requests.get(url, headers={"Accept": "application/json"}, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.debug("crt.sh request failed for %s: %s", domain, e)
        data = None

    # fallback to local file named {domain}.json in repo root
    if data is None and use_local_fallback:
        local = Path.cwd() / f"{domain}.json"
        if local.is_file():
            try:
                data = json.loads(local.read_text(encoding="utf-8"))
                logger.debug("Loaded local crt.sh sample %s", str(local))
            except Exception as e:
                logger.debug("Failed to load local crt.sh sample %s: %s", str(local), e)

    if not data:
        return []

    # data is a list of dicts; extract common_name and name_value
    for item in data:
        if not isinstance(item, dict):
            continue
        for key in ("common_name", "name_value"):
            if key in item and item[key]:
                # name_value may contain multiple names separated by newlines
                raw = item[key]
                # sometimes name_value is a single string or a list depending on source
                if isinstance(raw, list):
                    candidates = raw
                else:
                    # split by newlines and commas conservatively
                    candidates = re.split(r"[\n,]+", str(raw))
                for cand in candidates:
                    name = _clean_name(cand)
                    if not name:
                        continue
                    # skip IPs
                    if _is_ip(name):
                        continue
                    # ensure it ends with the target domain
                    if name == domain or name.endswith("." + domain):
                        hosts.add(name.lower())

    cleaned = sorted(hosts)
    logger.info("crt.sh found %s subdomains that matches the target domain.", len(cleaned))
    return cleaned

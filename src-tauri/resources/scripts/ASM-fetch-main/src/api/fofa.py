"""FOFA API client helpers."""
import base64
import logging
import re
import requests
import certifi
import time
import os
from requests.exceptions import SSLError, RequestException
from config.settings import Settings

logger = logging.getLogger(__name__)

FOFA_URL = "https://fofa.so/api/v1/search/all"


def _clean_host_from_result(item: str) -> str:
    """Normalize FOFA result items into hostnames without protocol or port.

    Examples:
    - https://www.example.com -> www.example.com
    - http://example.com:8080/path -> example.com
    - 192.0.2.1 -> (will be filtered out by caller)
    """
    if not item:
        return ""
    # strip surrounding whitespace
    s = item.strip()
    # remove protocol
    s = re.sub(r'^https?://', '', s, flags=re.IGNORECASE)
    # remove path and query
    s = re.split(r'[/?#]', s)[0]
    # remove trailing port
    s = re.sub(r':\d+$', '', s)
    return s


def _is_ip(s: str) -> bool:
    if not s:
        return False
    return re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s) is not None


def get_fofa_subdomains(domain: str, key: str = None, size: int = 10000, fields: str = "host") -> list:
    """Query FOFA for hosts matching domain or cert and return a deduplicated list of hostnames.

    key: FOFA API key; if None, read from Settings.FOFA_API_KEY
    """
    if key is None:
        key = Settings.FOFA_API_KEY
    if not key:
        logger.debug("No FOFA API key configured")
        return []

    # Build base64-encoded query
    #q = f'domain="{domain}" || cert="{domain}"'
    q = f'domain="{domain}"'
    qbase64 = base64.b64encode(q.encode()).decode()

    params = {
        "key": key,
        "qbase64": qbase64,
        "fields": fields,
        "size": size,
    }
    # Prefer a system CA bundle if present (matches curl behavior in many images).
    possible_system_bundles = [
        "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",    # RHEL/CentOS
        "/etc/ssl/cert.pem",                    # Alpine / some images
    ]
    cafile = None
    for p in possible_system_bundles:
        if os.path.exists(p):
            cafile = p
            break
    if not cafile:
        # fallback to certifi
        try:
            cafile = certifi.where()
        except Exception:
            cafile = None

    try:
        logger.debug("FOFA using CA bundle: %s (exists=%s)", cafile, os.path.exists(cafile) if cafile else False)
    except Exception:
        logger.debug("FOFA could not inspect CA bundle")

    # Try with retries using certifi bundle. If all retries fail with SSL issues,
    # fall back to an insecure request (verify=False) as a last resort with a warning.
    data = None
    last_exc = None
    for attempt in range(1, 4):
        try:
            resp = requests.get(FOFA_URL, params=params, timeout=15, verify=cafile)
            resp.raise_for_status()
            data = resp.json()
            last_exc = None
            break
        except SSLError as e:
            last_exc = e
            logger.warning("FOFA SSL error attempt %s/3 for %s: %s", attempt, domain, e)
        except RequestException as e:
            last_exc = e
            logger.warning("FOFA request error attempt %s/3 for %s: %s", attempt, domain, e)
        # backoff
        time.sleep(1 * attempt)

    if data is None and last_exc is not None:
        # try insecurely as a last resort (not recommended for production)
        try:
            logger.warning("FOFA: falling back to verify=False for domain %s (insecure).", domain)
            resp = requests.get(FOFA_URL, params=params, timeout=15, verify=False)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.warning("FOFA request failed (even insecure) for %s: %s", domain, e)
            return []
    if data is None:
        return []

    results = data.get("results") or []
    out = set()
    for item in results:
        try:
            h = _clean_host_from_result(item)
            if not h:
                continue
            if _is_ip(h):
                continue
            if h != domain and not h.endswith("." + domain):
                continue
            out.add(h)
        except Exception:
            continue
    cleaned = sorted(out)
    logger.info("Fofa found %s subdomains that matches the target domain.", len(cleaned))
    return cleaned

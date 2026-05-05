"""
Single entry point for optional MISP, TAXII 2.1, and VirusTotal lookups.

Configure environment variables (see All_Scripts ``README.txt`` and ``shared_cti/config.py``), then import:

    from shared_cti.bridge import virustotal_file_report, misp_search_attributes, taxii_get_objects
"""

from __future__ import annotations

import json
from typing import Any

import requests
from urllib.parse import urljoin

from .config import CtiConfig, load_cti_config, misp_configured, virustotal_configured

VT_V3 = "https://www.virustotal.com/api/v3"


def _get_cfg(config: CtiConfig | None) -> CtiConfig:
    return config or load_cti_config()


# --- VirusTotal (file/hash enrichment) ---


def virustotal_file_report(
    file_id: str,
    *,
    config: CtiConfig | None = None,
    session: requests.Session | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Return the VT v3 JSON document for a file object *file_id* (md5, sha1, or sha256 per VT).
    """
    c = _get_cfg(config)
    if not virustotal_configured(c):
        raise RuntimeError("Set VT_API_KEY in the environment (see shared_cti/config.py).")
    sess = session or requests.Session()
    url = f"{VT_V3}/files/{file_id}"
    r = sess.get(
        url,
        headers={"x-apikey": c.virustotal_api_key},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


# --- MISP (REST: attribute search) ---


def misp_search_attributes(
    ioc: str,
    *,
    config: CtiConfig | None = None,
    session: requests.Session | None = None,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    """
    Return MISP attribute records for a value (IP, domain, URL, hash, etc.).

    POSTs to ``/attributes/restSearch`` with your auth key. Key format depends on
    MISP (often the full ``Authorization: <key>`` value).
    """
    c = _get_cfg(config)
    if not misp_configured(c):
        raise RuntimeError("Set MISP_URL and MISP_KEY in the environment.")
    sess = session or requests.Session()
    body: dict[str, Any] = {"returnFormat": "json", "value": ioc}
    url = urljoin(c.misp_url + "/", "attributes/restSearch")
    r = sess.post(
        url,
        headers={
            "Authorization": c.misp_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        data=json.dumps(body),
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and "Attribute" in data:
        return data["Attribute"]  # type: ignore[return-value]
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "response" in data:
        return data.get("Attribute") or data.get("response") or []
    return []


# --- TAXII 2.1 (uses taxii2-client when installed) ---


def taxii_get_objects(
    collection_href: str | None = None,
    *,
    config: CtiConfig | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """
    Return STIX objects from a TAXII 2.1 *collection* endpoint.

    Pass the collection URL (``.../collections/{id}/``), or set ``TAXII_COLLECTION_HREF``.
    Install: ``pip install taxii2-client stix2``.
    """
    c = _get_cfg(config)
    href = (collection_href or c.taxii_collection_href or "").strip()
    if not href:
        raise RuntimeError("Pass collection_href or set TAXII_COLLECTION_HREF.")
    if not href.endswith("/"):
        href = href + "/"
    try:
        from taxii2client.v21 import Collection
    except ImportError as e:
        raise RuntimeError("Install: pip install taxii2-client stix2") from e
    u = c.taxii_user or None
    p = c.taxii_password or None
    col = Collection(href, user=u, password=p)  # type: ignore[call-arg]
    bundle = col.get_objects(limit=limit)
    if bundle is None:
        return []
    if hasattr(bundle, "serialize"):
        raw = json.loads(bundle.serialize())
    else:
        raw = bundle
    if isinstance(raw, dict) and "objects" in raw:
        return list(raw["objects"])
    if isinstance(raw, list):
        return [x if isinstance(x, dict) else {"data": x} for x in raw]
    if isinstance(raw, dict):
        return [raw]
    return []

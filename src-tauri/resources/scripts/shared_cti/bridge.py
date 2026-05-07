"""
MISP, TAXII 2.1, and VirusTotal lookups with constructor-injected configuration and HTTP client.

Tests and composition roots own the :class:`requests.Session` and :class:`CtiConfig` instances::

    import requests
    from shared_cti import CtiConfig, SharedCtiBridge, load_cti_config

    bridge = SharedCtiBridge(load_cti_config(), requests.Session())
    data = bridge.virustotal_file_report(sha256)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import requests
from urllib.parse import urljoin

_scripts = Path(__file__).resolve().parent.parent
if str(_scripts / "shared_utils") not in sys.path:
    sys.path.insert(0, str(_scripts / "shared_utils"))

for _root in Path(__file__).resolve().parents:
    if (_root / "exceptions.py").is_file():
        if str(_root) not in sys.path:
            sys.path.insert(0, str(_root))
        break
else:
    raise ImportError("Could not locate repo root (exceptions.py).")

from circuit_breaker import circuit_protect
from exceptions import InternalLogicError, ValidationError

from .config import CtiConfig, misp_configured, virustotal_configured
from .constants import (
    CIRCUIT_BREAKER_MISP,
    CIRCUIT_BREAKER_TAXII,
    CIRCUIT_BREAKER_VIRUSTOTAL,
    DEPENDENCY_TAXII2_CLIENT,
    DETAIL_TAXII2CLIENT_IMPORT_FAILED,
    MISP_ATTRIBUTES_REST_SEARCH_PATH,
    MSG_MISP_CREDENTIALS_REQUIRED,
    MSG_TAXII_CLIENT_INSTALL,
    MSG_TAXII_COLLECTION_HREF_REQUIRED,
    MSG_VIRUSTOTAL_API_KEY_REQUIRED,
    VIRUSTOTAL_API_V3_BASE_URL,
    VIRUSTOTAL_FILES_SUBPATH,
)


class SharedCtiBridge:
    """
    CTI HTTP integrations. No network clients are created inside request methods — only
    :class:`requests.Session` provided at construction time is used (VirusTotal, MISP).
    """

    def __init__(self, config: CtiConfig, http: requests.Session) -> None:
        self._config = config
        self._http = http

    def virustotal_file_report(self, file_id: str, *, timeout: float = 30.0) -> dict[str, Any]:
        """
        Return the VT v3 JSON document for a file object *file_id* (md5, sha1, or sha256 per VT).
        """
        c = self._config
        if not virustotal_configured(c):
            raise ValidationError(
                {"service": "virustotal", "reason": "VT_API_KEY_unset"},
                message=MSG_VIRUSTOTAL_API_KEY_REQUIRED,
            )
        url = f"{VIRUSTOTAL_API_V3_BASE_URL}/{VIRUSTOTAL_FILES_SUBPATH}/{file_id}"

        def _vt_get() -> dict[str, Any]:
            r = self._http.get(
                url,
                headers={"x-apikey": c.virustotal_api_key},
                timeout=timeout,
            )
            r.raise_for_status()
            return r.json()

        return circuit_protect(CIRCUIT_BREAKER_VIRUSTOTAL, _vt_get)

    def misp_search_attributes(self, ioc: str, *, timeout: float = 30.0) -> list[dict[str, Any]]:
        """
        Return MISP attribute records for a value (IP, domain, URL, hash, etc.).

        POSTs to ``/attributes/restSearch`` with your auth key. Key format depends on
        MISP (often the full ``Authorization: <key>`` value).
        """
        c = self._config
        if not misp_configured(c):
            raise ValidationError(
                {"service": "misp", "reason": "MISP_URL_or_MISP_KEY_unset"},
                message=MSG_MISP_CREDENTIALS_REQUIRED,
            )
        body: dict[str, Any] = {"returnFormat": "json", "value": ioc}
        url = urljoin(c.misp_url + "/", MISP_ATTRIBUTES_REST_SEARCH_PATH)

        def _misp_post() -> Any:
            r = self._http.post(
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
            return r.json()

        data = circuit_protect(CIRCUIT_BREAKER_MISP, _misp_post)
        if isinstance(data, dict) and "Attribute" in data:
            return data["Attribute"]  # type: ignore[return-value]
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "response" in data:
            return data.get("Attribute") or data.get("response") or []
        return []

    def taxii_get_objects(
        self,
        collection_href: str | None = None,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Return STIX objects from a TAXII 2.1 *collection* endpoint.

        Pass the collection URL (``.../collections/{id}/``), or set ``TAXII_COLLECTION_HREF`` on
        the injected :class:`CtiConfig`. Install: ``pip install taxii2-client stix2``.
        """
        c = self._config
        href = (collection_href or c.taxii_collection_href or "").strip()
        if not href:
            raise ValidationError(
                {"service": "taxii", "reason": "collection_href_missing"},
                message=MSG_TAXII_COLLECTION_HREF_REQUIRED,
            )
        if not href.endswith("/"):
            href = href + "/"
        try:
            from taxii2client.v21 import Collection
        except ImportError as e:
            raise InternalLogicError(
                {"dependency": DEPENDENCY_TAXII2_CLIENT, "detail": DETAIL_TAXII2CLIENT_IMPORT_FAILED},
                message=MSG_TAXII_CLIENT_INSTALL,
            ) from e
        u = c.taxii_user or None
        p = c.taxii_password or None
        col = Collection(href, user=u, password=p)  # type: ignore[call-arg]
        bundle = circuit_protect(CIRCUIT_BREAKER_TAXII, lambda: col.get_objects(limit=limit))
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

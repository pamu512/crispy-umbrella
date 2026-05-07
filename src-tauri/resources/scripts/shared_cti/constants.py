"""
Shared literals for shared CTI integrations: API bases, paths, circuit-breaker names, and messages.
"""

from __future__ import annotations

from typing import Final

# --- VirusTotal API v3 ---
VIRUSTOTAL_API_V3_BASE_URL: Final[str] = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_FILES_SUBPATH: Final[str] = "files"

# --- MISP (path segment under the instance base URL) ---
MISP_ATTRIBUTES_REST_SEARCH_PATH: Final[str] = "attributes/restSearch"

# --- Optional integration env keys (read by :func:`config.load_cti_config`) ---
ENV_MISP_URL: Final[str] = "MISP_URL"
ENV_MISP_KEY: Final[str] = "MISP_KEY"
ENV_TAXII_COLLECTION_HREF: Final[str] = "TAXII_COLLECTION_HREF"
ENV_TAXII_USER: Final[str] = "TAXII_USER"
ENV_TAXII_PASSWORD: Final[str] = "TAXII_PASSWORD"
ENV_TAXII_DISCOVERY_URL: Final[str] = "TAXII_DISCOVERY_URL"
ENV_VT_API_KEY: Final[str] = "VT_API_KEY"

# --- Circuit breaker keys (stable identifiers for shared_utils ``circuit_breaker``) ---
CIRCUIT_BREAKER_VIRUSTOTAL: Final[str] = "shared_cti_virustotal"
CIRCUIT_BREAKER_MISP: Final[str] = "shared_cti_misp"
CIRCUIT_BREAKER_TAXII: Final[str] = "shared_cti_taxii"

# --- User-facing / log messages ---
MSG_VIRUSTOTAL_API_KEY_REQUIRED: Final[str] = (
    "Set VT_API_KEY in the environment (see shared_cti/config.py)."
)
MSG_MISP_CREDENTIALS_REQUIRED: Final[str] = "Set MISP_URL and MISP_KEY in the environment."
MSG_TAXII_COLLECTION_HREF_REQUIRED: Final[str] = (
    "Pass collection_href or set TAXII_COLLECTION_HREF."
)
MSG_TAXII_CLIENT_INSTALL: Final[str] = "Install: pip install taxii2-client stix2"

# --- Internal logic / diagnostics ---
DEPENDENCY_TAXII2_CLIENT: Final[str] = "taxii2-client"
DETAIL_TAXII2CLIENT_IMPORT_FAILED: Final[str] = "taxii2client_import_failed"

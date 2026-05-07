"""Environment-driven settings for shared CTI integrations. Copy keys from your vault, never commit them."""

import os
from dataclasses import dataclass

from .constants import (
    ENV_MISP_KEY,
    ENV_MISP_URL,
    ENV_TAXII_COLLECTION_HREF,
    ENV_TAXII_DISCOVERY_URL,
    ENV_TAXII_PASSWORD,
    ENV_TAXII_USER,
    ENV_VT_API_KEY,
)


@dataclass
class CtiConfig:
    misp_url: str
    misp_key: str
    # TAXII 2.1 collection href, often like .../collections/<uuid>/
    taxii_collection_href: str
    taxii_user: str
    taxii_password: str
    # Optional: future Server-based discovery (browse api roots)
    taxii_discovery_url: str
    virustotal_api_key: str


def load_cti_config() -> CtiConfig:
    return CtiConfig(
        misp_url=os.environ.get(ENV_MISP_URL, "").rstrip("/"),
        misp_key=os.environ.get(ENV_MISP_KEY, ""),
        taxii_collection_href=os.environ.get(ENV_TAXII_COLLECTION_HREF, "").rstrip("/"),
        taxii_user=os.environ.get(ENV_TAXII_USER, ""),
        taxii_password=os.environ.get(ENV_TAXII_PASSWORD, ""),
        taxii_discovery_url=os.environ.get(ENV_TAXII_DISCOVERY_URL, "").rstrip("/"),
        virustotal_api_key=os.environ.get(ENV_VT_API_KEY, ""),
    )


def misp_configured(c: CtiConfig) -> bool:
    return bool(c.misp_url and c.misp_key)


def taxii_configured(c: CtiConfig) -> bool:
    return bool(c.taxii_collection_href)


def virustotal_configured(c: CtiConfig) -> bool:
    return bool(c.virustotal_api_key)

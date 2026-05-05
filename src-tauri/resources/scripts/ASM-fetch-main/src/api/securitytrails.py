"""
SecurityTrails API module for subdomain discovery (securitytrails).
"""

import logging
import time
from typing import Set

import requests
from src.utils.validators import is_valid_domain


logger = logging.getLogger(__name__)


def get_securitytrails_subdomains(domain: str, api_keys: list[str], verbose: bool = False) -> Set[str]:
    """
    Fetch subdomains from SecurityTrails API with key rotation.

    Args:
        domain: Root domain to query.
        api_keys: List of SecurityTrails API keys.
        verbose: Enable verbose logging.

    Returns:
        Set of unique subdomains.
    """
    subdomains: Set[str] = set()
    if not api_keys:
        logger.error("No SecurityTrails API keys provided")
        return subdomains

    for key_idx, api_key in enumerate(api_keys):
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 429:
                logger.warning(f"SecurityTrails API key {key_idx+1} hit rate limit, rotating...")
                time.sleep(2)
                continue
            response.raise_for_status()
            data = response.json()
            subs = data.get("subdomains", [])
            for sub in subs:
                full_domain = f"{sub}.{domain}"
                if is_valid_domain(full_domain) and full_domain.endswith(domain):
                    subdomains.add(full_domain)
            logger.info(f"SecurityTrails found {len(subdomains)} subdomains that matches the target domain.")
            break  # Exit on success
        except requests.exceptions.RequestException as e:
            logger.error(f"SecurityTrails key {key_idx+1} failed: {e}")
            if key_idx < len(api_keys) - 1:
                logger.info("Retrying with next API key...")
                time.sleep(2)
            continue
    if not subdomains and verbose:
        logger.warning(f"No subdomains found for {domain} via SecurityTrails")
    return subdomains
"""
WHOIS info fetching module (whois).
"""

import logging
import whois
from typing import Optional, Dict

logger = logging.getLogger(__name__)


def get_whois_info(domain: str, rapidapi_key: str = None) -> Dict[str, str]:
    """
    Fetch WHOIS info using python-whois library.

    Args:
        domain: Domain to query.
        rapidapi_key: Ignored (kept for compatibility).

    Returns:
        Dictionary of WHOIS data or "N/A" if failed/empty.
    """
    try:
        w = whois.whois(domain)
        if not w:
            return "N/A"
        
        # Helper to convert datetimes to strings
        def serialize_whois(data):
            import datetime
            if isinstance(data, dict):
                return {k: serialize_whois(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [serialize_whois(i) for i in data]
            elif isinstance(data, (datetime.datetime, datetime.date)):
                return data.isoformat()
            else:
                return data

        return serialize_whois(dict(w))
    except Exception as e:
        logger.error(f"WHOIS error for {domain}: {e}")
        return "N/A"
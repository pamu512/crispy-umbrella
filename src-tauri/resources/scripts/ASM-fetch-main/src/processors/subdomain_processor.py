"""
Processor for subdomain data.
"""

import logging
from typing import List, Dict, Optional
import tldextract

from src.api.whois import get_whois_info
from src.api.dns import query_dns_record
from src.utils.validators import is_private_ip


logger = logging.getLogger(__name__)


def process_subdomain(
    subdomain: str, verbose: bool = False, rapidapi_key: str = None, ip_hints: List[str] = None, whois_cache: Dict[str, str] = None
) -> List[Dict[str, str]]:
    """
    Process a single subdomain, fetching DNS, WHOIS, ASN, SPF, DMARC, DKIM.
    
    Args:
        subdomain: Subdomain to process.
        verbose: Verbose mode.
        rapidapi_key: RapidAPI key for DNS and WHOIS queries.
        ip_hints: List of IP hints (A records).
        whois_cache: Dictionary of domain -> whois info string.

    Returns:
        List of row dicts (one per IP).
    """
    if ip_hints:
        a_records = ip_hints
    else:
        dns_result = query_dns_record(subdomain, "A", rapidapi_key, verbose=verbose)
        a_records = dns_result["records"] if dns_result["success"] else []

    record_type = "A" if a_records else "N/A"

    # WHOIS lookup via cache
    whois_info = "N/A"
    if whois_cache:
        try:
            extracted = tldextract.extract(subdomain)
            registered_domain = f"{extracted.domain}.{extracted.suffix}"
            whois_info = whois_cache.get(registered_domain, "N/A")
        except Exception:
            whois_info = "N/A"
    else:
        # Fallback if no cache provided (though typically it should be)
        whois_info = get_whois_info(subdomain)

    # These are domain-wide, so we fetch them ONCE per subdomain
    spf_result = query_dns_record(subdomain, "SPF", rapidapi_key, verbose=verbose)
    spf_info = spf_result["records"][0] if spf_result["records"] else "N/A"
    dmarc_result = query_dns_record(subdomain, "DMARC", rapidapi_key, verbose=verbose)
    dmarc_info = dmarc_result["records"][0] if dmarc_result["records"] else "N/A"
    dkim_result = query_dns_record(subdomain, "DKIM", rapidapi_key, verbose=verbose)
    dkim_info = dkim_result["records"][0] if dkim_result["records"] else "N/A"

    result = []
    # Identify unique IPs to process
    unique_ips = sorted(list(set(a_records))) if a_records else ["N/A"]

    for ip in unique_ips:
        asn, asn_name = _get_asn_info(ip)
        result.append({
            "Hosts": subdomain,
            "IPs": ip,
            "Type": record_type,
            "ASN": asn,
            "ASN Name": asn_name,
            "WHOIS": whois_info,
            "CVE": "N/A",  # Filled later
            "SPF": spf_info,
            "DMARC": dmarc_info,
            "DKIM": dkim_info,
            "Opened Ports": "N/A"  # Filled later
        })
    return result


def _get_asn_info(ip: str) -> tuple[str, str]:
    """Fetch ASN and name, skipping invalid/private IPs."""
    from ipwhois import IPWhois
    if ip == "N/A" or ip == "0.0.0.0" or is_private_ip(ip):
        return "N/A", "N/A"
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        asn = results.get('asn', 'N/A')
        asn_name = results.get('asn_description', 'N/A')
        return f"ASN:{asn}", asn_name
    except Exception as e:
        if "Private-Use Networks" in str(e) or "Loopback" in str(e):
            return "N/A", "N/A"
        logger.error(f"Error fetching ASN for {ip}: {e}")
        return "N/A", "N/A"
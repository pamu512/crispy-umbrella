"""
Processor for MX host data.
"""

import concurrent.futures
import logging
from typing import List, Dict
import tldextract

from src.api.whois import get_whois_info
from src.api.dns import query_dns_record
from src.utils.validators import is_private_ip


logger = logging.getLogger(__name__)


def process_mx_host(mx_host: str, rapidapi_key: str, verbose: bool = False, whois_cache: Dict[str, str] = None) -> List[Dict[str, str]]:
    """
    Process a single MX host, fetching A, WHOIS, ASN, SPF, DMARC, DKIM.

    Args:
        mx_host: MX host to process.
        rapidapi_key: RapidAPI key for DNS and WHOIS queries.
        verbose: Verbose mode.
        whois_cache: Dictionary of domain -> whois info string.

    Returns:
        List of row dicts (one per IP).
    """
    # Parallel DNS queries
    record_types = ["A", "SPF", "DMARC", "DKIM"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_type = {
            executor.submit(query_dns_record, mx_host, rtype, rapidapi_key, verbose=verbose): rtype
            for rtype in record_types
        }
        results = {}
        for future in future_to_type:
            rtype = future_to_type[future]
            try:
                results[rtype] = future.result()
            except Exception as e:
                logger.error(f"Error fetching {rtype} for MX host {mx_host}: {e}")
                results[rtype] = {"success": False, "records": []}

    a_records = results["A"]["records"] if results["A"]["success"] else []
    spf_info = results["SPF"]["records"][0] if results["SPF"]["records"] else "N/A"
    dmarc_info = results["DMARC"]["records"][0] if results["DMARC"]["records"] else "N/A"
    dkim_info = results["DKIM"]["records"][0] if results["DKIM"]["records"] else "N/A"

    dkim_info = results["DKIM"]["records"][0] if results["DKIM"]["records"] else "N/A"
    
    whois_info = "N/A"
    if whois_cache:
        try:
            extracted = tldextract.extract(mx_host)
            registered_domain = f"{extracted.domain}.{extracted.suffix}"
            whois_info = whois_cache.get(registered_domain, "N/A")
        except Exception:
            whois_info = "N/A"
    else:
        whois_info = get_whois_info(mx_host)
    result = []
    cleaned_host = mx_host.rstrip(".")  # Clean trailing dot
    for ip in a_records if a_records else ["N/A"]:
        asn, asn_name = _get_asn_info(ip)
        result.append({
            "Hosts": cleaned_host,
            "IPs": ip,
            "Type": "MX",
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
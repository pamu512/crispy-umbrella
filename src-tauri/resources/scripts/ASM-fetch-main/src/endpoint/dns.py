"""
DNS record querying module using RapidAPI (dns).
"""

import concurrent.futures
import logging
import re
import time
from typing import Dict, List

import requests
from circuit_breaker import circuit_protect
from src.utils.validators import is_valid_domain


logger = logging.getLogger(__name__)


def query_dns_record(
    host: str,
    record_type: str,
    rapidapi_key: str,
    dkim_selector: str = None,
    verbose: bool = False,
    max_retries: int = 3,
    backoff: int = 2
) -> Dict[str, any]:
    """
    Query DNS records for a given host and record type.
    For A records, query both Google and Cloudflare providers in parallel (5 times each, with retries).
    For other records, use Google provider only (with retries).
    Returns extracted data for each record type.

    Args:
        host: The domain or host to query.
        record_type: DNS record type (e.g., 'A', 'MX', 'SPF', 'DMARC', 'DKIM').
        rapidapi_key: RapidAPI key for authentication.
        dkim_selector: Optional DKIM selector (unused here).
        verbose: Enable verbose warnings.
        max_retries: Number of retry attempts.
        backoff: Base backoff delay in seconds.

    Returns:
        Dict with 'success' bool and 'records' list.
    """
    if not rapidapi_key:
        logger.error("RAPIDAPI_KEY is not provided")
        return {"success": False, "records": []}

    if not is_valid_domain(host):
        logger.error(f"Skipping invalid domain for {record_type}: {host}")
        return {"success": False, "records": []}

    logger.debug(f"Using RAPIDAPI_KEY: {rapidapi_key[:4]}...{rapidapi_key[-4:]} for {host} ({record_type})")

    record_type = record_type.upper()
    extracted = {"success": False, "records": []}
    selectors = ["default", "google", "mail", "selector1", "selector2"]

    def dns_api_call(query: str, api_type: str, provider: str, max_retries: int, backoff: int) -> Dict:
        url = f"https://dnslookup-fast.p.rapidapi.com/{provider}/"
        payload = {"query": query, "record_type": api_type}
        headers = {
            "x-rapidapi-key": rapidapi_key,
            "x-rapidapi-host": "dnslookup-fast.p.rapidapi.com",
            "Content-Type": "application/json"
        }
        for attempt in range(max_retries):
            try:
                response = circuit_protect(
                    "asm_rapidapi_dns",
                    lambda: requests.post(url, json=payload, headers=headers, timeout=10),
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"DNS error for {query} [{api_type}] via {provider}, retry {attempt+1}/{max_retries}: {e}")
                time.sleep(backoff ** attempt)  # Exponential backoff
        return {}

    try:
        if record_type == "DKIM":
            # Try selectors with Google
            for selector in selectors:
                query = f"{selector}._domainkey.{host}"
                result = dns_api_call(query, "TXT", "google", max_retries, backoff)
                answers = result.get("data", {}).get("Answer", [])
                dkim_records = [a["data"] for a in answers if any(kw in a.get("data", "") for kw in ["v=DKIM1", "k=rsa"])]
                if dkim_records:
                    extracted["success"] = True
                    extracted["records"] = dkim_records
                    logger.info(f"Found DKIM record for {host} with selectorinked to domain {selector}")
                    break
            if not extracted["records"] and verbose:
                logger.warning(f"No DKIM record found for {host}")
            return extracted

        # Configure query for non-DKIM
        if record_type == "SPF":
            query, api_type, provider = f"{host}", "TXT", "google"
        elif record_type == "DMARC":
            query, api_type, provider = f"_dmarc.{host}", "TXT", "google"
        elif record_type == "A":
            query, api_type = host, "A"
            # Parallel queries for A records
            providers = ["google", "cloudflare"]
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(dns_api_call, query, api_type, provider, max_retries, backoff)
                    for provider in providers for _ in range(5)
                ]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    answers = result.get("data", {}).get("Answer", [])
                    results.extend([a["data"] for a in answers if a.get("type") == 1])
            unique_ips = list(set(results))
            extracted["success"] = bool(unique_ips)
            extracted["records"] = unique_ips
            if not unique_ips and verbose:
                logger.warning(f"No A records found for {host}")
            return extracted
        else:  # MX, etc.
            query, api_type, provider = host, record_type, "google"

        # Single call for other records
        result = dns_api_call(query, api_type, provider, max_retries, backoff)
        answers = result.get("data", {}).get("Answer", [])
        extracted["success"] = result.get("success", False)

        if record_type == "MX":
            mx_records = []
            for a in answers:
                if a.get("type") == 15:
                    parts = a["data"].split()
                    if len(parts) == 2:
                        mx_server = parts[1].rstrip(".")
                        mx_records.append(mx_server)
            extracted["records"] = mx_records
            if not extracted["records"] and verbose:
                logger.warning(f"No MX records found for {host}")
        elif record_type == "SPF":
            extracted["records"] = [a["data"] for a in answers if "v=spf1" in a.get("data", "")]
            if not extracted["records"] and verbose:
                logger.warning(f"No SPF record found for {host}")
        elif record_type == "DMARC":
            extracted["records"] = [a["data"] for a in answers if "v=DMARC1" in a.get("data", "")]
            if not extracted["records"] and verbose:
                logger.warning(f"No DMARC record found for {host}")
        else:
            extracted["records"] = [a["data"] for a in answers]

        return extracted
    except Exception as e:
        logger.error(f"Error fetching {record_type} for {host}: {e}")
        return extracted
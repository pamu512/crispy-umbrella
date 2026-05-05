"""
Shodan API module for subdomain discovery and host info (shodan).
"""

import logging
from typing import Dict, List, Set, Tuple

import shodan
from src.utils.validators import is_valid_domain


logger = logging.getLogger(__name__)


def get_shodan_subdomains(domain: str, shodan_api_key: str, verbose: bool = False) -> Dict[str, List[str]]:
    """
    Fetch subdomains and their IPs from Shodan using search_cursor for deep paging.

    Args:
        domain: Root domain.
        shodan_api_key: Shodan API key.
        verbose: Enable verbose logging.

    Returns:
        Dict of subdomain -> list of IPs.
    """
    try:
        api = shodan.Shodan(shodan_api_key)
        queries = [f'hostname:"{domain}"', f'http.html:"{domain}"', f'ssl:"{domain}"']
        
        domains: Dict[str, List[str]] = {}
        total_entries = 0
        missing_hostname_count = 0
        
        for query in queries:
            try:
                count_result = api.count(query)
                total = count_result.get('total', 0) if isinstance(count_result, dict) else int(count_result)
                logger.info(f"Shodan has {total} entries for query: {query}")
                
                
                matched_entries = 0
                for item in api.search_cursor(query, retries=300):
                    total_entries += 1
                    hostnames = item.get('hostnames', [])
                    ip = item.get('ip_str')
                    if not hostnames:
                        missing_hostname_count += 1
                    
                    for d in hostnames:
                        if d and is_valid_domain(d):
                            if d == domain or d.endswith("." + domain):
                                matched_entries += 1
                                if d not in domains:
                                    domains[d] = []
                                if ip and ip not in domains[d]:
                                    domains[d].append(ip)

                logger.info(f"Shodan query '{query}' found {total} entries, {matched_entries} matches the target domain.")

            except Exception as e:
                logger.error(f"Error processing Shodan query '{query}': {e}")
                continue

        logger.info(f"Shodan checked {total_entries} entries, {missing_hostname_count} missing hostnames.")
        all_ips = [ip for ip_list in domains.values() for ip in ip_list]
        unique_ips = len(set(all_ips))
        logger.info(f"Shodan found {len(domains)} subdomains with {len(all_ips)} IPs ({unique_ips} unique) matching the target domain.")

        return domains
    except shodan.APIError as e:
        if "No information available" in str(e):
            if verbose:
                logger.warning(f"Shodan: No subdomains found for {domain}")
        else:
            logger.error(f"Shodan API Error: {e}")
        return {}
    except Exception as e:
        logger.error(f"Shodan Processing Error: {e}")
        return {}


def batch_shodan_host_info(ip_list: List[str], shodan_api_key: str) -> Dict[str, Tuple[str, str]]:
    """
    Batch query Shodan for CVEs and open ports on IPs.

    Args:
        ip_list: List of IPs.
        shodan_api_key: Shodan API key.

    Returns:
        Dict of IP -> (CVE string, Ports string).
    """
    if not ip_list:
        return {}

    api = shodan.Shodan(shodan_api_key)
    batch_size = 100
    results: Dict[str, Dict[str, any]] = {}

    for i in range(0, len(ip_list), batch_size):
        batch = ip_list[i:i + batch_size]
        query = "ip:" + ",".join(batch)
        try:
            response = api.search(query, limit=batch_size)
            for match in response.get("matches", []):
                ip = match.get("ip_str")
                vulns = match.get("vulns", [])
                cve = ",".join(vulns) if vulns else "N/A"
                # store the raw Shodan match dict so callers can persist the full JSON
                raw_match = match.copy() if isinstance(match, dict) else match
                if ip not in results:
                    results[ip] = {"cve": set(), "ports": []}
                if cve != "N/A":
                    results[ip]["cve"].update(vulns)
                # If the Shodan match contains a 'data' key (a list of service details),
                # store those full 'data' entries instead of filtering specific keys.
                # This preserves the complete service payload for DB + API JSON output.
                if isinstance(raw_match, dict) and isinstance(raw_match.get('data'), list):
                    for data_entry in raw_match.get('data'):
                        # ensure we store dicts; if an entry is not a dict, wrap it
                        if isinstance(data_entry, dict):
                            results[ip]["ports"].append(data_entry)
                        else:
                            results[ip]["ports"].append({"data": data_entry})
                else:
                    results[ip]["ports"].append(raw_match)
        except shodan.APIError as e:
            logger.error(f"Shodan batch query error: {e}")
            for ip in batch:
                if ip not in results:
                    results[ip] = {"cve": set(), "ports": []}
        except Exception as e:
            logger.error(f"Error in batch_shodan_host_info: {e}")
            for ip in batch:
                if ip not in results:
                    results[ip] = {"cve": set(), "ports": []}

    # Finalize
    final: Dict[str, Tuple[List[str], List[Dict]]] = {}
    for ip in ip_list:
        ip_data = results.get(ip, {"cve": set(), "ports": []})
        cve_list = sorted(ip_data["cve"]) if ip_data["cve"] else []
        ports_list = ip_data["ports"] if ip_data["ports"] else []
        final[ip] = (cve_list, ports_list)

    return final


def _format_port_info(match: Dict) -> str:
    """Format port info from Shodan match."""
    safe = lambda val: val if val else "N/A"
    port = safe(match.get('port'))
    transport = safe(match.get('transport'))
    version = safe(match.get('version'))
    product = safe(match.get('product'))
    info_field = safe(match.get('info'))
    return f"Port:{port} (Transport:{transport}, Version:{version}, Product:{product}, Info:{info_field})"


def _format_port_struct(match: Dict) -> Dict:
    """Return structured port dict from Shodan match."""
    return {
        "port": match.get('port'),
        "transport": match.get('transport'),
        "version": match.get('version'),
        "product": match.get('product'),
        "info": match.get('info'),
    }
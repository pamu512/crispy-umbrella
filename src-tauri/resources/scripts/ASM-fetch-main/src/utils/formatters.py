# utils/formatters.py
"""
Utility functions for formatting data.
"""

import re
from datetime import datetime
from typing import Set
from typing import Any, Optional
import ast


def format_date(date_str: str) -> str:
    """Format a date string to YYYY-MM-DD."""
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return date_str


def extract_unusual_ports(open_ports_str: str) -> list:
    """
    Given the Opened Ports string, return a comma-separated string of unusual ports.
    Unusual ports are those not in the common set.
    """
    if not open_ports_str or open_ports_str == "N/A":
        return []

    # Unusual ports
    unusual_ports_set: Set[int] = {
        21, 22, 23, 110, 111, 135, 139, 143, 445, 993, 995,
        1433, 1521, 1723, 3306, 3389, 5432, 5900
    }
    ports: Set[str] = set()
    # open_ports_str can be a list of structured dicts (from Shodan) or a legacy string
    if isinstance(open_ports_str, list):
        for p in open_ports_str:
            try:
                port = int(p.get('port')) if p.get('port') is not None else None
            except Exception:
                port = None
            if port and port in unusual_ports_set:
                ports.add(str(port))
    else:
        # legacy string: split by semicolon and extract Port:NNN
        for part in str(open_ports_str).split(";"):
            match = re.search(r"Port:(\d+)", part)
            if match:
                port = int(match.group(1))
                if port in unusual_ports_set:
                    ports.add(str(port))

    # return as list of ints (as numbers) for JSON storage
    return [int(p) for p in sorted(ports, key=int)] if ports else []


def unusual_ports_to_string(ports) -> str:
    """Convert stored unusual ports (list or string) into legacy comma-separated string for exporters."""
    if not ports:
        return "N/A"
    if isinstance(ports, str):
        return ports
    try:
        return ",".join(str(int(p)) for p in ports)
    except Exception:
        return str(ports)


def format_opened_ports(opened_ports) -> str:
    """Return legacy semicolon-joined string for exporters from structured opened_ports.

    If opened_ports is already a string, return as-is.
    If it's a list of dicts, produce 'Port:80 (Transport:tcp, Version:..., Product:..., Info:...)' joined by '; '.
    """
    if not opened_ports or opened_ports == "N/A":
        return "N/A"
    if isinstance(opened_ports, str):
        return opened_ports
    if isinstance(opened_ports, list):
        parts = []
        for p in opened_ports:
            # If entry isn't a dict, we can't extract fields — represent it compactly
            if not isinstance(p, dict):
                parts.append(str(p))
                continue
            # Prefer the canonical keys in the Shodan/service payloads
            port = p.get('port') if 'port' in p else p.get('port_number') if 'port_number' in p else None
            transport = p.get('transport') if 'transport' in p else p.get('protocol') if 'protocol' in p else None
            version = p.get('version') if 'version' in p else None
            product = p.get('product') if 'product' in p else p.get('name') if 'name' in p else p.get('server') if 'server' in p else None
            info = p.get('info') if 'info' in p else None

            # If we didn't find port, try to discover a numeric port elsewhere
            if port is None:
                possible_ports = [v for k, v in p.items() if isinstance(v, int) and 0 < v < 65536]
                port = possible_ports[0] if possible_ports else None

            # If still no port, include compact dict string fallback
            if port is None:
                try:
                    parts.append(str(p))
                except Exception:
                    parts.append('N/A')
                continue

            # Normalize values to strings and set N/A defaults
            def safe_str(x):
                if x is None:
                    return 'N/A'
                # convert booleans/ints to strings
                try:
                    return str(x)
                except Exception:
                    return 'N/A'

            parts.append(f"Port:{safe_str(port)} (Transport:{safe_str(transport)}, Version:{safe_str(version)}, Product:{safe_str(product)}, Info:{safe_str(info)})")
        return "; ".join(parts) if parts else "N/A"
    # fallback
    return str(opened_ports)


def parse_tls_string(tls_str: str) -> dict:
    """
    Parse a TLS/SSL legacy string into a dict. Handles newline-separated lines like
    'key,value' or 'key: value', and attempts to extract key/value pairs from
    semicolon-joined strings when possible.
    """
    # If already a dict, return as-is
    if isinstance(tls_str, dict):
        return tls_str

    if not tls_str or tls_str in ("N/A", None):
        return {}

    s = str(tls_str)
    parsed = {}
    # Known keys
    keys_order = ['Grade', 'Server Name', 'Protocols', 'Cipher Suites', 'SigAlg', 'KeyAlg']
    # Find all occurrences of known keys (order-agnostic) and record their positions
    key_pattern = re.compile(r'(' + '|'.join(re.escape(k) for k in keys_order) + r')\s*[:=,]', flags=re.IGNORECASE)
    matches = list(key_pattern.finditer(s))
    # If we found key markers, extract value between this key's end and the next key's start
    if matches:
        for idx, m in enumerate(matches):
            key_name = m.group(1)
            start = m.end()
            end = matches[idx+1].start() if idx+1 < len(matches) else len(s)
            val = s[start:end].strip().rstrip(';').strip()
            val = re.sub(r'\s+', ' ', val)
            # If this is Server Name, its captured value may include unlabeled tokens (protocols/ciphers).
            if key_name.lower() == 'server name':
                tokens = [p.strip() for p in re.split(r'[;,]\s*', val) if p.strip()]
                server_parts = []
                found_protocols = []
                found_ciphers = []
                for tok in tokens:
                    # protocol-like tokens
                    if re.search(r'\bTLSv?\s*\d(?:\.\d)?\b', tok, flags=re.IGNORECASE):
                        norm = re.sub(r'\s+', ' ', tok.replace('v', ' ').upper()).strip()
                        if norm not in found_protocols:
                            found_protocols.append(norm)
                    # cipher-like tokens (contains underscore or common cipher name patterns)
                    elif '_' in tok or re.match(r'^[A-Z0-9_-]{10,}$', tok):
                        if tok not in found_ciphers:
                            found_ciphers.append(tok)
                    else:
                        server_parts.append(tok)
                if server_parts:
                    parsed['Server Name'] = '; '.join(server_parts)
                else:
                    parsed['Server Name'] = val
                if found_protocols:
                    # merge with any existing protocols found elsewhere
                    existing = parsed.get('Protocols', [])
                    merged = existing + [p for p in found_protocols if p not in existing]
                    parsed['Protocols'] = merged
                if found_ciphers:
                    existing = parsed.get('Cipher Suites', [])
                    merged = existing + [c for c in found_ciphers if c not in existing]
                    parsed['Cipher Suites'] = merged
            elif key_name.lower() == 'cipher suites':
                items = [it.strip() for it in re.split(r'[;,]\s*', val) if it.strip()]
                parsed['Cipher Suites'] = items
            elif key_name.lower() == 'protocols':
                parts = [p.strip() for p in re.split(r'[;,]\s*', val) if p.strip()]
                protocols = [p for p in parts if p.upper().startswith('TLS')]
                parsed['Protocols'] = protocols if protocols else parts
            else:
                parsed[key_name] = val
    else:
        # No explicit key markers found; fall back to heuristic extraction below
        pass

    # If Cipher Suites missing, try to extract tokens that look like cipher suite names
    if 'Cipher Suites' not in parsed:
        tokens = [t.strip() for t in re.split(r'[;\n]+', s) if t.strip()]
        ciphers = []
        for t in tokens:
            tclean = t
            # skip tokens that look like Grade/Server/Protocols labels
            if re.match(r'^(Grade|Server Name|Protocols|SigAlg|KeyAlg)\b', tclean, flags=re.IGNORECASE):
                continue
            if 'TLS' in tclean or '_' in tclean:
                cparts = [x.strip() for x in re.split(r'[;,]\s*', tclean) if x.strip()]
                ciphers.extend(cparts)
        if ciphers:
            seen = set(); dedup = []
            for c in ciphers:
                if c not in seen:
                    seen.add(c); dedup.append(c)
            parsed['Cipher Suites'] = dedup

    # Post-process Server Name: if Server Name contains trailing tokens that look like ciphers
    # (and Cipher Suites was not present earlier), split them out.
    if 'Server Name' in parsed and 'Cipher Suites' in parsed and parsed['Server Name']:
        # nothing to do if ciphers were explicitly found
        pass
    elif 'Server Name' in parsed and 'Cipher Suites' not in parsed:
        server_val = parsed.get('Server Name', '')
        parts = [p.strip() for p in re.split(r';\s*', server_val) if p.strip()]
        if len(parts) > 1:
            server_parts = []
            found_ciphers = []
            for part in parts:
                # simple heuristic: cipher tokens often contain '_' or start with 'TLS_' or look like uppercase tokens with underscores
                if '_' in part or re.match(r'^TLS[_ ]', part, flags=re.IGNORECASE) or re.match(r'^[A-Z0-9_]{10,}', part):
                    found_ciphers.append(part)
                else:
                    # also stop collecting server parts if we already started finding ciphers
                    if found_ciphers:
                        found_ciphers.append(part)
                    else:
                        server_parts.append(part)
            if found_ciphers and server_parts:
                parsed['Server Name'] = '; '.join(server_parts)
                # append found ciphers to Cipher Suites
                seen = set(); dedup = []
                for c in found_ciphers:
                    if c not in seen:
                        seen.add(c); dedup.append(c)
                parsed['Cipher Suites'] = dedup

    # If Protocols was not captured explicitly, try to detect TLS versions anywhere in the string
    if 'Protocols' not in parsed:
        # match variants like 'TLS 1.2', 'TLS1.3', 'TLSv1.2' (case-insensitive)
        proto_matches = re.findall(r'TLSv?\s*\d(?:\.\d)?', s, flags=re.IGNORECASE)
        if proto_matches:
            # normalize to 'TLS X.Y' and preserve first-seen order
            seen = set(); prots = []
            for p in proto_matches:
                norm = re.sub(r'\s+', ' ', p.replace('v', ' ').upper()).strip()
                if norm not in seen:
                    seen.add(norm); prots.append(norm)
            parsed['Protocols'] = prots

    return parsed


def format_tls_dict(tls: dict) -> str:
    """
    Format the tls dict back into legacy 'Key: Value; Key2: Value2' string for CSV/XLSX exports.
    """
    if not tls:
        return "N/A"
    parts = []
    for k, v in tls.items():
        if isinstance(v, list):
            parts.append(f"{k}: {'; '.join(map(str, v))}")
        else:
            parts.append(f"{k}: {v}")
    return "; ".join(parts)


# WHOIS formatter for export
def format_whois(whois_data):
    """
    Format WHOIS JSON/dict for legacy export (CSV/XLSX) as 'key1:value1; key2:value2'.
    whois_data: dict or str or None
    Returns: legacy string for export
    """
    if not whois_data or whois_data == "N/A":
        return "N/A"
    if not isinstance(whois_data, dict):
        return "N/A"
    parts = []
    for k, v in whois_data.items():
        if v is None:
            continue
        if isinstance(v, list):
            v_str = ', '.join(str(x) for x in v if x not in (None, ""))
            if not v_str:
                continue
        else:
            v_str = str(v).strip()
            if not v_str:
                continue
        parts.append(f"{k}:{v_str}")
    return "; ".join(parts) if parts else "N/A"


def parse_possible_dict(value: Any) -> Optional[dict]:
    """
    Try to coerce various representations into a dict.

    Accepts: dict (returned as-is), stringified dict (ast.literal_eval),
    and other objects with a string representation that looks like a dict.
    Returns: dict or None if not parseable.
    """
    if not value:
        return None
    # If already a dict
    if isinstance(value, dict):
        return value
    # If it's a string that looks like a dict
    if isinstance(value, str):
        s = value.strip()
        if s.startswith('{') and s.endswith('}'):
            try:
                parsed = ast.literal_eval(s)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return None
        return None
    # Fallback: try converting to string and parse
    try:
        s = str(value).strip()
        if s.startswith('{') and s.endswith('}'):
            parsed = ast.literal_eval(s)
            if isinstance(parsed, dict):
                return parsed
    except Exception:
        return None
    return None
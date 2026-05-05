# utils/validators.py
"""
Utility functions for validation.
"""

import re
import validators


def is_private_ip(ip: str) -> bool:
    """Check if an IP is private (RFC 1918) or loopback (RFC 1122)."""
    private_ranges = [
        r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$',  # 172.16.0.0/12
        r'^192\.168\.\d{1,3}\.\d{1,3}$',  # 192.168.0.0/16
        r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  # 127.0.0.0/8
    ]
    return any(re.match(pattern, ip) for pattern in private_ranges)


def is_valid_domain(domain: str) -> bool:
    """Validate if the input is a valid domain name (not an IP address)."""
    return validators.domain(domain)
"""
Compatibility wrapper: keep `src.api.dns` import path working after moving endpoint routers to `src/endpoint`.
This module re-exports query_dns_record from `src.endpoint.dns` for backward compatibility.
"""
from src.endpoint.dns import query_dns_record

__all__ = ["query_dns_record"]

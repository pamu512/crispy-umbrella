"""
Scan result retrieval API router.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database.crud import get_scan, list_subdomain_data
from src.database.schemas import ScanOut, SubdomainDataOut
from pydantic import BaseModel


class ScanResultsEnvelope(BaseModel):
    scan_id: int
    count: int
    results: list[SubdomainDataOut]

    class Config:
        from_attributes = True
from src.database.session import get_db

router = APIRouter()

@router.get("/{scan_id}/json", response_model=ScanResultsEnvelope)
def get_scan_result_json(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = list_subdomain_data(db, scan_id)
    # Map ORM objects to dicts and ensure tls_ssl is returned as JSON (dict)
    results = []
    for d in data:
        tls_val = d.tls_ssl
        from src.utils.formatters import parse_tls_string
        # If TLS is stored as a simple string, parse it
        if isinstance(tls_val, str) and tls_val not in (None, "N/A", ""):
            tls_val = parse_tls_string(tls_val)
        # If TLS is stored as a dict but some values contain embedded kv data, parse and merge
        if isinstance(tls_val, dict):
            merged = {}
            for k, v in list(tls_val.items()):
                if isinstance(v, str) and (':' in v or ';' in v or '{' in v):
                    parsed_inner = parse_tls_string(v)
                    if parsed_inner:
                        # merge parsed inner keys into merged dict
                        merged.update(parsed_inner)
                        continue
                # otherwise keep the original key/value
                merged[k] = v
            tls_val = merged
        elif tls_val in (None, "N/A"):
            tls_val = {}

        # Normalize sensitive_subdomains into a list for JSON API consumers
        ss_val = d.sensitive_subdomains
        if isinstance(ss_val, list):
            ss_list = ss_val
        elif isinstance(ss_val, str) and ss_val not in (None, "", "N/A"):
            # split on commas or semicolons
            import re
            ss_list = [s.strip() for s in re.split(r'[;,\n]+', ss_val) if s.strip()]
        else:
            ss_list = []

        # Normalize cve into a list for JSON API consumers
        cve_val = d.cve
        if isinstance(cve_val, list):
            cve_list = cve_val
        elif isinstance(cve_val, str) and cve_val not in (None, "", "N/A"):
            cve_list = [s.strip() for s in cve_val.split(',') if s.strip()]
        else:
            cve_list = []

        results.append({
            "host": d.host,
            "ip": d.ip,
            "type": d.type,
            "asn": d.asn,
            "asn_name": d.asn_name,
            "whois": d.whois,
            "cve": cve_list,
            "spf": d.spf,
            "dmarc": d.dmarc,
            "dkim": d.dkim,
            "tls_ssl": tls_val,
            "opened_ports": d.opened_ports,
            "unusual_ports": d.unusual_ports if isinstance(d.unusual_ports, list) else (d.unusual_ports or []),
            "sensitive_subdomains": ss_list,
        })
    return {"scan_id": scan_id, "count": len(results), "results": results}

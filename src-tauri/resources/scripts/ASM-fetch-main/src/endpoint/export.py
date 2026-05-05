"""
Export API router for CSV/XLSX.
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from src.database.crud import get_scan, list_subdomain_data
from src.database.session import get_db
from src.output.excel_utils import build_workbook
import csv
import io
from fastapi.responses import StreamingResponse
from src.utils.formatters import format_tls_dict
from src.utils.formatters import format_opened_ports
from src.utils.formatters import format_whois, parse_possible_dict
from src.utils.formatters import unusual_ports_to_string

router = APIRouter()

@router.get("/{scan_id}/csv")
def export_scan_csv(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = list_subdomain_data(db, scan_id)
    # Map ORM objects to clean dicts with explicit fields and ordering
    rows = []
    for d in data:
        rows.append({
            "Hosts": d.host,
            "IPs": d.ip,
            "Type": d.type,
            "ASN": d.asn,
            "ASN Name": d.asn_name,
            "WHOIS": d.whois,
            "CVE": d.cve,
            "SPF": d.spf,
            "DMARC": d.dmarc,
            "DKIM": d.dkim,
            # Keep tls_ssl as dict in DB but export as legacy string
            "TLS SSL": format_tls_dict(d.tls_ssl) if d.tls_ssl else "N/A",
            "Opened Ports": format_opened_ports(d.opened_ports),
            "Unusual Ports": d.unusual_ports,
            "Sensitive Subdomains": d.sensitive_subdomains,
            "created_at": d.created_at.isoformat() if hasattr(d.created_at, 'isoformat') else d.created_at,
        })
    # Use csv module to preserve header order and formatting
    headers = [
        "Hosts", "IPs", "Type", "ASN", "ASN Name", "WHOIS", "CVE", "SPF",
        "DMARC", "DKIM", "TLS SSL", "Opened Ports", "Unusual Ports", "Sensitive Subdomains"
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=headers)
    writer.writeheader()

    # Convert Unusual Ports to legacy comma-separated strings for CSV export
    for r in rows:
        up = r.get("Unusual Ports")
        if isinstance(up, (list, tuple)):
            r["Unusual Ports"] = unusual_ports_to_string(up)
        # Convert CVE list to comma-separated string for CSV/XLSX
        cv = r.get("CVE")
        if isinstance(cv, list):
            r["CVE"] = ",".join(cv) if cv else "N/A"

    # Flatten and write rows
    for r in rows:
        flat = {}
        for k in headers:
            v = r.get(k, "N/A")
            if k == "WHOIS":
                parsed = parse_possible_dict(v)
                if parsed is not None:
                    flat[k] = format_whois(parsed)
                    continue
            if isinstance(v, list):
                flat[k] = "; ".join(str(x) for x in v) if v else "N/A"
            elif isinstance(v, dict):
                flat[k] = str(v) if v else "N/A"
            else:
                flat[k] = v if v is not None else "N/A"
        writer.writerow(flat)
    return Response(content=buf.getvalue(), media_type="text/csv")

@router.get("/{scan_id}/xlsx")
def export_scan_xlsx(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = list_subdomain_data(db, scan_id)
    rows = []
    for d in data:
        rows.append({
            "Hosts": d.host,
            "IPs": d.ip,
            "Type": d.type,
            "ASN": d.asn,
            "ASN Name": d.asn_name,
            "WHOIS": d.whois,
            "CVE": d.cve,
            "SPF": d.spf,
            "DMARC": d.dmarc,
            "DKIM": d.dkim,
            "TLS SSL": d.tls_ssl,
            "Opened Ports": d.opened_ports,
            "Unusual Ports": d.unusual_ports,
            "Sensitive Subdomains": d.sensitive_subdomains,
            "created_at": d.created_at.isoformat() if hasattr(d.created_at, 'isoformat') else d.created_at,
        })
    # Normalize rows: stringify lists/dicts for consistent XLSX output
    def _normalize_for_xlsx(r: dict) -> dict:
        out = {}
        for k, v in r.items():
            # Special-case Opened Ports first to avoid generic list serialization
            if k == "Opened Ports":
                out[k] = format_opened_ports(v)
            elif k == "WHOIS":
                # Prefer formatted WHOIS string. If v is a dict, format it. If stringified dict, try parse then format.
                if isinstance(v, dict):
                    out[k] = format_whois(v)
                else:
                    parsed = parse_possible_dict(v)
                    if parsed is not None:
                        out[k] = format_whois(parsed)
                    else:
                        out[k] = v if v is not None else "N/A"
            elif k == "Unusual Ports":
                # Ensure exporters get a string representation
                if isinstance(v, (list, tuple)):
                    out[k] = unusual_ports_to_string(v)
                else:
                    out[k] = v if v is not None else "N/A"
            elif isinstance(v, list):
                out[k] = "; ".join(str(x) for x in v) if v else "N/A"
            elif isinstance(v, dict):
                # format tls_ssl dict back to key:value; semicolon separated string
                if k == "TLS SSL":
                    parts = []
                    for kk, vv in v.items():
                        if isinstance(vv, list):
                            parts.append(f"{kk}:{'; '.join(map(str,vv))}")
                        else:
                            parts.append(f"{kk}:{vv}")
                    out[k] = "; ".join(parts) if parts else "N/A"
                else:
                    out[k] = str(v) if v else "N/A"
            else:
                out[k] = v if v is not None else "N/A"
        # Ensure Unusual Ports is string
        up = out.get("Unusual Ports", "N/A")
        if isinstance(up, list):
            out["Unusual Ports"] = ",".join(str(x) for x in up) if up else "N/A"
        # Ensure Sensitive Subdomains is string
        ss = out.get("Sensitive Subdomains", "N/A")
        if isinstance(ss, list):
            out["Sensitive Subdomains"] = ", ".join(ss) if ss else "N/A"
        return out

    rows = [_normalize_for_xlsx(r) for r in rows]
    headers = [
        "Hosts", "IPs", "Type", "ASN", "ASN Name", "WHOIS", "CVE", "SPF",
        "DMARC", "DKIM", "TLS SSL", "Opened Ports", "Unusual Ports", "Sensitive Subdomains"
    ]
    wb = build_workbook(rows, headers)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

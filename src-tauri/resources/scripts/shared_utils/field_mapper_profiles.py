"""
CSV profile → vault row mapping split out of :class:`ingestor.FieldMapper` for cyclomatic complexity.

Imported lazily from :meth:`~ingestor.FieldMapper.map_fields` so ``import ingestor`` completes first.
"""

from __future__ import annotations

from typing import Callable

from db_manager import parse_cvss_base_score
from exceptions import JsonValue

MapRowResult = tuple[dict[str, JsonValue] | None, str | None]


def _pick(norm: dict[str, str], *keys: str) -> str:
    """First non-empty stripped value for the given column keys (replaces long ``or`` chains for CC)."""
    for k in keys:
        v = norm.get(k)
        if not v:
            continue
        s = v.strip()
        if s:
            return s
    return ""


def _ims() -> object:
    """Late-bound ingestor module (avoid circular import at package load)."""
    import ingestor as ing

    return ing


def dispatch_field_profile(
    profile: str,
    norm: dict[str, str],
    *,
    source_csv: str,
    fallback_scan_iso: str | None,
) -> MapRowResult:
    handler = _PROFILE_HANDLERS.get(profile)
    if handler is None:
        return None, f"Unknown FieldMapper profile: {profile!r}"
    return handler(norm, source_csv=source_csv, fallback_scan_iso=fallback_scan_iso)


def _field_map_intelx(
    norm: dict[str, str],
    *,
    source_csv: str,
    fallback_scan_iso: str | None,
) -> MapRowResult:
    ing = _ims()
    consumed = {
        "selector",
        "query",
        "type",
        "date",
        "timestamp",
        "description",
        "summary",
    }
    selector = _pick(norm, "selector", "query")
    if not selector:
        return None, "Intelx row missing IOC value (selector/query empty)"
    raw_type = norm.get("type") or ""
    ioc_type = ing._intelx_type_to_ioc_type(raw_type).lower()
    dt = ing.normalize_date(norm.get("date") or norm.get("timestamp")) or ing._default_date_iso()
    meta = ing._pack_metadata(norm, consumed, source_csv=source_csv)
    return {
        "table": "ioc",
        "ioc_value": selector,
        "ioc_type": ioc_type,
        "first_seen": dt,
        "last_seen": dt,
        "source_project": "Intelx_Crawler",
        "metadata": meta,
    }, None


def _field_map_nvd(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "cve_id",
        "score",
        "severity_score",
        "published",
        "published_date",
        "updated_at",
        "lastmodified",
        "summary",
        "description",
        "cvss_v3.1",
        "cvss_v4.0",
    }
    cve_id = norm.get("cve_id") or ""
    if not cve_id.startswith("CVE-"):
        return None, f"NVD row missing or invalid cve_id: {cve_id!r}"
    score_raw = _pick(norm, "score", "severity_score", "cvss_v3.1", "cvss_v4.0")
    sev: float | None
    try:
        sev = float(score_raw) if score_raw else None
    except ValueError:
        sev = parse_cvss_base_score(score_raw) if score_raw else None
    pub_raw = ing.normalize_date(_pick(norm, "published", "published_date"))
    pub = (pub_raw or "").strip()
    upd = ing.normalize_date(_pick(norm, "updated_at", "lastmodified")) or ing._default_date_iso()
    meta = ing._pack_metadata(norm, consumed, source_csv=source_csv)
    return {
        "table": "cve",
        "cve_id": cve_id,
        "severity_score": sev,
        "published_date": pub,
        "updated_at": upd,
        "metadata": meta,
    }, None


def _asm_combined_target(host: str, ip: str) -> str:
    if host and ip and ip.upper() != "N/A":
        return f"{host}|{ip}"
    if host:
        return host
    return ip


def _infer_asm_asset_type(norm: dict[str, str], service: str, ip: str) -> str:
    t = (norm.get("type") or "").strip()
    if t:
        return t
    if service:
        return "service"
    if ip:
        return "host_ip"
    return "host"


def _asm_metadata_extras(host: str, ip: str, port: str, service: str) -> dict[str, JsonValue]:
    extras: dict[str, JsonValue] = {}
    if port:
        extras["port"] = port[:400]
    if service:
        extras["service"] = service[:400]
    if host and ip:
        extras["host"] = host
        extras["ip"] = ip
    return extras


def _field_map_asm(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "host",
        "hosts",
        "ip",
        "ips",
        "port",
        "ports",
        "opened_ports",
        "service",
        "services",
        "last_scan",
        "last_scan_at",
        "type",
        "unusual_ports",
    }
    host = _pick(norm, "host", "hosts")
    ip = _pick(norm, "ip", "ips")
    if not host and not ip:
        return None, "ASM row missing asset_target (host/ip empty)"
    asset_target = _asm_combined_target(host, ip)
    port = _pick(norm, "port", "ports", "opened_ports")
    service = _pick(norm, "service", "services")
    scan_fb = fallback_scan_iso or ing._default_date_iso()
    last_scan = ing.normalize_date(_pick(norm, "last_scan", "last_scan_at")) or scan_fb
    asset_type = _infer_asm_asset_type(norm, service, ip)
    status = (norm.get("status") or "active").strip() or "active"
    extras = _asm_metadata_extras(host, ip, port, service)
    meta = ing._pack_metadata(norm, consumed, source_csv=source_csv, extras=extras)
    return {
        "table": "asm",
        "asset_target": asset_target,
        "asset_type": asset_type,
        "last_scan_at": last_scan,
        "status": status,
        "metadata": meta,
    }, None


def _field_map_ransomware(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "website",
        "url",
        "site",
        "date",
        "event_date",
        "victim_name",
        "company",
        "victim",
        "group",
        "group_name",
    }
    website = _pick(norm, "website", "url", "site")
    if not website:
        return None, "Ransomware row missing IOC value (website/url/site empty)"
    dt = ing.normalize_date(_pick(norm, "date", "event_date")) or ing._default_date_iso()
    victim = _pick(norm, "victim_name", "company", "victim")
    group = _pick(norm, "group", "group_name")
    meta = ing._pack_metadata(
        norm,
        consumed,
        source_csv=source_csv,
        extras={"victim_name": victim, "group": group},
    )
    return {
        "table": "ioc",
        "ioc_value": website,
        "ioc_type": "url",
        "first_seen": dt,
        "last_seen": dt,
        "source_project": "Ransomware_live_event_victim",
        "metadata": meta,
    }, None


def _field_map_ioc_crawler(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "indicator",
        "ioc_value",
        "type",
        "ioc_type",
        "source",
        "source_project",
        "tags",
        "tag",
        "first_seen",
        "last_seen",
    }
    indicator = _pick(norm, "indicator", "ioc_value")
    if not indicator:
        return None, "IOC_Crawler row missing IOC value (indicator/ioc_value empty)"
    ioc_type = (_pick(norm, "type", "ioc_type") or "unknown").lower() or "unknown"
    origin = _pick(norm, "source", "source_project") or "IOCs-crawler-main"
    tags = _pick(norm, "tags", "tag")
    fs = ing.normalize_date(norm.get("first_seen")) or ing._default_date_iso()
    ls = ing.normalize_date(norm.get("last_seen")) or ing._default_date_iso()
    meta = ing._pack_metadata(norm, consumed, source_csv=source_csv, extras={"tags": tags})
    return {
        "table": "ioc",
        "ioc_value": indicator,
        "ioc_type": ioc_type,
        "first_seen": fs,
        "last_seen": ls,
        "source_project": origin or "IOCs-crawler-main",
        "metadata": meta,
    }, None


def _field_map_phishing(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "phish_url",
        "url",
        "phishing_url",
        "target_brand",
        "brand",
        "target",
        "status",
        "first_seen",
        "last_seen",
    }
    url = _pick(norm, "phish_url", "url", "phishing_url")
    if not url:
        return None, "Phishing row missing IOC value (phish_url/url empty)"
    brand = _pick(norm, "target_brand", "brand", "target")
    status = norm.get("status") or ""
    fs = ing.normalize_date(norm.get("first_seen")) or ing._default_date_iso()
    ls = ing.normalize_date(norm.get("last_seen")) or ing._default_date_iso()
    meta = ing._pack_metadata(
        norm,
        consumed,
        source_csv=source_csv,
        extras={"target_brand": brand, "status": status},
    )
    return {
        "table": "ioc",
        "ioc_value": url,
        "ioc_type": "phishing_url",
        "first_seen": fs,
        "last_seen": ls,
        "source_project": "Phishing_and_Social_Media_All-in-one",
        "metadata": meta,
    }, None


def _field_map_social(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "profile_link",
        "url",
        "link",
        "handle",
        "username",
        "user",
        "platform",
        "first_seen",
        "last_seen",
    }
    link = _pick(norm, "profile_link", "url", "link")
    if not link:
        return None, "Social row missing IOC value (profile_link/url empty)"
    handle = _pick(norm, "handle", "username", "user")
    platform = norm.get("platform") or ""
    fs = ing.normalize_date(norm.get("first_seen")) or ing._default_date_iso()
    ls = ing.normalize_date(norm.get("last_seen")) or ing._default_date_iso()
    meta = ing._pack_metadata(
        norm,
        consumed,
        source_csv=source_csv,
        extras={"handle": handle, "platform": platform},
    )
    return {
        "table": "ioc",
        "ioc_value": link,
        "ioc_type": "social",
        "first_seen": fs,
        "last_seen": ls,
        "source_project": "Social_MediaV2",
        "metadata": meta,
    }, None


def _field_map_mac_audit(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "hash",
        "sha256",
        "ioc_value",
        "file_path",
        "path",
        "filepath",
        "detection_name",
        "detection",
        "name",
        "first_seen",
        "last_seen",
    }
    h = _pick(norm, "hash", "sha256", "ioc_value")
    if not h or len(h) < 32 or not all(c in "0123456789abcdefABCDEF" for c in h):
        return None, "Mac_Audit row missing or invalid hash (ioc_value)"
    fpath = _pick(norm, "file_path", "path", "filepath")
    det = _pick(norm, "detection_name", "detection", "name")
    fs = ing.normalize_date(norm.get("first_seen")) or ing._default_date_iso()
    ls = ing.normalize_date(norm.get("last_seen")) or ing._default_date_iso()
    meta = ing._pack_metadata(
        norm,
        consumed,
        source_csv=source_csv,
        extras={"file_path": fpath, "detection_name": det},
    )
    return {
        "table": "ioc",
        "ioc_value": h.lower(),
        "ioc_type": "sha256",
        "first_seen": fs,
        "last_seen": ls,
        "source_project": "Compromised_user_Mac",
        "metadata": meta,
    }, None


def _field_map_ioc_generic(norm: dict[str, str], *, source_csv: str, fallback_scan_iso: str | None) -> MapRowResult:
    ing = _ims()
    consumed = {
        "ioc_value",
        "value",
        "url",
        "email",
        "indicator",
        "ioc_type",
        "type",
        "first_seen",
        "firstseen",
        "last_seen",
        "lastseen",
        "source_project",
        "project",
    }
    val = _pick(norm, "ioc_value", "value", "url", "email", "indicator")
    if not val:
        return None, "IOC row missing IOC value"
    ioc_type = (_pick(norm, "ioc_type", "type") or "unknown").lower() or "unknown"
    fs = ing.normalize_date(_pick(norm, "first_seen", "firstseen")) or ing._default_date_iso()
    ls = ing.normalize_date(_pick(norm, "last_seen", "lastseen")) or ing._default_date_iso()
    proj = _pick(norm, "source_project", "project") or "csv_ingest"
    meta = ing._pack_metadata(norm, consumed, source_csv=source_csv)
    return {
        "table": "ioc",
        "ioc_value": val,
        "ioc_type": ioc_type,
        "first_seen": fs,
        "last_seen": ls,
        "source_project": proj or "csv_ingest",
        "metadata": meta,
    }, None


_PROFILE_HANDLERS: dict[str, Callable[..., MapRowResult]] = {
    "Intelx": _field_map_intelx,
    "NVD": _field_map_nvd,
    "ASM": _field_map_asm,
    "Ransomware": _field_map_ransomware,
    "IOC_Crawler": _field_map_ioc_crawler,
    "Phishing": _field_map_phishing,
    "Social": _field_map_social,
    "Mac_Audit": _field_map_mac_audit,
    "IOC_Generic": _field_map_ioc_generic,
}

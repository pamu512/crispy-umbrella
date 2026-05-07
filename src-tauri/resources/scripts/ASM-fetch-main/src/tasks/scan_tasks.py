"""
Celery scan execution and scheduling logic for ASM system.
"""
from celery import Celery
from celery.schedules import crontab
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config.settings import Settings
from src.database.crud import update_scan_status, get_scan, create_subdomain_data, create_scan, set_scan_task_id
from src.database.models import ScanStatus, SubscriptionFrequency
import time
import logging
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

_scripts_root = Path(__file__).resolve().parents[3]
_shared_utils = _scripts_root / "shared_utils"
if _shared_utils.is_dir() and str(_shared_utils) not in sys.path:
    sys.path.insert(0, str(_shared_utils))

from logger import audit_state_change
from time_execution import time_execution
from src.api.shodan import get_shodan_subdomains, batch_shodan_host_info
from src.api.securitytrails import get_securitytrails_subdomains
from src.api.fofa import get_fofa_subdomains
from src.api.pentest_tools import get_pentest_subdomains
from src.api.crt_sh import get_crt_subdomains
from src.api.dns import query_dns_record
from src.processors.subdomain_processor import process_subdomain
from src.processors.mx_processor import process_mx_host
from src.api.ssllabs import get_tls_ssl_info
from src.utils.formatters import extract_unusual_ports

from src.utils.validators import is_private_ip
import tldextract
from src.api.whois import get_whois_info

celery_app = Celery(
    "easm_tasks",
    broker=Settings.CELERY_BROKER_URL,
    backend=Settings.CELERY_RESULT_BACKEND,
)

# Configure periodic scheduled scans via Celery Beat
celery_app.conf.beat_schedule = {
    'run-daily-scans': {
        'task': 'easm_tasks.run_scheduled_scan',
        'schedule': crontab(minute=0, hour=0),
        'args': ('daily',)
    },
    'run-weekly-scans': {
        'task': 'easm_tasks.run_scheduled_scan',
        'schedule': crontab(minute=0, hour=0, day_of_week='mon'),
        'args': ('weekly',)
    },
    'run-monthly-scans': {
        'task': 'easm_tasks.run_scheduled_scan',
        'schedule': crontab(minute=0, hour=0, day_of_month='1'),
        'args': ('monthly',)
    }
}

engine = create_engine(Settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@celery_app.task(name="easm_tasks.run_instant_scan")
def run_instant_scan(scan_id, domain, params):
    db = SessionLocal()
    logger = logging.getLogger(__name__)
    # Retry fetching the scan row a few times to handle small commit visibility races
    scan = None
    for attempt in range(6):
        scan = get_scan(db, scan_id)
        if scan:
            break
        logger.info("Scan row %s not found yet (attempt %s/6), retrying...", scan_id, attempt + 1)
        time.sleep(0.5)
    if not scan:
        logger.error("Scan %s not found after retries, aborting", scan_id)
        db.close()
        return "Scan not found"
    # If the scan was terminated while this task was queued, stop immediately.
    if getattr(scan, 'status', None) == ScanStatus.terminated:
        logger.info("Scan %s has been terminated before execution; aborting", scan_id)
        db.close()
        return "Scan terminated"
    # FIFO enforcement: if there are pending scans with smaller IDs, defer this one
    try:
        # If this scan is NOT marked priority, we must respect FIFO ordering by id.
        if not getattr(scan, 'priority', False):
            lower_pending = db.query(scan.__class__).filter(
                scan.__class__.status == ScanStatus.pending,
                scan.__class__.id < scan_id
            ).order_by(scan.__class__.id.asc()).first()
            if lower_pending:
                try:
                    # preserve priority flag when re-queueing
                    new_task = run_instant_scan.apply_async((scan_id, domain, params), countdown=1)
                    set_scan_task_id(db, scan_id, new_task.id)
                    logger.info("FIFO: found lower pending scan %s; rescheduled scan %s as task %s", lower_pending.id, scan_id, new_task.id)
                except Exception as e:
                    logger.error(
                        "FIFO reschedule failed for scan %s: %s",
                        scan_id,
                        e,
                        exc_info=True,
                    )
                    db.close()
                    raise RuntimeError(
                        f"Failed to queue FIFO reschedule for scan {scan_id}"
                    ) from e
                db.close()
                return "Rescheduled for FIFO"
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(
            "FIFO check failed for scan %s: %s", scan_id, e, exc_info=True
        )
        db.close()
        raise RuntimeError(
            f"FIFO ordering check failed for scan {scan_id}"
        ) from e
    # Concurrency control: count running scans
    running = db.query(scan.__class__).filter(scan.__class__.status == ScanStatus.scanning).count()
    if running >= Settings.MAX_CONCURRENT_SCANS:
        # Reschedule this task to run shortly later instead of finishing immediately.
        # Use apply_async with a short countdown and persist the new task id so the
        # pending scan remains associated with an active Celery task.
        try:
            # Before rescheduling, re-fetch the scan row to ensure it hasn't been
            # terminated by a user in the meantime.
            latest = get_scan(db, scan_id)
            if not latest or getattr(latest, 'status', None) == ScanStatus.terminated:
                logger.info("Scan %s is no longer pending (status=%s); skipping reschedule", scan_id, getattr(latest, 'status', None))
                db.close()
                return "Scan not rescheduled"

            new_task = run_instant_scan.apply_async((scan_id, domain, params), countdown=5)
            set_scan_task_id(db, scan_id, new_task.id)
            update_scan_status(db, scan_id, ScanStatus.pending)
            logger.info("Concurrency limit reached — rescheduled scan %s as task %s", scan_id, new_task.id)
        except Exception as e:
            logger.exception("Failed to reschedule scan %s: %s", scan_id, e)
            db.close()
            raise RuntimeError(
                f"Concurrency limit reschedule failed for scan {scan_id}"
            ) from e
        db.close()
        return "Scan rescheduled (pending)"
    update_scan_status(db, scan_id, ScanStatus.scanning)
    audit_state_change(
        logger,
        component="ASM.scan_tasks.run_instant_scan",
        previous_state=ScanStatus.pending,
        new_state=ScanStatus.scanning,
        detail=f"scan_id={scan_id}",
    )
    try:
        with time_execution(
            logger,
            label="ASM.scan_tasks.run_instant_scan.execute",
            threshold_ms=500.0,
        ):
            # Load API keys from settings
            rapidapi = Settings.RAPIDAPI_KEY
            shodan_key = Settings.SHODAN_API_KEY
            securitytrails_keys = Settings.SECURITYTRAILS_API_KEYS

            # 1) Discover subdomains via Shodan and SecurityTrails
            shodan_domains = {}
            try:
                if shodan_key:
                    shodan_domains = get_shodan_subdomains(domain, shodan_key, verbose=False) or {}
            except Exception as e:
                logger.warning("Shodan discovery failed: %s", e)

            securitytrails_domains = {}
            try:
                if securitytrails_keys:
                    securitytrails_domains = get_securitytrails_subdomains(domain, securitytrails_keys, verbose=False) or {}
            except Exception as e:
                logger.warning("SecurityTrails discovery failed: %s", e)

            # Combine unique subdomains (include root domain) and FOFA results
            all_subdomains = set(shodan_domains.keys()).union(securitytrails_domains)
        
            # CRT.sh (certificate transparency) results
            try:
                crt_domains = get_crt_subdomains(domain)
                if crt_domains:
                    all_subdomains.update(crt_domains)
            except Exception as e:
                logger.warning("crt.sh discovery failed: %s", e)
            # FOFA may return hostnames with protocols/ports already stripped by helper
            try:
                fofa_domains = get_fofa_subdomains(domain)
                if fofa_domains:
                    all_subdomains.update(fofa_domains)
            except Exception as e:
                logger.warning("FOFA discovery failed: %s", e)
        
            # Pentest-Tools Subdomain Finder
            try:
                pentest_domains = get_pentest_subdomains(domain)
                if pentest_domains:
                    all_subdomains.update(pentest_domains)
            except Exception as e:
                logger.warning("Pentest-Tools discovery failed: %s", e)
            all_subdomains.add(domain)

            # 2) Process MX records (fetch early for unique TLD extraction)
            try:
                mx_result = query_dns_record(domain, "MX", rapidapi, verbose=False)
                mx_records = mx_result.get("records", []) if mx_result.get("success", False) else []
            except Exception:
                mx_records = []

            # 3) Pre-fetch WHOIS for unique TLDs to save time
            unique_tlds = set()
            # Collect all hostnames (subdomains + MX hosts)
            all_hosts = set(all_subdomains)
            all_hosts.update(mx_records)
        
            for host in all_hosts:
                try:
                    extracted = tldextract.extract(host)
                    # Registerable domain (e.g., example.com)
                    if extracted.domain and extracted.suffix:
                        unique_tlds.add(f"{extracted.domain}.{extracted.suffix}")
                except Exception:
                    continue

            whois_cache = {}
            # Fetch WHOIS for each unique TLD
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures_whois = {
                    executor.submit(get_whois_info, tld): tld 
                    for tld in unique_tlds
                }
                for fut in as_completed(futures_whois):
                    tld = futures_whois[fut]
                    try:
                        whois_cache[tld] = fut.result()
                    except Exception as e:
                        logger.error("Error fetching WHOIS for TLD %s: %s", tld, e)
                        whois_cache[tld] = "N/A"

            # 4) Process subdomains (A records and per-ip processing)
            csv_rows = []
            host_ip_pairs = set()
            max_workers = 50

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for sub in sorted(all_subdomains):
                    sh_ips = shodan_domains.get(sub, [])
                    try:
                        dns_result = query_dns_record(sub, "A", rapidapi, verbose=False)
                        a_records = dns_result.get("records", []) if dns_result.get("success", False) else []
                    except Exception:
                        a_records = []
                
                    # Combine IPs from DNS and Shodan
                    all_ips = set(a_records) | set(sh_ips)
                
                    # Convert to list or ["N/A"] if empty
                    target_ips = list(all_ips) if all_ips else ["N/A"]
                
                    # Submit ONE task per subdomain with ALL IPs
                    # Pass whois_cache
                    futures[executor.submit(process_subdomain, sub, False, rapidapi, target_ips, whois_cache)] = sub

                for fut in as_completed(futures):
                    pair = futures[fut]
                    try:
                        rows = fut.result()
                        for row in rows:
                            # ensure sensitive column exists
                            if "Sensitive Subdomains" not in row:
                                row["Sensitive Subdomains"] = "N/A"
                            csv_rows.append(row)
                    except Exception as e:
                        logger.error("Error processing %s: %s", pair, e)

            # Count and log subdomains
            total_subdomains_count = len(csv_rows)
            unique_subdomains_count = len(set(row.get("Hosts") for row in csv_rows if row.get("Hosts")))
        
            logger.info(f"Total Subdomains Found: {total_subdomains_count}")
            logger.info(f"Total Unique Subdomains Found: {unique_subdomains_count}")

            # 5) Process MX records (using cached WHOIS)
            with ThreadPoolExecutor(max_workers=10) as executor:
                # Pass whois_cache
                futures_mx = {executor.submit(process_mx_host, mx, rapidapi, False, whois_cache): mx for mx in mx_records}
                for fut in as_completed(futures_mx):
                    try:
                        rows = fut.result()
                        for row in rows:
                            if "Sensitive Subdomains" not in row:
                                row["Sensitive Subdomains"] = "N/A"
                            csv_rows.append(row)
                    except Exception as e:
                        logger.error("Error processing MX %s: %s", futures_mx[fut], e)

            # 6) Batch Shodan for CVE and open ports
            ip_set = {r["IPs"] for r in csv_rows if r["IPs"] not in ("N/A", "0.0.0.0") and not is_private_ip(r["IPs"])}
            ip_list = sorted(ip_set)
            if ip_list and shodan_key:
                try:
                    ip_to_shodan = batch_shodan_host_info(ip_list, shodan_key)
                except Exception as e:
                    logger.warning("Batch Shodan failed: %s", e)
                    ip_to_shodan = {}
            else:
                ip_to_shodan = {}

            for row in csv_rows:
                ip = row["IPs"]
                if ip in ip_to_shodan:
                    cve_list, open_ports = ip_to_shodan[ip]
                    # Ensure CVE is a list; shodan now returns list
                    row["CVE"] = cve_list if isinstance(cve_list, list) else ([cve_list] if cve_list else [])
                    # store open_ports as structured list of dicts (from Shodan)
                    row["Opened Ports"] = open_ports
                else:
                    row["CVE"] = row.get("CVE", "N/A")
                    row["Opened Ports"] = row.get("Opened Ports", "N/A")
                row["Unusual Ports"] = extract_unusual_ports(row.get("Opened Ports", []))

            # 7) TLS/SSL info
            unique_hosts = set(r["Hosts"] for r in csv_rows)
            tls_results = {}
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures_tls = {executor.submit(get_tls_ssl_info, host): host for host in unique_hosts}
                for fut in as_completed(futures_tls):
                    host = futures_tls[fut]
                    try:
                        tls_results[host] = fut.result()
                    except Exception as e:
                        logger.error("TLS error for %s: %s", host, e)
                        tls_results[host] = "N/A"

            for row in csv_rows:
                row["TLS SSL"] = tls_results.get(row["Hosts"], "N/A")

            # Sort results: non-MX first, then MX; both groups sorted by Hostname (case-insensitive)
            csv_rows.sort(key=lambda x: (x.get("Type") == "MX", x.get("Hosts", "").lower()))

            # 8) Store results into DB
            for row in csv_rows:
                try:
                    payload = {
                        "host": row.get("Hosts"),
                        "ip": row.get("IPs"),
                        "type": row.get("Type", "N/A"),
                        "asn": row.get("ASN", "N/A"),
                        "asn_name": row.get("ASN Name", "N/A"),
                        "whois": row.get("WHOIS", {}),
                        "cve": row.get("CVE", []) if isinstance(row.get("CVE", []), list) else (row.get("CVE") or []),
                        "spf": row.get("SPF", "N/A"),
                        "dmarc": row.get("DMARC", "N/A"),
                        "dkim": row.get("DKIM", "N/A"),
                        "opened_ports": row.get("Opened Ports", []),
                        "unusual_ports": row.get("Unusual Ports", []) if isinstance(row.get("Unusual Ports", []), list) else (row.get("Unusual Ports") or []),
                        # Detect sensitive keywords in hostnames and store as a list
                        "sensitive_subdomains": [],
                        # Ensure tls_ssl is stored as a JSON/dict in the DB. If it's a string, try to parse key:value pairs.
                        "tls_ssl": row.get("TLS SSL", {}),
                    }
                    # Normalize tls_ssl into a dict when possible
                    tls_val = payload.get("tls_ssl")
                    from src.utils.formatters import parse_tls_string
                    if isinstance(tls_val, str):
                        parsed = parse_tls_string(tls_val)
                        if parsed:
                            payload['tls_ssl'] = parsed
                        else:
                            payload['tls_ssl'] = {}
                    elif tls_val in (None, "N/A"):
                        payload['tls_ssl'] = {}
                    # Populate sensitive_subdomains from the host value
                    host_val = payload.get("host") or ""
                    sens = []
                    try:
                        h = host_val.lower()
                        keywords = [
                            "vpn", "uat", "admin", "remote",
                            "staging", "production", "prod",
                            "oat", "client-testing", "demo"
                        ]
                        for kw in keywords:
                            if kw in h:
                                sens.append(kw)
                    except Exception:
                        sens = []
                    payload["sensitive_subdomains"] = sens
                    create_subdomain_data(db, scan_id, payload)
                except Exception as e:
                    logger.error("Failed to store subdomain row %s: %s", row, e)

            update_scan_status(db, scan_id, ScanStatus.completed)
            audit_state_change(
                logger,
                component="ASM.scan_tasks.run_instant_scan",
                previous_state=ScanStatus.scanning,
                new_state=ScanStatus.completed,
                detail=f"scan_id={scan_id};domain={domain}",
            )
            db.close()
            return f"Scan completed for {domain}"
    except Exception as e:
        logger.exception("Scan failed: %s", e)
        update_scan_status(db, scan_id, ScanStatus.failed)
        audit_state_change(
            logger,
            component="ASM.scan_tasks.run_instant_scan",
            previous_state=ScanStatus.scanning,
            new_state=ScanStatus.failed,
            detail=f"scan_id={scan_id};error={e!s}",
        )
        db.close()
        return str(e)

@celery_app.task(name="easm_tasks.run_scheduled_scan")
def run_scheduled_scan(subscription_frequency):
    db = SessionLocal()
    sched_log = logging.getLogger(__name__)
    with time_execution(sched_log, label="ASM.scan_tasks.run_scheduled_scan"):
        # Query DB for all domains with the given subscription_frequency, launch scans
        from src.database.crud import list_domains

        all_domains = list_domains(db)
        domains = [d for d in all_domains if d.subscription_frequency == subscription_frequency]
        for domain in domains:
            # Insert new scan row with status 'pending'
            scan_obj = create_scan(db, domain.id, ScanStatus.pending)
            scan_id = scan_obj.id
            audit_state_change(
                sched_log,
                component="ASM.scan_tasks.run_scheduled_scan",
                previous_state="none",
                new_state=ScanStatus.pending,
                detail=f"scan_id={scan_id};domain_id={domain.id};frequency={subscription_frequency}",
            )
            # Launch scan
            run_instant_scan.delay(scan_id, domain.domain_name, {})
        db.close()
        return f"Scheduled scans launched for {subscription_frequency}"

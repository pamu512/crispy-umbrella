"""
Scan management API router.
"""
import logging
import sys
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database.crud import (
    create_domain,
    create_scan,
    get_domain,
    get_scan,
    get_scanning_and_pending_queue,
    list_scans,
    set_scan_task_id,
    update_scan_status,
)
from src.database.schemas import ScanCreate, ScanOut, ScanStatus, SubscriptionFrequency
from src.database.session import get_db

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3]
_SHARED_UTILS = _SCRIPTS_ROOT / "shared_utils"
if _SHARED_UTILS.is_dir() and str(_SHARED_UTILS) not in sys.path:
    sys.path.insert(0, str(_SHARED_UTILS))

from time_execution import time_execution

router = APIRouter()


@router.post("/instant", response_model=ScanOut)
def launch_instant_scan(
    scan: ScanCreate = Body(..., examples=[{"domain": "blackwired.com"}]),
    db: Session = Depends(get_db),
):
    log = logging.getLogger(__name__)
    # Resolve domain: client may send domain_id or domain (string)
    with time_execution(log, label="endpoint.scan.launch_instant_scan"):
        domain_obj = None
        domain_name = None
        try:
            if scan.domain_id:
                domain_obj = get_domain(db, scan.domain_id)
                if domain_obj:
                    domain_name = domain_obj.domain_name
            elif scan.domain:
                # Try to find existing domain by name
                domain_obj = get_domain(db, scan.domain)
                if domain_obj:
                    domain_name = domain_obj.domain_name
                else:
                    # Create new domain with 'none' subscription
                    domain_obj = create_domain(db, scan.domain, SubscriptionFrequency.none)
                    domain_name = domain_obj.domain_name
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Either domain_id or domain name must be provided",
                )

            # Ensure we have a domain_obj with an id
            if not domain_obj:
                raise HTTPException(
                    status_code=404,
                    detail="Domain not found or could not be created",
                )

            # Create scan row with status 'pending' and mark as priority so it is
            # scheduled before other pending subscription scans.
            scan_obj = create_scan(db, domain_obj.id, ScanStatus.pending, priority=True)

            # Trigger Celery task to perform the scan asynchronously
            from src.tasks.scan_tasks import run_instant_scan

            try:
                res = run_instant_scan.delay(scan_obj.id, domain_name, {})
                log.info("Enqueued scan task %s for domain %s", res.id, domain_name)
                # persist task id on the scan record so clients can correlate
                set_scan_task_id(db, scan_obj.id, res.id)
                # reload scan_obj to include task_id when returned
                scan_obj = get_scan(db, scan_obj.id)
            except Exception as e:
                log.exception("Failed to enqueue scan task: %s", e)
        except HTTPException:
            raise
        except Exception as e:
            log.exception("Error during instant scan request: %s", e)
            raise HTTPException(status_code=500, detail="Internal server error") from e
        return scan_obj

@router.get("/{scan_id}/status", response_model=ScanOut)
def check_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/", response_model=List[ScanOut])
def list_all_scans(domain_id: Optional[int] = None, db: Session = Depends(get_db)):
    """List all scans. Optional query parameter `domain_id` filters by domain."""
    return list_scans(db, domain_id)

@router.post("/{scan_id}/terminate", response_model=ScanOut)
def terminate_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = update_scan_status(db, scan_id, ScanStatus.terminated)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/queue", response_model=List[ScanOut])
def get_scan_queue(db: Session = Depends(get_db)):
    """Return scans currently scanning first, then pending scans in queue order."""
    return get_scanning_and_pending_queue(db)

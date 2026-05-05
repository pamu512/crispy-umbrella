"""
CRUD operations for ASM system.
"""
from sqlalchemy import func
from sqlalchemy.orm import Session
from .models import Domain, Scan, SubdomainData, SubscriptionFrequency, ScanStatus
from datetime import datetime

def create_domain(db: Session, domain_name: str, frequency: SubscriptionFrequency):
    # Set created_at explicitly to avoid relying on DB server defaults
    # Ensure updated_at defaults to the same value as created_at on initial insert
    now = datetime.utcnow()
    domain = Domain(domain_name=domain_name, subscription_frequency=frequency, created_at=now, updated_at=now)
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain

def get_domain(db: Session, identifier):
    """Get a Domain by id (int) or by domain_name (str)."""
    # Accept raw int, numeric-like types, or strings containing digits for id lookup.
    try:
        # Try exact int conversion first (handles numpy ints or other numeric proxies)
        ident_int = int(identifier)
        return db.query(Domain).filter(Domain.id == ident_int).first()
    except Exception:
        # Fall back to domain_name lookup
        return db.query(Domain).filter(Domain.domain_name == identifier).first()

def list_domains(db: Session):
    return db.query(Domain).order_by(Domain.id.asc()).all()


def update_domain_subscription(db: Session, domain_id: int, frequency: SubscriptionFrequency):
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if domain:
        domain.subscription_frequency = frequency
        db.commit()
        db.refresh(domain)
    return domain

def create_scan(db: Session, domain_id: int, status: ScanStatus = ScanStatus.pending, priority: bool = False):
    # Set timestamps explicitly to avoid relying on DB server defaults which may be incorrect
    now = datetime.utcnow()
    scan = Scan(domain_id=domain_id, status=status, priority=priority, created_at=now, scan_timestamp=now)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan

def update_scan_status(db: Session, scan_id: int, status: ScanStatus):
    # Defensive: ensure scan_id is an integer
    try:
        scan_id_int = int(scan_id)
    except Exception:
        return None

    scan = db.query(Scan).filter(Scan.id == scan_id_int).first()
    if scan:
        # Normalize incoming status to the models.ScanStatus enum when possible
        status_to_set = None
        try:
            # If status is an enum (pydantic or other), try to get its value
            status_value = getattr(status, "value", None) or status
            # Convert to the models.ScanStatus enum
            status_to_set = ScanStatus(status_value)
        except Exception:
            # Fallback: assign raw status (SQLAlchemy may accept string)
            status_to_set = status

        scan.status = status_to_set
        db.commit()
        db.refresh(scan)
    return scan

def set_scan_task_id(db: Session, scan_id: int, task_id: str):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        scan.task_id = task_id
        db.commit()
        db.refresh(scan)
    return scan

def get_scan(db: Session, scan_id: int):
    return db.query(Scan).filter(Scan.id == scan_id).first()

def list_scans(db: Session, domain_id: int = None):
    q = db.query(Scan)
    if domain_id:
        q = q.filter(Scan.domain_id == domain_id)
    # Return scans ordered by id ascending for deterministic listing
    return q.order_by(Scan.id.asc()).all()


def list_pending_scans(db: Session):
    # Return scans with status pending ordered deterministically by id ascending
    # Prioritize scans with priority=True, then order by id asc within each group
    return db.query(Scan).filter(Scan.status == ScanStatus.pending).order_by(Scan.priority.desc(), Scan.id.asc()).all()


def get_scanning_and_pending_queue(db: Session):
    """Return a list where currently scanning scans come first (ordered by scan_timestamp asc),
    followed by pending scans ordered by created_at asc.
    """
    # Order scanning by scan_timestamp then id to ensure stable ordering,
    # and pending by id asc for deterministic FIFO behavior.
    scanning = db.query(Scan).filter(Scan.status == ScanStatus.scanning).order_by(Scan.scan_timestamp.asc(), Scan.id.asc()).all()
    # Pending: priority scans first (priority desc), then by id asc
    pending = db.query(Scan).filter(Scan.status == ScanStatus.pending).order_by(Scan.priority.desc(), Scan.id.asc()).all()
    return scanning + pending

def create_subdomain_data(db: Session, scan_id: int, data: dict):
    # Ensure created_at is set explicitly
    subdomain = SubdomainData(scan_id=scan_id, **data, created_at=datetime.utcnow())
    db.add(subdomain)
    db.commit()
    db.refresh(subdomain)
    return subdomain

def list_subdomain_data(db: Session, scan_id: int):
    # Sort by type (non-MX first i.e. 'A', then 'MX') and then by host case-insensitively
    return db.query(SubdomainData).filter(SubdomainData.scan_id == scan_id)\
        .order_by((SubdomainData.type == 'MX'), func.lower(SubdomainData.host)).all()
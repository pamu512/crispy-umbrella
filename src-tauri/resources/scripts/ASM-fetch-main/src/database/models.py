"""
SQLAlchemy models for ASM system.
"""
from sqlalchemy import Column, Integer, String, Enum, TIMESTAMP, Text, ForeignKey, JSON, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()

class SubscriptionFrequency(enum.Enum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"
    none = "none"


class ScanStatus(enum.Enum):
    pending = "pending"
    scanning = "scanning"
    completed = "completed"
    failed = "failed"
    terminated = "terminated"
    partial = "partial"

class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True)
    domain_name = Column(String(255), unique=True, nullable=False)
    subscription_frequency = Column(Enum(SubscriptionFrequency), default=SubscriptionFrequency.none)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    scans = relationship("Scan", back_populates="domain", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)
    # Celery task id for tracking asynchronous scan jobs
    task_id = Column(String(255), nullable=True)
    scan_timestamp = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    domain = relationship("Domain", back_populates="scans")
    subdomain_data = relationship("SubdomainData", back_populates="scan", cascade="all, delete-orphan")
    # Priority flag: when True this pending scan should be scheduled before other pending scans
    priority = Column(Boolean, nullable=False, default=False)

class SubdomainData(Base):
    __tablename__ = "subdomain_data"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    host = Column(String(255), nullable=False)
    ip = Column(String(45), default="N/A")
    type = Column(String(10), nullable=False)  # 'A' or 'MX'
    asn = Column(String(50), default="N/A")
    asn_name = Column(String(255), default="N/A")
    whois = Column(JSON, default={})
    # Store CVE identifiers as a JSON list (e.g., ["CVE-2020-1234"]) instead of a comma string.
    cve = Column(JSON, default=[])
    spf = Column(Text, default="N/A")
    dmarc = Column(Text, default="N/A")
    dkim = Column(Text, default="N/A")
    # Place tls_ssl after dkim per API ordering requirement
    tls_ssl = Column(JSON, default={})
    opened_ports = Column(JSON, default=[])
    unusual_ports = Column(JSON, default=[])
    # Store sensitive_subdomains as a JSON list of lowercase keywords (e.g. ["vpn", "uat"]).
    # This allows structured reads/writes similar to `unusual_ports`.
    sensitive_subdomains = Column(JSON, default=[])
    created_at = Column(TIMESTAMP, server_default=func.now())
    scan = relationship("Scan", back_populates="subdomain_data")
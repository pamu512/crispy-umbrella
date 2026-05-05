"""
Pydantic schemas for API validation.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Any
import enum

class SubscriptionFrequency(str, enum.Enum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"
    none = "none"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    scanning = "scanning"
    completed = "completed"
    failed = "failed"
    terminated = "terminated"
    partial = "partial"

class DomainCreate(BaseModel):
    domain_name: str
    subscription_frequency: SubscriptionFrequency = SubscriptionFrequency.none

class DomainOut(BaseModel):
    id: int
    domain_name: str
    subscription_frequency: SubscriptionFrequency
    created_at: Any
    updated_at: Any

    class Config:
        from_attributes = True



class ScanCreate(BaseModel):
    # Accept either an existing domain id or a domain name string. Server will
    # resolve/insert domain as needed and proceed with the scan.
    domain_id: Optional[int] = None
    domain: Optional[str] = None
    params: Optional[dict] = None
    # client may optionally provide a task_id, but usually the server fills this
    task_id: Optional[str] = None
    class Config:
        json_schema_extra = {
            "example": {
                "domain": "blackwired.com"
            }
        }


class ScanOut(BaseModel):
    id: int
    domain_id: int
    scan_timestamp: Any
    status: ScanStatus
    task_id: Optional[str]
    created_at: Any

    class Config:
        from_attributes = True

class SubdomainDataOut(BaseModel):
    host: str
    ip: str
    type: str
    asn: str
    asn_name: str
    whois: Any
    cve: List[str] = Field(default_factory=list)
    spf: str
    dmarc: str
    dkim: str
    tls_ssl: Any
    opened_ports: Any
    unusual_ports: List[int] = Field(default_factory=list)
    sensitive_subdomains: List[str] = Field(default_factory=list)

    class Config:
        from_attributes = True
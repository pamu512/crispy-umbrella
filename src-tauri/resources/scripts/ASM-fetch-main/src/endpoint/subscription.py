"""
Subscription management API router.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database.crud import create_domain, get_domain, list_domains
from src.database.crud import update_domain_subscription
from src.database.schemas import DomainCreate, DomainOut, SubscriptionFrequency
from src.database.session import get_db

router = APIRouter()

@router.post("/", response_model=DomainOut)
def add_subscription(domain: DomainCreate, db: Session = Depends(get_db)):
    existing = get_domain(db, domain.domain_name)
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists")
    domain_obj = create_domain(db, domain.domain_name, domain.subscription_frequency)
    return domain_obj

@router.get("/", response_model=list[DomainOut])
def list_subscriptions(db: Session = Depends(get_db)):
    return list_domains(db)


@router.put("/{domain_id}", response_model=DomainOut)
def update_subscription(domain_id: int, frequency: SubscriptionFrequency, db: Session = Depends(get_db)):
    domain = update_domain_subscription(db, domain_id, frequency)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain

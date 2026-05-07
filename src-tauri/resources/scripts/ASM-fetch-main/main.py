
"""
FastAPI app entrypoint for ASM system.
Includes all API routers and DB setup.
"""
import sys
from pathlib import Path

# sibling CTI ``shared_utils`` (circuit breaker, logging, etc.)
_SCRIPTS_ROOT = Path(__file__).resolve().parent.parent
if str(_SCRIPTS_ROOT / "shared_utils") not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT / "shared_utils"))

from logger import configure_logging

configure_logging()

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from config.settings import Settings
from src.database.models import Base
from src.database.crud import *
from src.database.schemas import *
from src.database.session import engine
from src.middleware.error_handling import RequestIdMiddleware, setup_exception_handlers

# Create tables if not exist (for dev, Alembic for prod)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ASM Platform API", version="1.0")
setup_exception_handlers(app)

# CORS (inner); RequestIdMiddleware added last so it runs first on incoming requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIdMiddleware)

from src.database.session import get_db

# Routers will be included here
from src.endpoint.health import router as health_router
from src.endpoint.scan import router as scan_router
from src.endpoint.subscription import router as subscription_router
from src.endpoint.result import router as result_router
from src.endpoint.export import router as export_router
from src.endpoint.parameter import router as parameter_router

app.include_router(health_router, tags=["Health"])
app.include_router(scan_router, prefix="/scans", tags=["Scans"])
app.include_router(subscription_router, prefix="/subscriptions", tags=["Subscriptions"])
app.include_router(result_router, prefix="/results", tags=["Results"])
app.include_router(export_router, prefix="/export", tags=["Export"])
app.include_router(parameter_router, prefix="/parameters", tags=["Parameters"])

@app.get("/")
def root():
    return {"message": "ASM Platform API is running."}
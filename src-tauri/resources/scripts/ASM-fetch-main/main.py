
"""
FastAPI app entrypoint for ASM system.
Includes all API routers and DB setup.
"""
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from config.settings import Settings
from src.database.models import Base
from src.database.crud import *
from src.database.schemas import *
from src.database.session import engine

# Create tables if not exist (for dev, Alembic for prod)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="ASM Platform API", version="1.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from src.database.session import get_db

# Routers will be included here
from src.endpoint.scan import router as scan_router
from src.endpoint.subscription import router as subscription_router
from src.endpoint.result import router as result_router
from src.endpoint.export import router as export_router
from src.endpoint.parameter import router as parameter_router

app.include_router(scan_router, prefix="/scans", tags=["Scans"])
app.include_router(subscription_router, prefix="/subscriptions", tags=["Subscriptions"])
app.include_router(result_router, prefix="/results", tags=["Results"])
app.include_router(export_router, prefix="/export", tags=["Export"])
app.include_router(parameter_router, prefix="/parameters", tags=["Parameters"])

@app.get("/")
def root():
    return {"message": "ASM Platform API is running."}
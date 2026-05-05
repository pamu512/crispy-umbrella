"""
Parameter management API router (stub for future extension).
"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def list_parameters():
    return {"message": "Parameter management not yet implemented."}

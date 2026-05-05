"""
Configuration and environment management for ASM system.
"""
import os
import pathlib
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DB_HOST = os.getenv("DB_HOST", "db")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
    DB_NAME = os.getenv("DB_NAME", "asm_db")
    DATABASE_URL = os.getenv("DATABASE_URL", f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")
    RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    FOFA_API_KEY = os.getenv("FOFA_API_KEY", "")
    PENTEST_TOOLS_TOKEN = os.getenv("PENTEST_TOOLS_TOKEN", "3wEqNzxAbSQcWdn2qQYnPbQTvUwtLCzCA4D417Ur7872786a")
    # Prefer a file containing one key per line. Otherwise fall back to comma-separated env var.
    _st_keys_file = os.getenv("SECURITYTRAILS_API_KEYS_FILE", "")
    if _st_keys_file and pathlib.Path(_st_keys_file).is_file():
        SECURITYTRAILS_API_KEYS = [line.strip() for line in open(_st_keys_file, "r") if line.strip() and not line.strip().startswith("#")]
    else:
        SECURITYTRAILS_API_KEYS = [k.strip() for k in os.getenv("SECURITYTRAILS_API_KEYS", "").split(",") if k.strip()]
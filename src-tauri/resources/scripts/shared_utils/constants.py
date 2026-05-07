"""
Shared string constants: environment variable names, default identifiers, and path fragments.

Import from here instead of duplicating literals across ``config``, ``db_manager``, and ``ingestor``.
"""

from __future__ import annotations

from typing import Final

# --- Environment variable names (Tauri host / sidecars) ---

ENV_CTI_DB_PATH: Final[str] = "CTI_DB_PATH"
ENV_CTI_WORKSPACE_PATH: Final[str] = "CTI_WORKSPACE_PATH"
ENV_CTI_LOGS_DIR: Final[str] = "CTI_LOGS_DIR"
ENV_CTI_WRITABLE_ROOT: Final[str] = "CTI_WRITABLE_ROOT"
ENV_CTI_APP_DATA_ROOT: Final[str] = "CTI_APP_DATA_ROOT"
ENV_CTI_APP_IDENTIFIER: Final[str] = "CTI_APP_IDENTIFIER"
ENV_CTI_NON_INTERACTIVE: Final[str] = "CTI_NON_INTERACTIVE"
ENV_CTI_HTTP_TIMEOUT_SECONDS: Final[str] = "CTI_HTTP_TIMEOUT_SECONDS"

# Default bundle id (align with ``tauri.conf.json`` ``identifier`` when unset)
DEFAULT_CTI_APP_IDENTIFIER: Final[str] = "com.pamu512.crispyumbrella"

# Vault layout (mirrors Rust ``writable_cti_root`` / app data tree)
VAULT_SQLITE_FILENAME: Final[str] = "cti_vault.db"
CTI_APP_DIRECTORY_NAME: Final[str] = "cti-app"

# Ingest sidecar log file (under ``CTI_LOGS_DIR`` or fallbacks in ``ingestor._ingest_log_path``)
INGEST_LOG_FILENAME: Final[str] = "ingest.log"
# Directory segments under ``%LOCALAPPDATA%`` (Windows) when ``CTI_LOGS_DIR`` unset → …/Vault8/logs/ingest.log
WINDOWS_LOCALAPPDATA_VAULT8_LOG_PARTS: Final[tuple[str, str]] = ("Vault8", "logs")
# Directory segments under user home (Unix / macOS) → ~/.vault8/logs/ingest.log
HOME_DOT_VAULT8_LOG_PARTS: Final[tuple[str, str]] = (".vault8", "logs")

# Keys read by :class:`config.CtiAppConfig` (for tests and env audit tooling)
CTI_APP_CONFIG_ENV_KEYS: Final[tuple[str, ...]] = (
    ENV_CTI_DB_PATH,
    ENV_CTI_WORKSPACE_PATH,
    ENV_CTI_LOGS_DIR,
    ENV_CTI_WRITABLE_ROOT,
    ENV_CTI_APP_DATA_ROOT,
    ENV_CTI_APP_IDENTIFIER,
    ENV_CTI_NON_INTERACTIVE,
    ENV_CTI_HTTP_TIMEOUT_SECONDS,
)

# Same eight features as Rust ``validate_features_bundle`` / bundled All_Scripts trees
BUNDLED_PROJECT_FOLDER_NAMES: Final[tuple[str, ...]] = (
    "Intelx_Crawler",
    "CVE_Project_NVD",
    "ASM-fetch-main",
    "Ransomware_live_event_victim",
    "Phishing_and_Social_Media_All-in-one",
    "Social_MediaV2",
    "IOCs-crawler-main",
    "Compromised_user_Mac",
)

Place each CTI project folder here (Intelx_Crawler, CVE_Project_NVD, …) before packaging.
Bundled layout: scripts/<FeatureName>/main.py, requirements.txt, etc.
Writable outputs use AppData/cti-app/ via CTI_WORKSPACE_PATH / CTI_EXPORTS_DIR.

Python: the desktop app does not bundle CPython. On first workspace load it best-effort runs
`bootstrap_all_feature_venvs` (host python3/python + per-feature venvs under AppData/python_env/).
Optional: ship an embeddable Python and point future env vars at it for a true sidecar.

SQLite: Rust opens cti_vault.db with WAL + migrations (see vault_db.rs). Python scripts can use
shared_utils/db_manager.py with CTI_DB_PATH for the same WAL + busy_timeout settings.

CSV bridge: install pandas once for the host user (``pip install -r shared_utils/requirements.txt`` from
this scripts directory). The Tauri app runs ``shared_utils/ingestor.py sync`` after project runs and
exposes ``ingest_csv_vault`` for manual sync.

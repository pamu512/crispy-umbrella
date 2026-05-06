//! Central SQLite vault: WAL, busy timeout, foreign keys, schema migrations, IOC backfills.
//!
//! **Single source of truth for DDL:** all table creation and `PRAGMA user_version` bumps live
//! here. Python (`db_manager.CTIVault`) opens the same file but must not create or migrate schema;
//! open the vault from this module (Tauri) before relying on tables, or run any code path that
//! calls [`initialize_vault`] / [`open_vault`].
//!
//! **Single source of truth for the vault file path:** [`get_vault_path`] / [`vault_path`].
//! Resolution: explicit **`CTI_DB_PATH`**, else (when unset) [`install_canonical_cti_env`] seeds env from
//! the OS app-support layout (same namespace as Tauri `app.path().app_data_dir()` + `cti-app`; see
//! [`configure_canonical_paths_from_app`]). Legacy `{Documents}/CTI_Command` remains available via
//! **`CTI_COMMAND_CENTER_HOME`** override. Do not join DB paths onto
//! the operator’s project workspace tree.
//!
//! Canonical tables: `vault_meta`, `cve_data`, `asm_assets`, `ioc_records`, `ransomware_events`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;
use serde_json::json;
use tauri::AppHandle;

use crate::vector_db::{self as vdb, IOCRecord};

/// Matches `vault_meta.schema_version` after a full migration to the current layout.
const VAULT_META_SCHEMA_VERSION: &str = "2";

/// `PRAGMA user_version` after all built-in migrations have run.
const CURRENT_USER_VERSION: i32 = 3;

// ---------------------------------------------------------------------------
// Canonical vault location (CTI Command Center — no per-workspace ghost DBs)
// ---------------------------------------------------------------------------

/// Must match `identifier` in `tauri.conf.json` — directory name under the OS app data root
/// (e.g. `~/Library/Application Support/<identifier>` on macOS).
pub const TAURI_BUNDLE_IDENTIFIER: &str = "com.pamu512.crispyumbrella";

/// Folder under the user documents (or home) directory — legacy layout only when env overrides use it.
pub const CTI_COMMAND_CENTER_VAULT_DIR: &str = "CTI_Command";
/// Canonical SQLite filename (absolute path = [`cti_data_home`]`/`[`CTI_VAULT_DB_FILENAME`]).
pub const CTI_VAULT_DB_FILENAME: &str = "cti_vault.db";
/// Legacy filename; opened only when present and `cti_vault.db` does not exist.
const LEGACY_VAULT_DB_FILENAME: &str = "vault.db";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Same as [`get_vault_path`] — centralized resolver for the active vault SQLite file.
#[inline]
pub fn vault_path() -> PathBuf {
    get_vault_path()
}

/// Absolute directory for CTI Command Center data (same folder that contains `cti_vault.db`).
///
/// Override with **`CTI_COMMAND_CENTER_HOME`**. Otherwise [`default_cti_data_home`] (Documents layout).
pub fn cti_data_home() -> PathBuf {
    if let Ok(s) = std::env::var("CTI_COMMAND_CENTER_HOME") {
        let t = s.trim();
        if !t.is_empty() {
            return normalize_dir_path(Path::new(t));
        }
    }
    default_cti_data_home()
}

/// Legacy `{Documents}/CTI_Command` home (used only as fallback when env does not set [`cti_data_home`] inputs).
pub fn default_cti_data_home() -> PathBuf {
    let base = dirs::document_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(CTI_COMMAND_CENTER_VAULT_DIR)
}

/// Mirrors Tauri’s `app.path().app_data_dir()` for [`TAURI_BUNDLE_IDENTIFIER`] (before an [`AppHandle`] exists).
pub fn bundle_app_support_dir() -> PathBuf {
    os_app_support_root_for_bundle_id()
}

/// Mirrors Tauri’s app-support directory for [`TAURI_BUNDLE_IDENTIFIER`] (CLI / early bootstrap before [`AppHandle`] exists).
fn os_app_support_root_for_bundle_id() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Application Support")
            .join(TAURI_BUNDLE_IDENTIFIER)
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")))
            .join(TAURI_BUNDLE_IDENTIFIER)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(TAURI_BUNDLE_IDENTIFIER)
    }
}

/// Picks `cti_vault.db` when it exists or when legacy `vault.db` is absent; otherwise legacy path.
pub fn resolve_vault_sqlite_file_in(home: &Path) -> PathBuf {
    let primary = home.join(CTI_VAULT_DB_FILENAME);
    let legacy = home.join(LEGACY_VAULT_DB_FILENAME);
    if primary.exists() || !legacy.exists() {
        primary
    } else {
        legacy
    }
}

/// Seeds **`CTI_COMMAND_CENTER_HOME`** + **`CTI_DB_PATH`** when unset — OS app data + `cti-app`
/// (matches [`crate::cti_config::writable_cti_root`] layout).
///
/// GUI apps should call [`configure_canonical_paths_from_app`] from `setup` so paths match Tauri `app_data_dir()` exactly.
pub fn install_canonical_cti_env() {
    if std::env::var("CTI_DB_PATH")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }
    let home = os_app_support_root_for_bundle_id().join("cti-app");
    let _ = std::fs::create_dir_all(&home);
    let db = resolve_vault_sqlite_file_in(&home);
    std::env::set_var(
        "CTI_COMMAND_CENTER_HOME",
        home.to_string_lossy().as_ref(),
    );
    std::env::set_var("CTI_DB_PATH", db.to_string_lossy().as_ref());
}

/// Resolves the vault SQLite file under Tauri’s **`app.path().app_data_dir()`** + `cti-app/`
/// (same layout as [`crate::cti_config::writable_cti_root`]). Creates directories before returning.
pub fn get_db_path(handle: &AppHandle) -> Result<PathBuf, String> {
    let home = crate::cti_config::writable_cti_root(handle)?;
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let db_path = resolve_vault_sqlite_file_in(&home);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    Ok(db_path)
}

/// Sets **`CTI_COMMAND_CENTER_HOME`** + **`CTI_DB_PATH`** from [`get_db_path`].
pub fn configure_canonical_paths_from_app(handle: &AppHandle) -> Result<PathBuf, String> {
    let db_path = get_db_path(handle)?;
    let home = db_path
        .parent()
        .ok_or_else(|| "vault database path has no parent directory".to_string())?;
    std::env::set_var(
        "CTI_COMMAND_CENTER_HOME",
        home.to_string_lossy().as_ref(),
    );
    std::env::set_var("CTI_DB_PATH", db_path.to_string_lossy().as_ref());
    Ok(db_path)
}

fn normalize_dir_path(p: &Path) -> PathBuf {
    if p.as_os_str().is_empty() {
        return default_cti_data_home();
    }
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Absolute path to the CTI SQLite vault for this process.
///
/// Resolution order:
/// 1. [`install_canonical_cti_env`] (sets `CTI_DB_PATH` when unset).
/// 2. Non-empty **`CTI_DB_PATH`** (absolute or relative; expanded to absolute).
/// 3. **[`cti_data_home`]`/`[`resolve_vault_sqlite_file_in`]** when `CTI_DB_PATH` still empty.
pub fn get_vault_path() -> PathBuf {
    install_canonical_cti_env();
    if let Ok(s) = std::env::var("CTI_DB_PATH") {
        let t = s.trim();
        if !t.is_empty() {
            return normalize_vault_path(Path::new(t));
        }
    }
    let home = cti_data_home();
    normalize_vault_path(&resolve_vault_sqlite_file_in(&home))
}

fn normalize_vault_path(p: &Path) -> PathBuf {
    if p.as_os_str().is_empty() {
        let home = cti_data_home();
        return normalize_vault_path(&resolve_vault_sqlite_file_in(&home));
    }
    if p.exists() {
        return p.canonicalize().unwrap_or_else(|_| absolutize_logical(p));
    }
    absolutize_logical(p)
}

fn absolutize_logical(p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Delete a SQLite database file and its `-wal` / `-shm` sidecars (best-effort; ignores missing files).
pub fn remove_sqlite_cluster(path: &Path) {
    let base = path.to_string_lossy();
    for suffix in ["", "-wal", "-shm"] {
        let p: PathBuf = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            PathBuf::from(format!("{base}{suffix}"))
        };
        let _ = std::fs::remove_file(p);
    }
}

/// Wipe the local vault, embedded vector DB, CTI `logs/`, `config.json`, and `store.json` (plugin-store).
///
/// Call only when no [`crate::vault_pool::VaultPool`] is open (e.g. CLI **`cleanup --force`**). SQLite files
/// are removed from disk; there is no separate server connection to close.
pub fn wipe_local_cti_application_state() -> Result<(), String> {
    use std::fs;
    install_canonical_cti_env();
    let vault = get_vault_path();
    remove_sqlite_cluster(&vault);

    let Some(cti_home) = vault.parent().map(|p| p.to_path_buf()) else {
        return Err("vault database path has no parent directory".into());
    };

    remove_sqlite_cluster(&cti_home.join(CTI_VAULT_DB_FILENAME));
    remove_sqlite_cluster(&cti_home.join(LEGACY_VAULT_DB_FILENAME));

    let vv = cti_home.join("vector_vault");
    if vv.exists() {
        fs::remove_dir_all(&vv).map_err(|e| e.to_string())?;
    }

    let logs = cti_home.join("logs");
    if logs.is_dir() {
        for entry in fs::read_dir(&logs).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
            } else {
                let _ = fs::remove_file(&p);
            }
        }
    }

    let _ = fs::remove_file(cti_home.join("config.json"));

    let bundle = bundle_app_support_dir();
    let _ = fs::remove_file(bundle.join("store.json"));

    let bundle_logs = bundle.join("logs");
    if bundle_logs.is_dir() {
        for entry in fs::read_dir(&bundle_logs).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                fs::remove_dir_all(&p).map_err(|e| e.to_string())?;
            } else {
                let _ = fs::remove_file(&p);
            }
        }
    }

    Ok(())
}

/// Open the CTI vault SQLite file, create parent directories if needed, apply PRAGMAs, run migrations and
/// legacy self-heal passes. This is the **authoritative** vault initializer.
pub fn initialize_vault(db_path: &Path) -> Result<Connection, String> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    apply_connection_pragmas(&conn)?;
    run_migrations(&conn)?;
    self_heal_legacy_tables(&conn)?;
    Ok(conn)
}

/// Backwards-compatible alias for [`initialize_vault`].
pub fn open_vault(db_path: &Path) -> Result<Connection, String> {
    initialize_vault(db_path)
}

/// WAL, busy timeout, FK — [`rusqlite::Error`] for r2d2 pool connections.
///
/// Busy timeout is relatively high so concurrent writers (e.g. IOC crawl sidecar, embed jobs)
/// do not surface `database is locked` to the UI while WAL readers wait.
pub fn apply_pool_connection_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_millis(30_000))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

fn apply_connection_pragmas(conn: &Connection) -> Result<(), String> {
    apply_pool_connection_pragmas(conn).map_err(|e| e.to_string())
}

fn user_version(conn: &Connection) -> i32 {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0)
}

fn set_user_version(conn: &Connection, v: i32) -> Result<(), String> {
    conn.execute_batch(&format!("PRAGMA user_version = {v};"))
        .map_err(|e| e.to_string())
}

fn run_migrations(conn: &Connection) -> Result<(), String> {
    if user_version(conn) < 2 {
        migrate_to_v2(conn)?;
    }
    if user_version(conn) < 3 {
        migrate_to_v3(conn)?;
    }
    ensure_ioc_news(conn)?;
    set_user_version(conn, CURRENT_USER_VERSION)?;
    Ok(())
}

fn migrate_to_v3(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS ransomware_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_date TEXT,
            victim_name TEXT,
            attack_details TEXT,
            source TEXT
        );",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn table_exists(conn: &Connection, name: &str) -> Result<bool, String> {
    let n: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

pub fn column_names(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Baseline DDL (vault_meta + canonical tables)
// ---------------------------------------------------------------------------

fn ensure_vault_meta(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS vault_meta (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );",
    )
    .map_err(|e| e.to_string())
}

fn set_vault_schema_version_meta(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('schema_version', ?1)",
        [VAULT_META_SCHEMA_VERSION],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn create_modern_cve(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS cve_data (
            cve_id TEXT PRIMARY KEY NOT NULL,
            severity_score REAL,
            published_date TEXT,
            updated_at TEXT,
            metadata TEXT
        );",
    )
    .map_err(|e| e.to_string())
}

fn create_modern_asm(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS asm_assets (
            asset_target TEXT PRIMARY KEY NOT NULL,
            asset_type TEXT,
            last_scan_at TEXT,
            status TEXT,
            metadata TEXT
        );",
    )
    .map_err(|e| e.to_string())
}

pub fn ensure_ioc_records(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS ioc_records (
            ioc_value TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            source_project TEXT,
            metadata TEXT,
            PRIMARY KEY (ioc_value, ioc_type)
        );",
    )
    .map_err(|e| e.to_string())
}

/// IOC/news article staging written by `IOCs-crawler-main` Python crawlers (`ioc_news` → `ioc_records` backfill).
pub fn ensure_ioc_news(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS ioc_news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT,
            source TEXT,
            article_ts INTEGER,
            iocs TEXT,
            mitre TEXT,
            content_preview TEXT,
            ingested_at TEXT NOT NULL,
            created_at TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_ioc_news_url ON ioc_news(url);
        ",
    )
    .map_err(|e| e.to_string())?;
    // Older databases created by export scripts may omit created_at (required by vault_search).
    let cols = column_names(conn, "ioc_news")?;
    if !cols.iter().any(|c| c == "created_at") {
        conn.execute("ALTER TABLE ioc_news ADD COLUMN created_at TEXT", [])
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy layout → v2 canonical
// ---------------------------------------------------------------------------

/// Idempotent: normalize pre-v2 `cve_data` (id + description columns) into spec columns.
pub fn migrate_cve_legacy_if_needed(conn: &Connection) -> Result<(), String> {
    if !table_exists(conn, "cve_data")? {
        return create_modern_cve(conn);
    }
    let cols = column_names(conn, "cve_data")?;
    if cols.contains(&"metadata".to_string()) {
        return Ok(());
    }
    conn.execute("ALTER TABLE cve_data RENAME TO cve_data_legacy", [])
        .map_err(|e| e.to_string())?;
    create_modern_cve(conn)?;
    let now = time_now_iso();
    {
        let mut stmt = conn
            .prepare("SELECT cve_id, cvss_score, description FROM cve_data_legacy")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (cve_id, cvss, desc) = row.map_err(|e| e.to_string())?;
            let severity = cvss.as_deref().and_then(parse_cvss_base_score);
            let meta = json!({
                "description": desc.unwrap_or_default(),
                "legacy_cvss_display": cvss,
            })
            .to_string();
            conn.execute(
                "INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata) VALUES (?1, ?2, '', ?3, ?4)",
                rusqlite::params![cve_id, severity, &now, meta],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    conn.execute("DROP TABLE cve_data_legacy", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Idempotent: normalize legacy `asm_assets` (`asset`, `alert_type`) into spec columns.
pub fn migrate_asm_legacy_if_needed(conn: &Connection) -> Result<(), String> {
    if !table_exists(conn, "asm_assets")? {
        return create_modern_asm(conn);
    }
    let cols = column_names(conn, "asm_assets")?;
    if cols.contains(&"asset_target".to_string()) {
        return Ok(());
    }
    if cols.contains(&"asset".to_string()) {
        conn.execute("ALTER TABLE asm_assets RENAME TO asm_assets_legacy", [])
            .map_err(|e| e.to_string())?;
        create_modern_asm(conn)?;
        {
            let mut stmt = conn
                .prepare("SELECT asset, alert_type, timestamp FROM asm_assets_legacy")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (asset, alert, ts) = row.map_err(|e| e.to_string())?;
                let meta = json!({ "legacy_alert_type": alert }).to_string();
                let atype = if asset.contains('|') {
                    "host_ip"
                } else {
                    "subdomain"
                };
                conn.execute(
                    "INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata) VALUES (?1, ?2, ?3, 'active', ?4)",
                    rusqlite::params![asset, atype, ts.unwrap_or_default(), meta],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        conn.execute("DROP TABLE asm_assets_legacy", [])
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    create_modern_asm(conn)?;
    Ok(())
}

fn migrate_to_v2(conn: &Connection) -> Result<(), String> {
    ensure_vault_meta(conn)?;
    migrate_cve_legacy_if_needed(conn)?;
    migrate_asm_legacy_if_needed(conn)?;
    ensure_ioc_records(conn)?;
    ensure_ioc_news(conn)?;
    let _ = backfill_ioc_records_from_news(conn)?;
    let _ = backfill_ioc_records_from_legacy_iocs(conn)?;
    set_vault_schema_version_meta(conn)?;
    Ok(())
}

/// Re-run legacy normalizers if an external script recreated old shapes (`user_version` already current).
fn self_heal_legacy_tables(conn: &Connection) -> Result<(), String> {
    if user_version(conn) < CURRENT_USER_VERSION {
        return Ok(());
    }
    ensure_vault_meta(conn)?;
    migrate_cve_legacy_if_needed(conn)?;
    migrate_asm_legacy_if_needed(conn)?;
    ensure_ioc_records(conn)?;
    ensure_ioc_news(conn)?;
    let _ = backfill_ioc_records_from_news(conn)?;
    let _ = backfill_ioc_records_from_legacy_iocs(conn)?;
    set_vault_schema_version_meta(conn)?;
    Ok(())
}

pub fn time_now_iso() -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new())
}

pub fn parse_cvss_base_score(s: &str) -> Option<f64> {
    let t = s.trim();
    let num: String = t
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if num.is_empty() {
        return None;
    }
    num.parse().ok()
}

/// Map `ioc_news` rows into `ioc_records` (dedupe on value+type).
pub fn backfill_ioc_records_from_news(conn: &Connection) -> Result<usize, String> {
    if !table_exists(conn, "ioc_news")? {
        return Ok(0);
    }
    ensure_ioc_records(conn)?;
    let cols = column_names(conn, "ioc_news")?;
    if cols.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn
        .prepare("SELECT * FROM ioc_news")
        .map_err(|e| e.to_string())?;
    let ncols = stmt.column_count();
    let cnames: Vec<String> = (0..ncols)
        .map(|i| stmt.column_name(i).unwrap_or("").to_string())
        .collect();

    fn idx(names: &[String], key: &str) -> Option<usize> {
        names.iter().position(|n| n == key)
    }

    let i_url = idx(&cnames, "url");
    let i_title = idx(&cnames, "title");
    let i_source = idx(&cnames, "source");
    let i_preview = idx(&cnames, "content_preview");
    let i_created = idx(&cnames, "created_at").or_else(|| idx(&cnames, "ingested_at"));

    let mut n = 0usize;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let url = i_url
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let title = i_title
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let source = i_source
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let preview = i_preview
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let ts = i_created
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let ts2 = if ts.is_empty() {
            time_now_iso()
        } else {
            ts.clone()
        };

        let url_t = url.trim();
        let title_t = title.trim();
        if url_t.is_empty() && title_t.is_empty() {
            continue;
        }
        let (ioc_value, ioc_type) = if !url_t.is_empty() {
            (url_t.to_string(), "url".to_string())
        } else {
            (title_t.to_string(), "news_title".to_string())
        };
        let meta = json!({
            "title": title,
            "source": source,
            "content_preview": preview.chars().take(2000).collect::<String>(),
        })
        .to_string();
        conn.execute(
            "INSERT INTO ioc_records (ioc_value, ioc_type, first_seen, last_seen, source_project, metadata)
             VALUES (?1, ?2, ?3, ?4, 'IOCs-crawler-main', ?5)
             ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET
               last_seen = excluded.last_seen,
               metadata = excluded.metadata,
               source_project = excluded.source_project",
            rusqlite::params![ioc_value, ioc_type, ts2, ts2, meta],
        )
        .map_err(|e| e.to_string())?;
        let rowid = conn.last_insert_rowid();
        vdb::queue_embed_and_store(IOCRecord {
            ioc_value: ioc_value.clone(),
            ioc_type: ioc_type.clone(),
            first_seen: Some(ts2.clone()),
            last_seen: Some(ts2.clone()),
            source_project: Some("IOCs-crawler-main".into()),
            metadata: Some(meta.clone()),
            sqlite_rowid: Some(rowid),
        });
        n += 1;
    }
    Ok(n)
}

fn backfill_ioc_records_from_legacy_iocs(conn: &Connection) -> Result<usize, String> {
    if !table_exists(conn, "iocs")? {
        return Ok(0);
    }
    ensure_ioc_records(conn)?;
    let cols = column_names(conn, "iocs")?;
    if !cols.iter().any(|c| c == "ioc_value") {
        return Ok(0);
    }
    let tc = if cols.contains(&"ioc_type".to_string()) {
        "ioc_type"
    } else if cols.contains(&"type".to_string()) {
        "type"
    } else {
        return Ok(0);
    };
    let sql = format!(
        "INSERT INTO ioc_records (ioc_value, ioc_type, first_seen, last_seen, source_project, metadata)
         SELECT TRIM(ioc_value), TRIM(COALESCE({tc}, 'unknown')), '', '', 'legacy_iocs', NULL FROM iocs
         WHERE TRIM(ioc_value) != ''
         ON CONFLICT(ioc_value, ioc_type) DO NOTHING"
    );
    let n = conn.execute(&sql, []).map_err(|e| e.to_string())?;
    Ok(n as usize)
}

// ---------------------------------------------------------------------------
// Asset-to-CVE correlation (CPE) — DDL for a future migration
// ---------------------------------------------------------------------------

/// Complete `CREATE TABLE` batch for `asm_assets`, `cve_data`, and `asset_cve_mapping` with
/// `FOREIGN KEY` ... `ON DELETE CASCADE`. Execute with [`Connection::execute_batch`] after
/// [`apply_connection_pragmas`] (foreign keys must be enabled).
///
/// **Conflict:** This definition replaces the older v2 `asm_assets` / `cve_data` column sets.
/// Use only on a new database or after renaming/dropping legacy tables and migrating rows.
#[allow(dead_code)]
pub const MIGRATION_ASSET_CVE_CORRELATION_DDL: &str = r#"
CREATE TABLE asm_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    hostname VARCHAR,
    ip VARCHAR,
    cpe_string VARCHAR NOT NULL,
    os VARCHAR,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cve_data (
    cve_id TEXT PRIMARY KEY NOT NULL,
    cvss_score REAL,
    description TEXT,
    base_cpe TEXT NOT NULL,
    published_date TIMESTAMP
);

CREATE TABLE asset_cve_mapping (
    asset_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    matched_on_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id, cve_id),
    FOREIGN KEY (asset_id) REFERENCES asm_assets (id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cve_data (cve_id) ON DELETE CASCADE
);
"#;

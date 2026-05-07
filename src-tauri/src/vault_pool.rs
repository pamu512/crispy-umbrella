//! r2d2-backed pool for the canonical CTI SQLite vault file.
//!
//! Schema and DDL for `cve_data`, `ioc_records`, `asm_assets`, and `ransomware_events` live in [`crate::vault_db`];
//! [`init_db`] runs [`vault_db::initialize_vault`] first, then opens pooled connections with the
//! same WAL/PRAGMA settings as the rest of the app.
//!
//! Ingestion tools run as **Tauri external binaries** (PyInstaller sidecars next to the main executable),
//! via [`tauri_plugin_shell::ShellExt::shell`] — no host `python3` required in production.

use std::path::{Path, PathBuf};

use r2d2::Pool;
use rusqlite::Connection;
use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_shell::ShellExt;

use crate::cti_config;
use crate::vault_db;

#[derive(Debug)]
struct SqliteConnectionManager {
    path: PathBuf,
}

impl SqliteConnectionManager {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl r2d2::ManageConnection for SqliteConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> Result<Connection, rusqlite::Error> {
        let conn = Connection::open(&self.path)?;
        vault_db::apply_pool_connection_pragmas(&conn)?;
        Ok(conn)
    }

    fn is_valid(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.query_row("SELECT 1", [], |_| Ok(()))
    }

    fn has_broken(&self, conn: &mut Connection) -> bool {
        conn.execute("SELECT 1", []).is_err()
    }
}

/// Thread-safe connection pool to the resolved vault path (`CTI_DB_PATH` / [`vault_db::get_vault_path`]).
#[derive(Clone)]
pub struct VaultPool(Pool<SqliteConnectionManager>);

/// [`r2d2`] pool sizing for debug / `/status` dashboards (live connections in host process).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPoolDebugSnapshot {
    pub max_connections: u32,
    pub connections: u32,
    pub idle_connections: u32,
}

impl VaultPool {
    fn build(path: &Path) -> Result<Self, String> {
        let manager = SqliteConnectionManager::new(path.to_path_buf());
        let pool = Pool::builder()
            .max_size(16)
            .build(manager)
            .map_err(|e| e.to_string())?;
        Ok(VaultPool(pool))
    }

    /// Standard pattern for vault reads/writes: one pooled [`Connection`] per closure.
    pub fn with_connection<F, T>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(&Connection) -> Result<T, String>,
    {
        let conn = self.0.get().map_err(|e| e.to_string())?;
        f(&conn)
    }

    fn verify_core_tables(&self) -> Result<(), String> {
        self.with_connection(|conn| {
            for t in ["cve_data", "ioc_records", "asm_assets", "ransomware_events"] {
                if !vault_db::table_exists(conn, t)? {
                    return Err(format!(
                        "vault missing required table `{}` (run migrations or repair vault)",
                        t
                    ));
                }
            }
            Ok(())
        })
    }

    /// Current pool sizing from [`r2d2`] (not SQLite server stats — single-file vault).
    pub fn debug_snapshot(&self) -> VaultPoolDebugSnapshot {
        let st = self.0.state();
        VaultPoolDebugSnapshot {
            max_connections: self.0.max_size(),
            connections: st.connections,
            idle_connections: st.idle_connections,
        }
    }
}

/// Runs migrations on disk via [`vault_db::initialize_vault`], builds the pool, and verifies core tables exist.
pub fn init_db() -> Result<VaultPool, String> {
    vault_db::install_canonical_cti_env();
    let path = vault_db::get_vault_path();
    vault_db::initialize_vault(&path)?;
    let pool = VaultPool::build(&path)?;
    pool.verify_core_tables()?;
    Ok(pool)
}

/// Pooled vault access for ingestion and queries (alias of [`VaultPool::with_connection`]).
pub fn standard_vault_ingest<F, T>(pool: &VaultPool, f: F) -> Result<T, String>
where
    F: FnOnce(&Connection) -> Result<T, String>,
{
    pool.with_connection(f)
}

/// Maps bundled script paths to the sidecar basename copied next to the main executable (see `bundle.externalBin`).
/// `tauri-build` strips the `-<target-triple>` suffix when copying into `target/*/`.
fn sidecar_program(script_folder: &str, script_file: &str) -> Result<PathBuf, String> {
    match (script_folder, script_file) {
        ("Compromised_user_Mac", "main.py") => Ok(PathBuf::from("mac-stealer")),
        ("Ransomware_live_event_victim", "main.py") => Ok(PathBuf::from("ransomware-live")),
        ("CVE_Project_NVD", "main.py") => Ok(PathBuf::from("cve-nvd")),
        ("Intelx_Crawler", "intelx_native_sync.py") => Ok(PathBuf::from("intelx-scraper")),
        ("IOCs-crawler-main", "run_news_crawler.py") => Ok(PathBuf::from("ioc-news-crawler")),
        _ => Err(format!(
            "no bundled sidecar for `{}/{}`; run `npm run build:python` and rebuild",
            script_folder, script_file
        )),
    }
}

/// Run a PyInstaller sidecar for `resources/scripts/<script_folder>/<script_file>` with `CTI_DB_PATH` set.
pub fn execute_sidecar(
    handle: AppHandle,
    script_folder: &str,
    script_file: &str,
    args: Vec<String>,
) -> Result<String, String> {
    let base = cti_config::resolve_script_path(&handle, script_folder)?;
    let script_path = base.join(script_file);
    if !script_path.is_file() {
        return Err(format!(
            "bundled script not found (resources layout): {}",
            script_path.display()
        ));
    }
    let prog = sidecar_program(script_folder, script_file)?;
    let vault = vault_db::get_vault_path();
    let vault_abs = vault
        .canonicalize()
        .unwrap_or_else(|_| vault.clone())
        .to_string_lossy()
        .into_owned();

    let shell_cmd = handle
        .shell()
        .sidecar(prog)
        .map_err(|e| format!("open sidecar: {}", e))?;

    let output = tauri::async_runtime::block_on(async move {
        shell_cmd
            .args(args)
            .env("CTI_DB_PATH", vault_abs)
            .current_dir(base)
            .output()
            .await
    })
    .map_err(|e| format!("sidecar execution failed: {}", e))?;

    format_sidecar_output(&output)
}

/// Same as [`execute_sidecar`] but adds arbitrary environment pairs (e.g. `INTELX_API_KEY`).
pub fn execute_sidecar_with_env(
    handle: AppHandle,
    script_folder: &str,
    script_file: &str,
    args: Vec<String>,
    extra_env: &[(&str, &str)],
) -> Result<String, String> {
    let base = cti_config::resolve_script_path(&handle, script_folder)?;
    let script_path = base.join(script_file);
    if !script_path.is_file() {
        return Err(format!(
            "bundled script not found (resources layout): {}",
            script_path.display()
        ));
    }
    let prog = sidecar_program(script_folder, script_file)?;
    let vault = vault_db::get_vault_path();
    let vault_abs = vault
        .canonicalize()
        .unwrap_or_else(|_| vault.clone())
        .to_string_lossy()
        .into_owned();

    let shell_cmd = handle
        .shell()
        .sidecar(prog)
        .map_err(|e| format!("open sidecar: {}", e))?;

    let extra_owned: Vec<(String, String)> = extra_env
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();

    let output = tauri::async_runtime::block_on(async move {
        let mut cmd = shell_cmd
            .args(args)
            .env("CTI_DB_PATH", vault_abs)
            .current_dir(base);
        for (k, v) in extra_owned {
            cmd = cmd.env(k, v);
        }
        cmd.output().await
    })
    .map_err(|e| format!("sidecar execution failed: {}", e))?;

    format_sidecar_output(&output)
}

fn format_sidecar_output(
    output: &tauri_plugin_shell::process::Output,
) -> Result<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let combined = format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout, stderr
    );

    if !output.status.success() {
        return Err(format!(
            "sidecar exited with code {:?}:\n{}",
            output.status.code(),
            combined
        ));
    }

    Ok(combined)
}

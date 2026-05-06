// Prevents additional console window on Windows in release when launching the GUI only.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//
// Tauri IPC commands (e.g. `invoke_mac_stealer_fetch`) are defined and registered in `lib.rs`
// (`invoke_handler`); this file is the binary entry for CLI vs GUI only.
// Ingestion-related commands take a single `#[derive(Deserialize)] #[serde(rename_all = "camelCase")]`
// payload struct per command — see `MacStealerFetchPayload`, `RansomwareLiveSyncPayload`, etc. in `lib.rs`.
//
// IOC crawler background work uses `tokio::sync::mpsc` started from `lib.rs` (`Builder::setup` →
// `workers::ioc_crawler::start_ioc_crawler_worker`). The channel must attach to Tauri’s Tokio
// runtime, so it is not created here.
//
// IPC commands (including run_mac_stealer / run_intelx → execute_sidecar)
// are registered on the library crate invoke_handler in lib.rs; this binary entry only exposes helpers
// like resolve_script_path / fetch_recent_vault_context.

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use rusqlite::Connection;
use tauri::AppHandle;

/// Thread-safe `r2d2` pool for the native vault (see `vault_pool` module in the library crate).
pub type VaultPool = app_lib::VaultPool;

/// Shared application flags for the GUI (`is_dino_mode` defaults to `false`; enable at launch with `--dino-mode`).
pub type AppState = app_lib::AppState;

/// [`app_lib::RunOptions`] — pass `{ dino_mode: true }` from `main` when `Cli` includes `--dino-mode`.
pub type RunOptions = app_lib::RunOptions;

/// Initializes vault DDL/migrations and opens the pool; also invoked from `app_lib::run` at startup.
pub fn init_db() -> Result<VaultPool, String> {
    app_lib::init_db()
}

/// Pooled [`rusqlite::Connection`] for standard ingestion (INSERT/UPSERT batches, PRAGMA-safe reads).
pub fn standard_vault_ingest<F, T>(pool: &VaultPool, f: F) -> Result<T, String>
where
    F: FnOnce(&Connection) -> Result<T, String>,
{
    app_lib::standard_vault_ingest(pool, f)
}

/// Runs a bundled PyInstaller sidecar with `CTI_DB_PATH` set; captures full stdout/stderr.
pub fn execute_sidecar(
    handle: AppHandle,
    script_folder: &str,
    script_file: &str,
    args: Vec<String>,
) -> Result<String, String> {
    app_lib::execute_sidecar(handle, script_folder, script_file, args)
}

/// Resolves `resources/scripts/<script_name>/` via Tauri resource path resolution (`AppHandle::path` + `BaseDirectory::Resource`).
pub fn resolve_script_path(handle: &AppHandle, script_name: &str) -> Result<PathBuf, String> {
    app_lib::resolve_script_path(handle, script_name)
}

/// Latest IOC, CVE, and ransomware snapshot from the canonical vault for Barney / LLM context.
pub fn fetch_recent_vault_context() -> String {
    app_lib::fetch_recent_vault_context()
}

/// CTI Command Center: desktop UI (default), headless ingest, or maintenance subcommands.
#[derive(Parser, Debug)]
#[command(
    name = "cti-command-center",
    version,
    about = "CTI Command Center — Tauri GUI or headless vault ingestion"
)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    run: RunCli,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Wipes the local vault and resets application data.
    Cleanup {
        /// Required to delete the vault and logs (prevents accidental data loss).
        #[arg(long)]
        force: bool,
    },
}

#[derive(Parser, Debug)]
struct RunCli {
    /// Ingest IOC rows from a CSV file into the vault (Rust-native; no Python).
    #[arg(long, value_name = "CSV")]
    ingest_iocs: Option<PathBuf>,

    /// Ingest ASM asset rows from a subdomain-style CSV (expects a `Hosts` column; same rules as the bundled ASM ingestor).
    #[arg(long, value_name = "CSV")]
    ingest_assets: Option<PathBuf>,

    /// Absolute vault SQLite path. May be omitted: uses `CTI_DB_PATH` or the default app-data layout.
    #[arg(long, value_name = "DB", env = "CTI_DB_PATH")]
    vault: Option<PathBuf>,

    /// Enable Dino-Barney LLM persona (purple optimism + optional UI tint). Ignored for headless ingest.
    #[arg(long)]
    dino_mode: bool,
}

/// Set **`CTI_DINO_MODE=1`** (or `true`) when `tauri dev` cannot forward **`--dino-mode`** to the app binary.
fn env_cti_dino_mode() -> bool {
    match std::env::var("CTI_DINO_MODE") {
        Ok(v) => {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn main() {
    // Seed CTI_DB_PATH + CTI_COMMAND_CENTER_HOME (app-support `cti-app/`); GUI `setup` refines via app_data_dir().
    // Python `run_project` still sets per-project `CTI_WORKSPACE_PATH` on child processes.
    app_lib::install_cti_paths_early();

    let cli = Cli::parse();

    if let Some(Commands::Cleanup { force }) = &cli.command {
        match app_lib::run_cleanup_cli(*force) {
            Ok(()) => {
                println!("Success: Application state has been reset.");
                process::exit(0);
            }
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        }
    }

    let run = &cli.run;
    let headless = run.ingest_iocs.is_some() || run.ingest_assets.is_some();

    if headless {
        match app_lib::run_headless_cli(
            run.ingest_iocs.as_deref(),
            run.ingest_assets.as_deref(),
            run.vault.as_deref(),
        ) {
            Ok(summary) => {
                println!("{}", summary);
                process::exit(0);
            }
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    if run.vault.is_some() {
        eprintln!(
            "warning: --vault / CTI_DB_PATH is ignored when not using --ingest-iocs or --ingest-assets"
        );
    }

    // Native ingest cron (`workers::scheduler`, `tokio-cron-scheduler`) attaches inside
    // `app_lib::run()` → `tauri::Builder::default().setup(...)` immediately before `.run(...)`
    // blocks; it must run on Tauri’s Tokio runtime, not here in `main`.
    //
    // Armory / [`resolve_script_path`] (see `cti_config`) maps to packaged `resources/scripts/<tool>/`
    // via Tauri 2 `AppHandle::path().resolve(..., BaseDirectory::Resource)`. The GUI binary has no
    // `AppHandle` here — only delegate from IPC handlers that receive `AppHandle`.
    app_lib::run_with_options(app_lib::RunOptions {
        dino_mode: run.dino_mode || env_cti_dino_mode(),
    });
}

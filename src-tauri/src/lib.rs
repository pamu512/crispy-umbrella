use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::fs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_cron_scheduler::{Job, JobScheduler};
use std::sync::Arc;
use tokio::sync::Mutex;

mod vault_db;
mod vault_ingest;
mod cti_config;
mod config_manager;
pub mod ingestion;
mod llm_proxy;
mod vault_search;
mod query_compiler;
mod graph_pivot;
mod vector_db;
mod cpe_matcher;
mod dashboard;
mod logging;
mod workers;
mod vault_pool;
mod app_state;
mod dino_persona;

pub use app_state::AppState;
pub use cti_config::resolve_script_path;
pub use vault_db::{
    configure_canonical_paths_from_app, get_db_path, TAURI_BUNDLE_IDENTIFIER,
};
pub use vault_pool::{
    execute_sidecar, execute_sidecar_with_env, init_db, standard_vault_ingest, VaultPool,
};

struct SchedulerState(Arc<Mutex<Option<JobScheduler>>>);

/// Holds the native ransomware + CVE [`JobScheduler`] started from `Builder::setup`.
struct NativeIngestCronState(Arc<Mutex<Option<JobScheduler>>>);

#[derive(Clone, Serialize)]
struct LogPayload {
    project: String,
    message: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProjectStatus {
    pub name: String,
    pub exists: bool,
}

/// Prefer a project-local virtualenv so `pip install requests` does not require system-wide packages.
/// Root `main.py`, or known nested layouts (e.g. Phishing project uses `social_media/main.py`).
fn python_entry_workdir_and_script(project_dir: &Path) -> (PathBuf, PathBuf) {
    if project_dir.join("main.py").is_file() {
        return (project_dir.to_path_buf(), PathBuf::from("main.py"));
    }
    let nested = project_dir.join("social_media").join("main.py");
    if nested.is_file() {
        return (project_dir.join("social_media"), PathBuf::from("main.py"));
    }
    if project_dir.join("news_job.py").is_file() {
        return (project_dir.to_path_buf(), PathBuf::from("news_job.py"));
    }
    (project_dir.to_path_buf(), PathBuf::from("main.py"))
}

/// IOC/news SQLite ingest via PyInstaller sidecar (`run_news_crawler.py` → `ioc_news`, then `ioc_records` backfill).
fn run_iocs_export_to_vault(
    app: &AppHandle,
    _workspace_path: &str,
    _iocs_project_dir: &Path,
) -> Result<usize, String> {
    let _ = cti_config::init_if_needed(app)?;
    let combined = vault_pool::execute_sidecar(
        app.clone(),
        "IOCs-crawler-main",
        "run_news_crawler.py",
        vec![],
    )?;
    let _ = refresh_ioc_records_from_news(app);
    for line in combined.lines() {
        if let Some(rest) = line.trim().strip_prefix("INGESTED:") {
            if let Ok(n) = rest.trim().parse::<usize>() {
                return Ok(n);
            }
        }
    }
    Ok(0)
}

fn refresh_ioc_records_from_news(app: &AppHandle) -> Result<usize, String> {
    let _ = cti_config::init_if_needed(app);
    let p = vault_db::get_vault_path();
    let conn = vault_db::open_vault(&p)?;
    vault_db::backfill_ioc_records_from_news(&conn)
}

fn project_python_interpreter(project_dir: &Path) -> PathBuf {
    #[cfg(windows)]
    let candidates = [
        project_dir.join(".venv").join("Scripts").join("python.exe"),
        project_dir.join("venv").join("Scripts").join("python.exe"),
    ];
    #[cfg(not(windows))]
    let candidates = [
        project_dir.join(".venv").join("bin").join("python"),
        project_dir.join("venv").join("bin").join("python"),
    ];
    for c in candidates {
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from("python3")
}

fn find_compose_file(project: &Path) -> Option<std::path::PathBuf> {
    for name in [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ] {
        let p = project.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Match bacongris `scripts/workflow_runner.py`: prefer `docker compose`, else `docker-compose`.
fn docker_compose_prefix() -> Result<Vec<String>, String> {
    let compose_ok = std::process::Command::new("docker")
        .args(["compose", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if compose_ok {
        return Ok(vec!["docker".to_string(), "compose".to_string()]);
    }
    let legacy_ok = std::process::Command::new("docker-compose")
        .args(["version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if legacy_ok {
        return Ok(vec!["docker-compose".to_string()]);
    }
    Err(
        "Docker Compose not found. Install Docker Desktop and ensure `docker compose` works, or install `docker-compose`."
            .into(),
    )
}

fn inject_cti_env(cmd: &mut Command, app: &AppHandle) {
    let _ = cti_config::init_if_needed(app);
    vault_db::install_canonical_cti_env();
    let vault = vault_db::get_vault_path().to_string_lossy().into_owned();
    cmd.env("CTI_COMMAND_CENTER_HOME", vault_db::cti_data_home().to_string_lossy().as_ref());
    cmd.env("CTI_DB_PATH", vault.as_str());
    cmd.env("VAULT_PATH", vault.as_str());
    if let Ok(k) = std::env::var("INTELX_API_KEY") {
        let k = k.trim();
        if !k.is_empty() {
            cmd.env("INTELX_API_KEY", k);
        }
    } else if let Some(k) =
        config_manager::get_api_key(config_manager::KEYRING_INTELX_API_KEY).filter(|s| !s.trim().is_empty())
    {
        cmd.env("INTELX_API_KEY", k);
    }
    if let Ok(root) = cti_config::writable_cti_root(app) {
        let _ = cti_config::ensure_writable_tree(app);
        cmd.env(
            "CTI_WRITABLE_ROOT",
            root.to_string_lossy().to_string(),
        );
        cmd.env(
            "CTI_EXPORTS_DIR",
            root.join("exports").to_string_lossy().to_string(),
        );
        cmd.env(
            "CTI_LOGS_DIR",
            root.join("logs").to_string_lossy().to_string(),
        );
    }
}

/// Run bundled ``shared_utils/ingestor.py sync`` (Python) to bridge CSV outputs into the vault.
fn run_csv_ingestor_sync_blocking(app: &AppHandle, workspace_path: &str) -> Result<String, String> {
    let scripts = cti_config::resolve_bundled_scripts_dir(app)?;
    let su = scripts.join("shared_utils");
    let ingestor = su.join("ingestor.py");
    if !ingestor.is_file() {
        return Ok(String::new());
    }
    let py = std::env::var("CTI_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let mut cmd = std::process::Command::new(&py);
    cmd.current_dir(&su)
        .arg("ingestor.py")
        .arg("sync")
        .arg(workspace_path);
    inject_cti_env_std(&mut cmd, app);
    let out = cmd.output().map_err(|e| format!("csv ingestor spawn: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        return Err(format!(
            "csv ingestor exit {}: {}\n{}",
            out.status,
            stderr,
            stdout
        ));
    }
    Ok(if stdout.is_empty() { stderr } else { stdout })
}

fn maybe_spawn_csv_ingestor(app: &AppHandle, workspace_path: &str, project_name: &str) {
    const PROJECTS: &[&str] = &[
        "CVE_Project_NVD",
        "ASM-fetch-main",
        "Intelx_Crawler",
        "Social_MediaV2",
        "Ransomware_live_event_victim",
        "IOCs-crawler-main",
        "Phishing_and_Social_Media_All-in-one",
        "Compromised_user_Mac",
    ];
    if !PROJECTS.contains(&project_name) {
        return;
    }
    let app = app.clone();
    let wp = workspace_path.to_string();
    let pn = project_name.to_string();
    std::thread::spawn(move || match run_csv_ingestor_sync_blocking(&app, &wp) {
        Ok(msg) if !msg.is_empty() => {
            let head = msg.lines().next().unwrap_or(&msg).chars().take(500).collect::<String>();
            let _ = app.emit(
                "script-log",
                LogPayload {
                    project: pn,
                    message: format!("CSV ingestor (sync): {}", head),
                },
            );
        }
        Ok(_) => {}
        Err(e) => {
            let _ = app.emit(
                "script-log",
                LogPayload {
                    project: pn,
                    message: format!("CSV ingestor: {}", e),
                },
            );
        }
    });
}

fn inject_cti_env_std(cmd: &mut std::process::Command, app: &AppHandle) {
    let _ = cti_config::init_if_needed(app);
    vault_db::install_canonical_cti_env();
    let vault = vault_db::get_vault_path().to_string_lossy().into_owned();
    cmd.env("CTI_COMMAND_CENTER_HOME", vault_db::cti_data_home().to_string_lossy().as_ref());
    cmd.env("CTI_DB_PATH", vault.as_str());
    cmd.env("VAULT_PATH", vault.as_str());
    if let Ok(k) = std::env::var("INTELX_API_KEY") {
        let k = k.trim();
        if !k.is_empty() {
            cmd.env("INTELX_API_KEY", k);
        }
    } else if let Some(k) =
        config_manager::get_api_key(config_manager::KEYRING_INTELX_API_KEY).filter(|s| !s.trim().is_empty())
    {
        cmd.env("INTELX_API_KEY", k);
    }
    if let Ok(root) = cti_config::writable_cti_root(app) {
        let _ = cti_config::ensure_writable_tree(app);
        cmd.env(
            "CTI_WRITABLE_ROOT",
            root.to_string_lossy().to_string(),
        );
        cmd.env(
            "CTI_EXPORTS_DIR",
            root.join("exports").to_string_lossy().to_string(),
        );
        cmd.env(
            "CTI_LOGS_DIR",
            root.join("logs").to_string_lossy().to_string(),
        );
    }
}

fn intelx_stdin_payload(
    query: &str,
    start_override: Option<&str>,
    end_override: Option<&str>,
    limit_override: Option<&str>,
) -> String {
    let start = start_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| std::env::var("INTELX_START_DATE").ok())
        .unwrap_or_else(|| "2000-01-01".to_string());
    let end = end_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| std::env::var("INTELX_END_DATE").ok())
        .unwrap_or_else(|| "2099-12-31".to_string());
    let lim = limit_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| std::env::var("INTELX_SEARCH_LIMIT").ok())
        .unwrap_or_else(|| "2000".to_string());
    let lim = if lim.trim().is_empty() {
        "2000".to_string()
    } else {
        lim
    };
    format!("{}\n{}\n{}\n{}\n", query.trim(), start.trim(), end.trim(), lim.trim())
}

fn default_script_type_py() -> String {
    "python".into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunFeatureArguments {
    #[serde(default = "default_script_type_py")]
    script_type: String,
    #[serde(default)]
    intelx_query: Option<String>,
    #[serde(default)]
    intelx_start_date: Option<String>,
    #[serde(default)]
    intelx_end_date: Option<String>,
    #[serde(default)]
    intelx_search_limit: Option<String>,
    #[serde(default)]
    social_media_target: Option<String>,
    #[serde(default)]
    social_media_start_date: Option<String>,
    #[serde(default)]
    social_media_end_date: Option<String>,
    #[serde(default)]
    social_media_num_per_platform: Option<String>,
    #[serde(default)]
    phishing_scan_type: Option<String>,
    #[serde(default)]
    phishing_domains: Option<String>,
    #[serde(default)]
    phishing_keywords: Option<String>,
    #[serde(default)]
    phishing_start_date: Option<String>,
    #[serde(default)]
    phishing_end_date: Option<String>,
    #[serde(default)]
    rumark_domains: Option<String>,
    #[serde(default)]
    rumark_cookie: Option<String>,
}

#[tauri::command]
async fn run_project_script(
    app: AppHandle,
    workspace_path: String,
    project_name: String,
    script_type: String,
    intelx_query: Option<String>,
    intelx_start_date: Option<String>,
    intelx_end_date: Option<String>,
    intelx_search_limit: Option<String>,
    social_media_target: Option<String>,
    social_media_start_date: Option<String>,
    social_media_end_date: Option<String>,
    social_media_num_per_platform: Option<String>,
    phishing_scan_type: Option<String>,
    phishing_domains: Option<String>,
    phishing_keywords: Option<String>,
    phishing_start_date: Option<String>,
    phishing_end_date: Option<String>,
    rumark_domains: Option<String>,
    rumark_cookie: Option<String>,
    // When Some: bundled `Resource/scripts/…`; workspace_path is writable data root (AppData).
    scripts_root: Option<String>,
) -> Result<(), String> {
    let resource_layout = scripts_root
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();
    let scripts_parent = scripts_root
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Path::new)
        .unwrap_or_else(|| Path::new(&workspace_path));
    let primary_project_dir = scripts_parent.join(&project_name);
    let mut project_dir = primary_project_dir.clone();
    if let Ok(bundled_tool) = cti_config::get_tool_resource_path(&app, &project_name) {
        project_dir = bundled_tool;
    }
    if !project_dir.is_dir() {
        project_dir = primary_project_dir.clone();
    }
    if !project_dir.is_dir() {
        let bundled_root = cti_config::resolve_bundled_scripts_dir(&app)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|e| format!("(unresolved: {})", e));
        let expected_bundle = format!("{}/{}", bundled_root.trim_end_matches('/'), project_name);
        let msg = format!(
            "Armory resource missing for `{}`: expected bundled folder at `{}` or workspace `{}`. Copy All_Scripts/{}/ into src-tauri/resources/scripts/ (see bundle.resources in tauri.conf.json).",
            project_name,
            expected_bundle,
            primary_project_dir.display(),
            project_name
        );
        let _ = app.emit(
            "armory-tool-missing-resource",
            serde_json::json!({
                "tool": project_name,
                "bundledScriptsRoot": bundled_root,
                "expectedBundledPath": expected_bundle,
                "workspacePath": primary_project_dir.to_string_lossy(),
                "message": msg,
            }),
        );
        return Err(format!(
            "Project directory does not exist: {} — {}",
            primary_project_dir.display(),
            msg
        ));
    }

    // Intelx_Crawler: native `intelx_native_sync.py` (Resource/scripts); legacy Docker only if INTELX_LEGACY_DOCKER=1.
    if project_name == "Intelx_Crawler" {
        let query = intelx_query
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "IntelX needs a search query (email/domain). Pass intelxQuery from the UI.".to_string()
            })?;

        let native_py = project_dir.join("intelx_native_sync.py");
        if native_py.is_file() {
            let stdin_payload = intelx_stdin_payload(
                query,
                intelx_start_date.as_deref(),
                intelx_end_date.as_deref(),
                intelx_search_limit.as_deref(),
            );
            let vault_display = vault_db::get_vault_path().to_string_lossy().into_owned();
            let _ = app.emit(
                "armory-tool-started",
                serde_json::json!({
                    "target": query,
                    "vaultDbPath": vault_display,
                    "type": "python",
                }),
            );
            let py = std::env::var("CTI_PYTHON").unwrap_or_else(|_| "python3".to_string());
            let _ = app.emit(
                "script-log",
                LogPayload {
                    project: project_name.clone(),
                    message: format!(
                        "→ {} {} (native IntelX sync; CTI_DB_PATH={}; cwd={})",
                        py,
                        native_py.display(),
                        vault_display,
                        project_dir.display()
                    ),
                },
            );
            let mut child_cmd = Command::new(&py);
            child_cmd
                .arg(&native_py)
                .current_dir(&project_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("VAULT_PATH", &vault_display)
                .env("CTI_DB_PATH", &vault_display)
                .env("CTI_WORKSPACE_PATH", &workspace_path);
            inject_cti_env(&mut child_cmd, &app);
            let mut child = child_cmd.spawn().map_err(|e| e.to_string())?;

            if let Some(mut stdin) = child.stdin.take() {
                let payload = stdin_payload.clone();
                tokio::spawn(async move {
                    let _ = stdin.write_all(payload.as_bytes()).await;
                    let _ = stdin.shutdown().await;
                });
            }

            let r = stream_child_and_wait(app.clone(), project_name.clone(), child).await;
            if r.is_ok() {
                maybe_spawn_csv_ingestor(&app, &workspace_path, &project_name);
                let _ = app.emit(
                    "vault-updated",
                    serde_json::json!({
                        "kind": "intelx_native",
                        "project": project_name,
                    }),
                );
            }
            return r;
        }

        let run_sh = project_dir.join("run.sh");
        if !run_sh.is_file() {
            let legacy_docker = std::env::var("INTELX_LEGACY_DOCKER")
                .map(|v| v == "1")
                .unwrap_or(false);
            if legacy_docker && find_compose_file(&project_dir).is_some() {
                let service = std::env::var("INTELX_COMPOSE_SERVICE")
                    .unwrap_or_else(|_| "intelx-scraper".to_string());
                let dc = docker_compose_prefix()?;
                let stdin_payload = intelx_stdin_payload(
                    query,
                    intelx_start_date.as_deref(),
                    intelx_end_date.as_deref(),
                    intelx_search_limit.as_deref(),
                );

                let _ = app.emit(
                    "script-log",
                    LogPayload {
                        project: project_name.clone(),
                        message: format!(
                            "→ docker compose run (INTELX_LEGACY_DOCKER=1) {} … cwd={}",
                            service,
                            project_dir.display()
                        ),
                    },
                );

                let mut child_cmd = Command::new(&dc[0]);
                child_cmd
                    .args(&dc[1..])
                    .args(["run", "--rm", "-i", "-T", &service])
                    .current_dir(&project_dir)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                inject_cti_env(&mut child_cmd, &app);
                let mut child = child_cmd.spawn().map_err(|e| e.to_string())?;

                if let Some(mut stdin) = child.stdin.take() {
                    let payload = stdin_payload.clone();
                    tokio::spawn(async move {
                        let _ = stdin.write_all(payload.as_bytes()).await;
                        let _ = stdin.shutdown().await;
                    });
                }

                let r = stream_child_and_wait(app.clone(), project_name.clone(), child).await;
                if r.is_ok() {
                    maybe_spawn_csv_ingestor(&app, &workspace_path, &project_name);
                }
                return r;
            }
            let intelx_msg = format!(
                "IntelX launcher incomplete under `{}`: missing `intelx_native_sync.py` (and no run.sh). Optional legacy Docker: set INTELX_LEGACY_DOCKER=1 with docker-compose.yml.",
                project_dir.display()
            );
            let _ = app.emit(
                "armory-tool-missing-resource",
                serde_json::json!({
                    "tool": project_name,
                    "workspacePath": primary_project_dir.to_string_lossy(),
                    "projectDir": project_dir.to_string_lossy(),
                    "message": intelx_msg,
                }),
            );
            return Err(intelx_msg);
        }
        // fall through to sh run.sh when present
    }

    // Social_MediaV2: README docker-run.sh args → main.py -v1 target -v2 output -n num [--start-time][--end-time]
    if project_name == "Social_MediaV2" && script_type == "python" {
        let target = social_media_target
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "Social Media V2 needs a target name (keyword). Use the run dialog in the toolbox or hub."
                    .to_string()
            })?;
        let num_str = social_media_num_per_platform
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("10");
        let out_dir = if resource_layout {
            Path::new(&workspace_path).join("Social_MediaV2").join("output")
        } else {
            project_dir.join("output")
        };
        fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
        let out_abs = fs::canonicalize(&out_dir).unwrap_or_else(|_| out_dir.clone());

        let py = cti_config::python_for_feature_layout(
            &project_dir,
            Path::new(&workspace_path),
            &project_name,
        );
        let using_venv = py != Path::new("python3");
        let _ = app.emit(
            "script-log",
            LogPayload {
                project: project_name.clone(),
                message: if using_venv {
                    format!(
                        "→ {} main.py -v1 … -v2 {} -n {} (cwd={})",
                        py.display(),
                        out_abs.display(),
                        num_str,
                        project_dir.display()
                    )
                } else {
                    format!(
                        "→ python3 main.py … (cwd={}) — create .venv if imports fail",
                        project_dir.display()
                    )
                },
            },
        );

        let script_abs = project_dir.join("main.py");
        let soc_cwd = if resource_layout {
            Path::new(&workspace_path).join("Social_MediaV2")
        } else {
            project_dir.clone()
        };
        let _ = fs::create_dir_all(&soc_cwd);
        let mut cmd = Command::new(&py);
        cmd.arg(&script_abs)
            .current_dir(&soc_cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("-v1")
            .arg(target)
            .arg("-v2")
            .arg(&out_abs)
            .arg("-n")
            .arg(num_str);
        if let Some(s) = social_media_start_date
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd.arg("--start-time").arg(s);
        }
        if let Some(e) = social_media_end_date
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd.arg("--end-time").arg(e);
        }
        inject_cti_env(&mut cmd, &app);

        let child = cmd.spawn().map_err(|e| e.to_string())?;
        let wp = workspace_path.clone();
        let pn = project_name.clone();
        let app_ingest = app.clone();
        let result = stream_child_and_wait(app, pn.clone(), child).await;
        if result.is_ok() {
            maybe_spawn_csv_ingestor(&app_ingest, &wp, &pn);
            match vault_ingest::ingest_social_media_from_workspace(&wp) {
                Ok(n) => {
                    let _ = app_ingest.emit(
                        "script-log",
                        LogPayload {
                            project: pn.clone(),
                            message: format!(
                                "Vault: upserted {} social_media_results row(s) from Social_MediaV2/output/**/*.csv",
                                n
                            ),
                        },
                    );
                }
                Err(e) => {
                    let _ = app_ingest.emit(
                        "script-log",
                        LogPayload {
                            project: pn,
                            message: format!("Vault social ingest: {}", e),
                        },
                    );
                }
            }
        }
        return result;
    }

    // Phishing_and_Social_Media_All-in-one: Brand Scout (brand_scout.py) — README: PS / SMS / ALL + dates.
    if project_name == "Phishing_and_Social_Media_All-in-one" && script_type == "python" {
        let mode_raw = phishing_scan_type
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "Brand Scout needs a scan type (PS, SMS, or ALL). Use the Phishing+ run dialog.".to_string()
            })?;
        let mode = mode_raw.to_ascii_uppercase();
        if mode != "PS" && mode != "SMS" && mode != "ALL" {
            return Err("Scan type must be PS, SMS, or ALL.".into());
        }
        let start = phishing_start_date
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Brand Scout needs a start date (YYYY-MM-DD).".to_string())?;
        let end = phishing_end_date
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Brand Scout needs an end date (YYYY-MM-DD).".to_string())?;
        let domains = phishing_domains.as_deref().map(str::trim).unwrap_or("");
        let keywords = phishing_keywords.as_deref().map(str::trim).unwrap_or("");
        if (mode == "PS" || mode == "ALL") && domains.is_empty() {
            return Err("PS and ALL scans require domain(s) (comma-separated).".into());
        }
        if (mode == "SMS" || mode == "ALL") && keywords.is_empty() {
            return Err("SMS and ALL scans require keyword(s) (comma-separated).".into());
        }

        let scout = project_dir.join("brand_scout.py");
        if !scout.is_file() {
            return Err("brand_scout.py not found in Phishing_and_Social_Media_All-in-one (see README).".into());
        }
        let py = cti_config::python_for_feature_layout(
            &project_dir,
            Path::new(&workspace_path),
            &project_name,
        );
        let _using_venv = py != Path::new("python3");
        let scout_cwd = if resource_layout {
            Path::new(&workspace_path).join(&project_name)
        } else {
            project_dir.clone()
        };
        let _ = fs::create_dir_all(&scout_cwd);
        let _ = app.emit(
            "script-log",
            LogPayload {
                project: project_name.clone(),
                message: format!(
                    "→ {} {} -{} … (cwd={})",
                    py.display(),
                    scout.display(),
                    mode.to_ascii_lowercase(),
                    scout_cwd.display()
                ),
            },
        );

        let mut cmd = Command::new(&py);
        cmd.arg(&scout)
            .current_dir(&scout_cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match mode.as_str() {
            "PS" => {
                cmd.arg("-ps").arg(domains).arg(start).arg(end);
            }
            "SMS" => {
                cmd.arg("-sms").arg(keywords).arg(start).arg(end);
            }
            "ALL" => {
                cmd.arg("-all").arg(domains).arg(keywords).arg(start).arg(end);
            }
            _ => unreachable!(),
        }
        inject_cti_env(&mut cmd, &app);

        let child = cmd.spawn().map_err(|e| e.to_string())?;
        let pn = project_name.clone();
        let wp = workspace_path.clone();
        let result = stream_child_and_wait(app.clone(), pn.clone(), child).await;
        if result.is_ok() {
            maybe_spawn_csv_ingestor(&app, &wp, &pn);
            let prompt = format!(
                "Brand Scout scan completed (mode: {}). Workspace: {}. \
Read the script console for errors. Then: (1) Summarize phishing-relevant findings from domain folders (*_permutations*.csv, *_phish_results*.csv) and any social_media_output/* per the project README; \
(2) Call out highest-risk domains or URLs and registrar/WHOIS signals; (3) Suggest 3 concrete brand-abuse or SOC follow-ups. Use read_shared_utils on Phishing_and_Social_Media_All-in-one/README.md if needed.",
                mode,
                wp
            );
            let _ = app.emit(
                "script-log",
                LogPayload {
                    project: pn.clone(),
                    message:
                        "CTI: A draft analysis prompt was sent to Investigation Chat (composer). Review console output and CSV paths above."
                            .into(),
                },
            );
            let _ = app.emit("copilot_prefill", serde_json::json!({ "prompt": prompt }));
        }
        return result;
    }

    if script_type == "python" && project_name == "ASM-fetch-main" {
        let py = cti_config::python_for_feature_layout(
            &project_dir,
            Path::new(&workspace_path),
            &project_name,
        );
        let export_py = project_dir.join("export_asm_to_cti_vault.py");
        let using_venv = py != Path::new("python3");
        let use_export = export_py.is_file();
        let _ = app.emit(
            "script-log",
            LogPayload {
                project: project_name.clone(),
                message: if use_export {
                    format!(
                        "→ {} {} (cwd={}) — sync asm_assets → cti_vault.db (Postgres must be reachable).",
                        py.display(),
                        export_py.file_name().unwrap_or_default().to_string_lossy(),
                        project_dir.display()
                    )
                } else if using_venv {
                    format!(
                        "→ {} main.py (cwd={}) — add export_asm_to_cti_vault.py to sync the vault from Postgres.",
                        py.display(),
                        project_dir.display()
                    )
                } else {
                    format!(
                        "→ {} main.py (cwd={}) — no .venv/venv; add export_asm_to_cti_vault.py for vault sync.",
                        py.display(),
                        project_dir.display()
                    )
                },
            },
        );
        let asm_cwd = if resource_layout {
            Path::new(&workspace_path).join(&project_name)
        } else {
            project_dir.clone()
        };
        let _ = fs::create_dir_all(&asm_cwd);
        let mut cmd = Command::new(py);
        if use_export {
            cmd.arg(&export_py);
        } else {
            cmd.arg(project_dir.join("main.py"));
        }
        cmd.current_dir(&asm_cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("CTI_WORKSPACE_PATH", &workspace_path);
        inject_cti_env(&mut cmd, &app);
        let child = cmd.spawn().map_err(|e| e.to_string())?;
        let wp = workspace_path.clone();
        let pn = project_name.clone();
        let app_ingest = app.clone();
        let result = stream_child_and_wait(app, pn.clone(), child).await;
        if result.is_ok() {
            maybe_spawn_csv_ingestor(&app_ingest, &wp, &pn);
        }
        if result.is_ok() && use_export {
            let _ = app_ingest.emit(
                "script-log",
                LogPayload {
                    project: pn.clone(),
                    message: "Vault: asm_assets updated from ASM Postgres (see INGESTED:N in log above).".into(),
                },
            );
        } else if result.is_ok() && !use_export {
            match vault_ingest::ingest_asm_from_workspace(&wp) {
                Ok(n) if n > 0 => {
                    let _ = app_ingest.emit(
                        "script-log",
                        LogPayload {
                            project: pn.clone(),
                            message: format!(
                                "Vault: upserted {} asm_assets row(s) from *_subdomains.csv fallback",
                                n
                            ),
                        },
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = app_ingest.emit(
                        "script-log",
                        LogPayload {
                            project: pn.clone(),
                            message: format!("Vault ASM CSV fallback skipped: {}", e),
                        },
                    );
                }
            }
        }
        return result;
    }

    let mut cmd = match script_type.as_str() {
        "sh" => {
            let mut c = Command::new("sh");
            c.arg("run.sh")
                .current_dir(&project_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            inject_cti_env(&mut c, &app);
            c
        }
        "docker" => {
            let dc = docker_compose_prefix()?;
            let mut c = Command::new(&dc[0]);
            c.args(&dc[1..])
                .arg("up")
                .current_dir(&project_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            
            let vault_display = vault_db::get_vault_path().to_string_lossy().into_owned();
            c.env("VAULT_PATH", &vault_display);
            c.env("CTI_DB_PATH", &vault_display);
            
            let mut target_name = project_name.clone();
            
            if project_name == "Social_MediaV2" {
                if let Some(t) = social_media_target.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("TARGET_NAME", t);
                    target_name = t.to_string();
                }
                if let Some(n) = social_media_num_per_platform.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("NUM_PER_PLATFORM", n);
                }
                if let Some(sd) = social_media_start_date.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("START_DATE", sd);
                }
                if let Some(ed) = social_media_end_date.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("END_DATE", ed);
                }
                let out_dir = project_dir.join("output");
                let _ = fs::create_dir_all(&out_dir);
                if let Ok(out_abs) = fs::canonicalize(&out_dir) {
                    c.env("OUTPUT_PATH", out_abs);
                }
            } else if project_name == "Phishing_and_Social_Media_All-in-one" {
                if let Some(d) = phishing_domains.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("DOMAINS", d);
                    target_name = d.to_string();
                }
                if let Some(k) = phishing_keywords.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("KEYWORDS", k);
                    if target_name == project_name {
                        target_name = k.to_string();
                    }
                }
                if let Some(st) = phishing_scan_type.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("SCAN_TYPE", st);
                }
                if let Some(sd) = phishing_start_date.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("START_DATE", sd);
                }
                if let Some(ed) = phishing_end_date.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    c.env("END_DATE", ed);
                }
            }

            inject_cti_env(&mut c, &app);
            
            let _ = app.emit(
                "armory-tool-started",
                serde_json::json!({
                    "target": target_name,
                    "vaultDbPath": vault_display,
                    "type": "docker",
                }),
            );
            
            let _ = app.emit(
                "script-log",
                LogPayload {
                    project: project_name.clone(),
                    message: format!(
                        "→ {} compose up (cwd={})",
                        dc[0],
                        project_dir.display()
                    ),
                },
            );
            c
        }
        "python" => {
            let py = cti_config::python_for_feature_layout(
                &project_dir,
                Path::new(&workspace_path),
                &project_name,
            );
            let (py_cwd, py_script) = python_entry_workdir_and_script(&project_dir);
            let script_abs = py_cwd.join(&py_script);
            let cwd_run = if resource_layout {
                let d = Path::new(&workspace_path).join(&project_name);
                let _ = fs::create_dir_all(&d);
                d
            } else {
                py_cwd.clone()
            };
            let using_venv = py != Path::new("python3");
            let _ = app.emit(
                "script-log",
                LogPayload {
                    project: project_name.clone(),
                    message: if using_venv {
                        format!(
                            "→ {} {} (cwd={})",
                            py.display(),
                            script_abs.display(),
                            cwd_run.display()
                        )
                    } else {
                        format!(
                            "→ {} {} (cwd={}) — no venv: use Initialize in toolbox or python3 -m venv under AppData python_env/{}",
                            py.display(),
                            script_abs.display(),
                            cwd_run.display(),
                            project_name
                        )
                    },
                },
            );
            let mut c = Command::new(py);
            c.arg(&script_abs)
                .current_dir(cwd_run)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            c
        }
        _ => return Err("Unknown script type".into()),
    };
    if script_type == "python"
        && (project_name == "CVE_Project_NVD"
            || project_name == "Ransomware_live_event_victim"
            || project_name == "Compromised_user_Mac")
    {
        cmd.env("CTI_NON_INTERACTIVE", "1");
    }
    if project_name == "Compromised_user_Mac" && script_type == "python" {
        let vault_display = vault_db::get_vault_path().to_string_lossy().into_owned();
        cmd.env("VAULT_PATH", &vault_display);
        cmd.env("CTI_DB_PATH", &vault_display);
        
        let mut target_name = "Mac Compromise".to_string();
        if let Some(d) = rumark_domains
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd.env("RUMARK_DOMAINS", d);
            target_name = d.to_string();
        }
        if let Some(c) = rumark_cookie
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd.env("RUMARK_COOKIE", c);
        }
        
        let _ = app.emit(
            "armory-tool-started",
            serde_json::json!({
                "target": target_name,
                "vaultDbPath": vault_display,
                "type": "python",
            }),
        );
    }
    inject_cti_env(&mut cmd, &app);
    let child = cmd.spawn().map_err(|e| e.to_string())?;

    let wp = workspace_path.clone();
    let pn = project_name.clone();
    let app_ingest = app.clone();
    let result = stream_child_and_wait(app, pn.clone(), child).await;
    if result.is_ok() && pn == "CVE_Project_NVD" {
        match vault_ingest::ingest_cve_from_workspace(&wp) {
            Ok(n) => {
                let _ = app_ingest.emit(
                    "script-log",
                    LogPayload {
                        project: pn.clone(),
                        message: format!("Vault: upserted {} CVE row(s) into cti_vault.cve_data", n),
                    },
                );
            }
            Err(e) => {
                let _ = app_ingest.emit(
                    "script-log",
                    LogPayload {
                        project: pn.clone(),
                        message: format!("Vault ingest: {}", e),
                    },
                );
            }
        }
    }
    if result.is_ok() && pn == "IOCs-crawler-main" {
        match run_iocs_export_to_vault(&app_ingest, &wp, &project_dir) {
            Ok(n) => {
                let _ = app_ingest.emit(
                    "script-log",
                    LogPayload {
                        project: pn.clone(),
                        message: format!(
                            "Vault: news crawler completed ({} source(s) OK); ioc_records refreshed from ioc_news",
                            n
                        ),
                    },
                );
            }
            Err(e) => {
                let _ = app_ingest.emit(
                    "script-log",
                    LogPayload {
                        project: pn.clone(),
                        message: format!(
                            "Vault IOC news sync skipped or failed (build `ioc-news-crawler` sidecar with npm run build:python; or run ingest_iocs_vault later): {}",
                            e
                        ),
                    },
                );
            }
        }
    }
    if result.is_ok() {
        maybe_spawn_csv_ingestor(&app_ingest, &wp, &pn);
    }
    result
}

/// Bundled scripts (`Resource/scripts`) + writable AppData workspace (`cti-app/`).
#[tauri::command]
async fn run_feature_v2(
    app: AppHandle,
    feature_name: String,
    arguments: serde_json::Value,
) -> Result<(), String> {
    let _ = cti_config::init_if_needed(&app)?;
    let a: RunFeatureArguments = serde_json::from_value(arguments)
        .map_err(|e| format!("run_feature_v2 arguments: {}", e))?;
    let scripts = cti_config::resolve_bundled_scripts_dir(&app)?;
    let wp = cti_config::writable_cti_root(&app)?
        .to_string_lossy()
        .to_string();
    let scripts_root = Some(scripts.to_string_lossy().to_string());
    run_project_script(
        app,
        wp,
        feature_name,
        a.script_type,
        a.intelx_query,
        a.intelx_start_date,
        a.intelx_end_date,
        a.intelx_search_limit,
        a.social_media_target,
        a.social_media_start_date,
        a.social_media_end_date,
        a.social_media_num_per_platform,
        a.phishing_scan_type,
        a.phishing_domains,
        a.phishing_keywords,
        a.phishing_start_date,
        a.phishing_end_date,
        a.rumark_domains,
        a.rumark_cookie,
        scripts_root,
    )
    .await
}

async fn stream_child_and_wait(
    app: AppHandle,
    project_name: String,
    mut child: tokio::process::Child,
) -> Result<(), String> {
    let stdout = child.stdout.take().ok_or("stdout not piped")?;
    let stderr = child.stderr.take().ok_or("stderr not piped")?;

    let app_o = app.clone();
    let pn_o = project_name.clone();
    let out_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let _ = app_o.emit("script-log", LogPayload {
                project: pn_o.clone(),
                message: line,
            });
        }
    });

    let app_e = app.clone();
    let pn_e = project_name.clone();
    let err_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let _ = app_e.emit("script-log", LogPayload {
                project: pn_e.clone(),
                message: format!("ERROR: {}", line),
            });
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| format!("process wait: {}", e))?;

    let _ = out_task.await;
    let _ = err_task.await;

    let exit_msg = format!("Process exited with {}", status);
    let _ = app.emit(
        "script-log",
        LogPayload {
            project: project_name.clone(),
            message: exit_msg,
        },
    );

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} exited with non-success status: {}",
            project_name, status
        ))
    }
}

#[tauri::command]
fn validate_workspace(path: String) -> Result<Vec<ProjectStatus>, String> {
    let base_path = Path::new(&path);
    let folders = vec![
        "Intelx_Crawler",
        "CVE_Project_NVD",
        "ASM-fetch-main",
        "Ransomware_live_event_victim",
        "Phishing_and_Social_Media_All-in-one",
        "Social_MediaV2",
        "IOCs-crawler-main",
        "Compromised_user_Mac",
    ];

    let mut statuses = Vec::new();
    for folder in folders {
        let folder_path = base_path.join(folder);
        statuses.push(ProjectStatus {
            name: folder.to_string(),
            exists: folder_path.exists() && folder_path.is_dir(),
        });
    }
    
    Ok(statuses)
}

/// Parameterized vault search (no raw SQL from the client). See `vault_search::SearchParams`.
#[tauri::command]
fn search_vault(filters: vault_search::SearchParams) -> Result<Vec<Value>, String> {
    let path = vault_search::resolve_vault_db_path(&filters.workspace_path);
    let conn = vault_db::open_vault(&path).map_err(|e| e.to_string())?;
    vault_search::execute_search(&conn, &filters)
}

/// One-hop IOC pivot graph from the canonical vault ([`vault_db::get_vault_path`]).
/// `ioc_id` is `ioc_value`, or `ioc_value` + U+001F + `ioc_type` to pin one row when multiple types share a value.
/// For a workspace-scoped vault file, call [`graph_pivot::pivot_from_workspace`] from Rust or extend this command.
#[tauri::command]
fn get_pivot_graph(app: AppHandle, ioc_id: String) -> Result<graph_pivot::PivotGraph, String> {
    let _ = cti_config::init_if_needed(&app);
    let p = vault_db::get_vault_path();
    graph_pivot::build_pivot_graph(&p, &ioc_id)
}

#[tauri::command]
fn ingest_cve_vault(workspace_path: String) -> Result<usize, String> {
    vault_ingest::ingest_cve_from_workspace(&workspace_path)
}

/// Re-run ASM → vault export (Postgres script) or CSV fallback under ASM-fetch-main.
#[tauri::command]
fn ingest_asm_vault(workspace_path: String) -> Result<usize, String> {
    let proj = Path::new(&workspace_path).join("ASM-fetch-main");
    let export_py = proj.join("export_asm_to_cti_vault.py");
    let py = project_python_interpreter(&proj);
    if export_py.is_file() {
        let out = std::process::Command::new(&py)
            .current_dir(&proj)
            .env("CTI_WORKSPACE_PATH", &workspace_path)
            .env(
                "CTI_DB_PATH",
                vault_db::get_vault_path().to_string_lossy().as_ref(),
            )
            .arg(&export_py)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some(rest) = line.trim().strip_prefix("INGESTED:") {
                    return rest
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| format!("Bad INGESTED line: {}", line));
                }
            }
            return Ok(0);
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        return vault_ingest::ingest_asm_from_workspace(&workspace_path).map_err(|e| {
            let head = stderr.trim();
            if head.is_empty() {
                format!("ASM Postgres export failed (exit {}). CSV fallback: {}", out.status, e)
            } else {
                format!("ASM Postgres export failed: {}\nCSV fallback: {}", head, e)
            }
        });
    }
    vault_ingest::ingest_asm_from_workspace(&workspace_path)
}

/// Runs `run_news_crawler.py` (SQLite → `ioc_news`) via sidecar, then backfills `ioc_records`.
#[tauri::command]
fn ingest_iocs_vault(app: AppHandle, workspace_path: String) -> Result<usize, String> {
    let legacy = Path::new(&workspace_path).join("IOCs-crawler-main");
    let iocs = if legacy.is_dir() {
        legacy
    } else {
        cti_config::resolve_feature_dir(&app, "IOCs-crawler-main")?
    };
    run_iocs_export_to_vault(&app, &workspace_path, &iocs)
}

/// Same ingest as `ingest_iocs_vault` without requiring a workspace path (bundled `IOCs-crawler-main` + vault only).
#[tauri::command]
fn run_news_crawler(app: AppHandle) -> Result<String, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let out = vault_pool::execute_sidecar(
        app.clone(),
        "IOCs-crawler-main",
        "run_news_crawler.py",
        vec![],
    )?;
    let _ = refresh_ioc_records_from_news(&app);
    Ok(out)
}

#[tauri::command]
fn cti_bootstrap(app: AppHandle, state: State<'_, AppState>) -> Result<Value, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let root = cti_config::writable_cti_root(&app)?;
    let scripts = cti_config::resolve_bundled_scripts_dir(&app)
        .map(|p| Value::String(p.to_string_lossy().into_owned()))
        .unwrap_or(Value::Null);
    Ok(serde_json::json!({
        "writableRoot": root.to_string_lossy(),
        "vaultDbPath": vault_db::get_vault_path().to_string_lossy(),
        "scriptsRoot": scripts,
        "dinoMode": state.dino_mode(),
    }))
}

#[tauri::command]
fn resolve_feature_path(app: AppHandle, feature_name: String) -> Result<String, String> {
    let p = cti_config::resolve_feature_dir(&app, &feature_name)?;
    Ok(p.to_string_lossy().into_owned())
}

#[tauri::command]
fn feature_status(app: AppHandle, feature_name: String) -> Result<cti_config::FeatureStatusPayload, String> {
    cti_config::feature_status(&app, &feature_name)
}

#[tauri::command]
fn bootstrap_feature_venv(app: AppHandle, feature_name: String) -> Result<String, String> {
    cti_config::bootstrap_feature_venv(&app, &feature_name)
}

/// Best-effort: create AppData `python_env/<feature>/` and `pip install` for each bundled feature that has `requirements.txt`.
#[tauri::command]
fn bootstrap_all_feature_venvs(app: AppHandle) -> Result<Value, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let folders = [
        "Intelx_Crawler",
        "CVE_Project_NVD",
        "ASM-fetch-main",
        "Ransomware_live_event_victim",
        "Phishing_and_Social_Media_All-in-one",
        "Social_MediaV2",
        "IOCs-crawler-main",
        "Compromised_user_Mac",
    ];
    let mut results: Vec<Value> = Vec::new();
    for name in folders {
        if cti_config::bundled_requirements_path(&app, name).is_err() {
            results.push(serde_json::json!({
                "feature": name,
                "ok": false,
                "skipped": "bundle or requirements.txt missing",
            }));
            continue;
        }
        match cti_config::bootstrap_feature_venv(&app, name) {
            Ok(msg) => results.push(serde_json::json!({
                "feature": name,
                "ok": true,
                "message": msg,
            })),
            Err(e) => results.push(serde_json::json!({
                "feature": name,
                "ok": false,
                "error": e,
            })),
        }
    }
    Ok(Value::Array(results))
}

#[tauri::command]
fn ingest_csv_vault(app: AppHandle, workspace_path: String) -> Result<String, String> {
    run_csv_ingestor_sync_blocking(&app, workspace_path.trim())
}

/// Row counts for `ioc_records`, `asset_cve_mapping`, and `cve_data` on the canonical vault file.
#[tauri::command]
fn get_vault_stats() -> Result<dashboard::VaultStats, String> {
    let path = vault_db::vault_path();
    let conn = vault_db::initialize_vault(&path)?;
    let mut s = dashboard::collect_vault_stats(&conn)?;
    s.vault_db_absolute_path = path.to_string_lossy().into_owned();
    Ok(s)
}

/// Recent `cve_data` rows for Threat Pulse (ordered by `updated_at` / `published_date`).
#[tauri::command]
fn get_recent_cves_for_pulse(limit: Option<u32>) -> Result<Vec<dashboard::CvePulseRow>, String> {
    let path = vault_db::vault_path();
    let conn = vault_db::initialize_vault(&path)?;
    dashboard::query_recent_cves_for_pulse(&conn, limit.unwrap_or(18))
}

/// Recent `ioc_records` from the canonical vault (Threat Pulse / Barney).
#[tauri::command]
fn get_recent_iocs_for_pulse(limit: Option<u32>) -> Result<Vec<dashboard::IocPulseRow>, String> {
    let path = vault_db::vault_path();
    let conn = vault_db::initialize_vault(&path)?;
    dashboard::query_recent_iocs_for_pulse(&conn, limit.unwrap_or(18))
}

/// Markdown environmental context: top critical CVEs + recent IOCs for Barney / `invoke_local_llm`.
#[tauri::command]
fn get_barney_environmental_context() -> Result<String, String> {
    let path = vault_db::vault_path();
    let conn = vault_db::initialize_vault(&path)?;
    dashboard::format_barney_environmental_context(&conn)
}

/// Recent IOCs, CVEs, and ransomware events (plain text, sectioned) for Barney LLM injection via [`dashboard::format_recent_vault_llm_context`].
pub fn fetch_recent_vault_context() -> String {
    let path = vault_db::get_vault_path();
    match vault_db::initialize_vault(&path) {
        Ok(conn) => match dashboard::format_recent_vault_llm_context(&conn) {
            Ok(s) => s,
            Err(e) => format!("[vault query error: {}]", e),
        },
        Err(e) => format!("[vault unavailable: {}]", e),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HunterAlertArgs {
    #[serde(default)]
    event_payload: Option<Value>,
}

/// Short hunter alert line after vault sync (uses live triage counts).
#[tauri::command]
fn get_hunter_alert_notification(args: HunterAlertArgs) -> Result<String, String> {
    let _ = args.event_payload;
    let path = vault_db::vault_path();
    let conn = vault_db::initialize_vault(&path)?;
    let n = dashboard::high_priority_target_count(&conn)?;
    let body = if n > 0 {
        format!("Ingestion complete. I've identified {n} high-priority targets in the new batch.")
    } else {
        "Ingestion complete. I've reviewed the vault snapshot—no CVSS ≥8 CVEs or hot IOCs in the 72h triage window; still worth a pass through Environmental Context.".to_string()
    };
    Ok(format!("**Hunter Alert**\n\n{body}"))
}

/// SQLite IOC / asset–CVE counts and local vector store health (no WebView network calls).
#[tauri::command]
async fn get_dashboard_metrics(workspace_path: String) -> Result<dashboard::DashboardMetrics, String> {
    let _workspace = workspace_path.trim();
    let db_path = vault_db::vault_path();
    let vault_db_absolute_path = db_path.to_string_lossy().into_owned();
    let conn = vault_db::initialize_vault(&db_path)?;
    let (total_iocs, vulnerable_assets) = dashboard::collect_sqlite_metrics(&conn)?;
    let endpoint = vector_db::vector_store_endpoint();
    let (vector_db_connected, vector_db_collection_ready, vector_db_message) =
        match vector_db::vector_db_health_probe().await {
            Ok((ready, msg)) => (true, ready, msg),
            Err(e) => (false, false, e.to_string()),
        };
    Ok(dashboard::DashboardMetrics {
        total_iocs,
        vulnerable_assets,
        vector_db_connected,
        vector_db_collection_ready,
        vector_db_endpoint: endpoint,
        vector_db_message,
        vault_db_absolute_path,
    })
}

/// Restore `CTI_DB_PATH` after temporarily overriding it for ingestion commands.
pub(crate) fn restore_cti_db_env(prev: Option<String>) {
    match prev {
        Some(v) => std::env::set_var("CTI_DB_PATH", v),
        None => {
            let _ = std::env::remove_var("CTI_DB_PATH");
        }
    }
}

/// Official NVD CVE 2.0 JSON feed (incremental / modified).
const DEFAULT_NVD_MODIFIED_FEED_ZIP: &str =
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CveNvdUpdateResult {
    zip_path: String,
    cve_rows_upserted: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MacStealerFetchPayload {
    cookie: String,
    domains: String,
    /// UI echo of [`vault_db::get_vault_path`] for debugging; host always uses canonical resolution.
    #[serde(default)]
    vault_db_absolute_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RansomwareLiveSyncPayload {
    start_date: String,
    end_date: String,
    #[serde(default)]
    vault_db_absolute_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EasmScanPayload {
    domain: String,
    #[serde(default)]
    vault_db_absolute_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveNvdUpdatePayload {
    workspace_path: String,
    feed_url: Option<String>,
    #[serde(default)]
    vault_db_absolute_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunIntelxPayload {
    target: String,
    start_date: String,
    end_date: String,
    limit: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunMacStealerPayload {
    #[serde(default)]
    cookie: Option<String>,
    domains: String,
}

/// RUMARK MAC stealer scrape via bundled `Compromised_user_Mac/main.py` (`execute_sidecar`).
#[tauri::command]
fn run_mac_stealer(app: AppHandle, payload: RunMacStealerPayload) -> Result<String, String> {
    let domains = payload.domains.trim().to_string();
    if domains.is_empty() {
        return Err("domains must not be empty".into());
    }
    let cookie_inline = payload.cookie.as_deref().unwrap_or("").trim();
    let cookie = if cookie_inline.is_empty() {
        config_manager::get_api_key(config_manager::KEYRING_MAC_RUMARK_COOKIE)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                "RUMARK session cookie: paste it in the MAC Stealer form or save it under Data ingestion hub → Saved credentials (mac_stealer_rumark_cookie)."
                    .to_string()
            })?
    } else {
        cookie_inline.to_string()
    };
    let _ = cti_config::init_if_needed(&app)?;
    vault_pool::execute_sidecar(
        app,
        "Compromised_user_Mac",
        "main.py",
        vec![
            "--cookie".into(),
            cookie,
            "--domains".into(),
            domains,
        ],
    )
}

/// Native IntelX vault sync via bundled `intelx_native_sync.py` (`execute_sidecar_with_env`).
#[tauri::command]
fn run_intelx(app: AppHandle, payload: RunIntelxPayload) -> Result<String, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let intelx_key = config_manager::get_api_key(config_manager::KEYRING_INTELX_API_KEY)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("INTELX_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| {
            "IntelX API key: save it under Data ingestion hub → Saved credentials (intelx_api_key), or set INTELX_API_KEY for the desktop process."
                .to_string()
        })?;
    vault_pool::execute_sidecar_with_env(
        app,
        "Intelx_Crawler",
        "intelx_native_sync.py",
        vec![
            payload.target.trim().to_string(),
            payload.start_date.trim().to_string(),
            payload.end_date.trim().to_string(),
            payload.limit.trim().to_string(),
        ],
        &[("INTELX_API_KEY", intelx_key.as_str())],
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunRansomwareSyncPayload {
    #[serde(default)]
    api_key: Option<String>,
    start_date: String,
    end_date: String,
}

/// Ransomware.live PRO → `ransomware_events` via bundled `Ransomware_live_event_victim/main.py`.
#[tauri::command]
fn run_ransomware_sync(app: AppHandle, payload: RunRansomwareSyncPayload) -> Result<String, String> {
    let start_date = payload.start_date.trim().to_string();
    let end_date = payload.end_date.trim().to_string();
    if start_date.is_empty() || end_date.is_empty() {
        return Err("start_date and end_date are required".into());
    }
    let api_key_inline = payload.api_key.as_deref().unwrap_or("").trim();
    let api_key = if api_key_inline.is_empty() {
        config_manager::get_api_key(config_manager::KEYRING_RANSOMWARE_LIVE)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                "Ransomware.live API key: save it under Data ingestion hub → Saved credentials (ransomware_live), or paste a one-off key in the sync form."
                    .to_string()
            })?
    } else {
        api_key_inline.to_string()
    };
    let _ = cti_config::init_if_needed(&app)?;
    vault_pool::execute_sidecar(
        app,
        "Ransomware_live_event_victim",
        "main.py",
        vec![
            "--api-key".into(),
            api_key,
            "--start-date".into(),
            start_date,
            "--end-date".into(),
            end_date,
        ],
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IngestionSecretSlotMeta {
    service: &'static str,
    label: &'static str,
    description: &'static str,
    env_fallback: Option<&'static str>,
}

/// Metadata for ingestion secrets stored in the OS keychain (`config_manager`).
#[tauri::command]
fn list_ingestion_secret_slots() -> Vec<IngestionSecretSlotMeta> {
    vec![
        IngestionSecretSlotMeta {
            service: config_manager::KEYRING_INTELX_API_KEY,
            label: "Intelligence X API key",
            description: "Used by intelx_native_sync.py. Falls back to INTELX_API_KEY if set on the host process.",
            env_fallback: Some("INTELX_API_KEY"),
        },
        IngestionSecretSlotMeta {
            service: config_manager::KEYRING_RANSOMWARE_LIVE,
            label: "Ransomware.live PRO API key",
            description: "Victims / press ingest into ransomware_events via bundled main.py.",
            env_fallback: None,
        },
        IngestionSecretSlotMeta {
            service: config_manager::KEYRING_MAC_RUMARK_COOKIE,
            label: "RUMARK session cookie",
            description: "Optional default session cookie for MAC Stealer when the inline field is left blank.",
            env_fallback: None,
        },
        IngestionSecretSlotMeta {
            service: config_manager::KEYRING_EASM_SHODAN,
            label: "Shodan API key",
            description: "DNS / host recon for EASM passive scans (invoke_easm_scan).",
            env_fallback: None,
        },
        IngestionSecretSlotMeta {
            service: config_manager::KEYRING_EASM_PENTEST_TOOLS,
            label: "Pentest-Tools API token",
            description: "Bearer token for Pentest-Tools subdomain finder (EASM pipeline).",
            env_fallback: None,
        },
    ]
}

#[tauri::command]
fn get_ingestion_secret_statuses() -> Result<HashMap<String, bool>, String> {
    let mut m = HashMap::new();
    for svc in [
        config_manager::KEYRING_INTELX_API_KEY,
        config_manager::KEYRING_RANSOMWARE_LIVE,
        config_manager::KEYRING_MAC_RUMARK_COOKIE,
        config_manager::KEYRING_EASM_SHODAN,
        config_manager::KEYRING_EASM_PENTEST_TOOLS,
    ] {
        let ok = config_manager::get_api_key(svc)
            .filter(|s| !s.trim().is_empty())
            .is_some();
        m.insert(svc.to_string(), ok);
    }
    Ok(m)
}

#[tauri::command]
fn save_ingestion_secret(service: String, secret: String) -> Result<(), String> {
    let svc = config_manager::normalize_ingestion_keyring_service(&service)?;
    config_manager::save_api_key(svc, secret.trim()).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_ingestion_secret(service: String) -> Result<(), String> {
    let svc = config_manager::normalize_ingestion_keyring_service(&service)?;
    config_manager::delete_api_key(svc).map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunCveSyncPayload {
    action: String,
    start_date: Option<String>,
    end_date: Option<String>,
    vendor: Option<String>,
}

/// CVE_Project_NVD `main.py`: `--action download|update|search` (search ingests into `cve_data` via `CTI_DB_PATH`).
#[tauri::command]
fn run_cve_sync(app: AppHandle, payload: RunCveSyncPayload) -> Result<String, String> {
    let action = payload.action.trim().to_lowercase();
    if !matches!(action.as_str(), "download" | "update" | "search") {
        return Err(format!(
            "action must be download, update, or search; got `{}`",
            payload.action
        ));
    }
    let mut args = vec!["--action".to_string(), action.clone()];
    if action == "search" {
        let sd = payload.start_date.as_deref().unwrap_or("").trim();
        let ed = payload.end_date.as_deref().unwrap_or("").trim();
        let vendor = payload.vendor.as_deref().unwrap_or("").trim();
        if sd.is_empty() || ed.is_empty() || vendor.is_empty() {
            return Err(
                "search requires startDate, endDate, and vendor (use '*' for all vendors)".into(),
            );
        }
        args.extend([
            "--start-date".into(),
            sd.to_string(),
            "--end-date".into(),
            ed.to_string(),
            "--vendor".into(),
            vendor.to_string(),
        ]);
    }
    let _ = cti_config::init_if_needed(&app)?;
    vault_pool::execute_sidecar(app, "CVE_Project_NVD", "main.py", args)
}

fn log_client_vault_hint(label: &str, hint: &Option<String>, canonical: &Path) {
    if let Some(s) = hint.as_ref().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        log::debug!(
            "{} client vault hint `{}` (canonical host path `{}`)",
            label,
            s,
            canonical.display()
        );
    }
}

/// Pull PRO ransomware victim data into the vault (requires keyring `ransomware_live` and vault DB).
#[tauri::command]
async fn invoke_ransomware_live_sync(
    app: AppHandle,
    payload: RansomwareLiveSyncPayload,
) -> Result<String, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let vault_path = vault_db::get_vault_path();
    log_client_vault_hint(
        "invoke_ransomware_live_sync",
        &payload.vault_db_absolute_path,
        &vault_path,
    );
    let vault = vault_path.to_string_lossy();
    let prev = std::env::var("CTI_DB_PATH").ok();
    std::env::set_var("CTI_DB_PATH", vault.as_ref());
    let out = ingestion::ransomware_live::fetch_ransomware_events(
        payload.start_date.trim(),
        payload.end_date.trim(),
    )
        .await
        .map(|_| "Ransomware.live sync completed.".into())
        .map_err(|e| e.to_string());
    restore_cti_db_env(prev);
    out
}

/// External attack surface scan into `asm_assets` (DNS/TLS/API-derived); requires vault path via config (`CTI_DB_PATH` during run).
#[tauri::command]
async fn invoke_easm_scan(app: AppHandle, payload: EasmScanPayload) -> Result<usize, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let vault_path = vault_db::get_vault_path();
    log_client_vault_hint("invoke_easm_scan", &payload.vault_db_absolute_path, &vault_path);
    let vault = vault_path.to_string_lossy();
    let prev = std::env::var("CTI_DB_PATH").ok();
    std::env::set_var("CTI_DB_PATH", vault.as_ref());
    let out = ingestion::easm_scanner::run_easm_scan(payload.domain.trim())
        .await
        .map_err(|e| e.to_string());
    restore_cti_db_env(prev);
    out
}

/// Download the NVD modified CVE JSON ZIP into `workspace_path/CVE_Project_NVD/`, then stream-ingest into `cve_data`.
#[tauri::command]
async fn invoke_cve_nvd_update(app: AppHandle, payload: CveNvdUpdatePayload) -> Result<CveNvdUpdateResult, String> {
    let _ = cti_config::init_if_needed(&app)?;
    let vault_path = vault_db::get_vault_path();
    log_client_vault_hint(
        "invoke_cve_nvd_update",
        &payload.vault_db_absolute_path,
        &vault_path,
    );
    let vault = vault_path.to_string_lossy();
    let prev = std::env::var("CTI_DB_PATH").ok();
    std::env::set_var("CTI_DB_PATH", vault.as_ref());
    log::info!(
        "CVE NVD update: using CTI_DB_PATH={} for stream ingest (ZIP under workspace)",
        vault_path.display()
    );
    let result = async {
        let wp = Path::new(payload.workspace_path.trim());
        if wp.as_os_str().is_empty() {
            return Err("workspace_path is empty".into());
        }
        let cve_dir = wp.join("CVE_Project_NVD");
        fs::create_dir_all(&cve_dir).map_err(|e| e.to_string())?;
        let out_zip = cve_dir.join("nvdcve-2.0-modified.json.zip");
        let url = payload
            .feed_url
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| DEFAULT_NVD_MODIFIED_FEED_ZIP.to_string());
        let window = app.get_webview_window("main");
        ingestion::cve_downloader::download_cve_feed_with_window(&url, &out_zip, window.as_ref())
            .await
            .map_err(|e| e.to_string())?;
        let n = ingestion::cve_downloader::process_cve_zip(&out_zip)
            .await
            .map_err(|e| e.to_string())?;
        Ok(CveNvdUpdateResult {
            zip_path: out_zip.to_string_lossy().into_owned(),
            cve_rows_upserted: n,
        })
    }
    .await;
    restore_cti_db_env(prev);
    if let Ok(ref ok) = result {
        let _ = app.emit(
            "vault-updated",
            serde_json::json!({
                "kind": "cve_nvd",
                "cveRowsUpserted": ok.cve_rows_upserted,
            }),
        );
    }
    result
}

/// Fetch MAC / RUMARK-style stealer logs into `ioc_records`. The cookie is used only for this request
/// and is not written to disk by this command (callers must not persist it in local storage).
#[tauri::command]
async fn invoke_mac_stealer_fetch(app: AppHandle, payload: MacStealerFetchPayload) -> Result<String, String> {
    if payload.domains.trim().is_empty() {
        return Err("domains is empty".into());
    }
    let _ = cti_config::init_if_needed(&app)?;
    let db = vault_db::get_vault_path();
    log_client_vault_hint(
        "invoke_mac_stealer_fetch",
        &payload.vault_db_absolute_path,
        &db,
    );
    vault_db::initialize_vault(&db)?;
    ingestion::mac_stealer::fetch_mac_logs(&payload.cookie, vec![payload.domains], Some(db.as_path()))
        .await
        .map_err(|e| e.to_string())?;
    Ok("MAC stealer fetch completed.".into())
}

/// Scan ``asm_assets`` + ``cve_data``, match CPE bases / keywords, upsert ``asset_cve_mapping``.
#[tauri::command]
async fn run_asset_cve_correlation(_workspace_path: String) -> Result<usize, String> {
    let db = vault_db::get_vault_path();
    vault_db::initialize_vault(&db)?;
    cpe_matcher::run_cpe_matching_background(&db).await
}

#[tauri::command]
fn validate_features_bundle(app: AppHandle) -> Result<Vec<ProjectStatus>, String> {
    let scripts = cti_config::resolve_bundled_scripts_dir(&app)?;
    let folders = [
        "Intelx_Crawler",
        "CVE_Project_NVD",
        "ASM-fetch-main",
        "Ransomware_live_event_victim",
        "Phishing_and_Social_Media_All-in-one",
        "Social_MediaV2",
        "IOCs-crawler-main",
        "Compromised_user_Mac",
    ];
    let mut out = Vec::new();
    for name in folders {
        out.push(ProjectStatus {
            name: name.to_string(),
            exists: scripts.join(name).is_dir(),
        });
    }
    Ok(out)
}

#[tauri::command]
async fn start_background_scheduler(
    state: State<'_, SchedulerState>,
    workspace_path: String,
) -> Result<(), String> {
    let mut sched_opt = state.0.lock().await;

    if let Some(_old_sched) = sched_opt.take() {
        // Old scheduler dropped
    }

    let sched = JobScheduler::new().await.map_err(|e| e.to_string())?;

    let wp1 = workspace_path.clone();
    let cve_job = Job::new_async("0 0 0,12 * * * *", move |_uuid, mut _l| {
        let wp = wp1.clone();
        Box::pin(async move {
            let project_dir = Path::new(&wp).join("CVE_Project_NVD");
            let py = project_python_interpreter(&project_dir);
            if let Ok(mut child) = Command::new(py)
                .arg("main.py")
                .current_dir(project_dir)
                .spawn()
            {
                let _ = child.wait().await;
            }
        })
    }).map_err(|e| e.to_string())?;
    sched.add(cve_job).await.map_err(|e| e.to_string())?;

    let wp2 = workspace_path.clone();
    let ioc_job = Job::new_async("0 0/15 * * * * *", move |_uuid, mut _l| {
        let wp = wp2.clone();
        Box::pin(async move {
            let project_dir = Path::new(&wp).join("IOCs-crawler-main");
            let py = project_python_interpreter(&project_dir);
            if let Ok(mut child) = Command::new(py)
                .arg("news_job.py")
                .current_dir(project_dir)
                .spawn()
            {
                let _ = child.wait().await;
            }
        })
    }).map_err(|e| e.to_string())?;
    sched.add(ioc_job).await.map_err(|e| e.to_string())?;

    let cpe_job = Job::new_async("0 0 3 * * * *", move |_uuid, mut _l| {
        Box::pin(async move {
            let db = vault_db::get_vault_path();
            if let Err(e) = vault_db::initialize_vault(&db) {
                log::warn!("Background CPE match: vault init failed: {}", e);
                return;
            }
            match cpe_matcher::run_cpe_matching_background(&db).await {
                Ok(n) => log::info!("Background CPE match: {} new mapping(s)", n),
                Err(e) => log::warn!("Background CPE match failed: {}", e),
            }
        })
    })
    .map_err(|e| e.to_string())?;
    sched.add(cpe_job).await.map_err(|e| e.to_string())?;

    sched.start().await.map_err(|e| e.to_string())?;
    *sched_opt = Some(sched);

    Ok(())
}

/// Headless vault ingestion for cron / automation (no Tauri window, no Python).
///
/// Resolves the database path from ``vault``, ``CTI_DB_PATH``, or [`vault_db::get_vault_path`] (app data `cti-app/` + `cti_vault.db`, or legacy layout via env).
pub fn run_headless_cli(
    ingest_iocs: Option<&std::path::Path>,
    ingest_assets: Option<&std::path::Path>,
    vault: Option<&std::path::Path>,
) -> Result<String, String> {
    vault_db::install_canonical_cti_env();
    let db_path = vault
        .map(|p| p.to_path_buf())
        .or_else(|| {
            std::env::var("CTI_DB_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(vault_db::get_vault_path);

    let vec_dir = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("vector_vault");
    std::fs::create_dir_all(&vec_dir).map_err(|e| e.to_string())?;
    vector_db::init_local_vector_store(vec_dir.join("vectors.sqlite"))?;

    let mut parts: Vec<String> = Vec::new();
    if let Some(p) = ingest_iocs {
        let n = vault_ingest::ingest_iocs_from_csv(&db_path, p)?;
        parts.push(format!("ingest-iocs: {} row(s) from {}", n, p.display()));
    }
    if let Some(p) = ingest_assets {
        let n = vault_ingest::ingest_asm_assets_from_csv(&db_path, p)?;
        parts.push(format!("ingest-assets: {} row(s) from {}", n, p.display()));
    }
    if parts.is_empty() {
        return Err("No ingestion operation requested.".into());
    }
    Ok(parts.join("\n"))
}

#[tauri::command]
fn enqueue_ioc_crawler_task(
    queue: State<'_, workers::ioc_crawler::IocCrawlerQueue>,
    workspace_path: String,
    kind: Option<String>,
) -> Result<(), String> {
    let wp = workspace_path.trim().to_string();
    if wp.is_empty() {
        return Err("workspace_path is empty".into());
    }
    let k = kind
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("elastic_security_labs");
    let task = if k.eq_ignore_ascii_case("elastic")
        || k.eq_ignore_ascii_case("elastic_security_labs")
    {
        workers::ioc_crawler::IocCrawlerTask::ElasticSecurityLabs {
            workspace_path: wp,
        }
    } else {
        workers::ioc_crawler::IocCrawlerTask::Custom {
            label: k.to_string(),
            workspace_path: wp,
        }
    };
    queue.try_enqueue(task)
}

/// Install absolute `CTI_DB_PATH` / `CTI_COMMAND_CENTER_HOME` before GUI or CLI (call from `main.rs`).
pub fn install_cti_paths_early() {
    vault_db::install_canonical_cti_env();
}

/// CLI **`cleanup --force`**: wipe vault, vector DB, logs, and local config (see [`vault_db::wipe_local_cti_application_state`]).
pub fn run_cleanup_cli(force: bool) -> Result<(), String> {
    if !force {
        return Err(
            "Refusing to delete data: this removes the CTI vault, WAL files, vector embeddings DB, log files, config.json, and store.json.\n\
             To confirm, run:  cti-command-center cleanup --force"
                .into(),
        );
    }
    vault_db::wipe_local_cti_application_state()
}

/// GUI launch options (e.g. from CLI in `main.rs`).
#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    /// When true, [`AppState::is_dino_mode`] starts enabled (purple Barney persona + optional UI tint).
    pub dino_mode: bool,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    run_with_options(RunOptions::default());
}

pub fn run_with_options(opts: RunOptions) {
    install_cti_paths_early();
    tauri::Builder::default()
        .manage(AppState::new(opts.dino_mode))
        .manage(SchedulerState(Arc::new(Mutex::new(None))))
        .manage(NativeIngestCronState(Arc::new(Mutex::new(None))))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .setup(|app| {
            if let Err(e) = vault_db::configure_canonical_paths_from_app(app.handle()) {
                log::error!("canonical vault paths (app_data_dir): {}", e);
                eprintln!("canonical vault paths (app_data_dir): {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e).into());
            }
            match crate::init_db() {
                Ok(pool) => {
                    app.manage(pool);
                }
                Err(e) => {
                    log::error!("vault SQLite pool init failed: {}", e);
                    eprintln!("vault SQLite pool init failed: {}", e);
                }
            }
            if let Err(e) = logging::init_app_log_forwarder(app.handle().clone()) {
                eprintln!("logging::init_app_log_forwarder: {}", e);
            }
            if let Err(e) = (|| -> Result<(), String> {
                let root = cti_config::ensure_writable_tree(app.handle())?;
                let dir = root.join("vector_vault");
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                vector_db::init_local_vector_store(dir.join("vectors.sqlite"))
            })() {
                log::error!("vector_db init: {}", e);
            }
            let q = workers::ioc_crawler::start_ioc_crawler_worker(app.handle().clone());
            app.manage(q);
            let handle = app.handle().clone();
            let cron = app.state::<NativeIngestCronState>().0.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = workers::scheduler::start_native_ingest_cron(handle, cron).await {
                    log::error!("native ingest cron failed to start: {}", e);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            validate_workspace,
            validate_features_bundle,
            get_dashboard_metrics,
            get_vault_stats,
            get_recent_cves_for_pulse,
            get_recent_iocs_for_pulse,
            get_barney_environmental_context,
            get_hunter_alert_notification,
            invoke_mac_stealer_fetch,
            invoke_ransomware_live_sync,
            invoke_easm_scan,
            invoke_cve_nvd_update,
            search_vault,
            get_pivot_graph,
            run_project_script,
            run_feature_v2,
            cti_bootstrap,
            resolve_feature_path,
            feature_status,
            bootstrap_feature_venv,
            bootstrap_all_feature_venvs,
            ingest_cve_vault,
            ingest_asm_vault,
            ingest_iocs_vault,
            run_news_crawler,
            ingest_csv_vault,
            run_intelx,
            run_mac_stealer,
            run_ransomware_sync,
            run_cve_sync,
            list_ingestion_secret_slots,
            get_ingestion_secret_statuses,
            save_ingestion_secret,
            clear_ingestion_secret,
            run_asset_cve_correlation,
            start_background_scheduler,
            llm_proxy::invoke_local_llm,
            vector_db::semantic_threat_search,
            enqueue_ioc_crawler_task
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::fs;
use serde::{Deserialize, Serialize};
use rusqlite::types::ValueRef;
use serde_json::{Map, Value};
use tauri::{AppHandle, Emitter, State};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_cron_scheduler::{Job, JobScheduler};
use std::sync::Arc;
use tokio::sync::Mutex;

mod vault_db;
mod vault_ingest;
mod cti_config;

struct SchedulerState(Arc<Mutex<Option<JobScheduler>>>);

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

fn parse_dotenv_file(path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let content = std::fs::read_to_string(path).unwrap_or_default();
    for raw in content.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.is_empty() {
            continue;
        }
        let mut val = v.trim().to_string();
        if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val = val[1..val.len() - 1].to_string();
        }
        out.insert(key.to_string(), val);
    }
    out
}

fn resolve_rethinkdb_host_port(workspace_path: &str) -> (Option<String>, Option<String>) {
    let wp = Path::new(workspace_path);
    let mut dotenv = HashMap::<String, String>::new();
    let ws_env = wp.join(".env");
    if ws_env.is_file() {
        dotenv.extend(parse_dotenv_file(&ws_env));
    }
    let proj_env = wp.join("IOCs-crawler-main").join(".env");
    if proj_env.is_file() {
        dotenv.extend(parse_dotenv_file(&proj_env));
    }

    let get = |k: &str| {
        std::env::var(k)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                dotenv
                    .get(k)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
    };

    let host = get("RTK_HOST")
        .or_else(|| get("RETHINKDB_HOST"))
        .or_else(|| get("RETHINKDB_HOSTNAME"));
    let port = get("RTK_PORT").or_else(|| get("RETHINKDB_PORT"));
    (host, port)
}

/// RethinkDB → SQLite for IOCs-crawler-main (`export_iocs_to_cti_vault.py`).
fn run_iocs_export_to_vault(
    app: &AppHandle,
    workspace_path: &str,
    iocs_project_dir: &Path,
) -> Result<usize, String> {
    let export_py = iocs_project_dir.join("export_iocs_to_cti_vault.py");
    let py = cti_config::python_for_feature_layout(
        iocs_project_dir,
        Path::new(workspace_path),
        "IOCs-crawler-main",
    );
    if !export_py.is_file() {
        return Err("export_iocs_to_cti_vault.py not found in IOCs-crawler-main.".into());
    }
    let (host, port) = resolve_rethinkdb_host_port(workspace_path);
    let mut cmd = std::process::Command::new(&py);
    cmd.current_dir(iocs_project_dir)
        .env("CTI_WORKSPACE_PATH", workspace_path)
        .arg(&export_py);
    inject_cti_env_std(&mut cmd, app);
    if let Some(h) = host {
        cmd.env("RTK_HOST", h);
    }
    if let Some(p) = port {
        cmd.env("RTK_PORT", p);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        // export_iocs_to_cti_vault.py already prints operator hints on stderr; avoid duplicating them here.
        return Err(format!(
            "IOC vault export failed (exit {}): {}\n{}",
            out.status,
            stderr.trim(),
            stdout.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("INGESTED:") {
            let n = rest
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("Bad INGESTED line: {}", line))?;
            let _ = refresh_ioc_records_from_news(app);
            return Ok(n);
        }
    }
    let _ = refresh_ioc_records_from_news(app);
    Ok(0)
}

fn refresh_ioc_records_from_news(app: &AppHandle) -> Result<usize, String> {
    let cfg = cti_config::load_config(app)?;
    let p = cfg.vault_db_path.trim();
    if p.is_empty() {
        return Ok(0);
    }
    let conn = vault_db::open_vault(Path::new(p))?;
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
    if let Ok(cfg) = cti_config::load_config(app) {
        let p = cfg.vault_db_path.trim();
        if !p.is_empty() {
            cmd.env("CTI_DB_PATH", p);
        }
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
    if let Ok(cfg) = cti_config::load_config(app) {
        let p = cfg.vault_db_path.trim();
        if !p.is_empty() {
            cmd.env("CTI_DB_PATH", p);
        }
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
    let project_dir = scripts_parent.join(&project_name);
    if !project_dir.is_dir() {
        return Err(format!(
            "Project directory does not exist: {}",
            project_dir.display()
        ));
    }

    // Intelx_Crawler: bacongris uses Docker Compose (see workflow_runner.py), not run.sh.
    if project_name == "Intelx_Crawler" {
        let run_sh = project_dir.join("run.sh");
        if !run_sh.is_file() {
            if find_compose_file(&project_dir).is_none() {
                return Err(
                    "Intelx_Crawler has no run.sh and no docker-compose / compose file.".into(),
                );
            }
            let query = intelx_query
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "IntelX needs a search query (email/domain). Pass intelxQuery from the UI."
                        .to_string()
                })?;
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
                        "→ docker compose run --rm -i -T {} (piped stdin: query + start + end + limit; cwd={})",
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
        if let Some(d) = rumark_domains
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd.env("RUMARK_DOMAINS", d);
        }
        if let Some(c) = rumark_cookie
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd.env("RUMARK_COOKIE", c);
        }
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
                            "Vault: upserted {} IOC news row(s) into cti_vault.ioc_news; ioc_records refreshed from news",
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
                            "Vault IOC sync skipped or failed (need RethinkDB + data; or run ingest_iocs_vault later): {}",
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

#[tauri::command]
fn query_db(workspace_path: String, query: String) -> Result<Vec<Value>, String> {
    let db_path = if workspace_path.trim_end().ends_with(".db") {
        PathBuf::from(workspace_path.trim())
    } else {
        Path::new(&workspace_path).join("cti_vault.db")
    };
    let conn = vault_db::open_vault(&db_path).map_err(|e| e.to_string())?;
    
    let mut stmt = conn.prepare(&query).map_err(|e| e.to_string())?;
    
    let column_names: Vec<String> = stmt.column_names().into_iter().map(|s| s.to_string()).collect();
    
    let rows = stmt.query_map([], |row| {
        let mut map = Map::new();
        for (i, col_name) in column_names.iter().enumerate() {
            let value = match row.get_ref(i).unwrap_or(ValueRef::Null) {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(i) => Value::Number(i.into()),
                ValueRef::Real(f) => serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null),
                ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Blob(b) => Value::String(String::from_utf8_lossy(b).into_owned()),
            };
            map.insert(col_name.clone(), value);
        }
        Ok(Value::Object(map))
    }).map_err(|e| e.to_string())?;
    
    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| e.to_string())?);
    }
    
    Ok(results)
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

/// RethinkDB `BW_crawler.news` → `ioc_news` then Rust backfills `ioc_records` (see IOCs-crawler-main/export_iocs_to_cti_vault.py).
#[tauri::command]
fn ingest_iocs_vault(app: AppHandle, workspace_path: String) -> Result<usize, String> {
    let legacy = Path::new(&workspace_path).join("IOCs-crawler-main");
    let iocs = if legacy.is_dir() {
        legacy
    } else {
        cti_config::resolve_feature_dir(&app, "IOCs-crawler-main")?
    };
    let n = run_iocs_export_to_vault(&app, &workspace_path, &iocs)?;
    let _ = refresh_ioc_records_from_news(&app);
    Ok(n)
}

#[tauri::command]
fn query_vault(app: AppHandle, query: String) -> Result<Vec<Value>, String> {
    let cfg = cti_config::load_config(&app)?;
    let p = cfg.vault_db_path.trim();
    if p.is_empty() {
        return Err("Configure vault_db_path via cti_bootstrap / config.json first.".into());
    }
    query_db(p.to_string(), query)
}

#[tauri::command]
fn cti_bootstrap(app: AppHandle) -> Result<Value, String> {
    let cfg = cti_config::init_if_needed(&app)?;
    let root = cti_config::writable_cti_root(&app)?;
    let scripts = cti_config::resolve_bundled_scripts_dir(&app)
        .map(|p| Value::String(p.to_string_lossy().into_owned()))
        .unwrap_or(Value::Null);
    Ok(serde_json::json!({
        "writableRoot": root.to_string_lossy(),
        "vaultDbPath": cfg.vault_db_path,
        "scriptsRoot": scripts,
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

    sched.start().await.map_err(|e| e.to_string())?;
    *sched_opt = Some(sched);

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(SchedulerState(Arc::new(Mutex::new(None))))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            validate_workspace,
            validate_features_bundle,
            query_db,
            query_vault,
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
            ingest_csv_vault,
            start_background_scheduler
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

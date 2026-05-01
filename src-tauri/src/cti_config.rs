//! Writable AppData layout + bundled `Resource/scripts` resolution.
//! See `resources/scripts/README.txt` for packaging.
//!
//! **Python “sidecar”:** The app does not ship an embedded CPython binary. Feature venvs are
//! created with the host `python3` / `python` (`python -m venv`), then `pip install -r` from each
//! bundled project. To ship a fully portable runtime later, replace the venv bootstrap with a
//! downloaded embeddable Python layout and set `CTI_PYTHON_HOME` (future hook).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::path::BaseDirectory;
use tauri::AppHandle;
use tauri::Manager;

pub const CONFIG_FILENAME: &str = "config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CtiAppConfig {
    /// Absolute path to SQLite vault (cti_vault.db).
    pub vault_db_path: String,
    /// Dev-only: absolute path to a folder containing the 8 project dirs (All_Scripts layout).
    pub resource_scripts_fallback: Option<String>,
}

impl Default for CtiAppConfig {
    fn default() -> Self {
        Self {
            vault_db_path: String::new(),
            resource_scripts_fallback: None,
        }
    }
}

/// `%APPDATA%/…/cti-app` style root (actually `app_data_dir()/cti-app`).
pub fn writable_cti_root(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app.path().app_data_dir().map_err(|e| e.to_string())?;
    Ok(base.join("cti-app"))
}

pub fn ensure_writable_tree(app: &AppHandle) -> Result<PathBuf, String> {
    let root = writable_cti_root(app)?;
    for sub in ["python_env", "exports", "logs", "work"] {
        fs::create_dir_all(root.join(sub)).map_err(|e| e.to_string())?;
    }
    Ok(root)
}

pub fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(writable_cti_root(app)?.join(CONFIG_FILENAME))
}

pub fn load_config(app: &AppHandle) -> Result<CtiAppConfig, String> {
    let p = config_path(app)?;
    if !p.is_file() {
        return Ok(CtiAppConfig::default());
    }
    let s = fs::read_to_string(&p).map_err(|e| e.to_string())?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

pub fn save_config(app: &AppHandle, cfg: &CtiAppConfig) -> Result<(), String> {
    let p = config_path(app)?;
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let s = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&p, s).map_err(|e| e.to_string())
}

/// Creates `cti-app/`, subdirs, default `config.json` with vault path.
pub fn init_if_needed(app: &AppHandle) -> Result<CtiAppConfig, String> {
    let root = ensure_writable_tree(app)?;
    let mut cfg = load_config(app)?;
    let mut changed = false;
    if cfg.vault_db_path.trim().is_empty() {
        cfg.vault_db_path = root.join("cti_vault.db").to_string_lossy().to_string();
        changed = true;
    }
    if changed {
        save_config(app, &cfg)?;
    }
    Ok(cfg)
}

/// Resolve bundled `scripts/` (Resource). Uses `resource_scripts_fallback` from config when set and valid.
pub fn resolve_bundled_scripts_dir(app: &AppHandle) -> Result<PathBuf, String> {
    if let Ok(cfg) = load_config(app) {
        if let Some(ref fb) = cfg.resource_scripts_fallback {
            let p = Path::new(fb.trim());
            if p.is_dir() {
                return Ok(p.to_path_buf());
            }
        }
    }
    app.path()
        .resolve("scripts", BaseDirectory::Resource)
        .map_err(|e| format!("Resource scripts not found (dev: set resourceScriptsFallback in config or add bundle resources): {}", e))
}

pub fn resolve_feature_dir(app: &AppHandle, feature_name: &str) -> Result<PathBuf, String> {
    let scripts = resolve_bundled_scripts_dir(app)?;
    let p = scripts.join(feature_name);
    if !p.is_dir() {
        return Err(format!(
            "Feature {:?} not found under {} (copy All_Scripts project folders into src-tauri/resources/scripts/ for dev)",
            feature_name,
            scripts.display()
        ));
    }
    Ok(p)
}

/// Venv root: `{writable}/python_env/{feature}/` (contains `bin/python` or `Scripts/python.exe`).
pub fn feature_venv_root(writable: &Path, feature: &str) -> PathBuf {
    writable.join("python_env").join(feature)
}

pub fn venv_python_executable(venv_root: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        venv_root.join("Scripts").join("python.exe")
    }
    #[cfg(not(windows))]
    {
        venv_root.join("bin").join("python")
    }
}

pub fn feature_has_ready_venv(writable: &Path, feature: &str) -> bool {
    venv_python_executable(&feature_venv_root(writable, feature)).is_file()
}

pub fn bundled_requirements_path(app: &AppHandle, feature: &str) -> Result<PathBuf, String> {
    let req = resolve_feature_dir(app, feature)?.join("requirements.txt");
    if !req.is_file() {
        return Err(format!("Bundled {} has no requirements.txt", feature));
    }
    Ok(req)
}

/// Create feature venv under writable + `pip install -r` bundled requirements.
pub fn bootstrap_feature_venv(app: &AppHandle, feature: &str) -> Result<String, String> {
    let _ = ensure_writable_tree(app)?;
    let vroot = feature_venv_root(&writable_cti_root(app)?, feature);
    let py = venv_python_executable(&vroot);
    if !py.is_file() {
        let py_launcher = if cfg!(windows) { "python" } else { "python3" };
        let status = std::process::Command::new(py_launcher)
            .args(["-m", "venv"])
            .arg(&vroot)
            .status()
            .map_err(|e| format!("{} -m venv failed: {} (install Python 3)", py_launcher, e))?;
        if !status.success() {
            return Err("venv creation exited with error".into());
        }
    }
    let req = bundled_requirements_path(app, feature)?;
    let status = std::process::Command::new(&py)
        .args(["-m", "pip", "install", "-r"])
        .arg(&req)
        .status()
        .map_err(|e| format!("pip install: {}", e))?;
    if !status.success() {
        return Err("pip install failed".into());
    }
    Ok(format!("venv ready at {}", vroot.display()))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureStatusPayload {
    pub feature_name: String,
    pub script_dir_exists: bool,
    pub venv_ready: bool,
    pub requirements_present: bool,
}

pub fn feature_status(app: &AppHandle, feature_name: &str) -> Result<FeatureStatusPayload, String> {
    let writable = writable_cti_root(app)?;
    let script_dir = resolve_bundled_scripts_dir(app)
        .ok()
        .map(|s| s.join(feature_name))
        .filter(|p| p.is_dir());
    let script_dir_exists = script_dir.is_some();
    let requirements_present = script_dir
        .as_ref()
        .map(|p| p.join("requirements.txt").is_file())
        .unwrap_or(false);
    let venv_ready = feature_has_ready_venv(&writable, feature_name);
    Ok(FeatureStatusPayload {
        feature_name: feature_name.to_string(),
        script_dir_exists,
        venv_ready,
        requirements_present,
    })
}

/// Python interpreter: AppData venv if present, else project-local `.venv` (legacy / dev copy).
pub fn python_for_feature_layout(
    script_project_dir: &Path,
    data_workspace: &Path,
    project_name: &str,
) -> PathBuf {
    let appvenv = venv_python_executable(&feature_venv_root(data_workspace, project_name));
    if appvenv.is_file() {
        return appvenv;
    }
    #[cfg(windows)]
    let candidates = [
        script_project_dir
            .join(".venv")
            .join("Scripts")
            .join("python.exe"),
        script_project_dir
            .join("venv")
            .join("Scripts")
            .join("python.exe"),
    ];
    #[cfg(not(windows))]
    let candidates = [
        script_project_dir.join(".venv").join("bin").join("python"),
        script_project_dir.join("venv").join("bin").join("python"),
    ];
    for c in candidates {
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from(if cfg!(windows) { "python" } else { "python3" })
}

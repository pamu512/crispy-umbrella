//! Native ingest cron (replaces Celery Beat for these paths). Uses `tokio-cron-scheduler` on the
//! Tauri Tokio runtime.

use std::sync::Arc;

use tauri::AppHandle;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job, JobScheduler};

use crate::cti_config;
use crate::ingestion;
use crate::vault_db;

/// Same feed URL as `invoke_cve_nvd_update` when `feed_url` is omitted.
const DEFAULT_NVD_MODIFIED_FEED_ZIP: &str =
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip";

/// Seven-field schedule: second minute hour day-of-month month day-of-week year (UTC).
const CRON_DAILY_MIDNIGHT_UTC: &str = "0 0 0 * * * *";
/// Every Monday 03:00 UTC — NVD modified ZIP download + vault ingest.
const CRON_WEEKLY_CVE_MONDAY_UTC: &str = "0 0 3 * * 1 *";

fn format_utc_ymd(d: time::Date) -> String {
    let fmt = time::format_description::parse("[year]-[month]-[day]")
        .expect("static YYYY-MM-DD format");
    d.format(&fmt)
        .unwrap_or_else(|_| d.to_string())
}

async fn run_ransomware_nightly(app: &AppHandle) {
    if let Err(e) = cti_config::init_if_needed(app) {
        log::warn!("native ingest cron: ransomware skipped (config): {}", e);
        return;
    }
    let vault_path = vault_db::get_vault_path();
    let vault = vault_path.to_string_lossy();
    let today = OffsetDateTime::now_utc().date();
    let yesterday = today.saturating_sub(TimeDuration::days(1));
    let start = format_utc_ymd(yesterday);
    let end = start.clone();

    let prev = std::env::var("CTI_DB_PATH").ok();
    std::env::set_var("CTI_DB_PATH", vault.as_ref());
    match ingestion::ransomware_live::fetch_ransomware_events(&start, &end).await {
        Ok(()) => log::info!(
            "native ingest cron: ransomware.live sync {}..{} completed",
            start,
            end
        ),
        Err(e) => log::warn!("native ingest cron: ransomware.live sync failed: {}", e),
    }
    crate::restore_cti_db_env(prev);
}

async fn run_cve_weekly(app: &AppHandle) {
    if let Err(e) = cti_config::init_if_needed(app) {
        log::warn!("native ingest cron: CVE job skipped (config): {}", e);
        return;
    }
    let vault_path = vault_db::get_vault_path();
    let vault = vault_path.to_string_lossy();
    let Some(ws_root) = vault_path.parent() else {
        log::warn!("native ingest cron: CVE job skipped (vault path has no parent)");
        return;
    };
    let cve_dir = ws_root.join("CVE_Project_NVD");
    if let Err(e) = std::fs::create_dir_all(&cve_dir) {
        log::warn!("native ingest cron: CVE mkdir: {}", e);
        return;
    }
    let out_zip = cve_dir.join("nvdcve-2.0-modified.json.zip");

    let prev = std::env::var("CTI_DB_PATH").ok();
    std::env::set_var("CTI_DB_PATH", vault.as_ref());
    let result = async {
        ingestion::cve_downloader::download_cve_feed(DEFAULT_NVD_MODIFIED_FEED_ZIP, &out_zip)
            .await
            .map_err(|e| e.to_string())?;
        ingestion::cve_downloader::process_cve_zip(&out_zip)
            .await
            .map_err(|e| e.to_string())
    }
    .await;
    crate::restore_cti_db_env(prev);

    match result {
        Ok(n) => log::info!(
            "native ingest cron: CVE modified feed ingested ({} row(s))",
            n
        ),
        Err(e) => log::warn!("native ingest cron: CVE update failed: {}", e),
    }
}

/// Build cron jobs, start the scheduler, and store it in `state` so it stays alive for the app lifetime.
pub async fn start_native_ingest_cron(
    app: AppHandle,
    state: Arc<Mutex<Option<JobScheduler>>>,
) -> Result<(), String> {
    let mut sched_opt = state.lock().await;
    if sched_opt.is_some() {
        return Ok(());
    }

    let sched = JobScheduler::new().await.map_err(|e| e.to_string())?;

    let app_r = app.clone();
    let job_r = Job::new_async(CRON_DAILY_MIDNIGHT_UTC, move |_uuid, mut _l| {
        let a = app_r.clone();
        Box::pin(async move {
            run_ransomware_nightly(&a).await;
        })
    })
    .map_err(|e| e.to_string())?;
    sched.add(job_r).await.map_err(|e| e.to_string())?;

    let app_c = app.clone();
    let job_c = Job::new_async(CRON_WEEKLY_CVE_MONDAY_UTC, move |_uuid, mut _l| {
        let a = app_c.clone();
        Box::pin(async move {
            run_cve_weekly(&a).await;
        })
    })
    .map_err(|e| e.to_string())?;
    sched.add(job_c).await.map_err(|e| e.to_string())?;

    sched.start().await.map_err(|e| e.to_string())?;
    *sched_opt = Some(sched);
    Ok(())
}

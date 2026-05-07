//! Internal debug dashboard: structured snapshot + ``cti::status`` log line (like ``/status``).

use serde::Serialize;
use tauri::State;

use crate::vault_pool::{VaultPool, VaultPoolDebugSnapshot};
use crate::vector_db;
use crate::workers::ioc_crawler::{self, IocCrawlerMetrics};

/// Aggregated runtime counters for observability (IPC + internal logs).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalDebugStatus {
    pub vault_pool: VaultPoolDebugSnapshot,
    pub ioc_crawler: IocCrawlerMetrics,
    pub vector_store_initialized: bool,
    pub vector_store_path: Option<String>,
}

pub fn build_internal_debug_status(pool: &VaultPool) -> InternalDebugStatus {
    InternalDebugStatus {
        vault_pool: pool.debug_snapshot(),
        ioc_crawler: ioc_crawler::ioc_crawler_metrics(),
        vector_store_initialized: vector_db::vector_store_initialized_for_debug(),
        vector_store_path: vector_db::vector_store_absolute_path_for_debug(),
    }
}

/// Returns the snapshot and writes one JSON line to the **`cti::status`** log target (filterable like ``/status``).
#[tauri::command]
pub async fn get_internal_debug_status(pool: State<'_, VaultPool>) -> Result<InternalDebugStatus, String> {
    let snapshot = build_internal_debug_status(&pool);
    let line = serde_json::to_string(&snapshot).map_err(|e| e.to_string())?;
    log::info!(target: "cti::status", "/status {}", line);
    Ok(snapshot)
}

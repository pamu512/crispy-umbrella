//! Forwards Rust [`log`] records to the WebView via [`Emitter::emit`] on channel **`app-log`**.
//!
//! Ingestion and other backend code should prefer `log::info!`, `log::warn!`, etc. The `log` crate
//! does not intercept `println!`; for ad-hoc lines use [`emit_line`] when you hold an [`AppHandle`].
//!
//! Initialize once from Tauri **`setup`** with [`init_app_log_forwarder`].

use log::{LevelFilter, Metadata, Record, SetLoggerError};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const EVENT: &str = "app-log";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLogPayload {
    pub level: String,
    pub target: String,
    pub message: String,
    pub timestamp: String,
}

fn format_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new())
}

/// Forward a line as **INFO** with target **`stdout`** (closest analogue to `println!` for the UI).
#[allow(dead_code)]
pub fn emit_line(app: &AppHandle, message: impl Into<String>) {
    let payload = AppLogPayload {
        level: "INFO".into(),
        target: "stdout".into(),
        message: message.into(),
        timestamp: format_timestamp(),
    };
    let _ = app.emit(EVENT, &payload);
}

struct AppLogForwarder {
    app: AppHandle,
}

impl log::Log for AppLogForwarder {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let payload = AppLogPayload {
            level: record.level().as_str().to_string(),
            target: record.target().to_string(),
            message: format!("{}", record.args()),
            timestamp: format_timestamp(),
        };
        let _ = self.app.emit(EVENT, &payload);
    }

    fn flush(&self) {}
}

/// Registers the global logger so every `log::info!` / `log::warn!` / … is mirrored to **`app-log`**.
///
/// Fails if another logger was already installed (e.g. a second init or another crate calling
/// `log::set_logger` first).
pub fn init_app_log_forwarder(app: AppHandle) -> Result<(), SetLoggerError> {
    let forwarder = AppLogForwarder { app };
    log::set_boxed_logger(Box::new(forwarder))?;
    log::set_max_level(LevelFilter::Debug);
    Ok(())
}

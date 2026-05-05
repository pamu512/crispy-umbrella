//! Secure storage for third-party API keys using the host OS credential manager.
//!
//! - **macOS:** Keychain (generic passwords)
//! - **Windows:** Credential Manager
//! - **Linux:** Secret Service (e.g. GNOME Keyring / KWallet), when available
//!
//! Secrets are **not** written to `.env`, JSON, or other plaintext files by this module.
//!
//! # Usage
//!
//! Choose a stable, unique `service` identifier per integration (e.g. `ransomware_live_my_api_key`).
//! The same string must be passed to [`get_api_key`] to retrieve the value.

use std::fmt;

use keyring::Entry;
use keyring::Error as KeyringError;

/// Application-wide keychain “service” label so credentials are grouped under one product name.
const KEYRING_SERVICE: &str = "CTI-Command-Center";

/// Reasonable upper bound for `service` labels (platform stores may impose their own limits).
const MAX_SERVICE_LEN: usize = 256;

/// Upper bound for secret length (avoids accidental huge payloads).
const MAX_KEY_LEN: usize = 16_384;

// ---------------------------------------------------------------------------
// Stable keychain user-name labels (must match existing ingests / EASM scanner).
// ---------------------------------------------------------------------------

/// Intelligence X API key (`INTELX_API_KEY` when passed to subprocesses).
pub const KEYRING_INTELX_API_KEY: &str = "intelx_api_key";
/// Ransomware.live PRO API (Python `main.py` and keyring-only Rust path).
pub const KEYRING_RANSOMWARE_LIVE: &str = "ransomware_live";
/// RUMARK session cookie for MAC stealer (`Compromised_user_Mac/main.py`).
pub const KEYRING_MAC_RUMARK_COOKIE: &str = "mac_stealer_rumark_cookie";
/// Shodan API key for EASM / `easm_scanner`.
pub const KEYRING_EASM_SHODAN: &str = "easm_shodan";
/// Pentest-Tools API bearer token for EASM subdomain discovery.
pub const KEYRING_EASM_PENTEST_TOOLS: &str = "easm_pentest_tools";

/// Normalize UI / IPC input to a trusted keyring slot id (prevents arbitrary keychain writes).
pub fn normalize_ingestion_keyring_service(user_input: &str) -> Result<&'static str, String> {
    match user_input.trim() {
        s if s == KEYRING_INTELX_API_KEY => Ok(KEYRING_INTELX_API_KEY),
        s if s == KEYRING_RANSOMWARE_LIVE => Ok(KEYRING_RANSOMWARE_LIVE),
        s if s == KEYRING_MAC_RUMARK_COOKIE => Ok(KEYRING_MAC_RUMARK_COOKIE),
        s if s == KEYRING_EASM_SHODAN => Ok(KEYRING_EASM_SHODAN),
        s if s == KEYRING_EASM_PENTEST_TOOLS => Ok(KEYRING_EASM_PENTEST_TOOLS),
        other => Err(format!(
            "unknown ingestion credential slot `{}`",
            other
        )),
    }
}

/// Errors returned by [`save_api_key`] (retrieval uses [`get_api_key`] and surfaces failures as `None`).
#[derive(Debug)]
pub enum SaveApiKeyError {
    InvalidService(&'static str),
    InvalidKey(&'static str),
    Keyring(String),
}

impl fmt::Display for SaveApiKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaveApiKeyError::InvalidService(s) => write!(f, "{}", s),
            SaveApiKeyError::InvalidKey(s) => write!(f, "{}", s),
            SaveApiKeyError::Keyring(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for SaveApiKeyError {}

impl From<keyring::Error> for SaveApiKeyError {
    fn from(e: keyring::Error) -> Self {
        SaveApiKeyError::Keyring(e.to_string())
    }
}

fn validate_service(service: &str) -> Result<&str, SaveApiKeyError> {
    let s = service.trim();
    if s.is_empty() {
        return Err(SaveApiKeyError::InvalidService(
            "`service` must not be empty",
        ));
    }
    if s.len() > MAX_SERVICE_LEN {
        return Err(SaveApiKeyError::InvalidService(
            "`service` exceeds maximum length",
        ));
    }
    Ok(s)
}

fn validate_key(key: &str) -> Result<&str, SaveApiKeyError> {
    if key.len() > MAX_KEY_LEN {
        return Err(SaveApiKeyError::InvalidKey(
            "API key exceeds maximum length",
        ));
    }
    Ok(key)
}

/// Stores `key` in the OS credential manager under the given logical `service` name.
///
/// Overwrites any existing secret for the same `service`. Does not write to disk files.
pub fn save_api_key(service: &str, key: &str) -> Result<(), SaveApiKeyError> {
    let service = validate_service(service)?;
    validate_key(key)?;
    let entry = Entry::new(KEYRING_SERVICE, service)?;
    entry.set_password(key)?;
    Ok(())
}

/// Returns the API key for `service`, or `None` if missing or if the OS store cannot be read.
///
/// Any error (including “no password saved”) is collapsed to `None` so callers can fall back
/// to other configuration without panicking.
pub fn get_api_key(service: &str) -> Option<String> {
    let service = service.trim();
    if service.is_empty() || service.len() > MAX_SERVICE_LEN {
        return None;
    }
    let entry = Entry::new(KEYRING_SERVICE, service).ok()?;
    entry.get_password().ok()
}

/// Removes the credential if present; succeeds when nothing was stored (`NoEntry`).
pub fn delete_api_key(service: &str) -> Result<(), SaveApiKeyError> {
    let service = validate_service(service)?;
    let entry = Entry::new(KEYRING_SERVICE, service)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(KeyringError::NoEntry) => Ok(()),
        Err(e) => Err(SaveApiKeyError::Keyring(e.to_string())),
    }
}

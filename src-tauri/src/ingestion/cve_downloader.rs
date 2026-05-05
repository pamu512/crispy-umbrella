//! Large-file CVE / NVD feed downloads using **reqwest** streaming with resume-capable retries.
//!
//! Progress is emitted through [`tauri::Emitter`] (e.g. [`tauri::WebviewWindow`]) as JSON-friendly payloads
//! suitable for a frontend progress bar.
//!
//! [`process_cve_zip`] reads **`.json`** members from a downloaded NVD-style ZIP **in memory**
//! (no extracted JSON files on disk) and upserts rows into **`cve_data`**.

use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use rusqlite::params;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde::Serialize;
use serde_json::{json, Value};
use tauri::{Emitter, Runtime, WebviewWindow};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use zip::ZipArchive;

use crate::vault_db::{self, time_now_iso};

/// Event name for byte-level progress (allowed Tauri event characters: alphanumeric, `-`, `/`, `_`, `:`).
pub const EVENT_CVE_FEED_DOWNLOAD_PROGRESS: &str = "cve-feed-download-progress";

/// Emitted when the Tor SOCKS5h proxy at `127.0.0.1:9050` is not usable and download continues over direct HTTPS.
pub const EVENT_CVE_FEED_TOR_UNAVAILABLE: &str = "cve-feed-tor-unavailable";

/// Payload emitted while downloading (clone + serialize for [`Emitter::emit`]).
#[derive(Clone, Serialize)]
pub struct CveFeedDownloadProgress {
    pub url: String,
    pub output_path: String,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub phase: &'static str,
}

#[derive(Debug)]
pub enum CveDownloadError {
    InvalidUrl(String),
    Http(String),
    Io(String),
    ExhaustedRetries,
    Zip(String),
    Json(String),
    MissingVaultPath(String),
    Vault(String),
}

impl std::fmt::Display for CveDownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveDownloadError::InvalidUrl(s) => write!(f, "{}", s),
            CveDownloadError::Http(s) => write!(f, "{}", s),
            CveDownloadError::Io(s) => write!(f, "{}", s),
            CveDownloadError::ExhaustedRetries => write!(f, "download exhausted retries"),
            CveDownloadError::Zip(s) => write!(f, "{}", s),
            CveDownloadError::Json(s) => write!(f, "{}", s),
            CveDownloadError::MissingVaultPath(s) => write!(f, "{}", s),
            CveDownloadError::Vault(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for CveDownloadError {}

const USER_AGENT: &str = "Mozilla/5.0 (compatible; CTI-CVE-Downloader/1.0; +https://example.invalid)";
const CONNECTION_MAX_ATTEMPTS: u32 = 12;
const CHUNK_STREAM_ERROR_RETRIES: u32 = 6;
const EMIT_PROGRESS_EVERY_BYTES: u64 = 256 * 1024;

fn partial_download_path(output_path: &Path) -> PathBuf {
    let mut p = output_path.as_os_str().to_owned();
    p.push(".part");
    PathBuf::from(p)
}

fn emit_progress<R: Runtime>(
    window: Option<&WebviewWindow<R>>,
    payload: CveFeedDownloadProgress,
) {
    if let Some(w) = window {
        let _ = w.emit(EVENT_CVE_FEED_DOWNLOAD_PROGRESS, payload);
    }
}

fn emit_tor_fallback_warning<R: Runtime>(window: Option<&WebviewWindow<R>>) {
    let message = format!(
        "Tor SOCKS5h proxy socks5h://127.0.0.1:9050 not reachable; continuing CVE feed download without Tor (direct HTTPS)."
    );
    if let Some(w) = window {
        let _ = w.emit(
            EVENT_CVE_FEED_TOR_UNAVAILABLE,
            json!({
                "message": message.clone(),
                "proxy": "socks5h://127.0.0.1:9050",
            }),
        );
    }
    log::warn!("{}", message);
}

/// Direct HTTPS client for CVE feeds (no proxy). Used when Tor is unavailable or fails to build.
fn build_cve_feed_reqwest_client_direct() -> Result<reqwest::Client, CveDownloadError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(45))
        .timeout(Duration::from_secs(86400 * 7))
        .build()
        .map_err(|e| CveDownloadError::Http(format!("reqwest direct client: {}", e)))
}

/// SOCKS5h client via local Tor (`socks5h://127.0.0.1:9050`) for CVE feed downloads.
fn build_cve_feed_reqwest_client_tor_socks5h() -> Result<reqwest::Client, CveDownloadError> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(45))
        .timeout(Duration::from_secs(86400 * 7))
        .proxy(
            reqwest::Proxy::all("socks5h://127.0.0.1:9050")
                .map_err(|e| CveDownloadError::Http(format!("Tor SOCKS5h proxy: {}", e)))?,
        )
        .build()
        .map_err(|e| CveDownloadError::Http(format!("reqwest Tor client: {}", e)))
}

/// Prefer SOCKS5h over Tor at `127.0.0.1:9050`; fall back to direct HTTPS if the client build or route probe fails.
async fn select_cve_feed_http_client<R: Runtime>(
    feed_url: &str,
    window: Option<&WebviewWindow<R>>,
) -> Result<reqwest::Client, CveDownloadError> {
    let tor_client = match build_cve_feed_reqwest_client_tor_socks5h() {
        Ok(c) => c,
        Err(e) => {
            log::warn!("CVE feed Tor client build failed: {}", e);
            emit_tor_fallback_warning(window);
            return build_cve_feed_reqwest_client_direct();
        }
    };

    let probe_ok = match tor_client
        .get(feed_url)
        .header(RANGE, "bytes=0-0")
        .timeout(Duration::from_secs(20))
        .send()
        .await
    {
        Ok(resp) => resp.bytes().await.is_ok(),
        Err(_) => false,
    };

    if !probe_ok {
        emit_tor_fallback_warning(window);
        return build_cve_feed_reqwest_client_direct();
    }

    Ok(tor_client)
}

/// Parse total entity length from `Content-Range` (`bytes a-b/total` or `bytes */total`).
fn total_from_content_range(cr: &str) -> Option<u64> {
    let rest = cr.strip_prefix("bytes ")?.trim();
    let (_, total_part) = rest.rsplit_once('/')?;
    if total_part == "*" {
        None
    } else {
        total_part.parse().ok()
    }
}

fn infer_total_bytes(
    headers: &reqwest::header::HeaderMap,
    status: reqwest::StatusCode,
    downloaded_before: u64,
) -> Option<u64> {
    if let Some(cr) = headers.get(CONTENT_RANGE).and_then(|h| h.to_str().ok()) {
        if let Some(t) = total_from_content_range(cr) {
            return Some(t);
        }
    }
    if let Some(len) = headers.get(CONTENT_LENGTH).and_then(|h| h.to_str().ok()) {
        let n: u64 = len.parse().ok()?;
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            return Some(downloaded_before.saturating_add(n));
        }
        if status == reqwest::StatusCode::OK {
            return Some(n);
        }
    }
    None
}

/// Download a CVE/NVD feed to disk with chunked streaming and automatic retries (no UI events).
///
/// For progress events on the frontend, use [`download_cve_feed_with_window`].
pub async fn download_cve_feed(feed_url: &str, output_path: &Path) -> Result<(), CveDownloadError> {
    download_cve_feed_with_window::<tauri::Wry>(feed_url, output_path, None).await
}

/// Same as [`download_cve_feed`], but emits [`EVENT_CVE_FEED_DOWNLOAD_PROGRESS`] through
/// [`Emitter`] when `window` is `Some`.
pub async fn download_cve_feed_with_window<R: Runtime>(
    feed_url: &str,
    output_path: &Path,
    window: Option<&WebviewWindow<R>>,
) -> Result<(), CveDownloadError> {
    let url = feed_url.trim();
    if url.is_empty() || !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(CveDownloadError::InvalidUrl(
            "feed_url must be a non-empty http(s) URL".into(),
        ));
    }

    let part_path = partial_download_path(output_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|e| CveDownloadError::Io(e.to_string()))?;
    }

    let mut downloaded: u64 = if part_path.is_file() {
        fs::metadata(&part_path)
            .await
            .map_err(|e| CveDownloadError::Io(e.to_string()))?
            .len()
    } else {
        0
    };

    let client = select_cve_feed_http_client(url, window).await?;

    let url_owned = url.to_string();
    let out_display = output_path.display().to_string();

    let mut total_hint: Option<u64> = None;
    let mut connection_attempt: u32 = 0;

    emit_progress(
        window,
        CveFeedDownloadProgress {
            url: url_owned.clone(),
            output_path: out_display.clone(),
            downloaded_bytes: downloaded,
            total_bytes: total_hint,
            phase: "starting",
        },
    );

    loop {
        connection_attempt += 1;
        if connection_attempt > CONNECTION_MAX_ATTEMPTS {
            return Err(CveDownloadError::ExhaustedRetries);
        }

        let mut req = client.get(url);
        if downloaded > 0 {
            let hv = reqwest::header::HeaderValue::from_str(&format!("bytes={}-", downloaded))
                .map_err(|_| CveDownloadError::Http("invalid Range header value".into()))?;
            req = req.header(RANGE, hv);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                log::warn!(
                    "CVE feed connection attempt {} failed: {}; retrying",
                    connection_attempt,
                    e
                );
                let backoff_ms = (400u64)
                    .saturating_mul(connection_attempt as u64)
                    .min(45_000);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                continue;
            }
        };

        let status = resp.status();
        let headers = resp.headers().clone();

        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            let _ = fs::remove_file(&part_path).await;
            downloaded = 0;
            total_hint = None;
            tokio::time::sleep(Duration::from_millis(300)).await;
            continue;
        }

        if status == reqwest::StatusCode::OK && downloaded > 0 {
            downloaded = 0;
            total_hint = None;
            let _ = fs::remove_file(&part_path).await;
            drop(resp);
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CveDownloadError::Http(format!(
                "HTTP {}: {}",
                status,
                body.chars().take(400).collect::<String>()
            )));
        }

        if total_hint.is_none() {
            total_hint = infer_total_bytes(&headers, status, downloaded);
        }

        emit_progress(
            window,
            CveFeedDownloadProgress {
                url: url_owned.clone(),
                output_path: out_display.clone(),
                downloaded_bytes: downloaded,
                total_bytes: total_hint,
                phase: "downloading",
            },
        );

        let mut file = if downloaded == 0 {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&part_path)
                .await
                .map_err(|e| CveDownloadError::Io(e.to_string()))?
        } else {
            OpenOptions::new()
                .write(true)
                .read(true)
                .open(&part_path)
                .await
                .map_err(|e| CveDownloadError::Io(e.to_string()))?
        };

        if downloaded > 0 {
            file
                .seek(std::io::SeekFrom::Start(downloaded))
                .await
                .map_err(|e| CveDownloadError::Io(e.to_string()))?;
        }

        let mut stream = resp.bytes_stream();
        let mut bytes_since_emit: u64 = 0;
        let mut stream_error_streak: u32 = 0;
        let mut stream_broken = false;

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    stream_error_streak = 0;
                    if chunk.is_empty() {
                        continue;
                    }
                    file
                        .write_all(&chunk)
                        .await
                        .map_err(|e| CveDownloadError::Io(e.to_string()))?;
                    downloaded = downloaded.saturating_add(chunk.len() as u64);
                    bytes_since_emit = bytes_since_emit.saturating_add(chunk.len() as u64);

                    if bytes_since_emit >= EMIT_PROGRESS_EVERY_BYTES {
                        bytes_since_emit = 0;
                        emit_progress(
                            window,
                            CveFeedDownloadProgress {
                                url: url_owned.clone(),
                                output_path: out_display.clone(),
                                downloaded_bytes: downloaded,
                                total_bytes: total_hint,
                                phase: "downloading",
                            },
                        );
                    }
                }
                Err(e) => {
                    stream_error_streak += 1;
                    log::warn!(
                        "CVE feed chunk stream error (retry {}/{}): {}",
                        stream_error_streak,
                        CHUNK_STREAM_ERROR_RETRIES,
                        e
                    );
                    if stream_error_streak >= CHUNK_STREAM_ERROR_RETRIES {
                        downloaded = fs::metadata(&part_path)
                            .await
                            .map_err(|err| CveDownloadError::Io(err.to_string()))?
                            .len();
                        let backoff_ms = (300u64)
                            .saturating_mul(stream_error_streak as u64)
                            .min(30_000);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        stream_broken = true;
                        break;
                    }
                    let backoff_ms = (150u64).saturating_mul(1u64 << stream_error_streak.min(10));
                    tokio::time::sleep(Duration::from_millis(backoff_ms.min(10_000))).await;
                }
            }
        }

        if stream_broken {
            continue;
        }

        if bytes_since_emit > 0 {
            emit_progress(
                window,
                CveFeedDownloadProgress {
                    url: url_owned.clone(),
                    output_path: out_display.clone(),
                    downloaded_bytes: downloaded,
                    total_bytes: total_hint,
                    phase: "downloading",
                },
            );
        }

        file.flush()
            .await
            .map_err(|e| CveDownloadError::Io(e.to_string()))?;
        file.sync_all()
            .await
            .map_err(|e| CveDownloadError::Io(e.to_string()))?;
        drop(file);

        break;
    }

    emit_progress(
        window,
        CveFeedDownloadProgress {
            url: url_owned.clone(),
            output_path: out_display.clone(),
            downloaded_bytes: downloaded,
            total_bytes: total_hint,
            phase: "finalizing",
        },
    );

    if output_path.exists() {
        fs::remove_file(output_path)
            .await
            .map_err(|e| CveDownloadError::Io(e.to_string()))?;
    }
    fs::rename(&part_path, output_path)
        .await
        .map_err(|e| CveDownloadError::Io(e.to_string()))?;

    emit_progress(
        window,
        CveFeedDownloadProgress {
            url: url_owned,
            output_path: out_display,
            downloaded_bytes: downloaded,
            total_bytes: total_hint,
            phase: "complete",
        },
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// In-ZIP NVD JSON → cve_data (streaming `serde_json::Deserializer::from_reader`)
// ---------------------------------------------------------------------------

fn resolve_cti_db_path_for_ingest() -> Result<PathBuf, CveDownloadError> {
    Ok(crate::vault_db::get_vault_path())
}

fn nvd_description_cve(cve: &Value) -> String {
    if let Some(arr) = cve.get("descriptions").and_then(|d| d.as_array()) {
        for d in arr {
            if d.get("lang").and_then(|l| l.as_str()) == Some("en") {
                if let Some(v) = d.get("value").and_then(|x| x.as_str()) {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

fn pick_cvss_base(metrics: &Value, key: &str) -> Option<f64> {
    let arr = metrics.get(key)?.as_array()?;
    let first = arr.first()?;
    let data = first.get("cvssData")?;
    data.get("baseScore")?.as_f64()
}

fn nvd_cvss_base_score(cve: &Value) -> Option<f64> {
    let metrics = cve.get("metrics")?;
    pick_cvss_base(metrics, "cvssMetricV31")
        .or_else(|| pick_cvss_base(metrics, "cvssMetricV30"))
        .or_else(|| pick_cvss_base(metrics, "cvssMetricV40"))
}

fn nvd_cwes(cve: &Value) -> Value {
    cve.get("weaknesses").cloned().unwrap_or(Value::Null)
}

fn nvd_refs(cve: &Value) -> Value {
    cve.get("references").cloned().unwrap_or(Value::Null)
}

fn legacy_description(cve: &Value) -> String {
    if let Some(arr) = cve
        .get("description")
        .and_then(|d| d.get("description_data"))
        .and_then(|d| d.as_array())
    {
        for d in arr {
            if d.get("lang").and_then(|l| l.as_str()) == Some("en") {
                if let Some(v) = d.get("value").and_then(|x| x.as_str()) {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

/// Upsert one NVD 2.0 `vulnerabilities[]` element (`{"cve":{...}}`) or legacy `CVE_Items[]` shape.
fn upsert_nvd_json_item(
    stmt: &mut rusqlite::CachedStatement<'_>,
    now: &str,
    item: &Value,
) -> Result<bool, String> {
    let Some(cve) = item.get("cve") else {
        return Ok(false);
    };

    if let Some(cve_id) = cve.get("id").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let published = cve
            .get("published")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let last_mod = cve
            .get("lastModified")
            .and_then(|v| v.as_str())
            .unwrap_or(&published)
            .to_string();
        let description = nvd_description_cve(cve);
        let severity = nvd_cvss_base_score(cve);
        let meta = json!({
            "description": description,
            "cwe": nvd_cwes(cve),
            "references": nvd_refs(cve),
            "raw_metrics": cve.get("metrics").cloned().unwrap_or(Value::Null),
        })
        .to_string();
        stmt.execute(params![cve_id, severity, published, last_mod, meta])
            .map_err(|e| e.to_string())?;
        return Ok(true);
    }

    if let Some(cve_id) = cve
        .get("CVE_data_meta")
        .and_then(|m| m.get("ID"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let mut published = cve
            .get("publishedDate")
            .or_else(|| cve.get("lastModifiedDate"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if published.is_empty() {
            published = now.to_string();
        }
        let last_mod = cve
            .get("lastModifiedDate")
            .and_then(|v| v.as_str())
            .unwrap_or(published.as_str())
            .to_string();
        let description = legacy_description(cve);
        let meta = json!({
            "description": description,
            "format": "nvd_1.1_cve_item",
        })
        .to_string();
        stmt.execute(params![cve_id, None::<f64>, published, last_mod, meta])
            .map_err(|e| e.to_string())?;
        return Ok(true);
    }

    Ok(false)
}

struct NvdRootConsumer<'a, F: FnMut(Value) -> Result<(), String>> {
    f: &'a mut F,
}

impl<'de, 'a, F> Visitor<'de> for NvdRootConsumer<'a, F>
where
    F: FnMut(Value) -> Result<(), String>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("NVD JSON root object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "vulnerabilities" | "CVE_Items" => {
                    map.next_value_seed(VulnerabilitiesArraySeed { f: self.f })?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct VulnerabilitiesArraySeed<'a, F: FnMut(Value) -> Result<(), String>> {
    f: &'a mut F,
}

impl<'de, 'a, F> DeserializeSeed<'de> for VulnerabilitiesArraySeed<'a, F>
where
    F: FnMut(Value) -> Result<(), String>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(VulnerabilitiesSeqVisitor { f: self.f })
    }
}

struct VulnerabilitiesSeqVisitor<'a, F: FnMut(Value) -> Result<(), String>> {
    f: &'a mut F,
}

impl<'de, 'a, F> Visitor<'de> for VulnerabilitiesSeqVisitor<'a, F>
where
    F: FnMut(Value) -> Result<(), String>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("NVD vulnerabilities or CVE_Items array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(elem) = seq.next_element::<Value>()? {
            (self.f)(elem).map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

/// Stream-parse one feed JSON from `reader` (ZIP entry or file) and upsert into `cve_data`.
///
/// Uses [`serde_json::Deserializer::from_reader`] so the parser does not build a full in-memory
/// `Value` tree for the outer `vulnerabilities` / `CVE_Items` array—only **one CVE object at a
/// time** is allocated as `Value`.
fn ingest_nvd_json_streaming<R: Read>(
    reader: R,
    conn: &rusqlite::Connection,
) -> Result<usize, CveDownloadError> {
    let now = time_now_iso();
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CveDownloadError::Vault(e.to_string()))?;
    let inserted = std::cell::RefCell::new(0usize);
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(cve_id) DO UPDATE SET
                   severity_score = excluded.severity_score,
                   published_date = excluded.published_date,
                   updated_at = excluded.updated_at,
                   metadata = excluded.metadata",
            )
            .map_err(|e| CveDownloadError::Vault(e.to_string()))?;

        let mut on_item = |v: Value| -> Result<(), String> {
            if upsert_nvd_json_item(&mut stmt, &now, &v)? {
                *inserted.borrow_mut() += 1;
            }
            Ok(())
        };
        let visitor = NvdRootConsumer { f: &mut on_item };
        let mut de = serde_json::Deserializer::from_reader(reader);
        de.deserialize_any(visitor)
            .map_err(|e| CveDownloadError::Json(e.to_string()))?;
    }
    tx.commit()
        .map_err(|e| CveDownloadError::Vault(e.to_string()))?;
    Ok(inserted.into_inner())
}

fn process_cve_zip_blocking(zip_path: &Path, db_path: &Path) -> Result<usize, CveDownloadError> {
    let file = File::open(zip_path).map_err(|e| CveDownloadError::Io(e.to_string()))?;
    let mut archive =
        ZipArchive::new(file).map_err(|e| CveDownloadError::Zip(format!("open zip: {}", e)))?;
    let conn = vault_db::open_vault(db_path).map_err(|e| CveDownloadError::Vault(e.to_string()))?;
    let mut total = 0usize;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| CveDownloadError::Zip(format!("zip index {}: {}", i, e)))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if name.contains("__MACOSX") {
            continue;
        }
        if !name.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        let br = BufReader::with_capacity(512 * 1024, &mut entry);
        match ingest_nvd_json_streaming(br, &conn) {
            Ok(n) => {
                total = total.saturating_add(n);
                log::info!("CVE ZIP {:?}: ingested {} row(s) from {}", zip_path, n, name);
            }
            Err(e) => {
                log::warn!(
                    "CVE ZIP {:?}: skipped {:?} ({})",
                    zip_path,
                    name,
                    e
                );
            }
        }
    }
    Ok(total)
}

/// Open an NVD/CVE **`.zip`** at `zip_path`, read each **`.json`** member through an in-memory
/// decode path (no extracted JSON files on disk), stream-parse CVE entries with
/// [`serde_json::Deserializer::from_reader`], and bulk-upsert into **`cve_data`**.
///
/// Requires **`CTI_DB_PATH`** pointing at `cti_vault.db`. Heavy work runs on the blocking pool.
pub async fn process_cve_zip(zip_path: &Path) -> Result<usize, CveDownloadError> {
    let db_path = resolve_cti_db_path_for_ingest()?;
    let zip_owned = zip_path.to_path_buf();
    tokio::task::spawn_blocking(move || process_cve_zip_blocking(&zip_owned, &db_path))
        .await
        .map_err(|e| CveDownloadError::Vault(format!("join: {}", e)))?
}

//! File-backed vector store for semantic IOC search — **no external Qdrant**.
//!
//! Storage: ``{writable_cti_root}/vector_vault/vectors.sqlite`` (initialized from Tauri `setup` and
//! headless CLI). Vectors are 768-dim `f32` (little-endian BLOB) aligned with Ollama `nomic-embed-text`.
//!
//! ## Ollama embeddings
//! - **`OLLAMA_HOST`**: HTTP base (default `http://127.0.0.1:11434`).
//! - **`OLLAMA_EMBED_MODEL`**: defaults to `nomic-embed-text` (`/api/embeddings`).

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::AppHandle;

use crate::vault_db;

/// Collection / table name (legacy Qdrant name kept for logs).
pub const THREAT_INTEL_COLLECTION: &str = "threat_intel";

/// Vector size for nomic-embed-text v1 / v1.5.
pub const NOMIC_EMBED_TEXT_DIM: u64 = 768;

pub const OLLAMA_HOST_ENV: &str = "OLLAMA_HOST";
pub const OLLAMA_EMBED_MODEL_ENV: &str = "OLLAMA_EMBED_MODEL";

const SEMANTIC_SEARCH_TOP_K: usize = 5;
const MAX_EMBED_CHARS: usize = 6000;

static VECTOR_STORE_PATH: OnceLock<PathBuf> = OnceLock::new();

/// One IOC row aligned with `ioc_records` (SQLite); `sqlite_rowid` ties the vector to the vault row.
#[derive(Debug, Clone)]
pub struct IOCRecord {
    pub ioc_value: String,
    pub ioc_type: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub source_project: Option<String>,
    pub metadata: Option<String>,
    /// `sqlite` `rowid` after insert/upsert when available.
    pub sqlite_rowid: Option<i64>,
}

#[derive(Debug)]
pub enum VectorDbError {
    Store(String),
    Ollama(String),
    Embed(String),
    Json(String),
    Vault(String),
}

impl fmt::Display for VectorDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VectorDbError::Store(s) => write!(f, "{s}"),
            VectorDbError::Ollama(s) => write!(f, "{s}"),
            VectorDbError::Embed(s) => write!(f, "{s}"),
            VectorDbError::Json(s) => write!(f, "{s}"),
            VectorDbError::Vault(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for VectorDbError {}

/// Initialize the local vector DB path (call once from app `setup` or headless CLI).
pub fn init_local_vector_store(path: PathBuf) -> Result<(), String> {
    if VECTOR_STORE_PATH.get().is_some() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let conn = Connection::open(&path).map_err(|e| e.to_string())?;
    ensure_schema(&conn).map_err(|e| e.to_string())?;
    VECTOR_STORE_PATH
        .set(path)
        .map_err(|_| "local vector store path already initialized".to_string())?;
    Ok(())
}

fn store_path() -> Result<&'static Path, VectorDbError> {
    VECTOR_STORE_PATH
        .get()
        .map(PathBuf::as_path)
        .ok_or_else(|| VectorDbError::Store(
            "vector store not initialized (missing app setup or headless init)".into(),
        ))
}

fn open_store() -> Result<Connection, VectorDbError> {
    let p = store_path()?;
    Connection::open(p).map_err(|e| VectorDbError::Store(e.to_string()))
}

fn ensure_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        r"
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS threat_intel_vectors (
            point_id INTEGER PRIMARY KEY NOT NULL,
            sqlite_rowid INTEGER,
            ioc_value TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            source_project TEXT,
            metadata TEXT,
            embedding_model TEXT,
            vector BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_threat_intel_vectors_row ON threat_intel_vectors(sqlite_rowid);
        ",
    )
}

/// Display string for dashboard (replaces legacy Qdrant URL).
pub fn vector_store_endpoint() -> String {
    store_path()
        .map(|p| format!("local://{}", p.display()))
        .unwrap_or_else(|_| "local://(not initialized)".to_string())
}

pub fn ollama_host_from_env() -> String {
    std::env::var(OLLAMA_HOST_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string())
}

pub fn ollama_embed_model_from_env() -> String {
    std::env::var(OLLAMA_EMBED_MODEL_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "nomic-embed-text".to_string())
}

#[derive(Deserialize)]
struct OllamaEmbeddingsResponse {
    embedding: Vec<f32>,
}

/// POST `{OLLAMA_HOST}/api/embeddings` with `nomic-embed-text` (or `OLLAMA_EMBED_MODEL`).
pub async fn ollama_embed_text(prompt: &str) -> Result<Vec<f32>, VectorDbError> {
    let base = ollama_host_from_env().trim_end_matches('/').to_string();
    let url = format!("{base}/api/embeddings");
    let model = ollama_embed_model_from_env();
    let body = json!({
        "model": model,
        "prompt": prompt,
    });
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| VectorDbError::Ollama(e.to_string()))?;
    let res = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| VectorDbError::Ollama(e.to_string()))?;
    let status = res.status();
    if !status.is_success() {
        let txt = res.text().await.unwrap_or_default();
        return Err(VectorDbError::Ollama(format!(
            "HTTP {status} from Ollama: {}",
            txt.chars().take(500).collect::<String>()
        )));
    }
    let parsed: OllamaEmbeddingsResponse = res
        .json()
        .await
        .map_err(|e| VectorDbError::Json(e.to_string()))?;
    Ok(parsed.embedding)
}

/// Text sent to Ollama: IOC fields + raw metadata JSON (truncated).
pub fn embedding_document(record: &IOCRecord) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("ioc_value: {}", record.ioc_value.trim()));
    parts.push(format!("ioc_type: {}", record.ioc_type.trim()));
    if let Some(fs) = record.first_seen.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("first_seen: {fs}"));
    }
    if let Some(ls) = record.last_seen.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("last_seen: {ls}"));
    }
    if let Some(sp) = record
        .source_project
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        parts.push(format!("source_project: {sp}"));
    }
    if let Some(meta) = record.metadata.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("metadata: {meta}"));
    }
    let mut s = parts.join("\n");
    if s.chars().count() > MAX_EMBED_CHARS {
        s = s.chars().take(MAX_EMBED_CHARS).collect();
    }
    s
}

fn stable_point_id(record: &IOCRecord) -> u64 {
    if let Some(r) = record.sqlite_rowid.filter(|&x| x > 0) {
        return r as u64;
    }
    let mut h = DefaultHasher::new();
    record.ioc_value.hash(&mut h);
    record.ioc_type.hash(&mut h);
    h.finish()
}

fn f32_slice_to_blob(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

fn blob_to_f32_vec(blob: &[u8]) -> Result<Vec<f32>, VectorDbError> {
    if blob.len() % 4 != 0 {
        return Err(VectorDbError::Store(format!(
            "invalid vector blob length {}",
            blob.len()
        )));
    }
    let mut v = Vec::with_capacity(blob.len() / 4);
    for chunk in blob.chunks_exact(4) {
        v.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(v)
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na <= 0.0 || nb <= 0.0 {
        return 0.0;
    }
    dot / (na * nb)
}

/// Ensure the local vectors table exists.
pub async fn ensure_threat_intel_collection() -> Result<(), VectorDbError> {
    tokio::task::spawn_blocking(|| {
        let conn = open_store()?;
        ensure_schema(&conn).map_err(|e| VectorDbError::Store(e.to_string()))
    })
    .await
    .map_err(|e| VectorDbError::Store(e.to_string()))??;
    Ok(())
}

/// Probe local store: open DB, ensure schema, return `(collection_ready, summary)`.
pub async fn vector_db_health_probe() -> Result<(bool, String), VectorDbError> {
    let inner = tokio::task::spawn_blocking(|| {
        let conn = open_store()?;
        ensure_schema(&conn).map_err(|e| VectorDbError::Store(e.to_string()))?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM threat_intel_vectors", [], |r| r.get(0))
            .map_err(|e| VectorDbError::Store(e.to_string()))?;
        let ready = true;
        let msg = if n > 0 {
            format!("CONNECTED (LOCAL) · {n} vector(s) in {THREAT_INTEL_COLLECTION}")
        } else {
            format!("CONNECTED (LOCAL) · ingest IOCs to populate {THREAT_INTEL_COLLECTION}")
        };
        Ok((ready, msg))
    })
    .await
    .map_err(|e| VectorDbError::Store(e.to_string()))?;
    Ok(inner?)
}

/// Embed [`IOCRecord`] via Ollama and upsert into the local vector table.
pub async fn embed_and_store(record: &IOCRecord) -> Result<(), VectorDbError> {
    ensure_threat_intel_collection().await?;

    let doc = embedding_document(record);
    if doc.trim().is_empty() {
        return Err(VectorDbError::Embed(
            "empty embedding document (no IOC fields)".into(),
        ));
    }

    let embedding = ollama_embed_text(&doc).await?;
    if embedding.len() != NOMIC_EMBED_TEXT_DIM as usize {
        return Err(VectorDbError::Embed(format!(
            "expected {} dims from Ollama, got {}",
            NOMIC_EMBED_TEXT_DIM,
            embedding.len()
        )));
    }
    for (i, v) in embedding.iter().enumerate() {
        if !v.is_finite() {
            return Err(VectorDbError::Embed(format!("non-finite value at index {i}")));
        }
    }

    let record = record.clone();
    let blob = f32_slice_to_blob(&embedding);
    let model = ollama_embed_model_from_env();
    let point_id = stable_point_id(&record) as i64;

    tokio::task::spawn_blocking(move || {
        let conn = open_store()?;
        ensure_schema(&conn).map_err(|e| VectorDbError::Store(e.to_string()))?;
        conn.execute(
            r"INSERT OR REPLACE INTO threat_intel_vectors
                (point_id, sqlite_rowid, ioc_value, ioc_type, first_seen, last_seen, source_project, metadata, embedding_model, vector)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                point_id,
                record.sqlite_rowid,
                record.ioc_value,
                record.ioc_type,
                record.first_seen,
                record.last_seen,
                record.source_project,
                record.metadata,
                model,
                blob,
            ],
        )
        .map_err(|e| VectorDbError::Store(e.to_string()))?;
        log::debug!(
            "vector_db: upserted point id={point_id} for IOC {} ({})",
            record.ioc_value,
            record.ioc_type
        );
        Ok::<(), VectorDbError>(())
    })
    .await
    .map_err(|e| VectorDbError::Store(e.to_string()))??;
    Ok(())
}

/// Full `ioc_records` row plus similarity score (camelCase for the frontend).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticThreatHit {
    pub score: f32,
    pub sqlite_rowid: i64,
    pub ioc_value: String,
    pub ioc_type: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub source_project: Option<String>,
    pub metadata: Option<String>,
}

fn fetch_hit_from_vault(
    _app: &AppHandle,
    score: f32,
    sqlite_rowid: Option<i64>,
    ioc_value: &str,
    ioc_type: &str,
) -> Result<Option<SemanticThreatHit>, VectorDbError> {
    let db_path = vault_db::get_vault_path();
    let conn = vault_db::open_vault(&db_path).map_err(VectorDbError::Vault)?;

    if let Some(rid) = sqlite_rowid.filter(|&x| x > 0) {
        let mut stmt = conn
            .prepare(
                "SELECT rowid, ioc_value, ioc_type, first_seen, last_seen, source_project, metadata \
                 FROM ioc_records WHERE rowid = ?1",
            )
            .map_err(|e| VectorDbError::Vault(e.to_string()))?;
        let mut rows = stmt
            .query_map([rid], |row| {
                Ok(SemanticThreatHit {
                    score,
                    sqlite_rowid: row.get(0)?,
                    ioc_value: row.get(1)?,
                    ioc_type: row.get(2)?,
                    first_seen: row.get(3)?,
                    last_seen: row.get(4)?,
                    source_project: row.get(5)?,
                    metadata: row.get(6)?,
                })
            })
            .map_err(|e| VectorDbError::Vault(e.to_string()))?;
        if let Some(r) = rows.next() {
            return Ok(Some(r.map_err(|e| VectorDbError::Vault(e.to_string()))?));
        }
    }

    let mut stmt = conn
        .prepare(
            "SELECT rowid, ioc_value, ioc_type, first_seen, last_seen, source_project, metadata \
             FROM ioc_records WHERE ioc_value = ?1 AND ioc_type = ?2 LIMIT 1",
        )
        .map_err(|e| VectorDbError::Vault(e.to_string()))?;
    let mut rows = stmt
        .query_map(rusqlite::params![ioc_value, ioc_type], |row| {
            Ok(SemanticThreatHit {
                score,
                sqlite_rowid: row.get(0)?,
                ioc_value: row.get(1)?,
                ioc_type: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                source_project: row.get(5)?,
                metadata: row.get(6)?,
            })
        })
        .map_err(|e| VectorDbError::Vault(e.to_string()))?;
    match rows.next() {
        Some(Ok(hit)) => Ok(Some(hit)),
        Some(Err(e)) => Err(VectorDbError::Vault(e.to_string())),
        None => Ok(None),
    }
}

async fn run_semantic_threat_search(app: &AppHandle, query: &str) -> Result<Vec<SemanticThreatHit>, VectorDbError> {
    let embed_input = if query.chars().count() > MAX_EMBED_CHARS {
        query.chars().take(MAX_EMBED_CHARS).collect::<String>()
    } else {
        query.to_string()
    };

    let vector = ollama_embed_text(&embed_input).await?;
    if vector.len() != NOMIC_EMBED_TEXT_DIM as usize {
        return Err(VectorDbError::Embed(format!(
            "expected {} dims from Ollama, got {}",
            NOMIC_EMBED_TEXT_DIM,
            vector.len()
        )));
    }
    for (i, v) in vector.iter().enumerate() {
        if !v.is_finite() {
            return Err(VectorDbError::Embed(format!("non-finite value at index {i}")));
        }
    }

    let scored = tokio::task::spawn_blocking({
        let vector = vector.clone();
        move || -> Result<Vec<(f32, i64, Option<i64>, String, String)>, VectorDbError> {
            let conn = open_store()?;
            ensure_schema(&conn).map_err(|e| VectorDbError::Store(e.to_string()))?;
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM threat_intel_vectors", [], |r| r.get(0))
                .map_err(|e| VectorDbError::Store(e.to_string()))?;
            if n == 0 {
                return Err(VectorDbError::Store(format!(
                    "collection '{THREAT_INTEL_COLLECTION}' is empty; ingest IOCs to build embeddings first"
                )));
            }

            let mut stmt = conn
                .prepare(
                    r"SELECT point_id, sqlite_rowid, ioc_value, ioc_type, vector FROM threat_intel_vectors",
                )
                .map_err(|e| VectorDbError::Store(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    let point_id: i64 = row.get(0)?;
                    let sqlite_rowid: Option<i64> = row.get(1)?;
                    let ioc_value: String = row.get(2)?;
                    let ioc_type: String = row.get(3)?;
                    let blob: Vec<u8> = row.get(4)?;
                    Ok((point_id, sqlite_rowid, ioc_value, ioc_type, blob))
                })
                .map_err(|e| VectorDbError::Store(e.to_string()))?;

            let mut scored: Vec<(f32, i64, Option<i64>, String, String)> = Vec::new();
            for r in rows {
                let (point_id, sqlite_rowid, ioc_value, ioc_type, blob) =
                    r.map_err(|e| VectorDbError::Store(e.to_string()))?;
                let emb = blob_to_f32_vec(&blob)?;
                let s = cosine_similarity(&vector, &emb);
                scored.push((s, point_id, sqlite_rowid, ioc_value, ioc_type));
            }
            scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            scored.truncate(SEMANTIC_SEARCH_TOP_K);
            Ok(scored)
        }
    })
    .await
    .map_err(|e| VectorDbError::Store(e.to_string()))??;

    let mut out: Vec<SemanticThreatHit> = Vec::new();
    for (sim, _point_id, sqlite_rowid, ioc_value, ioc_type) in scored {
        match fetch_hit_from_vault(app, sim, sqlite_rowid, &ioc_value, &ioc_type)? {
            Some(hit) => out.push(hit),
            None => log::debug!(
                "semantic_threat_search: no vault row for local hit ({ioc_value}, {ioc_type})"
            ),
        }
    }
    Ok(out)
}

/// Embed `query` with Ollama, run a top-5 cosine search in the local store, then load matching `ioc_records` from SQLite.
#[tauri::command]
pub async fn semantic_threat_search(app: AppHandle, query: String) -> Result<Vec<SemanticThreatHit>, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err("query must not be empty".into());
    }
    run_semantic_threat_search(&app, trimmed)
        .await
        .map_err(|e| e.to_string())
}

static EMBED_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn embed_runtime() -> &'static tokio::runtime::Runtime {
    EMBED_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("vector-embed")
            .build()
            .expect("vector embed tokio runtime")
    })
}

/// Schedule [`embed_and_store`] without blocking the SQLite ingest path.
pub fn queue_embed_and_store(record: IOCRecord) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            if let Err(e) = embed_and_store(&record).await {
                log::warn!("embed_and_store (spawned on app runtime): {e}");
            }
        });
    } else {
        embed_runtime().spawn(async move {
            if let Err(e) = embed_and_store(&record).await {
                log::warn!("embed_and_store (dedicated runtime): {e}");
            }
        });
    }
}

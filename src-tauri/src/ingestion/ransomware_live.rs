//! Ingest [Ransomware.live](https://www.ransomware.live/) PRO victim data into the CTI vault.
//!
//! Uses the OS keyring entry `ransomware_live` (see [`crate::config_manager::get_api_key`]) for
//! `X-API-KEY`. Date bounds filter the `attackdate` field after fetching per-month slices from
//! `GET /victims/` (year + month, `date=attacked`).
//!
//! Persists into `threat_actor`, `Ransomware_live_event_victim`, and `ioc_records` when a URL or
//! domain IOC can be derived.

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{StatusCode, Url};
use rusqlite::params;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};

use crate::config_manager::{get_api_key, KEYRING_RANSOMWARE_LIVE};
use crate::vault_db::{self, time_now_iso};

const DEFAULT_API_BASE: &str = "https://api-pro.ransomware.live";
const SOURCE_PROJECT: &str = "Ransomware_live_event_victim";
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str =
    "Mozilla/5.0 (compatible; CTI-Command-Center/1.0; +https://example.invalid)";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed failures for UI handling (e.g. prompt for API key when [`RansomwareLiveError::MissingApiKey`]).
#[derive(Debug, Clone)]
pub enum RansomwareLiveError {
    /// No API key in the OS credential store for service id `ransomware_live`.
    MissingApiKey,
    /// `CTI_DB_PATH` is not set or empty.
    MissingVaultPath,
    InvalidDateRange { details: String },
    InvalidHeaderValue { details: String },
    Http { message: String },
    Parse { details: String },
    Vault { details: String },
}

impl fmt::Display for RansomwareLiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RansomwareLiveError::MissingApiKey => write!(
                f,
                "Ransomware.live API key is not configured. Add your PRO API key under the \
                 keyring service id \"ransomware_live\" (e.g. via the app settings flow)."
            ),
            RansomwareLiveError::MissingVaultPath => write!(
                f,
                "CTI_DB_PATH is not set; cannot open cti_vault.db for ransomware ingest."
            ),
            RansomwareLiveError::InvalidDateRange { details } => {
                write!(f, "invalid date range: {}", details)
            }
            RansomwareLiveError::InvalidHeaderValue { details } => {
                write!(f, "invalid HTTP header value: {}", details)
            }
            RansomwareLiveError::Http { message } => write!(f, "{}", message),
            RansomwareLiveError::Parse { details } => write!(f, "{}", details),
            RansomwareLiveError::Vault { details } => write!(f, "{}", details),
        }
    }
}

impl std::error::Error for RansomwareLiveError {}

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

fn parse_calendar_date(raw: &str) -> Result<Date, RansomwareLiveError> {
    let t = raw.trim();
    let no_t = t.split('T').next().map_or(t, |s| s);
    let head = no_t.split_whitespace().next().map_or(no_t, |s| s);
    if head.is_empty() {
        return Err(RansomwareLiveError::InvalidDateRange {
            details: "empty date string".into(),
        });
    }
    Date::parse(head, &time::format_description::parse("[year]-[month]-[day]").map_err(|e| {
        RansomwareLiveError::InvalidDateRange {
            details: format!("internal date format compile error: {}", e),
        }
    })?)
    .map_err(|e| RansomwareLiveError::InvalidDateRange {
        details: format!("expected YYYY-MM-DD (or ISO-8601 prefix), got {:?}: {}", raw, e),
    })
}

fn parse_attack_date(raw: &str) -> Option<Date> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(dt) = OffsetDateTime::parse(t, &Rfc3339) {
        return Some(dt.date());
    }
    parse_calendar_date(t).ok()
}

/// Inclusive calendar months from `start` through `end` (first of month alignment).
fn year_months_in_range(start: Date, end: Date) -> Result<Vec<(i32, u8)>, RansomwareLiveError> {
    if end < start {
        return Err(RansomwareLiveError::InvalidDateRange {
            details: format!("end {} is before start {}", end, start),
        });
    }
    let mut y = start.year();
    let mut m = u8::from(start.month());
    let end_y = end.year();
    let end_m = u8::from(end.month());
    let mut out = Vec::new();
    let mut guard = 0usize;
    loop {
        out.push((y, m));
        if y == end_y && m == end_m {
            break;
        }
        if m == 12 {
            y = y.saturating_add(1);
            m = 1;
        } else {
            m = m.saturating_add(1);
        }
        guard = guard.saturating_add(1);
        if guard > 600 {
            return Err(RansomwareLiveError::InvalidDateRange {
                details: "range spans too many months".into(),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn api_base() -> String {
    std::env::var("RANSOMWARE_LIVE_API_BASE")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE.to_string())
}

fn map_reqwest(err: reqwest::Error) -> RansomwareLiveError {
    if err.is_timeout() {
        RansomwareLiveError::Http {
            message: format!("HTTP timeout: {}", err),
        }
    } else {
        RansomwareLiveError::Http {
            message: err.to_string(),
        }
    }
}

fn build_client() -> Result<reqwest::Client, RansomwareLiveError> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| RansomwareLiveError::Http {
            message: format!("build HTTP client: {}", e),
        })
}

fn victims_url(year: i32, month: u8) -> Result<Url, RansomwareLiveError> {
    let base = api_base();
    let root = base.trim_end_matches('/');
    let endpoint = format!("{}/victims/", root);
    let month_s = format!("{:02}", month);
    let year_s = format!("{}", year);
    Url::parse_with_params(
        &endpoint,
        [
            ("year", year_s.as_str()),
            ("month", month_s.as_str()),
            ("date", "attacked"),
        ],
    )
    .map_err(|e| RansomwareLiveError::Parse {
        details: format!("URL: {}", e),
    })
}

fn extract_victim_array(root: &Value) -> Vec<Value> {
    match root {
        Value::Array(a) => a.clone(),
        Value::Object(map) => {
            for key in ["victims", "data", "results", "items"] {
                if let Some(Value::Array(a)) = map.get(key) {
                    return a.clone();
                }
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

fn json_str(obj: &Value, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| match v {
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

/// Deterministic fingerprint (stable across runs; not cryptographic).
fn djb2_u64(s: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    h
}

fn stable_row_id(victim: &str, group: &str, attack_raw: &str, permalink: &str) -> String {
    let basis = if !permalink.is_empty() {
        permalink.to_string()
    } else {
        format!("{}|{}|{}", victim, group, attack_raw)
    };
    format!("rl{:016x}", djb2_u64(&basis))
}

fn ioc_from_record(obj: &Value) -> Option<(String, String)> {
    let domain = json_str(obj, "domain");
    let permalink = json_str(obj, "url");
    if let Some(d) = domain {
        let d = d.trim();
        if !d.is_empty() {
            let url = if d.contains("://") {
                d.to_string()
            } else {
                format!("https://{}", d)
            };
            return Some((url, "url".into()));
        }
    }
    if let Some(p) = permalink {
        let p = p.trim();
        if !p.is_empty() {
            return Some((p.to_string(), "url".into()));
        }
    }
    None
}

async fn fetch_month_json(
    client: &reqwest::Client,
    api_key: &str,
    year: i32,
    month: u8,
) -> Result<Value, RansomwareLiveError> {
    let url = victims_url(year, month)?;
    let hv = HeaderValue::from_str(api_key.trim()).map_err(|_| RansomwareLiveError::InvalidHeaderValue {
        details: "API key contains characters that are not valid in an HTTP header; remove newlines/control chars."
            .into(),
    })?;
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("x-api-key"),
        hv,
    );

    let resp = client
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(map_reqwest)?;

    if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN {
        return Err(RansomwareLiveError::Http {
            message: format!(
                "HTTP {} — API key rejected or lacks PRO access",
                resp.status()
            ),
        });
    }
    if resp.status() == StatusCode::TOO_MANY_REQUESTS {
        return Err(RansomwareLiveError::Http {
            message: "HTTP 429 — rate limit exceeded; retry later.".into(),
        });
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => format!("<failed to read body: {}>", e),
        };
        return Err(RansomwareLiveError::Http {
            message: format!("HTTP error {}: {}", status, body),
        });
    }

    let text = resp
        .text()
        .await
        .map_err(|e| RansomwareLiveError::Http {
            message: format!("read body: {}", e),
        })?;
    serde_json::from_str(&text).map_err(|e| RansomwareLiveError::Parse {
        details: format!("JSON: {}", e),
    })
}

// ---------------------------------------------------------------------------
// SQLite
// ---------------------------------------------------------------------------

fn sqlite_table_exists(conn: &rusqlite::Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let n: i32 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn ensure_threat_actor_table(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS threat_actor (
            name TEXT PRIMARY KEY NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            metadata TEXT
        );",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn ensure_ransomware_victim_table(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS Ransomware_live_event_victim (
            id TEXT PRIMARY KEY NOT NULL,
            company TEXT NOT NULL,
            group_name TEXT NOT NULL,
            event_date TEXT,
            country TEXT,
            domain TEXT,
            permalink TEXT,
            metadata TEXT
        );",
    )
    .map_err(|e| e.to_string())?;

    if sqlite_table_exists(conn, "Ransomware_live_event_victim").map_err(|e| e.to_string())? {
        let cols = vault_db::column_names(conn, "Ransomware_live_event_victim")?;
        if !cols.iter().any(|c| c == "id") {
            return Err(
                "Existing Ransomware_live_event_victim table has no `id` column; migrate or recreate the vault."
                    .into(),
            );
        }
    }
    Ok(())
}

struct NormalizedVictim {
    id: String,
    company: String,
    group_name: String,
    attack_raw: String,
    attack_date: Option<Date>,
    country: String,
    domain: String,
    permalink: String,
    activity: String,
    description: String,
    row_json: String,
}

fn normalize_victim_value(obj: &Value) -> Option<NormalizedVictim> {
    let group = json_str(obj, "group")?;
    let victim = json_str(obj, "victim").unwrap_or_default();
    if victim.trim().is_empty() {
        return None;
    }
    let attack_raw = json_str(obj, "attackdate").unwrap_or_default();
    let attack_date = parse_attack_date(&attack_raw);
    let permalink = json_str(obj, "url").unwrap_or_default();
    let id = stable_row_id(&victim, &group, &attack_raw, &permalink);
    let row_json = serde_json::to_string(obj).ok()?;
    Some(NormalizedVictim {
        id,
        company: victim,
        group_name: group,
        attack_raw,
        attack_date,
        country: json_str(obj, "country").unwrap_or_default(),
        domain: json_str(obj, "domain").unwrap_or_default(),
        permalink,
        activity: json_str(obj, "activity").unwrap_or_default(),
        description: json_str(obj, "description").unwrap_or_default(),
        row_json,
    })
}

fn date_iso(d: Date) -> String {
    let y = d.year();
    let m = u8::from(d.month());
    let day = d.day();
    format!("{:04}-{:02}-{:02}", y, m, day)
}

fn persist_batch(db_path: &Path, rows: &[NormalizedVictim]) -> Result<(), RansomwareLiveError> {
    let conn = vault_db::open_vault(db_path).map_err(|e| RansomwareLiveError::Vault {
        details: e,
    })?;
    vault_db::ensure_ioc_records(&conn).map_err(|e| RansomwareLiveError::Vault {
        details: e,
    })?;
    ensure_threat_actor_table(&conn).map_err(|e| RansomwareLiveError::Vault { details: e })?;
    ensure_ransomware_victim_table(&conn).map_err(|e| RansomwareLiveError::Vault { details: e })?;

    let now = time_now_iso();
    let today = OffsetDateTime::now_utc().date();
    let mut actor_bounds: HashMap<String, (Date, Date)> = HashMap::new();

    for r in rows {
        let d = r.attack_date.unwrap_or(today);
        actor_bounds
            .entry(r.group_name.clone())
            .and_modify(|(a, b)| {
                *a = cmp::min(*a, d);
                *b = cmp::max(*b, d);
            })
            .or_insert((d, d));
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| RansomwareLiveError::Vault {
            details: e.to_string(),
        })?;

    {
        let mut stmt_actor = tx
            .prepare_cached(
                "INSERT INTO threat_actor (name, first_seen, last_seen, metadata)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(name) DO UPDATE SET
                   first_seen = CASE WHEN excluded.first_seen < threat_actor.first_seen THEN excluded.first_seen ELSE threat_actor.first_seen END,
                   last_seen = CASE WHEN excluded.last_seen > threat_actor.last_seen THEN excluded.last_seen ELSE threat_actor.last_seen END,
                   metadata = COALESCE(excluded.metadata, threat_actor.metadata)",
            )
            .map_err(|e| RansomwareLiveError::Vault {
                details: e.to_string(),
            })?;

        for (name, (first_d, last_d)) in &actor_bounds {
            let first_seen = date_iso(*first_d);
            let last_seen = date_iso(*last_d);
            let meta = json!({ "source": "ransomware_live", "kind": "ransomware_group" }).to_string();
            stmt_actor
                .execute(params![name, first_seen, last_seen, meta])
                .map_err(|e| RansomwareLiveError::Vault {
                    details: e.to_string(),
                })?;
        }
    }

    {
        let mut stmt_v = tx
            .prepare_cached(
                "INSERT INTO Ransomware_live_event_victim
                 (id, company, group_name, event_date, country, domain, permalink, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                   company = excluded.company,
                   group_name = excluded.group_name,
                   event_date = excluded.event_date,
                   country = excluded.country,
                   domain = excluded.domain,
                   permalink = excluded.permalink,
                   metadata = COALESCE(excluded.metadata, Ransomware_live_event_victim.metadata)",
            )
            .map_err(|e| RansomwareLiveError::Vault {
                details: e.to_string(),
            })?;

        for r in rows {
            let raw_val: Value = match serde_json::from_str(&r.row_json) {
                Ok(v) => v,
                Err(_) => Value::String(r.row_json.clone()),
            };
            let meta = json!({
                "threat_actor": r.group_name,
                "activity": r.activity,
                "description": r.description,
                "raw": raw_val,
            })
            .to_string();
            stmt_v
                .execute(params![
                    &r.id,
                    &r.company,
                    &r.group_name,
                    &r.attack_raw,
                    &r.country,
                    &r.domain,
                    &r.permalink,
                    meta,
                ])
                .map_err(|e| RansomwareLiveError::Vault {
                    details: e.to_string(),
                })?;
        }
    }

    {
        let mut stmt_ioc = tx
            .prepare_cached(
                "INSERT INTO ioc_records (ioc_value, ioc_type, first_seen, last_seen, source_project, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   metadata = COALESCE(excluded.metadata, ioc_records.metadata),
                   source_project = CASE
                     WHEN excluded.source_project IS NOT NULL AND TRIM(COALESCE(excluded.source_project, '')) != ''
                     THEN excluded.source_project
                     ELSE ioc_records.source_project
                   END",
            )
            .map_err(|e| RansomwareLiveError::Vault {
                details: e.to_string(),
            })?;

        for r in rows {
            let obj: Value = match serde_json::from_str(&r.row_json) {
                Ok(v) => v,
                Err(_) => Value::Null,
            };
            if let Some((ioc_value, ioc_type)) = ioc_from_record(&obj) {
                let first_seen = r
                    .attack_date
                    .map(date_iso)
                    .filter(|s| !s.is_empty())
                    .map_or_else(|| now.clone(), |s| s);
                let last_seen = first_seen.clone();
                let meta = json!({
                    "threat_actor": r.group_name,
                    "victim": r.company,
                    "country": r.country,
                    "attackdate": r.attack_raw,
                    "permalink": r.permalink,
                    "source": "ransomware_live_api",
                })
                .to_string();
                stmt_ioc
                    .execute(params![
                        ioc_value,
                        ioc_type,
                        first_seen,
                        last_seen,
                        SOURCE_PROJECT,
                        meta,
                    ])
                    .map_err(|e| RansomwareLiveError::Vault {
                        details: e.to_string(),
                    })?;
            }
        }
    }

    tx.commit().map_err(|e| RansomwareLiveError::Vault {
        details: e.to_string(),
    })?;
    Ok(())
}

/// Fetches ransomware victim events between `start_date` and `end_date` (inclusive calendar days),
/// using the PRO `/victims/` API and the keyring key `ransomware_live`.
pub async fn fetch_ransomware_events(start_date: &str, end_date: &str) -> Result<(), RansomwareLiveError> {
    let api_key = get_api_key(KEYRING_RANSOMWARE_LIVE).filter(|s| !s.trim().is_empty());
    let Some(api_key) = api_key else {
        return Err(RansomwareLiveError::MissingApiKey);
    };

    let start = parse_calendar_date(start_date)?;
    let end = parse_calendar_date(end_date)?;
    let months = year_months_in_range(start, end)?;

    let db_path_buf = crate::vault_db::get_vault_path();

    let client = build_client()?;
    let mut seen_ids = HashSet::new();
    let mut normalized: Vec<NormalizedVictim> = Vec::new();

    for (year, month) in months {
        let body = fetch_month_json(&client, &api_key, year, month).await?;
        for item in extract_victim_array(&body) {
            let Some(obj) = item.as_object() else {
                continue;
            };
            let v = Value::Object(obj.clone());
            let Some(nv) = normalize_victim_value(&v) else {
                continue;
            };
            if let Some(ad) = nv.attack_date {
                if ad < start || ad > end {
                    continue;
                }
            } else {
                continue;
            }
            if !seen_ids.insert(nv.id.clone()) {
                continue;
            }
            normalized.push(nv);
        }
    }

    if normalized.is_empty() {
        return Ok(());
    }

    let rows = normalized;
    let db_path_clone = db_path_buf.clone();
    tokio::task::spawn_blocking(move || persist_batch(&db_path_clone, &rows))
        .await
        .map_err(|e| RansomwareLiveError::Vault {
            details: e.to_string(),
        })??;

    Ok(())
}

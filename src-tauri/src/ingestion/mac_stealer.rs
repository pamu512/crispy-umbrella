//! Headless fetch of RUMARK-style MAC stealer logs and upsert into `ioc_records`.
//!
//! Configure the origin with `RUMARK_API_BASE` (no trailing slash required). For `.onion`
//! hosts, a SOCKS proxy is required: set `RUMARK_SOCKS_PROXY` (e.g. `socks5h://127.0.0.1:9050`)
//! or rely on the default `socks5h://127.0.0.1:9050` when the base URL contains `.onion`.
//! HTTP(S) proxies are supported via `RUMARK_HTTP_PROXY` / `ALL_PROXY` style URLs on the
//! reqwest `Proxy::all` format.
//!
//! The vault path comes from `CTI_DB_PATH`, consistent with other ingest paths in this crate.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, COOKIE};
use reqwest::{Proxy, StatusCode, Url};
use rusqlite::params;
use scraper::{ElementRef, Html, Selector};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::vault_db::{self, time_now_iso};

const SOURCE_PROJECT: &str = "Compromised_user_Mac";
const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str =
    "Mozilla/5.0 (compatible; CTI-Command-Center/1.0; +https://example.invalid)";

/// Default public onion hostname (Tor required). Override with `RUMARK_API_BASE`.
const DEFAULT_RUMARK_ONION: &str =
    "http://rumarkstror5mvgzzodqizofkji3fna7lndfylmzeisj5tamqnwnr4ad.onion";

/// One stealer-log row after normalization (matches the Python script’s logical fields).
#[derive(Debug, Clone)]
pub struct MacLogEntry {
    pub stealer: String,
    pub target_link: String,
    pub other_links: Vec<String>,
    pub date: String,
    pub size: String,
}

#[derive(Debug)]
pub enum MacStealerError {
    InvalidCookie(String),
    NoDomains,
    MissingVaultPath(String),
    Vault(String),
    Http(String),
    Timeout(String),
    Parse(String),
    Json(String),
    Url(String),
}

impl fmt::Display for MacStealerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacStealerError::InvalidCookie(s) => write!(f, "invalid cookie: {}", s),
            MacStealerError::NoDomains => write!(f, "no domains supplied"),
            MacStealerError::MissingVaultPath(s) => write!(f, "{}", s),
            MacStealerError::Vault(s) => write!(f, "vault: {}", s),
            MacStealerError::Http(s) => write!(f, "http: {}", s),
            MacStealerError::Timeout(s) => write!(f, "timeout: {}", s),
            MacStealerError::Parse(s) => write!(f, "parse: {}", s),
            MacStealerError::Json(s) => write!(f, "json: {}", s),
            MacStealerError::Url(s) => write!(f, "url: {}", s),
        }
    }
}

impl std::error::Error for MacStealerError {}

/// Ergonomic alias matching the porting task signature.
pub type Error = MacStealerError;

// ---------------------------------------------------------------------------
// Cookie / client
// ---------------------------------------------------------------------------

fn validate_cookie(raw: &str) -> Result<String, MacStealerError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(MacStealerError::InvalidCookie(
            "cookie string is empty after trim".into(),
        ));
    }
    if s.len() > 65_536 {
        return Err(MacStealerError::InvalidCookie(format!(
            "cookie too long ({} bytes, max 65536)",
            s.len()
        )));
    }
    if s.contains('\0') {
        return Err(MacStealerError::InvalidCookie(
            "cookie contains NUL byte".into(),
        ));
    }
    if !s.contains('=') {
        return Err(MacStealerError::InvalidCookie(
            "expected at least one name=value pair".into(),
        ));
    }
    for part in s.split(';') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let (name, val) = p.split_once('=').ok_or_else(|| {
            MacStealerError::InvalidCookie(format!("cookie segment has no '=': {:?}", p))
        })?;
        if name.trim().is_empty() {
            return Err(MacStealerError::InvalidCookie(
                "empty cookie name in segment".into(),
            ));
        }
        if val.is_empty() {
            return Err(MacStealerError::InvalidCookie(format!(
                "cookie {:?} has empty value",
                name.trim()
            )));
        }
    }
    HeaderValue::from_str(s).map_err(|_| {
        MacStealerError::InvalidCookie(
            "cookie is not a valid HTTP header value (remove newlines/control chars)".into(),
        )
    })?;
    Ok(s.to_string())
}

fn normalize_domains(domains: Vec<String>) -> Result<Vec<String>, MacStealerError> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for d in domains {
        for part in d.split(',') {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            let key = t.to_ascii_lowercase();
            if seen.insert(key.clone()) {
                out.push(key);
            }
        }
    }
    if out.is_empty() {
        Err(MacStealerError::NoDomains)
    } else {
        Ok(out)
    }
}

fn rumark_api_base() -> String {
    std::env::var("RUMARK_API_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RUMARK_ONION.to_string())
}

fn map_reqwest(err: reqwest::Error) -> MacStealerError {
    if err.is_timeout() {
        MacStealerError::Timeout(err.to_string())
    } else {
        MacStealerError::Http(err.to_string())
    }
}

fn build_http_client() -> Result<reqwest::Client, MacStealerError> {
    let base = rumark_api_base();
    let mut builder = reqwest::Client::builder()
        .timeout(DEFAULT_BODY_TIMEOUT)
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .user_agent(USER_AGENT);

    if let Ok(p) = std::env::var("RUMARK_HTTP_PROXY") {
        let p = p.trim();
        if !p.is_empty() {
            let proxy = Proxy::all(p).map_err(|e| MacStealerError::Http(e.to_string()))?;
            builder = builder.proxy(proxy);
        }
    } else if let Ok(p) = std::env::var("RUMARK_SOCKS_PROXY") {
        let p = p.trim();
        if !p.is_empty() {
            let proxy = Proxy::all(p).map_err(|e| MacStealerError::Http(e.to_string()))?;
            builder = builder.proxy(proxy);
        }
    } else if base.contains(".onion") {
        let proxy = Proxy::all("socks5h://127.0.0.1:9050")
            .map_err(|e| MacStealerError::Http(e.to_string()))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| MacStealerError::Http(e.to_string()))
}

fn logs_url(domain: &str) -> Result<Url, MacStealerError> {
    let base = rumark_api_base();
    let root = base.trim_end_matches('/');
    let endpoint = format!("{}/logs", root);
    Url::parse_with_params(
        &endpoint,
        [
            ("emaildom", domain),
            ("page", "1"),
            ("perpage", "100"),
            ("withcookies", "0"),
        ],
    )
    .map_err(|e| MacStealerError::Url(e.to_string()))
}

// ---------------------------------------------------------------------------
// Parse JSON / HTML
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MacJsonRow {
    #[serde(default)]
    stealer: String,
    #[serde(default, alias = "targetLink", alias = "url", alias = "link")]
    target_link: String,
    #[serde(default)]
    other_links: Option<Value>,
    #[serde(default)]
    date: String,
    #[serde(default)]
    size: String,
}

fn other_links_from_json(v: &Value) -> Vec<String> {
    match v {
        Value::Null => vec![],
        Value::String(s) => {
            if s.contains(',') {
                s.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            } else if s.is_empty() {
                vec![]
            } else {
                vec![s.clone()]
            }
        }
        Value::Array(a) => a
            .iter()
            .filter_map(|x| {
                if let Some(s) = x.as_str() {
                    Some(s.to_string())
                } else {
                    x.get("url")
                        .or_else(|| x.get("href"))
                        .and_then(|u| u.as_str())
                        .map(|s| s.to_string())
                }
            })
            .filter(|s| !s.is_empty())
            .collect(),
        _ => vec![],
    }
}

fn json_row_to_entry(row: MacJsonRow) -> Option<MacLogEntry> {
    let target = row.target_link.trim();
    if target.is_empty() {
        return None;
    }
    let other = row
        .other_links
        .as_ref()
        .map(other_links_from_json)
        .unwrap_or_default();
    Some(MacLogEntry {
        stealer: row.stealer.trim().to_string(),
        target_link: target.to_string(),
        other_links: other,
        date: row.date.trim().to_string(),
        size: row.size.trim().to_string(),
    })
}

fn try_parse_json_array_items(items: &[Value]) -> Vec<MacLogEntry> {
    let mut out = Vec::new();
    for item in items {
        if let Ok(row) = serde_json::from_value::<MacJsonRow>(item.clone()) {
            if let Some(e) = json_row_to_entry(row) {
                out.push(e);
            }
        }
    }
    out
}

fn try_parse_json_body(body: &str) -> Result<Vec<MacLogEntry>, MacStealerError> {
    let val: Value =
        serde_json::from_str(body.trim()).map_err(|e| MacStealerError::Json(e.to_string()))?;
    let items: Vec<Value> = match val {
        Value::Array(a) => a,
        Value::Object(map) => {
            let keys = ["data", "rows", "items", "results", "logs", "records"];
            let mut found = Vec::new();
            for k in keys {
                if let Some(Value::Array(a)) = map.get(k) {
                    found = a.clone();
                    break;
                }
            }
            if found.is_empty() {
                return Err(MacStealerError::Parse(
                    "JSON object had no known array field (data/rows/items/results/logs/records)"
                        .into(),
                ));
            }
            found
        }
        _ => {
            return Err(MacStealerError::Parse(
                "expected JSON array or object with a data array".into(),
            ))
        }
    };
    Ok(try_parse_json_array_items(&items))
}

fn text_of(el: &ElementRef<'_>) -> String {
    el.text()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn hrefs_from_td(td: &ElementRef<'_>, a_sel: &Selector) -> Vec<String> {
    td.select(a_sel)
        .filter_map(|a| a.value().attr("href").map(|h| h.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_html_rows(html: &str) -> Result<Vec<MacLogEntry>, MacStealerError> {
    let doc = Html::parse_document(html);
    let td_sel = Selector::parse("td").map_err(|e| MacStealerError::Parse(e.to_string()))?;
    let a_sel = Selector::parse("a").map_err(|e| MacStealerError::Parse(e.to_string()))?;

    let row_selectors = ["table tbody tr", "table tr"];
    let mut out = Vec::new();

    for rs in row_selectors {
        let tr_sel = Selector::parse(rs).map_err(|e| MacStealerError::Parse(e.to_string()))?;
        for tr in doc.select(&tr_sel) {
            let tds: Vec<_> = tr.select(&td_sel).collect();
            if tds.len() < 5 {
                continue;
            }
            let stealer = text_of(&tds[0]);
            if stealer.eq_ignore_ascii_case("stealer") {
                continue;
            }
            let col1 = hrefs_from_td(&tds[1], &a_sel);
            let target_link = col1
                .first()
                .cloned()
                .or_else(|| {
                    let t = text_of(&tds[1]);
                    if t.is_empty() {
                        None
                    } else {
                        Some(t)
                    }
                })
                .unwrap_or_default();
            if target_link.is_empty() {
                continue;
            }
            let mut other = hrefs_from_td(&tds[2], &a_sel);
            let t2 = text_of(&tds[2]);
            if other.is_empty() && !t2.is_empty() {
                other.push(t2);
            }
            other.retain(|u| u != &target_link);
            out.push(MacLogEntry {
                stealer,
                target_link,
                other_links: other,
                date: text_of(&tds[3]),
                size: text_of(&tds[4]),
            });
        }
        if !out.is_empty() {
            break;
        }
    }
    Ok(out)
}

fn parse_mac_response_body(body: &str) -> Result<Vec<MacLogEntry>, MacStealerError> {
    let t = body.trim();
    if t.starts_with('[') || t.starts_with('{') {
        match try_parse_json_body(body) {
            Ok(rows) if !rows.is_empty() => return Ok(rows),
            Ok(_) => {}
            Err(e) => {
                let html_try = parse_html_rows(body)?;
                if !html_try.is_empty() {
                    return Ok(html_try);
                }
                return Err(e);
            }
        }
    }
    let html_rows = parse_html_rows(body)?;
    if !html_rows.is_empty() {
        return Ok(html_rows);
    }
    if t.starts_with('[') || t.starts_with('{') {
        return Err(MacStealerError::Parse(
            "JSON parsed but produced zero usable rows".into(),
        ));
    }
    Err(MacStealerError::Parse(
        "could not parse response as JSON rows or HTML table".into(),
    ))
}

// ---------------------------------------------------------------------------
// HTTP + DB
// ---------------------------------------------------------------------------

async fn fetch_domain_page(
    client: &reqwest::Client,
    cookie: &str,
    domain: &str,
) -> Result<Vec<MacLogEntry>, MacStealerError> {
    let url = logs_url(domain)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(cookie).expect("cookie validated earlier"),
    );

    let resp = client
        .get(url)
        .headers(headers)
        .send()
        .await
        .map_err(map_reqwest)?;

    if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN {
        return Err(MacStealerError::Http(format!(
            "HTTP {} — cookie may be expired or invalid",
            resp.status()
        )));
    }
    if !resp.status().is_success() {
        return Err(MacStealerError::Http(format!(
            "HTTP {}",
            resp.status()
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| MacStealerError::Http(e.to_string()))?;
    parse_mac_response_body(&body)
}

fn dedupe_rows(rows: Vec<MacLogEntry>) -> Vec<MacLogEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in rows {
        let key = (r.target_link.clone(), r.date.clone(), r.size.clone());
        if seen.insert(key) {
            out.push(r);
        }
    }
    out
}

fn parse_date_or_fallback(raw: &str, fallback: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        return fallback.to_string();
    }
    if let Ok(dt) = time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
    {
        return dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| fallback.to_string());
    }
    t.to_string()
}

fn insert_mac_rows(db_path: &Path, rows: &[MacLogEntry]) -> Result<(), MacStealerError> {
    let conn = vault_db::open_vault(db_path).map_err(|e| MacStealerError::Vault(e.to_string()))?;
    vault_db::ensure_ioc_records(&conn).map_err(|e| MacStealerError::Vault(e.to_string()))?;
    let now = time_now_iso();
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| MacStealerError::Vault(e.to_string()))?;
    {
        let mut stmt = tx
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
            .map_err(|e| MacStealerError::Vault(e.to_string()))?;

        for row in rows {
            let ioc_value = row.target_link.trim();
            if ioc_value.is_empty() {
                continue;
            }
            let first_seen = parse_date_or_fallback(&row.date, &now);
            let last_seen = first_seen.clone();
            let meta = json!({
                "stealer": row.stealer,
                "target_link": row.target_link,
                "other_links": row.other_links,
                "date": row.date,
                "size": row.size,
                "ingest": "mac_stealer",
            })
            .to_string();

            stmt.execute(params![
                ioc_value,
                "stealer_log",
                first_seen,
                last_seen,
                SOURCE_PROJECT,
                meta,
            ])
            .map_err(|e| MacStealerError::Vault(e.to_string()))?;
        }
    }
    tx.commit().map_err(|e| MacStealerError::Vault(e.to_string()))?;
    Ok(())
}

/// Fetches stealer-log rows for each domain and upserts them into `ioc_records`.
///
/// When `vault_db` is `None`, reads the database path from the `CTI_DB_PATH` environment variable.
/// Uses `RUMARK_API_BASE` when set.
pub async fn fetch_mac_logs(
    cookie: &str,
    domains: Vec<String>,
    vault_db: Option<&Path>,
) -> Result<(), Error> {
    let cookie = validate_cookie(cookie)?;
    let domains = normalize_domains(domains)?;
    let client = build_http_client()?;

    let mut all = Vec::new();
    for d in &domains {
        let mut rows = fetch_domain_page(&client, &cookie, d).await?;
        all.append(&mut rows);
    }
    let all = dedupe_rows(all);
    if all.is_empty() {
        return Ok(());
    }

    let db_path: PathBuf = if let Some(p) = vault_db {
        p.to_path_buf()
    } else {
        crate::vault_db::get_vault_path()
    };
    let db_path = db_path.to_string_lossy().trim().to_string();
    if db_path.is_empty() {
        return Err(MacStealerError::MissingVaultPath(
            "resolved vault database path is empty".into(),
        ));
    }
    let rows = all;
    tokio::task::spawn_blocking(move || insert_mac_rows(Path::new(&db_path), &rows))
        .await
        .map_err(|e| MacStealerError::Vault(e.to_string()))??;

    Ok(())
}

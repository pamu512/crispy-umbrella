//! IOC crawler: RSS/Atom feeds + article HTML, regex IOC extraction, SQLite `ioc_records` ingest.
//!
//! Uses `tokio::sync::mpsc` for job delivery and **reqwest + feed-rs + scraper** for fetching and
//! parsing. Rate limits and transient failures use **exponential backoff** via `tokio::time::sleep`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use feed_rs::model::Entry;
use regex::Regex;
use reqwest::header::USER_AGENT;
use reqwest::StatusCode;
use rusqlite::params;
use scraper::{Html, Selector};
use serde_json::json;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;

use crate::vault_db::{self, time_now_iso};

/// Bounded queue depth; backpressure when full (`try_send` / `send` errors).
const CHANNEL_CAPACITY: usize = 128;

const SOURCE_PROJECT: &str = "IOCs-crawler-main";
const HTTP_USER_AGENT_VALUE: &str =
    "Mozilla/5.0 (compatible; CTI-Command-Center-IOC/1.0; +https://example.invalid)";

/// Default RSS sources (Elastic blog + Unit 42). Elastic entries are filtered to security-relevant posts.
const FEED_ELASTIC_BLOG: &str = "https://www.elastic.co/blog/feed";
const FEED_UNIT42: &str = "https://unit42.paloaltonetworks.com/feed/";

const MAX_ARTICLES_PER_FEED: usize = 12;
const POLITE_DELAY_MS: u64 = 850;
const MAX_FETCH_ATTEMPTS: u32 = 14;
const BACKOFF_CAP: Duration = Duration::from_secs(90);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Regex IOC extractors (lazy, compiled once)
// ---------------------------------------------------------------------------

static RE_SHA256: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{64}\b").expect("sha256 regex")
});
static RE_SHA1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{40}\b").expect("sha1 regex")
});
static RE_MD5: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{32}\b").expect("md5 regex"));
static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b",
    )
    .expect("ipv4 regex")
});
/// Conservative FQDN: avoids matching pure decimals; TLD must be alpha, 2–24 chars.
static RE_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?=[a-z0-9][a-z0-9.-]{1,253}\.[a-z]{2,24}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    )
    .expect("domain regex")
});

// ---------------------------------------------------------------------------
// Public job types + queue
// ---------------------------------------------------------------------------

/// Work items the crawler worker understands (extend with new variants as ports land).
#[derive(Debug, Clone)]
pub enum IocCrawlerTask {
    /// Elastic-focused threat research crawl (Elastic blog RSS subset + Unit 42).
    ElasticSecurityLabs { workspace_path: String },
    /// Named crawl slot; if `label` is an `http(s)` URL it is treated as an extra Atom/RSS feed.
    Custom {
        label: String,
        workspace_path: String,
    },
}

/// Which feeds to pull for [`crawl_threat_intel_feeds_to_vault`].
#[derive(Debug, Clone)]
pub enum ThreatCrawlProfile {
    ElasticSecurityLabs,
    /// Always includes default feeds, plus this RSS/Atom URL.
    WithExtraFeed { extra_feed_url: String },
}

struct IocCrawlerSlot {
    tx: mpsc::Sender<IocCrawlerTask>,
}

/// Multi-producer handle; replaces the inner sender if the worker channel dies (self-heal).
#[derive(Clone)]
pub struct IocCrawlerQueue {
    slot: Arc<Mutex<IocCrawlerSlot>>,
    app: AppHandle,
}

impl IocCrawlerQueue {
    /// Non-blocking enqueue from sync contexts (e.g. synchronous `#[tauri::command]`).
    /// Respawns the worker once if the channel is closed (e.g. after a task panic killed the consumer loop).
    pub fn try_enqueue(&self, task: IocCrawlerTask) -> Result<(), String> {
        let mut task = task;
        for attempt in 0..2 {
            let tx = {
                let g = self
                    .slot
                    .lock()
                    .map_err(|_| "IOC crawler queue mutex poisoned".to_string())?;
                g.tx.clone()
            };
            match tx.try_send(task) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    return Err(format!(
                        "IOC crawler queue is full (max {} pending); try again shortly",
                        CHANNEL_CAPACITY
                    ));
                }
                Err(mpsc::error::TrySendError::Closed(t)) => {
                    task = t;
                    if attempt == 0 {
                        respawn_ioc_worker(&self.slot, &self.app)?;
                        continue;
                    }
                    return Err(
                        "IOC crawler worker is not running; restart the application.".into(),
                    );
                }
            }
        }
        Err("IOC crawler enqueue failed after worker respawn".into())
    }
}

fn spawn_receiver_loop(mut rx: mpsc::Receiver<IocCrawlerTask>, app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        log::info!(
            "IOC crawler worker started (tokio mpsc capacity={})",
            CHANNEL_CAPACITY
        );
        while let Some(task) = rx.recv().await {
            let join = tokio::spawn(async move { run_task(task).await });
            match join.await {
                Ok(Ok(())) => {
                    let _ = app.emit(
                        "vault-updated",
                        json!({
                            "kind": "ioc_crawler_rss",
                        }),
                    );
                }
                Ok(Err(e)) => log::error!("IOC crawler task error: {}", e),
                Err(e) => {
                    if e.is_panic() {
                        log::error!("IOC crawler task panicked (job isolated; worker continues): {}", e);
                    } else {
                        log::error!("IOC crawler task cancelled: {}", e);
                    }
                }
            }
        }
        log::warn!("IOC crawler worker stopped (receiver dropped)");
    });
}

fn respawn_ioc_worker(slot: &Arc<Mutex<IocCrawlerSlot>>, app: &AppHandle) -> Result<(), String> {
    let (tx, rx) = mpsc::channel::<IocCrawlerTask>(CHANNEL_CAPACITY);
    {
        let mut g = slot
            .lock()
            .map_err(|_| "IOC crawler queue mutex poisoned".to_string())?;
        g.tx = tx.clone();
    }
    spawn_receiver_loop(rx, app.clone());
    log::warn!("IOC crawler worker respawned after a closed/failed channel");
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP + backoff
// ---------------------------------------------------------------------------

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .user_agent(HTTP_USER_AGENT_VALUE)
        .build()
        .map_err(|e| e.to_string())
}

/// GET `url` and return response body text. Handles **429 / 503** and transient transport errors
/// with exponential backoff (`tokio::time::sleep`).
pub async fn fetch_text_with_backoff(client: &reqwest::Client, url: &str) -> Result<String, String> {
    let mut delay = INITIAL_BACKOFF;
    let mut attempt: u32 = 0;

    loop {
        attempt = attempt.saturating_add(1);
        if attempt > MAX_FETCH_ATTEMPTS {
            return Err(format!(
                "giving up on {} after {} attempts (last backoff {:?})",
                url, MAX_FETCH_ATTEMPTS, delay
            ));
        }

        match client
            .get(url)
            .header(USER_AGENT, HTTP_USER_AGENT_VALUE)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status == StatusCode::TOO_MANY_REQUESTS
                    || status == StatusCode::SERVICE_UNAVAILABLE
                    || status == StatusCode::BAD_GATEWAY
                {
                    log::warn!(
                        "{} {} — sleeping {:?} then retry (attempt {})",
                        status,
                        url,
                        delay,
                        attempt
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(BACKOFF_CAP);
                    continue;
                }
                if !status.is_success() {
                    return Err(format!("GET {} -> HTTP {}", url, status));
                }
                return resp.text().await.map_err(|e| format!("read body {}: {}", url, e));
            }
            Err(e) => {
                let retry = e.is_timeout() || e.is_connect() || e.is_request();
                if retry {
                    log::warn!(
                        "fetch {} failed ({}) — sleeping {:?} (attempt {})",
                        url,
                        e,
                        delay,
                        attempt
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(BACKOFF_CAP);
                    continue;
                }
                return Err(format!("GET {}: {}", url, e));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RSS + HTML text
// ---------------------------------------------------------------------------

fn entry_blob_text(entry: &Entry) -> String {
    let mut out = String::new();
    if let Some(t) = &entry.title {
        out.push_str(t.content.trim());
        out.push('\n');
    }
    for l in &entry.links {
        out.push_str(l.href.trim());
        out.push('\n');
    }
    if let Some(s) = &entry.summary {
        out.push_str(s.content.trim());
        out.push('\n');
    }
    if let Some(c) = &entry.content {
        if let Some(b) = &c.body {
            out.push_str(b.trim());
            out.push('\n');
        }
    }
    out
}

fn primary_article_url(entry: &Entry) -> Option<String> {
    entry
        .links
        .iter()
        .find(|l| {
            let h = l.href.to_ascii_lowercase();
            h.starts_with("http://") || h.starts_with("https://")
        })
        .map(|l| l.href.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn elastic_entry_security_relevant(entry: &Entry) -> bool {
    let blob = entry_blob_text(entry).to_ascii_lowercase();
    let needles = [
        "security",
        "threat",
        "malware",
        "ransom",
        "siem",
        "detection",
        "attack",
        "vulnerability",
        "cve",
        "ioc",
        "intrusion",
    ];
    needles.iter().any(|n| blob.contains(n))
}

fn html_to_plain_text(html: &str) -> String {
    let doc = Html::parse_document(html);
    let selectors = [
        "article",
        "main",
        "[role='main']",
        ".post-content",
        ".entry-content",
        ".article-body",
        "body",
    ];
    let mut chunks: Vec<String> = Vec::new();
    for sel_s in selectors {
        if let Ok(sel) = Selector::parse(sel_s) {
            for el in doc.select(&sel) {
                let t: String = el.text().collect::<Vec<_>>().join(" ");
                let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
                if t.len() > 40 {
                    chunks.push(t);
                }
            }
        }
    }
    if chunks.is_empty() {
        // Fallback: strip tags coarsely
        let re = Regex::new(r"<[^>]+>").ok();
        if let Some(r) = re {
            return r.replace_all(html, " ").to_string();
        }
        return html.to_string();
    }
    chunks.join("\n")
}

async fn collect_text_for_entry(
    client: &reqwest::Client,
    entry: &Entry,
) -> Result<(String, String, String), String> {
    let title = entry
        .title
        .as_ref()
        .map(|t| t.content.trim().to_string())
        .unwrap_or_default();
    let link = primary_article_url(entry).unwrap_or_default();
    let mut corpus = entry_blob_text(entry);
    if !link.is_empty() && link.starts_with("http") {
        match fetch_text_with_backoff(client, &link).await {
            Ok(html) => {
                corpus.push_str("\n");
                corpus.push_str(&html_to_plain_text(&html));
            }
            Err(e) => {
                log::warn!("article fetch skipped {}: {}", link, e);
            }
        }
    }
    Ok((title, link, corpus))
}

fn parse_feed_xml(xml: &str) -> Result<feed_rs::model::Feed, String> {
    feed_rs::parser::parse(xml.as_bytes()).map_err(|e| format!("feed parse: {:?}", e))
}

// ---------------------------------------------------------------------------
// IOC regex extraction
// ---------------------------------------------------------------------------

fn is_plausible_domain(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    // Drop obvious file-name extensions masquerading as TLDs in path contexts
    if h.ends_with(".png")
        || h.ends_with(".jpg")
        || h.ends_with(".jpeg")
        || h.ends_with(".gif")
        || h.ends_with(".svg")
        || h.ends_with(".css")
        || h.ends_with(".js")
        || h.ends_with(".wasm")
    {
        return false;
    }
    true
}

fn normalize_ioc_value(kind: &str, raw: &str) -> String {
    match kind {
        "domain" => raw.trim().to_ascii_lowercase(),
        "ipv4" | "sha256" | "sha1" | "md5" => raw.trim().to_ascii_lowercase(),
        _ => raw.trim().to_string(),
    }
}

/// Extract IOC tuples `(value, ioc_type)` from free text. Order: hashes → IPv4 → domains
/// (domains last to reduce overlap with dotted artifacts inside URLs already mined).
pub fn extract_iocs_from_text(text: &str) -> Vec<(String, String)> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<(String, String)> = Vec::new();

    for caps in RE_SHA256.captures_iter(text) {
        if let Some(m) = caps.get(0) {
            let v = normalize_ioc_value("sha256", m.as_str());
            if seen.insert((v.clone(), "sha256".into())) {
                out.push((v, "sha256".into()));
            }
        }
    }
    for caps in RE_SHA1.captures_iter(text) {
        if let Some(m) = caps.get(0) {
            let v = normalize_ioc_value("sha1", m.as_str());
            if seen.insert((v.clone(), "sha1".into())) {
                out.push((v, "sha1".into()));
            }
        }
    }
    for caps in RE_MD5.captures_iter(text) {
        if let Some(m) = caps.get(0) {
            let v = normalize_ioc_value("md5", m.as_str());
            if seen.insert((v.clone(), "md5".into())) {
                out.push((v, "md5".into()));
            }
        }
    }
    for caps in RE_IPV4.captures_iter(text) {
        if let Some(m) = caps.get(0) {
            let v = normalize_ioc_value("ipv4", m.as_str());
            if seen.insert((v.clone(), "ipv4".into())) {
                out.push((v, "ipv4".into()));
            }
        }
    }
    for caps in RE_DOMAIN.captures_iter(text) {
        if let Some(m) = caps.get(0) {
            let raw = m.as_str();
            if !is_plausible_domain(raw) {
                continue;
            }
            let v = normalize_ioc_value("domain", raw);
            if seen.insert((v.clone(), "domain".into())) {
                out.push((v, "domain".into()));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SQLite
// ---------------------------------------------------------------------------

fn persist_iocs_blocking(
    vault_db: PathBuf,
    rows: Vec<(String, String, String, String, String)>,
) -> Result<usize, String> {
    if rows.is_empty() {
        return Ok(0);
    }
    let conn = vault_db::open_vault(&vault_db).map_err(|e| e.to_string())?;
    vault_db::ensure_ioc_records(&conn).map_err(|e| e.to_string())?;
    let now = time_now_iso();
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let mut n = 0usize;
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
            .map_err(|e| e.to_string())?;

        for (val, ty, meta, _, _) in rows {
            stmt.execute(params![val, ty, &now, &now, SOURCE_PROJECT, meta])
                .map_err(|e| e.to_string())?;
            n = n.saturating_add(1);
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(n)
}

/// Canonical vault path ([`crate::vault_db::get_vault_path`]); workspace is not used for DB location.
pub fn resolve_vault_db_path(_workspace_path: &str) -> Result<PathBuf, String> {
    Ok(crate::vault_db::get_vault_path())
}

/// Fetches threat RSS/Atom sources, optionally filters Elastic posts to security themes, follows
/// article links to gather HTML text, extracts IOCs via regex, and upserts into `ioc_records`.
///
/// Returns the number of IOC rows written (including upserts counted as executions).
pub async fn crawl_threat_intel_feeds_to_vault(
    vault_db: &Path,
    profile: ThreatCrawlProfile,
) -> Result<usize, String> {
    let client = http_client()?;
    let mut feed_jobs: Vec<(String, bool)> = Vec::new();
    feed_jobs.push((FEED_ELASTIC_BLOG.to_string(), true));
    feed_jobs.push((FEED_UNIT42.to_string(), false));
    if let ThreatCrawlProfile::WithExtraFeed { extra_feed_url } = &profile {
        let u = extra_feed_url.trim();
        if u.starts_with("http://") || u.starts_with("https://") {
            feed_jobs.push((u.to_string(), false));
        }
    }

    let mut collected: Vec<(String, String, String, String, String)> = Vec::new();

    for (feed_url, elastic_filter) in feed_jobs {
        let xml = fetch_text_with_backoff(&client, &feed_url).await?;
        let feed = parse_feed_xml(&xml)?;
        let mut count = 0usize;
        for entry in feed.entries.iter() {
            if count >= MAX_ARTICLES_PER_FEED {
                break;
            }
            if elastic_filter && !elastic_entry_security_relevant(entry) {
                continue;
            }
            let (title, article_url, corpus) = collect_text_for_entry(&client, entry).await?;
            let iocs = extract_iocs_from_text(&corpus);
            for (val, ty) in iocs {
                let meta = json!({
                    "ingestor": "ioc_crawler_rss",
                    "feed": feed_url,
                    "article_title": title,
                    "article_url": article_url,
                    "ioc_type": ty,
                })
                .to_string();
                collected.push((val, ty, meta, feed_url.clone(), article_url.clone()));
            }
            count = count.saturating_add(1);
            tokio::time::sleep(Duration::from_millis(POLITE_DELAY_MS)).await;
        }
    }

    let vault = vault_db.to_path_buf();
    let n = tokio::task::spawn_blocking(move || persist_iocs_blocking(vault, collected))
        .await
        .map_err(|e| format!("sqlite join: {}", e))??;
    Ok(n)
}

// ---------------------------------------------------------------------------
// Task runner + worker process
// ---------------------------------------------------------------------------

async fn run_task(task: IocCrawlerTask) -> Result<(), String> {
    match task {
        IocCrawlerTask::ElasticSecurityLabs { workspace_path } => {
            let db = resolve_vault_db_path(&workspace_path)?;
            let n = crawl_threat_intel_feeds_to_vault(&db, ThreatCrawlProfile::ElasticSecurityLabs).await?;
            log::info!(
                "IOC crawler ElasticSecurityLabs finished — {} ioc_record row(s) touched for {}",
                n,
                db.display()
            );
            Ok(())
        }
        IocCrawlerTask::Custom {
            label,
            workspace_path,
        } => {
            let db = resolve_vault_db_path(&workspace_path)?;
            let profile = if label.trim().starts_with("http://") || label.trim().starts_with("https://")
            {
                ThreatCrawlProfile::WithExtraFeed {
                    extra_feed_url: label.trim().to_string(),
                }
            } else {
                ThreatCrawlProfile::ElasticSecurityLabs
            };
            let n = crawl_threat_intel_feeds_to_vault(&db, profile).await?;
            log::info!(
                "IOC crawler custom job finished — {} ioc_record row(s) touched for {}",
                n,
                db.display()
            );
            Ok(())
        }
    }
}

/// Spawns the single-consumer Tokio task and returns the multi-producer handle.
///
/// Must run **after** the Tauri / Tokio runtime exists — call from [`tauri::Builder::setup`].
pub fn start_ioc_crawler_worker(app: AppHandle) -> IocCrawlerQueue {
    let (tx, rx) = mpsc::channel::<IocCrawlerTask>(CHANNEL_CAPACITY);
    spawn_receiver_loop(rx, app.clone());
    IocCrawlerQueue {
        slot: Arc::new(Mutex::new(IocCrawlerSlot { tx })),
        app,
    }
}

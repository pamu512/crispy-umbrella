//! Automated correlation between ``asm_assets`` and ``cve_data`` using CPE 2.3 semantics.
//!
//! The canonical vault uses ``asm_assets(asset_target PRIMARY KEY, …, metadata JSON text)``
//! and ``cve_data(cve_id, …, metadata JSON text)``.  This module creates ``asset_cve_mapping``
//! keyed by ``asset_target`` (see [`ensure_asset_cve_mapping_table`]) and fills it by:
//! 1. Deriving candidate **base CPE** keys (``part:vendor:product``) from each asset’s
//!    ``asset_type``, ``asset_target``, and ``metadata`` (OS / software / embedded ``cpe:`` strings).
//! 2. Extracting CPE strings from each CVE’s ``metadata`` (NVD ``configurations`` trees and any
//!    embedded ``cpe:2.3:`` literals), then normalizing to the same base keys.
//! 3. Inserting ``(asset_target, cve_id, …)`` on any intersection.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{params, Connection};
use serde_json::Value;

// ---------------------------------------------------------------------------
// DDL — exact SQL (SQLite)
// ---------------------------------------------------------------------------

/// Creates the junction table used by this matcher. Safe to run on every open.
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS asset_cve_mapping (
///     asset_target TEXT NOT NULL,
///     cve_id TEXT NOT NULL,
///     matched_on_date TEXT NOT NULL DEFAULT (datetime('now')),
///     matched_cpe TEXT,
///     match_basis TEXT NOT NULL,
///     PRIMARY KEY (asset_target, cve_id),
///     FOREIGN KEY (asset_target) REFERENCES asm_assets(asset_target) ON DELETE CASCADE,
///     FOREIGN KEY (cve_id) REFERENCES cve_data(cve_id) ON DELETE CASCADE
/// );
/// ```
pub fn ensure_asset_cve_mapping_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS asset_cve_mapping (
            asset_target TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            matched_on_date TEXT NOT NULL DEFAULT (datetime('now')),
            matched_cpe TEXT,
            match_basis TEXT NOT NULL,
            PRIMARY KEY (asset_target, cve_id),
            FOREIGN KEY (asset_target) REFERENCES asm_assets(asset_target) ON DELETE CASCADE,
            FOREIGN KEY (cve_id) REFERENCES cve_data(cve_id) ON DELETE CASCADE
        );",
    )
    .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// CPE normalization
// ---------------------------------------------------------------------------

/// Normalize a CPE 2.3 URI into a **base** key: ``part:vendor:product`` (lower‑cased fields).
/// Example: ``cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*`` → ``a:apache:http_server``
pub fn cpe_uri_to_base_key(cpe: &str) -> Option<String> {
    let s = cpe.trim();
    let lower = s.to_ascii_lowercase();
    let rest = lower.strip_prefix("cpe:2.3:")?;
    let mut parts = rest.split(':');
    let part = parts.next()?;
    let vendor = parts.next()?;
    let product = parts.next()?;
    if part.is_empty() || vendor.is_empty() || product.is_empty() {
        return None;
    }
    Some(format!("{part}:{vendor}:{product}"))
}

// ---------------------------------------------------------------------------
// JSON: collect CPE strings from CVE metadata (NVD-style + literals)
// ---------------------------------------------------------------------------

fn push_cpe_unique(out: &mut Vec<String>, cpe: String) {
    let t = cpe.trim();
    if !t.to_ascii_lowercase().starts_with("cpe:2.3:") {
        return;
    }
    if !out.iter().any(|x| x.eq_ignore_ascii_case(t)) {
        out.push(t.to_string());
    }
}

/// Depth-limited walk: any string value containing ``cpe:2.3:`` is captured.
fn collect_literal_cpes_from_json(v: &Value, depth: usize, out: &mut Vec<String>) {
    if depth > 32 {
        return;
    }
    match v {
        Value::String(s) => {
            if s.contains("cpe:2.3:") {
                for token in s.split_whitespace() {
                    let t = token.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == ')');
                    if t.to_ascii_lowercase().starts_with("cpe:2.3:") {
                        push_cpe_unique(out, t.to_string());
                    }
                }
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_literal_cpes_from_json(x, depth + 1, out);
            }
        }
        Value::Object(m) => {
            for x in m.values() {
                collect_literal_cpes_from_json(x, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Parse NVD ``configurations`` / ``nodes`` / ``cpeMatch`` (2.0 feed shape).
fn collect_cpes_from_configurations(cfg: &Value, out: &mut Vec<String>) {
    let blocks: Vec<&Value> = match cfg {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![cfg],
        _ => return,
    };
    for block in blocks {
        let Some(nodes) = block.get("nodes").and_then(|n| n.as_array()) else {
            continue;
        };
        for node in nodes {
            let Some(matches) = node.get("cpeMatch").and_then(|m| m.as_array()) else {
                continue;
            };
            for cm in matches {
                if let Some(criteria) = cm.get("criteria").and_then(|c| c.as_str()) {
                    push_cpe_unique(out, criteria.to_string());
                }
            }
        }
    }
}

/// Extract all CPE URIs from stored ``cve_data.metadata`` JSON.
pub fn extract_cpe_uris_from_cve_metadata(meta: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(meta) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(cfg) = v.get("configurations") {
        collect_cpes_from_configurations(cfg, &mut out);
    }
    collect_literal_cpes_from_json(&v, 0, &mut out);
    out
}

pub fn cpe_metadata_base_keys(meta: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for uri in extract_cpe_uris_from_cve_metadata(meta) {
        if let Some(k) = cpe_uri_to_base_key(&uri) {
            set.insert(k);
        }
    }
    set
}

// ---------------------------------------------------------------------------
// Asset: OS / software / banner → candidate base keys + literal CPEs
// ---------------------------------------------------------------------------

/// Known OS / product phrases → ``part:vendor:product`` (lower case). Extend as needed.
fn heuristic_software_to_cpe_bases(text: &str) -> HashSet<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = HashSet::new();

    let mut add = |k: &str| {
        if let Some(b) = cpe_uri_to_base_key(&format!("cpe:2.3:{k}:*:*:*:*:*:*:*:*")) {
            out.insert(b);
        }
    };

    if lower.contains("windows nt 10") || lower.contains("windows 10") {
        add("o:microsoft:windows_10");
    }
    if lower.contains("windows server 2019") {
        add("o:microsoft:windows_server_2019");
    }
    if lower.contains("windows server 2022") {
        add("o:microsoft:windows_server_2022");
    }
    if lower.contains("windows 11") {
        add("o:microsoft:windows_11");
    }
    if lower.contains("ubuntu") {
        add("o:canonical:ubuntu_linux");
    }
    if lower.contains("debian") {
        add("o:debian:debian_linux");
    }
    if lower.contains("red hat enterprise") || lower.contains("rhel") {
        add("o:redhat:enterprise_linux");
    }
    if lower.contains("amazon linux") {
        add("o:amazon:amazon_linux");
    }
    if lower.contains("openssl") {
        add("a:openssl:openssl");
    }
    if lower.contains("nginx") {
        add("a:f5:nginx");
        add("a:nginx:nginx");
    }
    if lower.contains("apache") && lower.contains("http") {
        add("a:apache:http_server");
    }
    if lower.contains("openssh") {
        add("a:openbsd:openssh");
    }
    if lower.contains("mysql") {
        add("a:oracle:mysql");
    }
    if lower.contains("postgresql") || lower.contains("postgres") {
        add("a:postgresql:postgresql");
    }
    if lower.contains("tomcat") {
        add("a:apache:tomcat");
    }
    if lower.contains("kubernetes") || lower.contains(" k8s") {
        add("a:kubernetes:kubernetes");
    }
    if lower.contains("docker") {
        add("a:docker:docker");
    }

    // ``nginx/1.20.1`` style
    if let Some(i) = lower.find("nginx/") {
        let tail = &lower[i..];
        if tail.starts_with("nginx/") {
            add("a:f5:nginx");
            add("a:nginx:nginx");
        }
    }
    if lower.contains("apache/2.") || lower.contains("apache/1.") {
        add("a:apache:http_server");
    }

    out
}

/// Concatenate short string fields from JSON (banners, OS fields, etc.) for heuristics.
fn collect_asset_text_blobs(meta: &str, asset_type: &str, asset_target: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(asset_type.to_string());
    parts.push(asset_target.to_string());
    if let Ok(v) = serde_json::from_str::<Value>(meta) {
        collect_json_string_values(&v, 0, 6, &mut parts);
    } else if !meta.trim().is_empty() {
        parts.push(meta.chars().take(4000).collect());
    }
    parts.join(" ")
}

fn collect_json_string_values(v: &Value, depth: usize, max_depth: usize, out: &mut Vec<String>) {
    if depth > max_depth {
        return;
    }
    match v {
        Value::String(s) => {
            if s.len() > 2 && s.len() < 8000 {
                out.push(s.clone());
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_json_string_values(x, depth + 1, max_depth, out);
            }
        }
        Value::Object(m) => {
            for x in m.values() {
                collect_json_string_values(x, depth + 1, max_depth, out);
            }
        }
        _ => {}
    }
}

/// All **base CPE keys** and literal CPE URIs we can infer for one asset row.
pub fn asset_signal_keys(asset_type: &str, asset_target: &str, metadata: &str) -> (HashSet<String>, Vec<String>) {
    let mut bases = HashSet::new();
    let mut literal_cpes = Vec::new();

    let blob = collect_asset_text_blobs(metadata, asset_type, asset_target);
    for k in heuristic_software_to_cpe_bases(&blob) {
        bases.insert(k);
    }

    if let Ok(v) = serde_json::from_str::<Value>(metadata) {
        collect_literal_cpes_from_json(&v, 0, &mut literal_cpes);
    }
    for uri in &literal_cpes {
        if let Some(b) = cpe_uri_to_base_key(uri) {
            bases.insert(b);
        }
    }

    (bases, literal_cpes)
}

fn bases_overlap(asset: &HashSet<String>, cve: &HashSet<String>) -> Option<String> {
    for a in asset {
        if cve.contains(a) {
            return Some(a.clone());
        }
    }
    None
}

/// Secondary: keyword overlap between a short **software hint** from the asset blob and the CVE
/// English description stored in ``metadata.description`` (no CPE in feed).
fn description_keyword_hit(asset_blob_lower: &str, desc_lower: &str) -> bool {
    const MIN_LEN: usize = 5;
    let mut tokens: Vec<&str> = asset_blob_lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '/')
        .filter(|t| t.len() >= MIN_LEN)
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    let mut hits = 0usize;
    for t in tokens.iter().take(24) {
        if desc_lower.contains(t) {
            hits += 1;
            if hits >= 2 {
                return true;
            }
        }
    }
    false
}

fn cve_description_lower(meta: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(meta) else {
        return String::new();
    };
    v.get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Core job — exact SQL used at runtime
// ---------------------------------------------------------------------------

/// ```sql
/// SELECT asset_target, asset_type, IFNULL(metadata, '') AS metadata
///   FROM asm_assets;
/// ```
/// ```sql
/// SELECT cve_id, IFNULL(metadata, '') AS metadata FROM cve_data;
/// ```
/// ```sql
/// INSERT INTO asset_cve_mapping (asset_target, cve_id, matched_on_date, matched_cpe, match_basis)
/// VALUES (?1, ?2, datetime('now'), ?3, ?4)
/// ON CONFLICT(asset_target, cve_id) DO NOTHING;
/// ```
pub fn run_cpe_matching_job(conn: &Connection) -> Result<usize, String> {
    ensure_asset_cve_mapping_table(conn)?;

    let mut cve_bases: HashMap<String, HashSet<String>> = HashMap::new();
    let mut cve_desc: HashMap<String, String> = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT cve_id, IFNULL(metadata, '') AS metadata FROM cve_data")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for r in rows {
            let (cve_id, meta) = r.map_err(|e| e.to_string())?;
            cve_bases.insert(cve_id.clone(), cpe_metadata_base_keys(&meta));
            cve_desc.insert(cve_id, cve_description_lower(&meta));
        }
    }

    let mut assets: Vec<(String, String, String)> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT asset_target, IFNULL(asset_type, ''), IFNULL(metadata, '') AS metadata FROM asm_assets",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for r in rows {
            assets.push(r.map_err(|e| e.to_string())?);
        }
    }

    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    let mut inserted = 0usize;
    {
        let mut insert_stmt = tx
            .prepare(
                r"INSERT INTO asset_cve_mapping (asset_target, cve_id, matched_on_date, matched_cpe, match_basis)
                   VALUES (?1, ?2, datetime('now'), ?3, ?4)
                   ON CONFLICT(asset_target, cve_id) DO NOTHING",
            )
            .map_err(|e| e.to_string())?;

        for (asset_target, asset_type, metadata) in assets {
            let (asset_bases, literals) = asset_signal_keys(&asset_type, &asset_target, &metadata);
            let blob_lower =
                collect_asset_text_blobs(&metadata, &asset_type, &asset_target).to_ascii_lowercase();

            for (cve_id, cve_base_set) in &cve_bases {
                let mut basis: Option<&'static str> = None;
                let mut matched: Option<String> = None;

                if let Some(k) = bases_overlap(&asset_bases, cve_base_set) {
                    basis = Some("cpe_base");
                    matched = Some(format!("cpe:2.3:{k}:*:*:*:*:*:*:*:*"));
                } else if cve_base_set.is_empty() {
                    if let Some(desc) = cve_desc.get(cve_id) {
                        if !desc.is_empty() && description_keyword_hit(&blob_lower, desc) {
                            basis = Some("keyword");
                            matched = literals.first().cloned().or_else(|| {
                                asset_bases
                                    .iter()
                                    .next()
                                    .map(|k| format!("cpe:2.3:{k}:*:*:*:*:*:*:*:*"))
                            });
                        }
                    }
                }

                if let Some(b) = basis {
                    let n = insert_stmt
                        .execute(params![
                            &asset_target,
                            cve_id,
                            matched.as_deref().unwrap_or(""),
                            b
                        ])
                        .map_err(|e| e.to_string())?;
                    inserted += n;
                }
            }
        }
    }

    tx.commit().map_err(|e| e.to_string())?;
    log::info!("cpe_matcher: inserted {inserted} asset_cve_mapping row(s) (ON CONFLICT skipped duplicates).");
    Ok(inserted)
}

/// Run matching inside a blocking task (safe for async runtimes).
pub async fn run_cpe_matching_background(db_path: &Path) -> Result<usize, String> {
    let path = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let conn = crate::vault_db::open_vault(&path)?;
        run_cpe_matching_job(&conn)
    })
    .await
    .map_err(|e| format!("cpe_matcher join error: {e}"))?
}

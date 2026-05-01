//! Load CVE / ASM / social rows into `cti_vault.db` using canonical schemas (see `vault_db.rs`).

use std::path::Path;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::vault_db::{self, parse_cvss_base_score, time_now_iso};

/// Upserts CVE rows from the best available source under `CVE_Project_NVD/`.
pub fn ingest_cve_from_workspace(workspace_path: &str) -> Result<usize, String> {
    let db_path = Path::new(workspace_path).join("cti_vault.db");
    let conn = vault_db::open_vault(&db_path)?;

    let cve_root = Path::new(workspace_path).join("CVE_Project_NVD");
    if !cve_root.is_dir() {
        return Err("CVE_Project_NVD folder not found in workspace.".into());
    }

    let merged = cve_root.join("output_result/merged_cve_result.csv");
    let nvd_csv = cve_root.join("output_result/NVD_cve_search_result.csv");
    let cp_csv = cve_root.join("output_result/CP_cve_search_result.csv");

    let chosen = if merged.is_file() {
        Some(merged)
    } else if nvd_csv.is_file() {
        Some(nvd_csv)
    } else if cp_csv.is_file() {
        Some(cp_csv)
    } else {
        None
    };

    if let Some(path) = chosen {
        return ingest_from_search_csv(&conn, &path);
    }

    let json_dir = cve_root.join("NVD_CVE/JSON");
    let mut total = 0usize;
    for name in ["nvdcve-2.0-modified.json", "nvdcve-2.0-recent.json"] {
        let p = json_dir.join(name);
        if p.is_file() {
            total += ingest_nvd_json_file(&conn, &p)?;
        }
    }
    if total == 0 {
        return Err(
            "No ingest source found: add output_result/merged_cve_result.csv (or NVD/CP search CSV), \
             or NVD_CVE/JSON/nvdcve-2.0-modified.json / nvdcve-2.0-recent.json after a feed download."
                .into(),
        );
    }
    Ok(total)
}

fn header_indices(headers: &csv::StringRecord) -> Result<(usize, usize, usize), String> {
    let mut id = None;
    let mut cvss = None;
    let mut desc = None;
    for (i, h) in headers.iter().enumerate() {
        let t = h.trim_start_matches('\u{feff}').trim();
        match t {
            "CVE ID" => id = Some(i),
            "CVSS v3.1" if cvss.is_none() => cvss = Some(i),
            "CVSS v4.0" if cvss.is_none() => cvss = Some(i),
            "Description" => desc = Some(i),
            _ => {}
        }
    }
    let id = id.ok_or_else(|| "CSV missing column: CVE ID".to_string())?;
    let desc = desc.ok_or_else(|| "CSV missing column: Description".to_string())?;
    let cvss = cvss.ok_or_else(|| "CSV missing CVSS v3.1 / CVSS v4.0 column".to_string())?;
    Ok((id, cvss, desc))
}

fn ingest_from_search_csv(conn: &Connection, path: &Path) -> Result<usize, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|e| e.to_string())?;
    let headers = rdr.headers().map_err(|e| e.to_string())?.clone();
    let (i_id, i_cvss, i_desc) = header_indices(&headers)?;
    let now = time_now_iso();

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let mut n = 0usize;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata) VALUES (?1, ?2, '', ?3, ?4)
                 ON CONFLICT(cve_id) DO UPDATE SET
                   severity_score = excluded.severity_score,
                   updated_at = excluded.updated_at,
                   metadata = excluded.metadata",
            )
            .map_err(|e| e.to_string())?;
        for rec in rdr.records() {
            let rec = rec.map_err(|e| e.to_string())?;
            let cve_id = rec.get(i_id).unwrap_or("").trim();
            if cve_id.is_empty() || !cve_id.starts_with("CVE-") {
                continue;
            }
            let cvss_raw = rec.get(i_cvss).unwrap_or("").trim();
            let severity = parse_cvss_base_score(cvss_raw);
            let description = rec.get(i_desc).unwrap_or("").trim();
            let meta = json!({
                "description": description,
                "cvss_display": cvss_raw,
                "source_csv": path.file_name().and_then(|f| f.to_str()).unwrap_or(""),
            })
            .to_string();
            stmt.execute(rusqlite::params![cve_id, severity, &now, meta])
                .map_err(|e| e.to_string())?;
            n += 1;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(n)
}

fn ingest_nvd_json_file(conn: &Connection, path: &Path) -> Result<usize, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let data: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let vulns = data
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("Invalid NVD JSON (no vulnerabilities): {}", path.display()))?;

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let mut n = 0usize;
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
            .map_err(|e| e.to_string())?;
        for item in vulns {
            let Some(cve) = item.get("cve") else { continue };
            let cve_id = cve.get("id").and_then(|v| v.as_str()).unwrap_or("").trim();
            if cve_id.is_empty() {
                continue;
            }
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
            let description = nvd_description(cve);
            let severity = nvd_cvss_base_score(cve);
            let meta = json!({
                "description": description,
                "cwe": nvd_cwes(cve),
                "references": nvd_refs(cve),
                "raw_metrics": cve.get("metrics").cloned().unwrap_or(Value::Null),
            })
            .to_string();
            stmt.execute(rusqlite::params![
                cve_id,
                severity,
                published,
                last_mod,
                meta
            ])
            .map_err(|e| e.to_string())?;
            n += 1;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(n)
}

fn nvd_description(cve: &Value) -> String {
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

fn nvd_cwes(cve: &Value) -> Value {
    cve.get("weaknesses").cloned().unwrap_or(Value::Null)
}

fn nvd_refs(cve: &Value) -> Value {
    cve.get("references").cloned().unwrap_or(Value::Null)
}

fn nvd_cvss_base_score(cve: &Value) -> Option<f64> {
    let metrics = cve.get("metrics")?;
    if let Some(v) = pick_cvss_base_from_metrics(metrics, "cvssMetricV31") {
        return Some(v);
    }
    if let Some(v) = pick_cvss_base_from_metrics(metrics, "cvssMetricV30") {
        return Some(v);
    }
    if let Some(v) = pick_cvss_base_from_metrics(metrics, "cvssMetricV40") {
        return Some(v);
    }
    None
}

fn pick_cvss_base_from_metrics(metrics: &Value, key: &str) -> Option<f64> {
    let arr = metrics.get(key)?.as_array()?;
    let first = arr.first()?;
    let data = first.get("cvssData")?;
    data.get("baseScore")?.as_f64()
}

/// Fallback when Postgres export is unavailable: newest `*_subdomains.csv` under ASM-fetch-main.
pub fn ingest_asm_from_workspace(workspace_path: &str) -> Result<usize, String> {
    let db_path = Path::new(workspace_path).join("cti_vault.db");
    let asm_root = Path::new(workspace_path).join("ASM-fetch-main");
    if !asm_root.is_dir() {
        return Err("ASM-fetch-main not found in workspace.".into());
    }
    let conn = vault_db::open_vault(&db_path)?;
    let Some(csv_path) = find_newest_subdomain_csv(&asm_root) else {
        return Err(
            "No *_subdomains.csv under ASM-fetch-main. Use export_asm_to_cti_vault.py with Postgres, or save API CSV exports into the project tree.".into(),
        );
    };
    ingest_asm_subdomain_csv(&conn, &csv_path)
}

fn find_newest_subdomain_csv(asm_root: &Path) -> Option<std::path::PathBuf> {
    use std::time::SystemTime;
    use walkdir::WalkDir;
    let mut best: Option<(SystemTime, std::path::PathBuf)> = None;
    for e in WalkDir::new(asm_root)
        .max_depth(8)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let name = p.file_name()?.to_str()?;
        if !name.ends_with("_subdomains.csv") {
            continue;
        }
        let mt = std::fs::metadata(p)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        match &best {
            None => best = Some((mt, p.to_path_buf())),
            Some((t0, _)) if mt > *t0 => best = Some((mt, p.to_path_buf())),
            _ => {}
        }
    }
    best.map(|(_, p)| p)
}

fn ingest_asm_subdomain_csv(conn: &Connection, path: &Path) -> Result<usize, String> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let ts_iso = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| OffsetDateTime::from_unix_timestamp(d.as_secs() as i64).ok())
        .and_then(|odt| odt.format(&Rfc3339).ok())
        .unwrap_or_else(time_now_iso);

    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|e| e.to_string())?;
    let headers = rdr.headers().map_err(|e| e.to_string())?.clone();
    let idx = |name: &str| -> Option<usize> {
        headers
            .iter()
            .position(|h| h.trim_start_matches('\u{feff}').trim() == name)
    };
    let i_host = idx("Hosts").ok_or_else(|| format!("CSV missing Hosts column: {}", path.display()))?;
    let i_ip = idx("IPs");
    let i_type = idx("Type");
    let i_ports = idx("Opened Ports");
    let i_unusual = idx("Unusual Ports");

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let mut n = 0usize;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata) VALUES (?1, ?2, ?3, 'active', ?4)
                 ON CONFLICT(asset_target) DO UPDATE SET
                   asset_type = excluded.asset_type,
                   last_scan_at = excluded.last_scan_at,
                   status = excluded.status,
                   metadata = excluded.metadata",
            )
            .map_err(|e| e.to_string())?;
        for rec in rdr.records() {
            let rec = rec.map_err(|e| e.to_string())?;
            let host = rec.get(i_host).unwrap_or("").trim();
            if host.is_empty() {
                continue;
            }
            let ip = i_ip.and_then(|i| rec.get(i)).unwrap_or("").trim();
            let asset_target = if ip.is_empty() || ip == "N/A" {
                host.to_string()
            } else {
                format!("{}|{}", host, ip)
            };
            let asset_type = i_type
                .and_then(|i| rec.get(i))
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty() && *s != "N/A")
                .unwrap_or_else(|| {
                    if ip.is_empty() || ip == "N/A" {
                        "subdomain".into()
                    } else {
                        "host_ip".into()
                    }
                });
            let mut meta = serde_json::Map::new();
            meta.insert("source".into(), json!("asm_csv"));
            if let Some(i) = i_ports {
                if let Some(t) = rec.get(i) {
                    let s = t.trim();
                    if !s.is_empty() && s != "N/A" {
                        meta.insert(
                            "ports".into(),
                            json!(s.chars().take(400).collect::<String>()),
                        );
                    }
                }
            }
            if let Some(i) = i_unusual {
                if let Some(t) = rec.get(i) {
                    let s = t.trim();
                    if !s.is_empty() && s != "N/A" {
                        meta.insert(
                            "unusual_ports".into(),
                            json!(s.chars().take(200).collect::<String>()),
                        );
                    }
                }
            }
            meta.insert(
                "file".into(),
                json!(path.file_name().and_then(|f| f.to_str()).unwrap_or("")),
            );
            let metadata = Value::Object(meta).to_string();
            stmt.execute(rusqlite::params![asset_target, asset_type, ts_iso, metadata])
                .map_err(|e| e.to_string())?;
            n += 1;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(n)
}

const SOCIAL_PLATFORMS: &[&str] = &[
    "facebook",
    "twitter",
    "instagram",
    "linkedin",
    "tiktok",
    "pinterest",
    "youtube",
    "reddit",
    "snapchat",
];

/// Parse `getSearchResult.py` CSV stem `{folder}_{platform}` → (target display, platform).
fn social_platform_from_stem(stem: &str) -> Option<(&'static str, String)> {
    for pl in SOCIAL_PLATFORMS {
        let suf = format!("_{}", pl);
        if stem.to_ascii_lowercase().ends_with(&suf) {
            let t = stem[..stem.len() - suf.len()].to_string();
            return Some((*pl, t));
        }
    }
    None
}

fn ensure_social_media_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS social_media_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT NOT NULL,
            platform TEXT NOT NULL,
            title TEXT,
            url TEXT NOT NULL,
            abstract TEXT,
            result_date TEXT,
            source_csv TEXT NOT NULL,
            ingested_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_social_media_url_platform
          ON social_media_results(url, platform);
        ",
    )
    .map_err(|e| e.to_string())
}

/// Load `Social_MediaV2/output/<target>/*_<platform>.csv` into `cti_vault.db`.
pub fn ingest_social_media_from_workspace(workspace_path: &str) -> Result<usize, String> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let db_path = Path::new(workspace_path).join("cti_vault.db");
    let out_root = Path::new(workspace_path)
        .join("Social_MediaV2")
        .join("output");
    if !out_root.is_dir() {
        return Err(
            "Social_MediaV2/output not found (run a search with an output path under the project first)."
                .into(),
        );
    }

    let ts_iso = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());

    let conn = vault_db::open_vault(&db_path)?;
    ensure_social_media_schema(&conn)?;

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| e.to_string())?;
    let mut total = 0usize;
    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO social_media_results
             (target_name, platform, title, url, abstract, result_date, source_csv, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(url, platform) DO UPDATE SET
               target_name = excluded.target_name,
               title = excluded.title,
               abstract = excluded.abstract,
               result_date = excluded.result_date,
               source_csv = excluded.source_csv,
               ingested_at = excluded.ingested_at",
            )
            .map_err(|e| e.to_string())?;

        for subdir in std::fs::read_dir(&out_root).map_err(|e| e.to_string())? {
            let subdir = subdir.map_err(|e| e.to_string())?;
            let path = subdir.path();
            if !path.is_dir() {
                continue;
            }
            let folder_target = subdir
                .file_name()
                .to_str()
                .unwrap_or("")
                .to_string();
            for ent in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
                let ent = ent.map_err(|e| e.to_string())?;
                let p = ent.path();
                if p.extension().and_then(|e| e.to_str()) != Some("csv") {
                    continue;
                }
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let Some((platform, _stem_target)) = social_platform_from_stem(stem) else {
                    continue;
                };
                let rel = p
                    .strip_prefix(Path::new(workspace_path))
                    .unwrap_or(&p);
                let source_csv = rel.to_string_lossy().into_owned();

                let mut rdr = csv::ReaderBuilder::new()
                    .flexible(true)
                    .from_path(&p)
                    .map_err(|e| e.to_string())?;
                let headers = rdr.headers().map_err(|e| e.to_string())?.clone();
                let norm = |h: &str| h.trim_start_matches('\u{feff}').trim().to_ascii_lowercase();
                let idx_title = headers.iter().position(|h| norm(h) == "title");
                let idx_url = headers.iter().position(|h| norm(h) == "url");
                let idx_abstract = headers.iter().position(|h| norm(h) == "abstract");
                let idx_date = headers.iter().position(|h| norm(h) == "date");
                let (Some(i_title), Some(i_url)) = (idx_title, idx_url) else {
                    continue;
                };
                let i_abs = idx_abstract;
                let i_date = idx_date;

                for rec in rdr.records() {
                    let rec = rec.map_err(|e| e.to_string())?;
                    let url = rec.get(i_url).unwrap_or("").trim();
                    if url.is_empty() {
                        continue;
                    }
                    let title = rec.get(i_title).unwrap_or("").trim();
                    let abstract_txt = i_abs
                        .and_then(|i| rec.get(i))
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    let result_date = i_date
                        .and_then(|i| rec.get(i))
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    stmt.execute(rusqlite::params![
                        folder_target,
                        platform,
                        title,
                        url,
                        abstract_txt,
                        result_date,
                        source_csv,
                        ts_iso,
                    ])
                    .map_err(|e| e.to_string())?;
                    total += 1;
                }
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(total)
}

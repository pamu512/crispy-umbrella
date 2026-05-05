//! Rust-native parsing for threat intel feeds (CSV / JSON) into structs aligned with the
//! mature ``ioc_records`` layout and the CPE-centric ``cve_data`` / ``asm_assets`` / ``asset_cve_mapping`` DDL.

use std::fmt;
use std::fs;
use std::path::Path;

use csv::ReaderBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// I/O, CSV/JSON decoding, or semantic validation failures while reading feeds.
#[derive(Debug)]
pub enum IngestionError {
    Io(std::io::Error),
    Csv(csv::Error),
    Json(serde_json::Error),
    Format(String),
}

impl fmt::Display for IngestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestionError::Io(e) => write!(f, "I/O error: {}", e),
            IngestionError::Csv(e) => write!(f, "CSV error: {}", e),
            IngestionError::Json(e) => write!(f, "JSON error: {}", e),
            IngestionError::Format(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for IngestionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngestionError::Io(e) => Some(e),
            IngestionError::Csv(e) => Some(e),
            IngestionError::Json(e) => Some(e),
            IngestionError::Format(_) => None,
        }
    }
}

impl From<std::io::Error> for IngestionError {
    fn from(value: std::io::Error) -> Self {
        IngestionError::Io(value)
    }
}

impl From<csv::Error> for IngestionError {
    fn from(value: csv::Error) -> Self {
        IngestionError::Csv(value)
    }
}

impl From<serde_json::Error> for IngestionError {
    fn from(value: serde_json::Error) -> Self {
        IngestionError::Json(value)
    }
}

// ---------------------------------------------------------------------------
// Domain structs (mirror target DDL)
// ---------------------------------------------------------------------------

/// Row aligned with ``001_mature_ioc_records.sql`` / mature ``ioc_records`` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatureIocRecord {
    pub id: String,
    pub ioc_value: String,
    pub ioc_type: String,
    pub threat_actor: Option<String>,
    pub kill_chain_phase: Option<String>,
    pub confidence_score: i32,
    pub severity: String,
    pub tlp_level: String,
    pub expiration_date: Option<String>,
    pub created_at: String,
}

/// Row aligned with correlation ``cve_data`` (CPE-centric schema).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveRecord {
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub description: String,
    pub base_cpe: String,
    pub published_date: Option<String>,
}

/// Row aligned with correlation ``asm_assets`` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRecord {
    pub id: Option<i64>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub cpe_string: String,
    pub os: Option<String>,
    pub created_at: String,
}

/// Row aligned with ``asset_cve_mapping`` junction table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetCveMappingRecord {
    pub asset_id: i64,
    pub cve_id: String,
    pub matched_on_date: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_utf8_file(path: &Path) -> Result<String, IngestionError> {
    fs::read_to_string(path).map_err(IngestionError::from)
}

fn utc_now_iso() -> Result<String, IngestionError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| IngestionError::Format(format!("UTC timestamp formatting failed: {}", e)))
}

fn norm_csv_header(h: &str) -> String {
    h.trim_start_matches('\u{feff}')
        .trim()
        .to_ascii_lowercase()
        .replace(' ', "_")
}

fn find_header_index(headers: &csv::StringRecord, candidates: &[&str]) -> Option<usize> {
    let mapped: Vec<String> = headers.iter().map(norm_csv_header).collect();
    for cand in candidates {
        if let Some(i) = mapped.iter().position(|h| h == cand) {
            return Some(i);
        }
    }
    None
}

fn empty_opt(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn parse_i64_cell(s: &str) -> Result<Option<i64>, IngestionError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<i64>()
        .map(Some)
        .map_err(|e| IngestionError::Format(format!("invalid integer {:?}: {}", t, e)))
}

fn parse_i32_cell(s: &str, default: i32) -> Result<i32, IngestionError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(default);
    }
    t.parse::<i32>()
        .map_err(|e| IngestionError::Format(format!("invalid integer {:?}: {}", t, e)))
}

fn validate_uuid_len(id: &str) -> Result<(), IngestionError> {
    if id.len() != 36 {
        return Err(IngestionError::Format(format!(
            "IOC id must be a 36-character UUID string, got length {}",
            id.len()
        )));
    }
    Ok(())
}

fn validate_tlp(tlp: &str) -> Result<String, IngestionError> {
    let u = tlp.trim().to_ascii_uppercase();
    match u.as_str() {
        "RED" | "AMBER" | "GREEN" | "CLEAR" => Ok(u),
        _ => Err(IngestionError::Format(format!(
            "tlp_level must be RED, AMBER, GREEN, or CLEAR (got {:?})",
            tlp
        ))),
    }
}

fn validate_confidence(v: i32) -> Result<(), IngestionError> {
    if !(0..=100).contains(&v) {
        return Err(IngestionError::Format(format!(
            "confidence_score must be between 0 and 100 inclusive (got {})",
            v
        )));
    }
    Ok(())
}

fn validate_cvss_base(score: f64) -> Result<(), IngestionError> {
    if score.is_nan() || score.is_infinite() {
        return Err(IngestionError::Format(
            "cvss_score must be a finite number".into(),
        ));
    }
    if !(0.0..=10.0).contains(&score) {
        return Err(IngestionError::Format(format!(
            "cvss_score must be between 0.0 and 10.0 inclusive (got {})",
            score
        )));
    }
    Ok(())
}

fn new_ioc_uuid_string() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

// ---------------------------------------------------------------------------
// Mature IOC — CSV
// ---------------------------------------------------------------------------

/// Parse a CSV whose headers map to mature IOC columns (flexible names for legacy exports).
///
/// Recognized headers (normalized: lower case, spaces to underscores):
/// ``id``, ``ioc_value`` / ``value`` / ``url`` / ``email`` / ``indicator``, ``ioc_type`` / ``type``,
/// ``threat_actor``, ``kill_chain_phase``, ``confidence_score``, ``severity``, ``tlp_level``,
/// ``expiration_date``, ``created_at``. Missing optional fields receive safe defaults.
pub fn parse_mature_ioc_csv(path: &Path) -> Result<Vec<MatureIocRecord>, IngestionError> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)?;
    let headers = rdr.headers()?.clone();

    let i_id = find_header_index(&headers, &["id"]);
    let i_val = find_header_index(
        &headers,
        &["ioc_value", "value", "url", "email", "indicator"],
    )
    .ok_or_else(|| {
        IngestionError::Format(format!(
            "{}: missing IOC value column (ioc_value, value, url, email, or indicator)",
            path.display()
        ))
    })?;
    let i_type = find_header_index(&headers, &["ioc_type", "type"]);
    let i_actor = find_header_index(&headers, &["threat_actor", "actor", "threat"]);
    let i_kill = find_header_index(&headers, &["kill_chain_phase", "kill_chain", "phase"]);
    let i_conf = find_header_index(&headers, &["confidence_score", "confidence"]);
    let i_sev = find_header_index(&headers, &["severity"]);
    let i_tlp = find_header_index(&headers, &["tlp_level", "tlp"]);
    let i_exp = find_header_index(&headers, &["expiration_date", "expires", "expiry"]);
    let i_created = find_header_index(&headers, &["created_at", "ingested_at"]);

    let default_now = utc_now_iso()?;
    let mut out: Vec<MatureIocRecord> = Vec::new();

    for rec in rdr.into_records() {
        let rec = rec?;
        let raw_val = rec.get(i_val).unwrap_or("").trim();
        if raw_val.is_empty() {
            continue;
        }

        let id = if let Some(i) = i_id {
            let s = rec.get(i).unwrap_or("").trim();
            if s.is_empty() {
                new_ioc_uuid_string()
            } else {
                validate_uuid_len(s)?;
                s.to_string()
            }
        } else {
            new_ioc_uuid_string()
        };

        let mut ioc_type = i_type
            .and_then(|i| rec.get(i))
            .unwrap_or("")
            .trim()
            .to_string();
        if ioc_type.is_empty() {
            ioc_type = "unknown".into();
        }

        let threat_actor = i_actor
            .and_then(|i| rec.get(i))
            .and_then(|s| empty_opt(s));
        let kill_chain_phase = i_kill
            .and_then(|i| rec.get(i))
            .and_then(|s| empty_opt(s));

        let confidence_score = if let Some(i) = i_conf {
            parse_i32_cell(rec.get(i).unwrap_or(""), 50)?
        } else {
            50
        };
        validate_confidence(confidence_score)?;

        let severity = i_sev
            .and_then(|i| rec.get(i))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "UNKNOWN".into());

        let tlp_raw = i_tlp
            .and_then(|i| rec.get(i))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("CLEAR");
        let tlp_level = validate_tlp(tlp_raw)?;

        let expiration_date = i_exp
            .and_then(|i| rec.get(i))
            .and_then(|s| empty_opt(s));

        let created_at = if let Some(i) = i_created {
            let s = rec.get(i).unwrap_or("").trim();
            if s.is_empty() {
                default_now.clone()
            } else {
                s.to_string()
            }
        } else {
            default_now.clone()
        };

        out.push(MatureIocRecord {
            id,
            ioc_value: raw_val.to_string(),
            ioc_type,
            threat_actor,
            kill_chain_phase,
            confidence_score,
            severity,
            tlp_level,
            expiration_date,
            created_at,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Mature IOC — JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IocJsonRow {
    id: Option<String>,
    ioc_value: String,
    #[serde(default)]
    ioc_type: Option<String>,
    threat_actor: Option<String>,
    kill_chain_phase: Option<String>,
    #[serde(default)]
    confidence_score: Option<i32>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tlp_level: Option<String>,
    expiration_date: Option<String>,
    created_at: Option<String>,
}

/// Parse a JSON file containing either a top-level array of IOC objects, or an object with one of
/// ``records``, ``iocs``, ``data`` holding that array.
pub fn parse_mature_ioc_json(path: &Path) -> Result<Vec<MatureIocRecord>, IngestionError> {
    let raw = read_utf8_file(path)?;
    let root: Value = serde_json::from_str(&raw)?;
    let arr = if let Some(a) = root.as_array() {
        a
    } else if let Some(obj) = root.as_object() {
        let key = ["records", "iocs", "data"]
            .iter()
            .find_map(|k| obj.get(*k))
            .ok_or_else(|| {
                IngestionError::Format(format!(
                    "{}: expected top-level JSON array or object with records/iocs/data array",
                    path.display()
                ))
            })?;
        key.as_array().ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: JSON property must be an array",
                path.display()
            ))
        })?
    } else {
        return Err(IngestionError::Format(format!(
            "{}: root JSON value must be an array or object",
            path.display()
        )));
    };

    let default_now = utc_now_iso()?;
    let mut out: Vec<MatureIocRecord> = Vec::new();

    for (idx, item) in arr.iter().enumerate() {
        let row: IocJsonRow = serde_json::from_value(item.clone()).map_err(|e| {
            IngestionError::Format(format!(
                "{}: row {}: {}",
                path.display(),
                idx,
                e
            ))
        })?;

        let raw_val = row.ioc_value.trim();
        if raw_val.is_empty() {
            continue;
        }

        let id = if let Some(ref s) = row.id {
            let t = s.trim();
            if t.is_empty() {
                new_ioc_uuid_string()
            } else {
                validate_uuid_len(t)?;
                t.to_string()
            }
        } else {
            new_ioc_uuid_string()
        };

        let mut ioc_type = row
            .ioc_type
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        if ioc_type.is_empty() {
            ioc_type = "unknown".into();
        }

        let confidence_score = row.confidence_score.unwrap_or(50);
        validate_confidence(confidence_score)?;

        let severity = row
            .severity
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "UNKNOWN".into());

        let tlp_raw = row
            .tlp_level
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("CLEAR");
        let tlp_level = validate_tlp(tlp_raw)?;

        let created_at = row
            .created_at
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_now.clone());

        out.push(MatureIocRecord {
            id,
            ioc_value: raw_val.to_string(),
            ioc_type,
            threat_actor: row.threat_actor.and_then(|s| empty_opt(&s)),
            kill_chain_phase: row.kill_chain_phase.and_then(|s| empty_opt(&s)),
            confidence_score,
            severity,
            tlp_level,
            expiration_date: row.expiration_date.and_then(|s| empty_opt(&s)),
            created_at,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// CVE — NVD JSON 2.0 feed
// ---------------------------------------------------------------------------

fn nvd_description_en(cve: &Value) -> String {
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

fn pick_cvss_base_from_metrics(metrics: &Value, key: &str) -> Option<f64> {
    let arr = metrics.get(key)?.as_array()?;
    let first = arr.first()?;
    let data = first.get("cvssData")?;
    data.get("baseScore")?.as_f64()
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

fn first_cpe23_criteria(cve: &Value) -> Option<String> {
    let configs = cve.get("configurations")?.as_array()?;
    for cfg in configs {
        let nodes = cfg.get("nodes")?.as_array()?;
        for node in nodes {
            let cpe_match = node.get("cpeMatch")?.as_array()?;
            for m in cpe_match {
                if let Some(c) = m.get("criteria").and_then(|x| x.as_str()) {
                    if c.starts_with("cpe:2.3:") {
                        return Some(c.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Parse an NVD CVE JSON 2.0 feed (``vulnerabilities`` array) into [`CveRecord`] rows.
///
/// Rows without a discoverable ``cpe:2.3:`` criteria string are skipped because ``base_cpe`` is
/// required in the target schema.
pub fn parse_cve_records_from_nvd_json(path: &Path) -> Result<Vec<CveRecord>, IngestionError> {
    let raw = read_utf8_file(path)?;
    let data: Value = serde_json::from_str(&raw)?;
    let vulns = data
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: invalid NVD JSON (missing top-level \"vulnerabilities\" array)",
                path.display()
            ))
        })?;

    let mut out: Vec<CveRecord> = Vec::new();

    for item in vulns {
        let Some(cve) = item.get("cve") else {
            continue;
        };
        let cve_id = cve
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        let Some(cve_id) = cve_id else {
            continue;
        };

        let Some(base_cpe) = first_cpe23_criteria(cve) else {
            continue;
        };

        let description = nvd_description_en(cve);
        let published = cve
            .get("published")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let cvss_score = if let Some(s) = nvd_cvss_base_score(cve) {
            validate_cvss_base(s)?;
            Some(s)
        } else {
            None
        };

        out.push(CveRecord {
            cve_id: cve_id.to_string(),
            cvss_score,
            description,
            base_cpe,
            published_date: published,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Assets — CSV (explicit or ASM subdomain export)
// ---------------------------------------------------------------------------

/// Parse asset rows from CSV.
///
/// **Explicit layout** (headers ``hostname``, ``ip``, ``cpe_string``, ``os``, optional ``id``, ``created_at``).
///
/// **ASM subdomain export** (headers ``Hosts``, ``IPs``, plus required ``cpe_string`` or ``cpe`` for CPE 2.3 URI).
pub fn parse_asset_records_csv(path: &Path) -> Result<Vec<AssetRecord>, IngestionError> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)?;
    let headers = rdr.headers()?.clone();

    let i_id = find_header_index(&headers, &["id"]);
    let i_hostname = find_header_index(&headers, &["hostname", "host", "asset"]);
    let i_hosts = find_header_index(&headers, &["hosts"]);
    let i_ip = find_header_index(&headers, &["ip", "ips", "ipv4", "ipv6"]);
    let i_cpe = find_header_index(&headers, &["cpe_string", "cpe", "cpe_uri"]);
    let i_os = find_header_index(&headers, &["os", "operating_system", "platform"]);
    let i_created = find_header_index(&headers, &["created_at", "ingested_at", "last_scan_at"]);

    let has_hosts = i_hosts.is_some();
    let has_hostname = i_hostname.is_some();
    let has_cpe = i_cpe.is_some();

    let default_now = utc_now_iso()?;

    if has_hosts && has_cpe {
        let i_h = i_hosts.ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: internal error resolving Hosts column",
                path.display()
            ))
        })?;
        let i_c = i_cpe.ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: internal error resolving cpe column",
                path.display()
            ))
        })?;

        let mut out: Vec<AssetRecord> = Vec::new();
        for rec in rdr.into_records() {
            let rec = rec?;
            let host = rec.get(i_h).unwrap_or("").trim();
            if host.is_empty() {
                continue;
            }
            let ip_raw = i_ip
                .and_then(|i| rec.get(i))
                .unwrap_or("")
                .trim();
            let ip = if ip_raw.is_empty() || ip_raw.eq_ignore_ascii_case("n/a") {
                None
            } else {
                Some(ip_raw.to_string())
            };
            let cpe_string = rec.get(i_c).unwrap_or("").trim().to_string();
            if cpe_string.is_empty() {
                return Err(IngestionError::Format(format!(
                    "{}: cpe_string must not be empty for row with host {:?}",
                    path.display(),
                    host
                )));
            }
            let os = i_os
                .and_then(|i| rec.get(i))
                .and_then(|s| empty_opt(s));
            let id = if let Some(i) = i_id {
                parse_i64_cell(rec.get(i).unwrap_or(""))?
            } else {
                None
            };
            let created_at = if let Some(i) = i_created {
                let s = rec.get(i).unwrap_or("").trim();
                if s.is_empty() {
                    default_now.clone()
                } else {
                    s.to_string()
                }
            } else {
                default_now.clone()
            };

            out.push(AssetRecord {
                id,
                hostname: Some(host.to_string()),
                ip,
                cpe_string,
                os,
                created_at,
            });
        }
        return Ok(out);
    }

    if has_hostname && has_cpe {
        let i_h = i_hostname.ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: explicit layout requires a hostname column",
                path.display()
            ))
        })?;
        let i_c = i_cpe.ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: explicit layout requires cpe_string (or cpe / cpe_uri)",
                path.display()
            ))
        })?;

        let mut out: Vec<AssetRecord> = Vec::new();
        for rec in rdr.into_records() {
            let rec = rec?;
            let hostname = empty_opt(rec.get(i_h).unwrap_or(""));
            let ip = i_ip
                .and_then(|i| rec.get(i))
                .and_then(|s| empty_opt(s));
            let cpe_string = rec.get(i_c).unwrap_or("").trim().to_string();
            if cpe_string.is_empty() {
                return Err(IngestionError::Format(format!(
                    "{}: cpe_string must not be empty",
                    path.display()
                )));
            }
            let os = i_os
                .and_then(|i| rec.get(i))
                .and_then(|s| empty_opt(s));
            let id = if let Some(i) = i_id {
                parse_i64_cell(rec.get(i).unwrap_or(""))?
            } else {
                None
            };
            let created_at = if let Some(i) = i_created {
                let s = rec.get(i).unwrap_or("").trim();
                if s.is_empty() {
                    default_now.clone()
                } else {
                    s.to_string()
                }
            } else {
                default_now.clone()
            };

            out.push(AssetRecord {
                id,
                hostname,
                ip,
                cpe_string,
                os,
                created_at,
            });
        }
        return Ok(out);
    }

    Err(IngestionError::Format(format!(
        "{}: unrecognized asset CSV layout (expected hostname+cpe_string columns, or Hosts+cpe_string for ASM-style exports)",
        path.display()
    )))
}

// ---------------------------------------------------------------------------
// Asset–CVE mapping — CSV
// ---------------------------------------------------------------------------

/// Parse junction rows from a CSV with ``asset_id``, ``cve_id``, optional ``matched_on_date``.
pub fn parse_asset_cve_mapping_csv(path: &Path) -> Result<Vec<AssetCveMappingRecord>, IngestionError> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)?;
    let headers = rdr.headers()?.clone();

    let i_asset = find_header_index(&headers, &["asset_id", "asset", "fk_asset"])
        .ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: missing asset_id column",
                path.display()
            ))
        })?;
    let i_cve = find_header_index(&headers, &["cve_id", "cve", "fk_cve"])
        .ok_or_else(|| {
            IngestionError::Format(format!(
                "{}: missing cve_id column",
                path.display()
            ))
        })?;
    let i_matched = find_header_index(
        &headers,
        &["matched_on_date", "matched_at", "created_at"],
    );

    let default_now = utc_now_iso()?;
    let mut out: Vec<AssetCveMappingRecord> = Vec::new();

    for rec in rdr.into_records() {
        let rec = rec?;
        let asset_raw = rec.get(i_asset).unwrap_or("").trim();
        if asset_raw.is_empty() {
            continue;
        }
        let asset_id = asset_raw
            .parse::<i64>()
            .map_err(|e| IngestionError::Format(format!("invalid asset_id {:?}: {}", asset_raw, e)))?;

        let cve_id = rec.get(i_cve).unwrap_or("").trim().to_string();
        if cve_id.is_empty() {
            continue;
        }

        let matched_on_date = if let Some(i) = i_matched {
            let s = rec.get(i).unwrap_or("").trim();
            if s.is_empty() {
                default_now.clone()
            } else {
                s.to_string()
            }
        } else {
            default_now.clone()
        };

        out.push(AssetCveMappingRecord {
            asset_id,
            cve_id,
            matched_on_date,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Generic JSON value (raw feed inspection)
// ---------------------------------------------------------------------------

/// Read arbitrary JSON from disk (useful before dispatching to a typed parser).
pub fn parse_json_value(path: &Path) -> Result<Value, IngestionError> {
    let raw = read_utf8_file(path)?;
    let v: Value = serde_json::from_str(&raw)?;
    Ok(v)
}

pub mod cve_downloader;
pub mod easm_scanner;
pub mod mac_stealer;
pub mod ransomware_live;

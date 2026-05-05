//! Aggregated metrics for the main dashboard (SQLite + local vector store status).

use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardMetrics {
    pub total_iocs: u64,
    pub vulnerable_assets: u64,
    pub vector_db_connected: bool,
    pub vector_db_collection_ready: bool,
    pub vector_db_endpoint: String,
    pub vector_db_message: String,
    /// Canonical absolute SQLite vault path ([`crate::vault_db::get_vault_path`]).
    pub vault_db_absolute_path: String,
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let n: i32 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// ```sql
/// SELECT COUNT(*) FROM ioc_records;
/// ```
/// ```sql
/// SELECT COUNT(DISTINCT asset_target) FROM asset_cve_mapping;
/// ```
pub fn collect_sqlite_metrics(conn: &Connection) -> Result<(u64, u64), String> {
    let total_iocs = if table_exists(conn, "ioc_records").map_err(|e| e.to_string())? {
        conn.query_row("SELECT COUNT(*) FROM ioc_records", [], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())? as u64
    } else {
        0
    };

    let vulnerable_assets = if table_exists(conn, "asset_cve_mapping").map_err(|e| e.to_string())? {
        conn
            .query_row(
                "SELECT COUNT(DISTINCT asset_target) FROM asset_cve_mapping",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())? as u64
    } else {
        0
    };

    Ok((total_iocs, vulnerable_assets))
}

/// Row counts for core vault tables (canonical DB file — same source as ingestion).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStats {
    pub ioc_records: u64,
    pub asset_cve_mapping_rows: u64,
    pub cve_data_rows: u64,
    pub distinct_assets_with_cve: u64,
    pub vault_db_absolute_path: String,
}

pub fn collect_vault_stats(conn: &Connection) -> Result<VaultStats, String> {
    let ioc_records = if table_exists(conn, "ioc_records").map_err(|e| e.to_string())? {
        conn.query_row("SELECT COUNT(*) FROM ioc_records", [], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())? as u64
    } else {
        0
    };

    let asset_cve_mapping_rows = if table_exists(conn, "asset_cve_mapping").map_err(|e| e.to_string())? {
        conn.query_row("SELECT COUNT(*) FROM asset_cve_mapping", [], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())? as u64
    } else {
        0
    };

    let cve_data_rows = if table_exists(conn, "cve_data").map_err(|e| e.to_string())? {
        conn.query_row("SELECT COUNT(*) FROM cve_data", [], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())? as u64
    } else {
        0
    };

    let distinct_assets_with_cve = if table_exists(conn, "asset_cve_mapping").map_err(|e| e.to_string())? {
        conn
            .query_row(
                "SELECT COUNT(DISTINCT asset_target) FROM asset_cve_mapping",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())? as u64
    } else {
        0
    };

    Ok(VaultStats {
        ioc_records,
        asset_cve_mapping_rows,
        cve_data_rows,
        distinct_assets_with_cve,
        vault_db_absolute_path: String::new(),
    })
}

fn cve_description_from_metadata(meta: Option<String>) -> String {
    let Some(s) = meta.filter(|x| !x.is_empty()) else {
        return String::new();
    };
    if let Ok(v) = serde_json::from_str::<Value>(&s) {
        if let Some(d) = v.get("description").and_then(|x| x.as_str()) {
            return d.to_string();
        }
    }
    s.chars().take(400).collect()
}

/// Recent rows from `cve_data` for Threat Pulse (canonical vault only).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CvePulseRow {
    pub cve_id: String,
    pub severity_score: Option<f64>,
    pub description: String,
}

pub fn query_recent_cves_for_pulse(conn: &Connection, limit: u32) -> Result<Vec<CvePulseRow>, String> {
    if !table_exists(conn, "cve_data").map_err(|e| e.to_string())? {
        return Ok(Vec::new());
    }
    let lim = limit.clamp(1, 500) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT cve_id, severity_score, metadata FROM cve_data \
             ORDER BY datetime(COALESCE(NULLIF(updated_at, ''), NULLIF(published_date, ''), '1970-01-01')) DESC, cve_id DESC \
             LIMIT ?",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([lim], |row| {
            Ok(CvePulseRow {
                cve_id: row.get(0)?,
                severity_score: row.get(1)?,
                description: cve_description_from_metadata(row.get(2)?),
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Recent `ioc_records` for Threat Pulse / Barney (canonical vault).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IocPulseRow {
    pub ioc_value: String,
    pub ioc_type: String,
    pub last_seen: Option<String>,
    pub source_project: Option<String>,
}

pub fn query_recent_iocs_for_pulse(conn: &Connection, limit: u32) -> Result<Vec<IocPulseRow>, String> {
    if !table_exists(conn, "ioc_records").map_err(|e| e.to_string())? {
        return Ok(Vec::new());
    }
    let lim = limit.clamp(1, 500) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT ioc_value, ioc_type, last_seen, source_project FROM ioc_records \
             ORDER BY datetime(COALESCE(NULLIF(last_seen, ''), NULLIF(first_seen, ''), '1970-01-01')) DESC, ioc_value \
             LIMIT ?",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([lim], |row| {
            Ok(IocPulseRow {
                ioc_value: row.get(0)?,
                ioc_type: row.get(1)?,
                last_seen: row.get(2)?,
                source_project: row.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Recent `ransomware_events` rows for Threat Pulse / Barney LLM context (canonical vault).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RansomwarePulseRow {
    pub id: i64,
    pub event_date: Option<String>,
    pub victim_name: String,
    pub attack_details: String,
    pub source: Option<String>,
}

/// Five (or fewer) most recent ransomware incidents, ordered by event date when parseable, else by row id.
pub fn query_recent_ransomware_events(conn: &Connection, limit: u32) -> Result<Vec<RansomwarePulseRow>, String> {
    if !table_exists(conn, "ransomware_events").map_err(|e| e.to_string())? {
        return Ok(Vec::new());
    }
    let lim = limit.clamp(1, 500) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT id, event_date, victim_name, attack_details, source \
             FROM ransomware_events \
             ORDER BY \
               datetime( \
                 CASE \
                   WHEN event_date IS NOT NULL AND TRIM(event_date) != '' \
                   THEN TRIM(event_date) \
                   ELSE '1970-01-01' \
                 END \
               ) DESC, \
               id DESC \
             LIMIT ?",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([lim], |row| {
            Ok(RansomwarePulseRow {
                id: row.get(0)?,
                event_date: row.get(1)?,
                victim_name: row.get(2)?,
                attack_details: row.get(3)?,
                source: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Top CVEs by CVSS / recency for Barney environmental context.
pub fn query_critical_cves_for_barney(conn: &Connection, limit: u32) -> Result<Vec<CvePulseRow>, String> {
    if !table_exists(conn, "cve_data").map_err(|e| e.to_string())? {
        return Ok(Vec::new());
    }
    let lim = limit.clamp(1, 50) as i64;
    let mut stmt = conn
        .prepare(
            "SELECT cve_id, severity_score, metadata FROM cve_data \
             ORDER BY COALESCE(severity_score, -1.0) DESC, \
               datetime(COALESCE(NULLIF(updated_at, ''), NULLIF(published_date, ''), '1970-01-01')) DESC, \
               cve_id DESC \
             LIMIT ?",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([lim], |row| {
            Ok(CvePulseRow {
                cve_id: row.get(0)?,
                severity_score: row.get(1)?,
                description: cve_description_from_metadata(row.get(2)?),
            })
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Rough high-priority surface for hunter alerts (CVSS ≥ 8 CVEs + IOCs active in last 72h), capped at 10.
pub fn high_priority_target_count(conn: &Connection) -> Result<u32, String> {
    let cve_n: i64 = if table_exists(conn, "cve_data").map_err(|e| e.to_string())? {
        conn.query_row(
            "SELECT COUNT(*) FROM cve_data WHERE COALESCE(severity_score, 0) >= 8.0",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?
    } else {
        0
    };
    let ioc_n: i64 = if table_exists(conn, "ioc_records").map_err(|e| e.to_string())? {
        conn.query_row(
            "SELECT COUNT(*) FROM ioc_records WHERE \
             datetime(COALESCE(NULLIF(last_seen, ''), NULLIF(first_seen, ''), '1970-01-01')) > datetime('now', '-3 days')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?
    } else {
        0
    };
    let sum = (cve_n + std::cmp::min(ioc_n, 5)).min(10).max(0) as u32;
    Ok(sum)
}

fn llm_truncate_detail(s: &str, max_chars: usize) -> String {
    s.chars()
        .take(max_chars)
        .collect::<String>()
        .replace('\n', " ")
}

/// Compact plain-text summary for LLM injection: recent IOCs, CVEs, and ransomware activity with clear section markers.
pub fn format_recent_vault_llm_context(conn: &Connection) -> Result<String, String> {
    let iocs = query_recent_iocs_for_pulse(conn, 10)?;
    let cves = query_recent_cves_for_pulse(conn, 10)?;
    let ransomware = query_recent_ransomware_events(conn, 5)?;
    let mut lines: Vec<String> = Vec::new();

    lines.push("--- Recent IOCs ---".to_string());
    if iocs.is_empty() {
        lines.push("  (none in ioc_records)".to_string());
    } else {
        for r in &iocs {
            lines.push(format!(
                "  - [{}] {} | last_seen={:?} | source={:?}",
                r.ioc_type,
                r.ioc_value,
                r.last_seen.as_deref().unwrap_or("—"),
                r.source_project.as_deref().unwrap_or("—")
            ));
        }
    }

    lines.push(String::new());
    lines.push("--- Recent CVEs ---".to_string());
    if cves.is_empty() {
        lines.push("  (none in cve_data)".to_string());
    } else {
        for c in &cves {
            let desc = c.description.chars().take(200).collect::<String>();
            lines.push(format!(
                "  - {} | severity={:?} | {}",
                c.cve_id,
                c.severity_score,
                desc.replace('\n', " ")
            ));
        }
    }

    lines.push(String::new());
    lines.push("--- Recent Ransomware Activity ---".to_string());
    if ransomware.is_empty() {
        lines.push("  (none in ransomware_events)".to_string());
    } else {
        for ev in &ransomware {
            let detail = llm_truncate_detail(&ev.attack_details, 320);
            lines.push(format!(
                "  - id={} | date={:?} | victim={} | source={:?} | details={}",
                ev.id,
                ev.event_date.as_deref().unwrap_or("—"),
                ev.victim_name,
                ev.source.as_deref().unwrap_or("—"),
                detail
            ));
        }
    }

    Ok(lines.join("\n"))
}

/// Markdown block for Barney system context (last 10 critical CVEs + 10 recent IOCs).
pub fn format_barney_environmental_context(conn: &Connection) -> Result<String, String> {
    let cves = query_critical_cves_for_barney(conn, 10)?;
    let iocs = query_recent_iocs_for_pulse(conn, 10)?;
    let mut s = String::from("### Critical CVEs (top by score / recency)\n");
    if cves.is_empty() {
        s.push_str("_(none in cve_data)_\n");
    } else {
        for (i, c) in cves.iter().enumerate() {
            let desc = c.description.chars().take(200).collect::<String>();
            s.push_str(&format!(
                "{}. **{}** · score={:?} · {}\n",
                i + 1,
                c.cve_id,
                c.severity_score,
                desc.replace('\n', " ")
            ));
        }
    }
    s.push_str("\n### Recent IOCs (ioc_records)\n");
    if iocs.is_empty() {
        s.push_str("_(none in ioc_records)_\n");
    } else {
        for (i, r) in iocs.iter().enumerate() {
            s.push_str(&format!(
                "{}. `{}` · **{}** · last_seen={:?} · src={:?}\n",
                i + 1,
                r.ioc_value,
                r.ioc_type,
                r.last_seen.as_deref().unwrap_or("—"),
                r.source_project.as_deref().unwrap_or("—")
            ));
        }
    }
    Ok(s)
}

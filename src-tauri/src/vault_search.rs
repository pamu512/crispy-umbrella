//! Parameterized vault reads — no string-built SQL from untrusted callers.

use std::path::PathBuf;

use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Which vault relation to query (camelCase in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultEntity {
    IocRecords,
    IocNews,
    IocsLegacy,
    CveData,
    AsmAssets,
    RansomwareVictims,
}

/// Inclusive-ish date window on the entity’s primary timestamp columns (ISO-8601 strings).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DateRange {
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub end: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SearchOrder {
    RecentFirst,
    OldestFirst,
}

/// Strongly typed filters for [`search_vault`]. All string conditions are bound as parameters (`?`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchParams {
    pub workspace_path: String,
    pub entity: VaultEntity,
    #[serde(default)]
    pub text_contains: Option<String>,
    #[serde(default)]
    pub ioc_type: Option<String>,
    #[serde(default)]
    pub threat_actor: Option<String>,
    #[serde(default)]
    pub source_project: Option<String>,
    #[serde(default)]
    pub date_range: Option<DateRange>,
    #[serde(default)]
    pub cve_id_prefix: Option<String>,
    #[serde(default)]
    pub min_cvss: Option<f64>,
    #[serde(default)]
    pub max_cvss: Option<f64>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub order: Option<SearchOrder>,
}

/// Returns the canonical vault path ([`crate::vault_db::get_vault_path`]).
///
/// `workspace_path` is ignored for the database file location; workspace is only used by callers
/// for feature project directories.
pub fn resolve_vault_db_path(_workspace_path: &str) -> PathBuf {
    crate::vault_db::get_vault_path()
}

fn clamp_limit(limit: Option<u32>) -> u32 {
    let n = limit.unwrap_or(50);
    n.max(1).min(500)
}

fn like_pattern(raw: &str) -> String {
    let esc = raw.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("%{}%", esc)
}

fn row_to_json(cols: &[String], row: &rusqlite::Row<'_>) -> Result<Value, rusqlite::Error> {
    let mut map = Map::new();
    for (i, name) in cols.iter().enumerate() {
        let v = match row.get_ref(i)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(i) => Value::Number(i.into()),
            ValueRef::Real(f) => serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null),
            ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => Value::String(String::from_utf8_lossy(b).into_owned()),
        };
        map.insert(name.clone(), v);
    }
    Ok(Value::Object(map))
}

fn is_no_such_table(err: &rusqlite::Error) -> bool {
    err.to_string().to_lowercase().contains("no such table")
}

fn order_clause(entity: VaultEntity, order: Option<SearchOrder>) -> &'static str {
    let recent_first = matches!(order.unwrap_or(SearchOrder::RecentFirst), SearchOrder::RecentFirst);
    match entity {
        VaultEntity::CveData => {
            if recent_first {
                "ORDER BY datetime(COALESCE(NULLIF(updated_at, ''), NULLIF(published_date, ''), '1970-01-01')) DESC, cve_id DESC"
            } else {
                "ORDER BY datetime(COALESCE(NULLIF(updated_at, ''), NULLIF(published_date, ''), '1970-01-01')) ASC, cve_id ASC"
            }
        }
        VaultEntity::IocRecords => {
            if recent_first {
                "ORDER BY datetime(COALESCE(NULLIF(last_seen, ''), NULLIF(first_seen, ''), '1970-01-01')) DESC, ioc_value ASC"
            } else {
                "ORDER BY datetime(COALESCE(NULLIF(last_seen, ''), NULLIF(first_seen, ''), '1970-01-01')) ASC, ioc_value ASC"
            }
        }
        VaultEntity::AsmAssets => {
            if recent_first {
                "ORDER BY datetime(COALESCE(NULLIF(last_scan_at, ''), '1970-01-01')) DESC, asset_target ASC"
            } else {
                "ORDER BY datetime(COALESCE(NULLIF(last_scan_at, ''), '1970-01-01')) ASC, asset_target ASC"
            }
        }
        VaultEntity::IocNews => {
            if recent_first {
                "ORDER BY datetime(COALESCE(NULLIF(created_at, ''), NULLIF(ingested_at, ''), '1970-01-01')) DESC, url ASC"
            } else {
                "ORDER BY datetime(COALESCE(NULLIF(created_at, ''), NULLIF(ingested_at, ''), '1970-01-01')) ASC, url ASC"
            }
        }
        VaultEntity::IocsLegacy | VaultEntity::RansomwareVictims => {
            if recent_first {
                "ORDER BY rowid DESC"
            } else {
                "ORDER BY rowid ASC"
            }
        }
    }
}

/// Execute a vault search using only fixed SQL templates and `?` bindings.
pub fn execute_search(conn: &Connection, filters: &SearchParams) -> Result<Vec<Value>, String> {
    let lim = clamp_limit(filters.limit) as i64;
    match filters.entity {
        VaultEntity::IocRecords => search_ioc_records(conn, filters, lim),
        VaultEntity::IocNews => search_ioc_news(conn, filters, lim),
        VaultEntity::IocsLegacy => search_iocs_legacy(conn, filters, lim),
        VaultEntity::CveData => search_cve_data(conn, filters, lim),
        VaultEntity::AsmAssets => search_asm_assets(conn, filters, lim),
        VaultEntity::RansomwareVictims => search_ransomware(conn, filters, lim),
    }
}

fn search_ioc_records(
    conn: &Connection,
    f: &SearchParams,
    lim: i64,
) -> Result<Vec<Value>, String> {
    let ord = order_clause(VaultEntity::IocRecords, f.order);
    let mut sql = String::from(
        "SELECT ioc_value, ioc_type, first_seen, last_seen, source_project, metadata FROM ioc_records WHERE 1 = 1",
    );
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ref t) = f.text_contains {
        let pat = like_pattern(t.trim());
        sql.push_str(
            " AND (ioc_value LIKE ? ESCAPE '\\' OR ioc_type LIKE ? ESCAPE '\\' OR IFNULL(metadata, '') LIKE ? ESCAPE '\\')",
        );
        for _ in 0..3 {
            params.push(SqlValue::Text(pat.clone()));
        }
    }
    if let Some(ref t) = f.ioc_type {
        if !t.trim().is_empty() {
            sql.push_str(" AND ioc_type = ?");
            params.push(SqlValue::Text(t.trim().to_string()));
        }
    }
    if let Some(ref p) = f.source_project {
        if !p.trim().is_empty() {
            sql.push_str(" AND source_project = ?");
            params.push(SqlValue::Text(p.trim().to_string()));
        }
    }
    if let Some(ref a) = f.threat_actor {
        if !a.trim().is_empty() {
            sql.push_str(" AND lower(json_extract(metadata, '$.threat_actor')) = lower(?)");
            params.push(SqlValue::Text(a.trim().to_string()));
        }
    }
    if let Some(ref dr) = f.date_range {
        if let Some(ref s) = dr.start {
            if !s.trim().is_empty() {
                sql.push_str(" AND datetime(COALESCE(NULLIF(last_seen, ''), first_seen)) >= datetime(?)");
                params.push(SqlValue::Text(s.trim().to_string()));
            }
        }
        if let Some(ref e) = dr.end {
            if !e.trim().is_empty() {
                sql.push_str(" AND datetime(COALESCE(NULLIF(last_seen, ''), first_seen)) <= datetime(?)");
                params.push(SqlValue::Text(e.trim().to_string()));
            }
        }
    }

    sql.push(' ');
    sql.push_str(ord);
    sql.push_str(" LIMIT ?");
    params.push(SqlValue::Integer(lim));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params_from_iter(params), |row| row_to_json(&cols, row))
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn search_ioc_news(conn: &Connection, f: &SearchParams, lim: i64) -> Result<Vec<Value>, String> {
    let ord = order_clause(VaultEntity::IocNews, f.order);
    let mut sql = String::from(
        "SELECT title, url, source, content_preview, created_at, ingested_at FROM ioc_news WHERE 1 = 1",
    );
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ref t) = f.text_contains {
        let pat = like_pattern(t.trim());
        sql.push_str(
            " AND (IFNULL(title,'') LIKE ? ESCAPE '\\' OR IFNULL(url,'') LIKE ? ESCAPE '\\' OR IFNULL(source,'') LIKE ? ESCAPE '\\' OR IFNULL(content_preview,'') LIKE ? ESCAPE '\\')",
        );
        for _ in 0..4 {
            params.push(SqlValue::Text(pat.clone()));
        }
    }
    sql.push(' ');
    sql.push_str(ord);
    sql.push_str(" LIMIT ?");
    params.push(SqlValue::Integer(lim));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params_from_iter(params), |row| row_to_json(&cols, row))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn search_iocs_legacy(conn: &Connection, f: &SearchParams, lim: i64) -> Result<Vec<Value>, String> {
    let ord = order_clause(VaultEntity::IocsLegacy, f.order);
    let mut sql = String::from("SELECT ioc_value, type FROM iocs WHERE 1 = 1");
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ref t) = f.text_contains {
        let pat = like_pattern(t.trim());
        sql.push_str(" AND (ioc_value LIKE ? ESCAPE '\\' OR IFNULL(type,'') LIKE ? ESCAPE '\\')");
        params.push(SqlValue::Text(pat.clone()));
        params.push(SqlValue::Text(pat));
    }
    if let Some(ref ty) = f.ioc_type {
        if !ty.trim().is_empty() {
            sql.push_str(" AND type = ?");
            params.push(SqlValue::Text(ty.trim().to_string()));
        }
    }
    sql.push(' ');
    sql.push_str(ord);
    sql.push_str(" LIMIT ?");
    params.push(SqlValue::Integer(lim));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params_from_iter(params), |row| row_to_json(&cols, row))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn search_cve_data(conn: &Connection, f: &SearchParams, lim: i64) -> Result<Vec<Value>, String> {
    let ord = order_clause(VaultEntity::CveData, f.order);
    let mut sql = String::from(
        "SELECT cve_id, severity_score, published_date, updated_at, metadata FROM cve_data WHERE 1 = 1",
    );
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ref t) = f.text_contains {
        let pat = like_pattern(t.trim());
        sql.push_str(" AND (cve_id LIKE ? ESCAPE '\\' OR IFNULL(metadata,'') LIKE ? ESCAPE '\\')");
        params.push(SqlValue::Text(pat.clone()));
        params.push(SqlValue::Text(pat));
    }
    if let Some(ref p) = f.cve_id_prefix {
        if !p.trim().is_empty() {
            let pref = format!("{}%", p.trim().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
            sql.push_str(" AND cve_id LIKE ? ESCAPE '\\'");
            params.push(SqlValue::Text(pref));
        }
    }
    if let Some(lo) = f.min_cvss {
        sql.push_str(" AND severity_score IS NOT NULL AND severity_score >= ?");
        params.push(SqlValue::Real(lo));
    }
    if let Some(hi) = f.max_cvss {
        sql.push_str(" AND severity_score IS NOT NULL AND severity_score <= ?");
        params.push(SqlValue::Real(hi));
    }
    if let Some(ref dr) = f.date_range {
        if let Some(ref s) = dr.start {
            if !s.trim().is_empty() {
                sql.push_str(" AND datetime(COALESCE(NULLIF(published_date, ''), '1970-01-01')) >= datetime(?)");
                params.push(SqlValue::Text(s.trim().to_string()));
            }
        }
        if let Some(ref e) = dr.end {
            if !e.trim().is_empty() {
                sql.push_str(" AND datetime(COALESCE(NULLIF(published_date, ''), '1970-01-01')) <= datetime(?)");
                params.push(SqlValue::Text(e.trim().to_string()));
            }
        }
    }

    sql.push(' ');
    sql.push_str(ord);
    sql.push_str(" LIMIT ?");
    params.push(SqlValue::Integer(lim));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params_from_iter(params), |row| row_to_json(&cols, row))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn search_asm_assets(conn: &Connection, f: &SearchParams, lim: i64) -> Result<Vec<Value>, String> {
    let ord = order_clause(VaultEntity::AsmAssets, f.order);
    let mut sql = String::from(
        "SELECT asset_target, asset_type, last_scan_at, status, metadata FROM asm_assets WHERE 1 = 1",
    );
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ref t) = f.text_contains {
        let pat = like_pattern(t.trim());
        sql.push_str(" AND (asset_target LIKE ? ESCAPE '\\' OR IFNULL(metadata,'') LIKE ? ESCAPE '\\')");
        params.push(SqlValue::Text(pat.clone()));
        params.push(SqlValue::Text(pat));
    }
    sql.push(' ');
    sql.push_str(ord);
    sql.push_str(" LIMIT ?");
    params.push(SqlValue::Integer(lim));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params_from_iter(params), |row| row_to_json(&cols, row))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn search_ransomware(conn: &Connection, f: &SearchParams, lim: i64) -> Result<Vec<Value>, String> {
    let ord = order_clause(VaultEntity::RansomwareVictims, f.order);
    let mut sql = String::from("SELECT company, group_name FROM Ransomware_live_event_victim WHERE 1 = 1");
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(ref t) = f.text_contains {
        let pat = like_pattern(t.trim());
        sql.push_str(" AND (IFNULL(company,'') LIKE ? ESCAPE '\\' OR IFNULL(group_name,'') LIKE ? ESCAPE '\\')");
        params.push(SqlValue::Text(pat.clone()));
        params.push(SqlValue::Text(pat));
    }
    sql.push(' ');
    sql.push_str(ord);
    sql.push_str(" LIMIT ?");
    params.push(SqlValue::Integer(lim));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt
        .query_map(params_from_iter(params), |row| row_to_json(&cols, row))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

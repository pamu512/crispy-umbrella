//! Central SQLite vault: WAL, busy timeout, schema migrations, IOC backfills.
//! Canonical tables: `cve_data`, `asm_assets`, `ioc_records` (see product spec).

use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;
use serde_json::json;

pub fn open_vault(db_path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    conn
        .busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    conn
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| e.to_string())?;
    conn
        .pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| e.to_string())?;
    run_migrations(&conn)?;
    self_heal_legacy_tables(&conn)?;
    Ok(conn)
}

fn user_version(conn: &Connection) -> i32 {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0)
}

fn set_user_version(conn: &Connection, v: i32) -> Result<(), String> {
    conn.execute_batch(&format!("PRAGMA user_version = {v};"))
        .map_err(|e| e.to_string())
}

fn run_migrations(conn: &Connection) -> Result<(), String> {
    if user_version(conn) < 2 {
        migrate_to_v2(conn)?;
        set_user_version(conn, 2)?;
    }
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, String> {
    let n: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

pub fn column_names(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

fn create_modern_cve(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS cve_data (
            cve_id TEXT PRIMARY KEY NOT NULL,
            severity_score REAL,
            published_date TEXT,
            updated_at TEXT,
            metadata TEXT
        );",
    )
    .map_err(|e| e.to_string())
}

fn create_modern_asm(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS asm_assets (
            asset_target TEXT PRIMARY KEY NOT NULL,
            asset_type TEXT,
            last_scan_at TEXT,
            status TEXT,
            metadata TEXT
        );",
    )
    .map_err(|e| e.to_string())
}

pub fn ensure_ioc_records(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r"CREATE TABLE IF NOT EXISTS ioc_records (
            ioc_value TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            source_project TEXT,
            metadata TEXT,
            PRIMARY KEY (ioc_value, ioc_type)
        );",
    )
    .map_err(|e| e.to_string())
}

/// Idempotent: normalize pre-v2 `cve_data` (id + description columns) into spec columns.
pub fn migrate_cve_legacy_if_needed(conn: &Connection) -> Result<(), String> {
    if !table_exists(conn, "cve_data")? {
        return create_modern_cve(conn);
    }
    let cols = column_names(conn, "cve_data")?;
    if cols.contains(&"metadata".to_string()) {
        return Ok(());
    }
    conn.execute("ALTER TABLE cve_data RENAME TO cve_data_legacy", [])
        .map_err(|e| e.to_string())?;
    create_modern_cve(conn)?;
    let now = time_now_iso();
    {
        let mut stmt = conn
            .prepare(
                "SELECT cve_id, cvss_score, description FROM cve_data_legacy",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (cve_id, cvss, desc) = row.map_err(|e| e.to_string())?;
            let severity = cvss.as_deref().and_then(parse_cvss_base_score);
            let meta = json!({
                "description": desc.unwrap_or_default(),
                "legacy_cvss_display": cvss,
            })
            .to_string();
            conn.execute(
                "INSERT INTO cve_data (cve_id, severity_score, published_date, updated_at, metadata) VALUES (?1, ?2, '', ?3, ?4)",
                rusqlite::params![cve_id, severity, &now, meta],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    conn.execute("DROP TABLE cve_data_legacy", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Idempotent: normalize legacy `asm_assets` (`asset`, `alert_type`) into spec columns.
pub fn migrate_asm_legacy_if_needed(conn: &Connection) -> Result<(), String> {
    if !table_exists(conn, "asm_assets")? {
        return create_modern_asm(conn);
    }
    let cols = column_names(conn, "asm_assets")?;
    if cols.contains(&"asset_target".to_string()) {
        return Ok(());
    }
    if cols.contains(&"asset".to_string()) {
        conn.execute("ALTER TABLE asm_assets RENAME TO asm_assets_legacy", [])
            .map_err(|e| e.to_string())?;
        create_modern_asm(conn)?;
        {
            let mut stmt = conn
                .prepare("SELECT asset, alert_type, timestamp FROM asm_assets_legacy")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (asset, alert, ts) = row.map_err(|e| e.to_string())?;
                let meta = json!({ "legacy_alert_type": alert }).to_string();
                let atype = if asset.contains('|') {
                    "host_ip"
                } else {
                    "subdomain"
                };
                conn.execute(
                    "INSERT INTO asm_assets (asset_target, asset_type, last_scan_at, status, metadata) VALUES (?1, ?2, ?3, 'active', ?4)",
                    rusqlite::params![asset, atype, ts.unwrap_or_default(), meta],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        conn.execute("DROP TABLE asm_assets_legacy", [])
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    create_modern_asm(conn)?;
    Ok(())
}

fn migrate_to_v2(conn: &Connection) -> Result<(), String> {
    migrate_cve_legacy_if_needed(conn)?;
    migrate_asm_legacy_if_needed(conn)?;
    ensure_ioc_records(conn)?;
    let _ = backfill_ioc_records_from_news(conn)?;
    let _ = backfill_ioc_records_from_legacy_iocs(conn)?;
    Ok(())
}

/// Re-run legacy normalizers if an external script recreated old shapes (user_version already 2).
fn self_heal_legacy_tables(conn: &Connection) -> Result<(), String> {
    if user_version(conn) < 2 {
        return Ok(());
    }
    migrate_cve_legacy_if_needed(conn)?;
    migrate_asm_legacy_if_needed(conn)?;
    ensure_ioc_records(conn)?;
    let _ = backfill_ioc_records_from_news(conn)?;
    let _ = backfill_ioc_records_from_legacy_iocs(conn)?;
    Ok(())
}

pub fn time_now_iso() -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new())
}

pub fn parse_cvss_base_score(s: &str) -> Option<f64> {
    let t = s.trim();
    let num: String = t
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if num.is_empty() {
        return None;
    }
    num.parse().ok()
}

/// Map `ioc_news` rows into `ioc_records` (dedupe on value+type).
pub fn backfill_ioc_records_from_news(conn: &Connection) -> Result<usize, String> {
    if !table_exists(conn, "ioc_news")? {
        return Ok(0);
    }
    ensure_ioc_records(conn)?;
    let cols = column_names(conn, "ioc_news")?;
    if cols.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn
        .prepare("SELECT * FROM ioc_news")
        .map_err(|e| e.to_string())?;
    let ncols = stmt.column_count();
    let cnames: Vec<String> = (0..ncols)
        .map(|i| stmt.column_name(i).unwrap_or("").to_string())
        .collect();

    fn idx(names: &[String], key: &str) -> Option<usize> {
        names.iter().position(|n| n == key)
    }

    let i_url = idx(&cnames, "url");
    let i_title = idx(&cnames, "title");
    let i_source = idx(&cnames, "source");
    let i_preview = idx(&cnames, "content_preview");
    let i_created = idx(&cnames, "created_at").or_else(|| idx(&cnames, "ingested_at"));

    let mut n = 0usize;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let url = i_url
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let title = i_title
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let source = i_source
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let preview = i_preview
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let ts = i_created
            .and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
            .unwrap_or_default();
        let ts2 = if ts.is_empty() {
            time_now_iso()
        } else {
            ts.clone()
        };

        let url_t = url.trim();
        let title_t = title.trim();
        if url_t.is_empty() && title_t.is_empty() {
            continue;
        }
        let (ioc_value, ioc_type) = if !url_t.is_empty() {
            (url_t.to_string(), "url".to_string())
        } else {
            (title_t.to_string(), "news_title".to_string())
        };
        let meta = json!({
            "title": title,
            "source": source,
            "content_preview": preview.chars().take(2000).collect::<String>(),
        })
        .to_string();
        conn.execute(
            "INSERT INTO ioc_records (ioc_value, ioc_type, first_seen, last_seen, source_project, metadata)
             VALUES (?1, ?2, ?3, ?4, 'IOCs-crawler-main', ?5)
             ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET
               last_seen = excluded.last_seen,
               metadata = excluded.metadata,
               source_project = excluded.source_project",
            rusqlite::params![ioc_value, ioc_type, ts2, ts2, meta],
        )
        .map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

fn backfill_ioc_records_from_legacy_iocs(conn: &Connection) -> Result<usize, String> {
    if !table_exists(conn, "iocs")? {
        return Ok(0);
    }
    ensure_ioc_records(conn)?;
    let cols = column_names(conn, "iocs")?;
    if !cols.iter().any(|c| c == "ioc_value") {
        return Ok(0);
    }
    let tc = if cols.contains(&"ioc_type".to_string()) {
        "ioc_type"
    } else if cols.contains(&"type".to_string()) {
        "type"
    } else {
        return Ok(0);
    };
    let sql = format!(
        "INSERT INTO ioc_records (ioc_value, ioc_type, first_seen, last_seen, source_project, metadata)
         SELECT TRIM(ioc_value), TRIM(COALESCE({tc}, 'unknown')), '', '', 'legacy_iocs', NULL FROM iocs
         WHERE TRIM(ioc_value) != ''
         ON CONFLICT(ioc_value, ioc_type) DO NOTHING"
    );
    let n = conn.execute(&sql, []).map_err(|e| e.to_string())?;
    Ok(n as usize)
}

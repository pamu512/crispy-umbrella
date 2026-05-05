//! One-degree pivot graph over `ioc_records` for analyst exploration.
//!
//! `ioc_id` is normally the raw `ioc_value`. Optionally append a unit separator (U+001F)
//! and `ioc_type` to pin a single row: `example.com\u{001f}domain`.
//!
//! Relationships (edges) within one hop:
//! - **same_source_project** — another IOC row shares the same non-empty `source_project`.
//! - **same_threat_actor** — `json_extract(metadata, '$.threat_actor')` matches (case-insensitive), non-empty.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::vault_db;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    /// IOC indicator category (e.g. `domain`, `url`, `ip`).
    #[serde(rename = "type")]
    pub node_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PivotGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

// ---------------------------------------------------------------------------
// IOC identity helpers
// ---------------------------------------------------------------------------

const IOC_ID_SEP: char = '\u{001f}';

/// Stable graph id: `ioc_value` + unit separator + `ioc_type` (separator is invalid in URLs).
pub fn ioc_graph_id(ioc_value: &str, ioc_type: &str) -> String {
    format!("{ioc_value}{IOC_ID_SEP}{ioc_type}")
}

fn parse_ioc_selector(ioc_id: &str) -> (String, Option<String>) {
    let t = ioc_id.trim();
    if let Some(i) = t.find(IOC_ID_SEP) {
        let v = t[..i].trim().to_string();
        let ty = t[i + IOC_ID_SEP.len_utf8()..].trim().to_string();
        if v.is_empty() {
            return (String::new(), None);
        }
        if ty.is_empty() {
            return (v, None);
        }
        return (v, Some(ty));
    }
    if t.is_empty() {
        (String::new(), None)
    } else {
        (t.to_string(), None)
    }
}

fn is_no_such_table(err: &rusqlite::Error) -> bool {
    err.to_string().to_lowercase().contains("no such table")
}

// ---------------------------------------------------------------------------
// Core query + mapping
// ---------------------------------------------------------------------------

/// Full SQL: anchor IOC (latest activity), then all distinct neighbors linked by project or threat actor.
const PIVOT_NEIGHBORS_SQL: &str = r#"
WITH anchor AS (
    SELECT
        i.ioc_value AS av,
        i.ioc_type AS at,
        NULLIF(TRIM(COALESCE(i.source_project, '')), '') AS sp,
        lower(trim(COALESCE(json_extract(i.metadata, '$.threat_actor'), '')))) AS th
    FROM ioc_records AS i
    WHERE i.ioc_value = ?1
      AND (?2 = '' OR i.ioc_type = ?2)
    ORDER BY
        datetime(COALESCE(NULLIF(i.last_seen, ''), NULLIF(i.first_seen, ''), '1970-01-01')) DESC,
        i.ioc_type ASC
    LIMIT 1
),
neighbor_rows AS (
    SELECT
        n.ioc_value AS nv,
        n.ioc_type AS nt,
        n.source_project AS nsp,
        n.metadata AS nmeta,
        'same_source_project' AS rel
    FROM anchor AS a
    INNER JOIN ioc_records AS n
        ON a.sp IS NOT NULL
       AND NULLIF(TRIM(COALESCE(n.source_project, '')), '') = a.sp
       AND NOT (n.ioc_value = a.av AND n.ioc_type = a.at)
    UNION ALL
    SELECT
        n.ioc_value AS nv,
        n.ioc_type AS nt,
        n.source_project AS nsp,
        n.metadata AS nmeta,
        'same_threat_actor' AS rel
    FROM anchor AS a
    INNER JOIN ioc_records AS n
        ON a.th IS NOT NULL
       AND a.th != ''
       AND lower(trim(COALESCE(json_extract(n.metadata, '$.threat_actor'), '')))) = a.th
       AND NOT (n.ioc_value = a.av AND n.ioc_type = a.at)
)
SELECT nv, nt, nsp, nmeta, rel FROM neighbor_rows
"#;

fn fetch_anchor_row(
    conn: &Connection,
    ioc_value: &str,
    type_filter: Option<&str>,
) -> Result<Option<(String, String, Option<String>, Option<String>)>, String> {
    let tf = type_filter.map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("");
    let mut stmt = match conn.prepare(
        r#"
        SELECT
            i.ioc_value,
            i.ioc_type,
            i.source_project,
            i.metadata
        FROM ioc_records AS i
        WHERE i.ioc_value = ?1
          AND (?2 = '' OR i.ioc_type = ?2)
        ORDER BY
            datetime(COALESCE(NULLIF(i.last_seen, ''), NULLIF(i.first_seen, ''), '1970-01-01')) DESC,
            i.ioc_type ASC
        LIMIT 1
        "#,
    ) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let row = stmt
        .query_row(params![ioc_value, tf], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(row)
}

fn node_label(ioc_value: &str, ioc_type: &str) -> String {
    if ioc_type.is_empty() || ioc_type == "unknown" {
        ioc_value.to_string()
    } else {
        format!("{ioc_value} ({ioc_type})")
    }
}

fn row_to_graph_node(ioc_value: &str, ioc_type: &str) -> GraphNode {
    GraphNode {
        id: ioc_graph_id(ioc_value, ioc_type),
        label: node_label(ioc_value, ioc_type),
        node_type: ioc_type.to_string(),
    }
}

/// Build a pivot graph for the IOC identified by `ioc_id` (see [`parse_ioc_selector`]).
pub fn build_pivot_graph(db_path: &Path, ioc_id: &str) -> Result<PivotGraph, String> {
    let (ioc_value, type_opt) = parse_ioc_selector(ioc_id);
    if ioc_value.is_empty() {
        return Err("ioc_id is empty".into());
    }
    let type_filter = type_opt.as_deref();

    let conn = vault_db::open_vault(db_path)?;

    let anchor = match fetch_anchor_row(&conn, &ioc_value, type_filter)? {
        Some(a) => a,
        None => {
            return Ok(PivotGraph {
                nodes: vec![],
                edges: vec![],
            });
        }
    };

    let (av, at, _, _) = &anchor;
    let anchor_id = ioc_graph_id(av, at);

    let mut nodes_map: HashMap<String, GraphNode> = HashMap::new();
    nodes_map.insert(anchor_id.clone(), row_to_graph_node(av, at));

    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut edge_keys: HashSet<(String, String, String)> = HashSet::new();

    let tf = type_filter.unwrap_or("").to_string();
    let mut stmt = match conn.prepare(PIVOT_NEIGHBORS_SQL) {
        Ok(s) => s,
        Err(e) if is_no_such_table(&e) => {
            return Ok(PivotGraph {
                nodes: nodes_map.into_values().collect(),
                edges,
            });
        }
        Err(e) => return Err(e.to_string()),
    };

    let mut rows = stmt.query(params![ioc_value, tf]).map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let nv: String = row.get(0).map_err(|e| e.to_string())?;
        let nt: String = row.get(1).map_err(|e| e.to_string())?;
        let rel: String = row.get(4).map_err(|e| e.to_string())?;

        let nid = ioc_graph_id(&nv, &nt);
        nodes_map.entry(nid.clone()).or_insert_with(|| row_to_graph_node(&nv, &nt));

        let ek = (anchor_id.clone(), nid.clone(), rel.clone());
        if edge_keys.insert(ek) {
            edges.push(GraphEdge {
                source_id: anchor_id.clone(),
                target_id: nid,
                relationship_type: rel,
            });
        }
    }

    let mut nodes: Vec<GraphNode> = nodes_map.into_values().collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    edges.sort_by(|a, b| {
        a.source_id
            .cmp(&b.source_id)
            .then_with(|| a.target_id.cmp(&b.target_id))
            .then_with(|| a.relationship_type.cmp(&b.relationship_type))
    });

    Ok(PivotGraph { nodes, edges })
}

/// [`build_pivot_graph`] using the canonical vault path ([`vault_db::get_vault_path`]).
#[allow(dead_code)]
pub fn pivot_from_workspace(_workspace_path: &str, ioc_id: &str) -> Result<PivotGraph, String> {
    let db_path = vault_db::get_vault_path();
    build_pivot_graph(&db_path, ioc_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_graph_id_roundtrip() {
        let id = ioc_graph_id("1.2.3.4", "ip");
        assert_eq!(parse_ioc_selector(&id), ("1.2.3.4".into(), Some("ip".into())));
    }
}

//! Compile Structured Hunter JSON AST into parameterized SQLite for the CTI vault.
//!
//! All dynamic values are bound as `?` parameters. Tables and column references are fixed
//! whitelists per [`VaultEntity`] — never built from user input.
#![allow(dead_code)] // Public API for upcoming Tauri wiring; `cargo test` exercises it.

use std::fmt;

use rusqlite::types::Value as SqlValue;
use serde_json::Value;

use crate::vault_search::VaultEntity;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Full `SELECT … FROM … WHERE … ORDER BY … LIMIT ?` with `?` only in the WHERE/LIMIT tail.
#[derive(Debug, Clone)]
pub struct CompiledQuery {
    pub sql: String,
    pub params: Vec<SqlValue>,
}

#[derive(Debug, Clone)]
pub enum CompileError {
    InvalidJson(String),
    UnsupportedSchemaVersion(u64),
    MissingRootKey(&'static str),
    MissingNodeType,
    UnknownAstNodeType(String),
    MissingPredicateKey(&'static str),
    UnknownPredicateField(String),
    UnknownOperator(String),
    UnsupportedOperatorForField {
        surface: VaultEntity,
        field: HuntField,
        operator: HuntOperator,
    },
    UnsupportedFieldForSurface {
        surface: VaultEntity,
        field: HuntField,
    },
    InvalidNumericValue(String),
    MissingGroupChildren,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::InvalidJson(s) => write!(f, "invalid JSON: {s}"),
            CompileError::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported AST schemaVersion: {v} (expected 1)")
            }
            CompileError::MissingRootKey(k) => write!(f, "missing root key: {k}"),
            CompileError::MissingNodeType => write!(f, "AST node missing \"type\""),
            CompileError::UnknownAstNodeType(t) => write!(f, "unknown AST node type: {t}"),
            CompileError::MissingPredicateKey(k) => write!(f, "predicate missing key: {k}"),
            CompileError::UnknownPredicateField(s) => write!(f, "unknown predicate field: {s}"),
            CompileError::UnknownOperator(s) => write!(f, "unknown operator: {s}"),
            CompileError::UnsupportedOperatorForField {
                surface,
                field,
                operator,
            } => write!(
                f,
                "operator {operator:?} is not allowed for field {field:?} on surface {surface:?}"
            ),
            CompileError::UnsupportedFieldForSurface { surface, field } => {
                write!(f, "field {field:?} is not supported for surface {surface:?}")
            }
            CompileError::InvalidNumericValue(s) => {
                write!(f, "value must be a valid number for this comparison: {s}")
            }
            CompileError::MissingGroupChildren => write!(f, "group node missing \"children\" array"),
        }
    }
}

impl std::error::Error for CompileError {}

/// Parse JSON (root object with `schemaVersion` + `tree`) and compile to executable SQL.
pub fn compile_hunt_ast_json(
    surface: VaultEntity,
    ast_json: &str,
    limit: u32,
) -> Result<CompiledQuery, CompileError> {
    let v: Value = serde_json::from_str(ast_json).map_err(|e| CompileError::InvalidJson(e.to_string()))?;
    let root = parse_ast_root(&v)?;
    compile_hunt_ast(surface, &root, limit)
}

fn parse_ast_root(v: &Value) -> Result<AstRoot, CompileError> {
    let ver = v
        .get("schemaVersion")
        .and_then(|x| x.as_u64())
        .ok_or(CompileError::MissingRootKey("schemaVersion"))?;
    if ver != 1 {
        return Err(CompileError::UnsupportedSchemaVersion(ver));
    }
    let tree = v.get("tree").ok_or(CompileError::MissingRootKey("tree"))?;
    let tree = parse_node(tree)?;
    Ok(AstRoot { tree })
}

pub fn compile_hunt_ast(surface: VaultEntity, root: &AstRoot, limit: u32) -> Result<CompiledQuery, CompileError> {
    let lim = limit.max(1).min(500) as i64;
    let (where_sql, mut params) = compile_node(surface, &root.tree)?;
    let order = order_clause_sql(surface);
    let (select_from, _) = select_from_for_surface(surface);
    let sql = format!("{select_from} WHERE ({where_sql}) {order} LIMIT ?");
    params.push(SqlValue::Integer(lim));
    Ok(CompiledQuery { sql, params })
}

// ---------------------------------------------------------------------------
// AST (mirrors frontend `StructuredHunter`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AstRoot {
    pub tree: AstNode,
}

#[derive(Debug, Clone)]
pub enum AstNode {
    Predicate {
        field: HuntField,
        operator: HuntOperator,
        value: String,
    },
    Group {
        op: GroupOp,
        children: Vec<AstNode>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuntField {
    ThreatActor,
    Severity,
    IocType,
    IocValue,
    CveId,
    AssetTarget,
    SourceProject,
    IngestedAfter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuntOperator {
    Eq,
    Neq,
    Contains,
    StartsWith,
    EndsWith,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl HuntField {
    fn from_wire(s: &str) -> Result<Self, CompileError> {
        match s {
            "threat_actor" => Ok(Self::ThreatActor),
            "severity" => Ok(Self::Severity),
            "ioc_type" => Ok(Self::IocType),
            "ioc_value" => Ok(Self::IocValue),
            "cve_id" => Ok(Self::CveId),
            "asset_target" => Ok(Self::AssetTarget),
            "source_project" => Ok(Self::SourceProject),
            "ingested_after" => Ok(Self::IngestedAfter),
            other => Err(CompileError::UnknownPredicateField(other.to_string())),
        }
    }
}

impl HuntOperator {
    fn from_wire(s: &str) -> Result<Self, CompileError> {
        match s {
            "eq" => Ok(Self::Eq),
            "neq" => Ok(Self::Neq),
            "contains" => Ok(Self::Contains),
            "starts_with" => Ok(Self::StartsWith),
            "ends_with" => Ok(Self::EndsWith),
            "gt" => Ok(Self::Gt),
            "gte" => Ok(Self::Gte),
            "lt" => Ok(Self::Lt),
            "lte" => Ok(Self::Lte),
            other => Err(CompileError::UnknownOperator(other.to_string())),
        }
    }
}

fn parse_node(v: &Value) -> Result<AstNode, CompileError> {
    let ty = v
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or(CompileError::MissingNodeType)?;
    match ty {
        "predicate" => {
            let field = v
                .get("field")
                .and_then(|x| x.as_str())
                .ok_or(CompileError::MissingPredicateKey("field"))?;
            let operator = v
                .get("operator")
                .and_then(|x| x.as_str())
                .ok_or(CompileError::MissingPredicateKey("operator"))?;
            let value = v
                .get("value")
                .and_then(|x| x.as_str())
                .ok_or(CompileError::MissingPredicateKey("value"))?;
            Ok(AstNode::Predicate {
                field: HuntField::from_wire(field)?,
                operator: HuntOperator::from_wire(operator)?,
                value: value.to_string(),
            })
        }
        "group" => {
            let op = v
                .get("op")
                .and_then(|x| x.as_str())
                .ok_or(CompileError::MissingPredicateKey("op"))?;
            let op = match op {
                "and" => GroupOp::And,
                "or" => GroupOp::Or,
                other => return Err(CompileError::UnknownAstNodeType(format!("group.op={other}"))),
            };
            let arr = v.get("children").and_then(|x| x.as_array()).ok_or(CompileError::MissingGroupChildren)?;
            let mut children = Vec::with_capacity(arr.len());
            for item in arr {
                children.push(parse_node(item)?);
            }
            Ok(AstNode::Group { op, children })
        }
        other => Err(CompileError::UnknownAstNodeType(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Field / operator whitelist
// ---------------------------------------------------------------------------

fn field_on_surface(surface: VaultEntity, field: HuntField) -> bool {
    use HuntField::*;
    matches!(
        (surface, field),
        (VaultEntity::IocRecords, ThreatActor | Severity | IocType | IocValue | SourceProject | IngestedAfter)
            | (VaultEntity::CveData, CveId | Severity | ThreatActor | IngestedAfter)
            | (VaultEntity::AsmAssets, AssetTarget | ThreatActor | Severity | IngestedAfter)
            | (VaultEntity::IocNews, SourceProject | IocValue | IngestedAfter)
            | (VaultEntity::IocsLegacy, IocType | IocValue)
            | (VaultEntity::RansomwareVictims, IocValue)
    )
}

fn operator_allowed_on_surface(surface: VaultEntity, field: HuntField, op: HuntOperator) -> bool {
    use HuntField::*;
    use HuntOperator::*;
    let text_ops = [Eq, Neq, Contains, StartsWith, EndsWith];
    let all = [Eq, Neq, Contains, StartsWith, EndsWith, Gt, Gte, Lt, Lte];

    match (surface, field) {
        (VaultEntity::IocRecords, ThreatActor) => text_ops.contains(&op),
        (VaultEntity::IocRecords, Severity) => all.contains(&op),
        (VaultEntity::IocRecords, IocType | IocValue | SourceProject) => text_ops.contains(&op),
        (VaultEntity::IocRecords, IngestedAfter) => [Eq, Gt, Gte, Lt, Lte, Neq].contains(&op),

        (VaultEntity::CveData, CveId) => text_ops.contains(&op),
        (VaultEntity::CveData, Severity) => all.contains(&op),
        (VaultEntity::CveData, ThreatActor) => text_ops.contains(&op),
        (VaultEntity::CveData, IngestedAfter) => [Eq, Gt, Gte, Lt, Lte, Neq].contains(&op),

        (VaultEntity::AsmAssets, AssetTarget) => text_ops.contains(&op),
        (VaultEntity::AsmAssets, ThreatActor) => text_ops.contains(&op),
        (VaultEntity::AsmAssets, Severity) => all.contains(&op),
        (VaultEntity::AsmAssets, IngestedAfter) => [Eq, Gt, Gte, Lt, Lte, Neq].contains(&op),

        (VaultEntity::IocNews, SourceProject) => text_ops.contains(&op),
        (VaultEntity::IocNews, IocValue) => text_ops.contains(&op),
        (VaultEntity::IocNews, IngestedAfter) => [Eq, Gt, Gte, Lt, Lte, Neq].contains(&op),

        (VaultEntity::IocsLegacy, IocType | IocValue) => text_ops.contains(&op),

        (VaultEntity::RansomwareVictims, IocValue) => text_ops.contains(&op),

        _ => false,
    }
}

// ---------------------------------------------------------------------------
// SQL fragments
// ---------------------------------------------------------------------------

fn like_escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn like_substring_pattern(raw: &str) -> String {
    let esc = like_escape(raw.trim());
    format!("%{esc}%")
}

fn like_prefix_pattern(raw: &str) -> String {
    let esc = like_escape(raw.trim());
    format!("{esc}%")
}

fn like_suffix_pattern(raw: &str) -> String {
    let esc = like_escape(raw.trim());
    format!("%{esc}")
}

fn parse_f64_for_compare(s: &str) -> Result<f64, CompileError> {
    s.trim()
        .parse::<f64>()
        .map_err(|_| CompileError::InvalidNumericValue(s.to_string()))
}

fn compile_node(surface: VaultEntity, node: &AstNode) -> Result<(String, Vec<SqlValue>), CompileError> {
    match node {
        AstNode::Predicate {
            field,
            operator,
            value,
        } => compile_predicate(surface, *field, *operator, value),
        AstNode::Group { op, children } => {
            if children.is_empty() {
                return Ok(("1 = 1".to_string(), Vec::new()));
            }
            let join = match op {
                GroupOp::And => " AND ",
                GroupOp::Or => " OR ",
            };
            let mut parts = Vec::with_capacity(children.len());
            let mut params: Vec<SqlValue> = Vec::new();
            for ch in children {
                let (s, mut ps) = compile_node(surface, ch)?;
                parts.push(format!("({s})"));
                params.append(&mut ps);
            }
            Ok((parts.join(join), params))
        }
    }
}

fn compile_predicate(
    surface: VaultEntity,
    field: HuntField,
    op: HuntOperator,
    value: &str,
) -> Result<(String, Vec<SqlValue>), CompileError> {
    if !field_on_surface(surface, field) {
        return Err(CompileError::UnsupportedFieldForSurface { surface, field });
    }
    if !operator_allowed_on_surface(surface, field, op) {
        return Err(CompileError::UnsupportedOperatorForField {
            surface,
            field,
            operator: op,
        });
    }

    match surface {
        VaultEntity::IocRecords => compile_ioc_records(field, op, value),
        VaultEntity::CveData => compile_cve_data(field, op, value),
        VaultEntity::AsmAssets => compile_asm_assets(field, op, value),
        VaultEntity::IocNews => compile_ioc_news(field, op, value),
        VaultEntity::IocsLegacy => compile_iocs_legacy(field, op, value),
        VaultEntity::RansomwareVictims => compile_ransomware(field, op, value),
    }
}

/// `expr` is a SQLite value expression (column / json_extract). When `case_insensitive` is true,
/// `eq` / `neq` / `contains` style ops compare on `lower(trim(expr))`.
fn text_cmp_sql(
    expr: &str,
    op: HuntOperator,
    case_insensitive: bool,
    raw_value: &str,
) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntOperator::*;
    let e = if case_insensitive {
        format!("lower(trim({expr}))")
    } else {
        format!("trim({expr})")
    };
    match op {
        Eq => {
            let v = if case_insensitive {
                raw_value.trim().to_lowercase()
            } else {
                raw_value.trim().to_string()
            };
            Ok((format!("{e} = ?"), vec![SqlValue::Text(v)]))
        }
        Neq => {
            let v = if case_insensitive {
                raw_value.trim().to_lowercase()
            } else {
                raw_value.trim().to_string()
            };
            Ok((format!("{e} <> ?"), vec![SqlValue::Text(v)]))
        }
        Contains => {
            let pat = like_substring_pattern(raw_value);
            Ok((format!("{expr} LIKE ? ESCAPE '\\'"), vec![SqlValue::Text(pat)]))
        }
        StartsWith => {
            let pat = like_prefix_pattern(raw_value);
            Ok((format!("{expr} LIKE ? ESCAPE '\\'"), vec![SqlValue::Text(pat)]))
        }
        EndsWith => {
            let pat = like_suffix_pattern(raw_value);
            Ok((format!("{expr} LIKE ? ESCAPE '\\'"), vec![SqlValue::Text(pat)]))
        }
        Gt | Gte | Lt | Lte => Err(CompileError::UnsupportedOperatorForField {
            surface: VaultEntity::IocRecords,
            field: HuntField::IocValue,
            operator: op,
        }),
    }
}

fn datetime_expr_ioc_records() -> &'static str {
    "datetime(COALESCE(NULLIF(last_seen, ''), NULLIF(first_seen, ''), '1970-01-01'))"
}

fn compile_datetime_compare(
    surface: VaultEntity,
    field: HuntField,
    col_expr: &str,
    op: HuntOperator,
    value: &str,
) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntOperator::*;
    let v = value.trim().to_string();
    if v.is_empty() {
        return Ok(("1 = 0".to_string(), vec![]));
    }
    let p = vec![SqlValue::Text(v)];
    let sql = match op {
        Eq => format!("date({col_expr}) = date(?)"),
        Gt => format!("{col_expr} > datetime(?)"),
        Gte => format!("{col_expr} >= datetime(?)"),
        Lt => format!("{col_expr} < datetime(?)"),
        Lte => format!("{col_expr} <= datetime(?)"),
        Neq => format!("date({col_expr}) <> date(?)"),
        Contains | StartsWith | EndsWith => {
            return Err(CompileError::UnsupportedOperatorForField {
                surface,
                field,
                operator: op,
            });
        }
    };
    Ok((sql, p))
}

fn compile_ioc_records(field: HuntField, op: HuntOperator, value: &str) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntField::*;
    use HuntOperator::*;

    let severity_text = "COALESCE(json_extract(metadata, '$.severity'), json_extract(metadata, '$.cvss'), '')";
    let severity_num = "COALESCE(CAST(NULLIF(json_extract(metadata, '$.cvss'), '') AS REAL), CAST(NULLIF(json_extract(metadata, '$.severity_score'), '') AS REAL))";

    match field {
        ThreatActor => {
            let inner = "COALESCE(json_extract(metadata, '$.threat_actor'), '')";
            match op {
                Eq => Ok((
                    "lower(trim(COALESCE(json_extract(metadata, '$.threat_actor'), ''))) = lower(trim(?))"
                        .to_string(),
                    vec![SqlValue::Text(value.to_string())],
                )),
                Neq => Ok((
                    "lower(trim(COALESCE(json_extract(metadata, '$.threat_actor'), ''))) <> lower(trim(?))"
                        .to_string(),
                    vec![SqlValue::Text(value.to_string())],
                )),
                Contains | StartsWith | EndsWith => text_cmp_sql(inner, op, false, value),
                Gt | Gte | Lt | Lte => Err(CompileError::UnsupportedOperatorForField {
                    surface: VaultEntity::IocRecords,
                    field,
                    operator: op,
                }),
            }
        }
        Severity => match op {
            Eq | Neq | Contains | StartsWith | EndsWith => text_cmp_sql(severity_text, op, true, value),
            Gt | Gte | Lt | Lte => {
                let n = parse_f64_for_compare(value)?;
                let cmp = match op {
                    Gt => ">",
                    Gte => ">=",
                    Lt => "<",
                    Lte => "<=",
                    _ => unreachable!(),
                };
                Ok((
                    format!("({severity_num}) IS NOT NULL AND ({severity_num}) {cmp} ?"),
                    vec![SqlValue::Real(n)],
                ))
            }
        },
        IocType => text_cmp_sql("COALESCE(ioc_type, '')", op, true, value),
        IocValue => text_cmp_sql("COALESCE(ioc_value, '')", op, true, value),
        SourceProject => text_cmp_sql("COALESCE(source_project, '')", op, true, value),
        IngestedAfter => {
            let col = datetime_expr_ioc_records();
            compile_datetime_compare(VaultEntity::IocRecords, field, col, op, value)
        }
        CveId | AssetTarget => Err(CompileError::UnsupportedFieldForSurface {
            surface: VaultEntity::IocRecords,
            field,
        }),
    }
}

fn compile_cve_data(field: HuntField, op: HuntOperator, value: &str) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntField::*;
    use HuntOperator::*;

    match field {
        CveId => text_cmp_sql("COALESCE(cve_id, '')", op, true, value),
        ThreatActor => text_cmp_sql(
            "COALESCE(json_extract(metadata, '$.threat_actor'), '')",
            op,
            true,
            value,
        ),
        Severity => match op {
            Eq | Neq | Contains | StartsWith | EndsWith => {
                text_cmp_sql("COALESCE(CAST(severity_score AS TEXT), '')", op, true, value)
            }
            Gt | Gte | Lt | Lte => {
                let n = parse_f64_for_compare(value)?;
                let cmp = match op {
                    Gt => ">",
                    Gte => ">=",
                    Lt => "<",
                    Lte => "<=",
                    _ => unreachable!(),
                };
                Ok((
                    format!("severity_score IS NOT NULL AND severity_score {cmp} ?"),
                    vec![SqlValue::Real(n)],
                ))
            }
        },
        IngestedAfter => {
            let col = "datetime(COALESCE(NULLIF(published_date, ''), '1970-01-01'))";
            compile_datetime_compare(VaultEntity::CveData, field, col, op, value)
        }
        _ => Err(CompileError::UnsupportedFieldForSurface {
            surface: VaultEntity::CveData,
            field,
        }),
    }
}

fn compile_asm_assets(field: HuntField, op: HuntOperator, value: &str) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntField::*;
    use HuntOperator::*;

    let severity_num =
        "COALESCE(CAST(NULLIF(json_extract(metadata, '$.cvss'), '') AS REAL), CAST(NULLIF(json_extract(metadata, '$.severity_score'), '') AS REAL))";
    let severity_text = "COALESCE(json_extract(metadata, '$.severity'), json_extract(metadata, '$.cvss'), '')";

    match field {
        AssetTarget => text_cmp_sql("COALESCE(asset_target, '')", op, true, value),
        ThreatActor => text_cmp_sql(
            "COALESCE(json_extract(metadata, '$.threat_actor'), '')",
            op,
            true,
            value,
        ),
        Severity => match op {
            Eq | Neq | Contains | StartsWith | EndsWith => text_cmp_sql(severity_text, op, true, value),
            Gt | Gte | Lt | Lte => {
                let n = parse_f64_for_compare(value)?;
                let cmp = match op {
                    Gt => ">",
                    Gte => ">=",
                    Lt => "<",
                    Lte => "<=",
                    _ => unreachable!(),
                };
                Ok((
                    format!("({severity_num}) IS NOT NULL AND ({severity_num}) {cmp} ?"),
                    vec![SqlValue::Real(n)],
                ))
            }
        },
        IngestedAfter => {
            let col = "datetime(COALESCE(NULLIF(last_scan_at, ''), '1970-01-01'))";
            compile_datetime_compare(VaultEntity::AsmAssets, field, col, op, value)
        }
        _ => Err(CompileError::UnsupportedFieldForSurface {
            surface: VaultEntity::AsmAssets,
            field,
        }),
    }
}

fn compile_ioc_news(field: HuntField, op: HuntOperator, value: &str) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntField::*;
    use HuntOperator::*;

    match field {
        SourceProject => text_cmp_sql("COALESCE(source, '')", op, true, value),
        IocValue => {
            let v = value.trim();
            if v.is_empty() {
                return Ok(("1 = 0".to_string(), vec![]));
            }
            match op {
                Eq => {
                    let lv = v.to_lowercase();
                    Ok((
                        "(lower(trim(COALESCE(title,''))) = ? OR lower(trim(COALESCE(url,''))) = ? OR lower(trim(COALESCE(content_preview,''))) = ?)"
                            .to_string(),
                        vec![
                            SqlValue::Text(lv.clone()),
                            SqlValue::Text(lv.clone()),
                            SqlValue::Text(lv),
                        ],
                    ))
                }
                Neq => {
                    let lv = v.to_lowercase();
                    Ok((
                        "(lower(trim(COALESCE(title,''))) <> ? AND lower(trim(COALESCE(url,''))) <> ? AND lower(trim(COALESCE(content_preview,''))) <> ?)"
                            .to_string(),
                        vec![
                            SqlValue::Text(lv.clone()),
                            SqlValue::Text(lv.clone()),
                            SqlValue::Text(lv),
                        ],
                    ))
                }
                Contains => {
                    let pat = like_substring_pattern(v);
                    Ok((
                        "(IFNULL(title,'') LIKE ? ESCAPE '\\' OR IFNULL(url,'') LIKE ? ESCAPE '\\' OR IFNULL(content_preview,'') LIKE ? ESCAPE '\\')".to_string(),
                        vec![
                            SqlValue::Text(pat.clone()),
                            SqlValue::Text(pat.clone()),
                            SqlValue::Text(pat),
                        ],
                    ))
                }
                StartsWith => {
                    let pat = like_prefix_pattern(v);
                    Ok((
                        "(IFNULL(title,'') LIKE ? ESCAPE '\\' OR IFNULL(url,'') LIKE ? ESCAPE '\\' OR IFNULL(content_preview,'') LIKE ? ESCAPE '\\')".to_string(),
                        vec![
                            SqlValue::Text(pat.clone()),
                            SqlValue::Text(pat.clone()),
                            SqlValue::Text(pat),
                        ],
                    ))
                }
                EndsWith => {
                    let pat = like_suffix_pattern(v);
                    Ok((
                        "(IFNULL(title,'') LIKE ? ESCAPE '\\' OR IFNULL(url,'') LIKE ? ESCAPE '\\' OR IFNULL(content_preview,'') LIKE ? ESCAPE '\\')".to_string(),
                        vec![
                            SqlValue::Text(pat.clone()),
                            SqlValue::Text(pat.clone()),
                            SqlValue::Text(pat),
                        ],
                    ))
                }
                Gt | Gte | Lt | Lte => Err(CompileError::UnsupportedOperatorForField {
                    surface: VaultEntity::IocNews,
                    field,
                    operator: op,
                }),
            }
        }
        IngestedAfter => {
            let col = "datetime(COALESCE(NULLIF(ingested_at, ''), NULLIF(created_at, ''), '1970-01-01'))";
            compile_datetime_compare(VaultEntity::IocNews, field, col, op, value)
        }
        _ => Err(CompileError::UnsupportedFieldForSurface {
            surface: VaultEntity::IocNews,
            field,
        }),
    }
}

fn compile_iocs_legacy(field: HuntField, op: HuntOperator, value: &str) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntField::*;

    match field {
        IocType => text_cmp_sql("COALESCE(type, '')", op, true, value),
        IocValue => text_cmp_sql("COALESCE(ioc_value, '')", op, true, value),
        _ => Err(CompileError::UnsupportedFieldForSurface {
            surface: VaultEntity::IocsLegacy,
            field,
        }),
    }
}

fn compile_ransomware(field: HuntField, op: HuntOperator, value: &str) -> Result<(String, Vec<SqlValue>), CompileError> {
    use HuntField::*;
    use HuntOperator::*;

    match field {
        IocValue => match op {
            Contains => {
                let pat = like_substring_pattern(value);
                Ok((
                    "(IFNULL(company,'') LIKE ? ESCAPE '\\' OR IFNULL(group_name,'') LIKE ? ESCAPE '\\')".to_string(),
                    vec![SqlValue::Text(pat.clone()), SqlValue::Text(pat)],
                ))
            }
            StartsWith => {
                let pat = like_prefix_pattern(value);
                Ok((
                    "(IFNULL(company,'') LIKE ? ESCAPE '\\' OR IFNULL(group_name,'') LIKE ? ESCAPE '\\')".to_string(),
                    vec![SqlValue::Text(pat.clone()), SqlValue::Text(pat)],
                ))
            }
            EndsWith => {
                let pat = like_suffix_pattern(value);
                Ok((
                    "(IFNULL(company,'') LIKE ? ESCAPE '\\' OR IFNULL(group_name,'') LIKE ? ESCAPE '\\')".to_string(),
                    vec![SqlValue::Text(pat.clone()), SqlValue::Text(pat)],
                ))
            }
            Eq => Ok((
                "(lower(trim(COALESCE(company,''))) = ? OR lower(trim(COALESCE(group_name,''))) = ?)".to_string(),
                vec![
                    SqlValue::Text(value.trim().to_lowercase()),
                    SqlValue::Text(value.trim().to_lowercase()),
                ],
            )),
            Neq => Ok((
                "(lower(trim(COALESCE(company,''))) <> ? AND lower(trim(COALESCE(group_name,''))) <> ?)".to_string(),
                vec![
                    SqlValue::Text(value.trim().to_lowercase()),
                    SqlValue::Text(value.trim().to_lowercase()),
                ],
            )),
            Gt | Gte | Lt | Lte => Err(CompileError::UnsupportedOperatorForField {
                surface: VaultEntity::RansomwareVictims,
                field,
                operator: op,
            }),
        },
        _ => Err(CompileError::UnsupportedFieldForSurface {
            surface: VaultEntity::RansomwareVictims,
            field,
        }),
    }
}

fn select_from_for_surface(surface: VaultEntity) -> (&'static str, &'static str) {
    match surface {
        VaultEntity::IocRecords => (
            "SELECT ioc_value, ioc_type, first_seen, last_seen, source_project, metadata FROM ioc_records",
            "ioc_records",
        ),
        VaultEntity::CveData => (
            "SELECT cve_id, severity_score, published_date, updated_at, metadata FROM cve_data",
            "cve_data",
        ),
        VaultEntity::AsmAssets => (
            "SELECT asset_target, asset_type, last_scan_at, status, metadata FROM asm_assets",
            "asm_assets",
        ),
        VaultEntity::IocNews => (
            "SELECT title, url, source, content_preview, created_at, ingested_at FROM ioc_news",
            "ioc_news",
        ),
        VaultEntity::IocsLegacy => ("SELECT ioc_value, type FROM iocs", "iocs"),
        VaultEntity::RansomwareVictims => (
            "SELECT company, group_name FROM Ransomware_live_event_victim",
            "Ransomware_live_event_victim",
        ),
    }
}

fn order_clause_sql(surface: VaultEntity) -> &'static str {
    match surface {
        VaultEntity::CveData => "ORDER BY datetime(COALESCE(NULLIF(updated_at, ''), NULLIF(published_date, ''), '1970-01-01')) DESC, cve_id DESC",
        VaultEntity::IocRecords => {
            "ORDER BY datetime(COALESCE(NULLIF(last_seen, ''), NULLIF(first_seen, ''), '1970-01-01')) DESC, ioc_value ASC"
        }
        VaultEntity::AsmAssets => "ORDER BY datetime(COALESCE(NULLIF(last_scan_at, ''), '1970-01-01')) DESC, asset_target ASC",
        VaultEntity::IocNews => {
            "ORDER BY datetime(COALESCE(NULLIF(created_at, ''), NULLIF(ingested_at, ''), '1970-01-01')) DESC, url ASC"
        }
        VaultEntity::IocsLegacy | VaultEntity::RansomwareVictims => "ORDER BY rowid DESC",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_field_errors() {
        let json = r#"{"schemaVersion":1,"tree":{"type":"predicate","field":"not_a_field","operator":"eq","value":"x"}}"#;
        let e = compile_hunt_ast_json(VaultEntity::IocRecords, json, 10).unwrap_err();
        assert!(matches!(e, CompileError::UnknownPredicateField(_)));
    }

    #[test]
    fn compiles_simple_predicate_ioc_records() {
        let json = r#"{"schemaVersion":1,"tree":{"type":"predicate","field":"threat_actor","operator":"eq","value":"APT29"}}"#;
        let q = compile_hunt_ast_json(VaultEntity::IocRecords, json, 10).unwrap();
        assert!(q.sql.contains("WHERE"));
        assert!(q.sql.contains("LIMIT ?"));
        assert!(!q.params.is_empty());
    }

    #[test]
    fn unsupported_field_for_surface() {
        let json = r#"{"schemaVersion":1,"tree":{"type":"predicate","field":"cve_id","operator":"eq","value":"CVE-1"}}"#;
        let e = compile_hunt_ast_json(VaultEntity::IocRecords, json, 10).unwrap_err();
        assert!(matches!(e, CompileError::UnsupportedFieldForSurface { .. }));
    }
}

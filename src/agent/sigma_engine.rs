//! Native Sigma rule matching engine. See ADR-020.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;

// ── Global compiled rules ──

pub static SIGMA_RULES: LazyLock<Arc<RwLock<Vec<CompiledRule>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(Vec::new())));

// ── Types ──

pub struct CompiledRule {
    pub id: String,
    pub title: String,
    pub level: String,
    pub logsource_category: Option<String>,
    pub logsource_product: Option<String>,
    pub logsource_service: Option<String>,
    pub tags: Vec<String>,
    pub matchers: HashMap<String, Vec<FieldMatcher>>, // named selections
    pub condition: Condition,
}

pub enum FieldMatcher {
    Exact(String, String),      // field, value
    Contains(String, String),   // field, substring
    StartsWith(String, String), // field, prefix
    EndsWith(String, String),   // field, suffix
    Wildcard(String, String),   // field, glob pattern
    AnyOf(String, Vec<String>), // field, [values]
}

pub enum Condition {
    Ref(String), // "selection"
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

pub struct SigmaMatch {
    pub rule_id: String,
    pub rule_title: String,
    pub level: String,
    pub matched_fields: Vec<(String, String)>,
}

// ── Compilation ──

/// Compile a detection_json JSONB into matchers + condition.
fn compile_detection(detection: &Value) -> Option<(HashMap<String, Vec<FieldMatcher>>, Condition)> {
    let obj = detection.as_object()?;
    let mut selections: HashMap<String, Vec<FieldMatcher>> = HashMap::new();
    let mut condition_str = String::new();

    for (key, val) in obj {
        if key == "condition" {
            condition_str = val.as_str().unwrap_or("selection").to_string();
        } else if key == "timeframe" {
            // Aggregation timeframe — handled separately
            continue;
        } else {
            // This is a named selection (e.g., "selection", "filter", "selection_1")
            let matchers = compile_selection(key, val);
            selections.insert(key.clone(), matchers);
        }
    }

    if condition_str.is_empty() {
        condition_str = "selection".into();
    }

    let condition = parse_condition(&condition_str, &selections);
    Some((selections, condition))
}

/// Compile a single selection object into field matchers.
fn compile_selection(name: &str, selection: &Value) -> Vec<FieldMatcher> {
    let mut matchers = Vec::new();

    match selection {
        Value::Object(map) => {
            for (key, val) in map {
                // Parse field|modifier syntax
                let parts: Vec<&str> = key.splitn(2, '|').collect();
                let field = parts[0].to_string();
                let modifier = parts.get(1).copied().unwrap_or("");

                match val {
                    Value::String(s) => {
                        matchers.push(make_matcher(&field, modifier, s));
                    }
                    Value::Number(n) => {
                        matchers.push(FieldMatcher::Exact(field, n.to_string()));
                    }
                    Value::Array(arr) => {
                        // List of values → AnyOf
                        let values: Vec<String> = arr
                            .iter()
                            .filter_map(|v| {
                                v.as_str()
                                    .map(String::from)
                                    .or_else(|| v.as_i64().map(|n| n.to_string()))
                            })
                            .collect();
                        matchers.push(FieldMatcher::AnyOf(field, values));
                    }
                    _ => {}
                }
            }
        }
        Value::Array(arr) => {
            // Array of selection objects (OR between them)
            for item in arr {
                matchers.extend(compile_selection(name, item));
            }
        }
        _ => {}
    }

    matchers
}

fn make_matcher(field: &str, modifier: &str, value: &str) -> FieldMatcher {
    match modifier {
        "contains" => FieldMatcher::Contains(field.to_string(), value.to_lowercase()),
        "startswith" => FieldMatcher::StartsWith(field.to_string(), value.to_lowercase()),
        "endswith" => FieldMatcher::EndsWith(field.to_string(), value.to_lowercase()),
        "re" => FieldMatcher::Wildcard(field.to_string(), value.to_string()), // simplified
        _ => {
            // Check if value contains wildcards
            if value.contains('*') || value.contains('?') {
                FieldMatcher::Wildcard(field.to_string(), value.to_lowercase())
            } else {
                FieldMatcher::Exact(field.to_string(), value.to_lowercase())
            }
        }
    }
}

/// Parse a condition string into a Condition tree.
/// Supports: "selection", "selection and not filter", "selection1 or selection2"
fn parse_condition(cond: &str, selections: &HashMap<String, Vec<FieldMatcher>>) -> Condition {
    let cond = cond.trim();

    // Handle "X and not Y"
    if let Some(pos) = cond.find(" and not ") {
        let left = &cond[..pos];
        let right = &cond[pos + 9..];
        return Condition::And(
            Box::new(parse_condition(left, selections)),
            Box::new(Condition::Not(Box::new(parse_condition(right, selections)))),
        );
    }

    // Handle "X and Y"
    if let Some(pos) = cond.find(" and ") {
        let left = &cond[..pos];
        let right = &cond[pos + 5..];
        return Condition::And(
            Box::new(parse_condition(left, selections)),
            Box::new(parse_condition(right, selections)),
        );
    }

    // Handle "X or Y"
    if let Some(pos) = cond.find(" or ") {
        let left = &cond[..pos];
        let right = &cond[pos + 4..];
        return Condition::Or(
            Box::new(parse_condition(left, selections)),
            Box::new(parse_condition(right, selections)),
        );
    }

    // Handle "not X"
    if let Some(rest) = cond.strip_prefix("not ") {
        return Condition::Not(Box::new(parse_condition(rest, selections)));
    }

    // Simple reference
    Condition::Ref(cond.to_string())
}

// ── Matching ──

/// Match a log against a single compiled rule.
fn match_rule(rule: &CompiledRule, log: &Value, log_tag: Option<&str>) -> Option<SigmaMatch> {
    // Check logsource filter
    if let Some(ref cat) = rule.logsource_category {
        if let Some(tag) = log_tag {
            if !tag.contains(cat) {
                return None;
            }
        }
    }
    if let Some(ref prod) = rule.logsource_product {
        if let Some(tag) = log_tag {
            if !tag.contains(prod) {
                return None;
            }
        }
    }

    // Evaluate condition
    let mut matched_fields = Vec::new();
    if eval_condition(&rule.condition, &rule.matchers, log, &mut matched_fields) {
        Some(SigmaMatch {
            rule_id: rule.id.clone(),
            rule_title: rule.title.clone(),
            level: rule.level.clone(),
            matched_fields,
        })
    } else {
        None
    }
}

fn eval_condition(
    cond: &Condition,
    selections: &HashMap<String, Vec<FieldMatcher>>,
    log: &Value,
    matched: &mut Vec<(String, String)>,
) -> bool {
    match cond {
        Condition::Ref(name) => {
            if let Some(matchers) = selections.get(name) {
                eval_selection(matchers, log, matched)
            } else {
                false
            }
        }
        Condition::And(a, b) => {
            eval_condition(a, selections, log, matched)
                && eval_condition(b, selections, log, matched)
        }
        Condition::Or(a, b) => {
            eval_condition(a, selections, log, matched)
                || eval_condition(b, selections, log, matched)
        }
        Condition::Not(inner) => {
            let mut dummy = Vec::new();
            !eval_condition(inner, selections, log, &mut dummy)
        }
    }
}

/// Check if ALL matchers in a selection match the log.
fn eval_selection(
    matchers: &[FieldMatcher],
    log: &Value,
    matched: &mut Vec<(String, String)>,
) -> bool {
    if matchers.is_empty() {
        return false;
    }
    for m in matchers {
        if !eval_matcher(m, log, matched) {
            return false;
        }
    }
    true
}

/// Check a single field matcher against the log JSONB.
fn eval_matcher(matcher: &FieldMatcher, log: &Value, matched: &mut Vec<(String, String)>) -> bool {
    match matcher {
        FieldMatcher::Exact(field, expected) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if val_lower == *expected {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::Contains(field, substring) => {
            if let Some(val) = find_field(log, field) {
                if val.to_lowercase().contains(substring) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            // Also search the entire log text for the substring
            let text = log.to_string().to_lowercase();
            if text.contains(substring) {
                matched.push((field.clone(), format!("(found in log body)")));
                return true;
            }
            false
        }
        FieldMatcher::StartsWith(field, prefix) => {
            if let Some(val) = find_field(log, field) {
                if val.to_lowercase().starts_with(prefix) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::EndsWith(field, suffix) => {
            if let Some(val) = find_field(log, field) {
                if val.to_lowercase().ends_with(suffix) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::Wildcard(field, pattern) => {
            if let Some(val) = find_field(log, field) {
                if wildcard_match(pattern, &val.to_lowercase()) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::AnyOf(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().any(|v| v.to_lowercase() == val_lower) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
    }
}

/// Find a field value in a JSONB log. Supports dot notation and flat search.
fn find_field(log: &Value, field: &str) -> Option<String> {
    // Try direct field access
    if let Some(val) = log.get(field) {
        return value_to_string(val);
    }

    // Try dot notation (e.g., "source.ip")
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = log;
    for part in &parts {
        match current.get(part) {
            Some(v) => current = v,
            None => {
                // Try case-insensitive search at current level
                if let Some(obj) = current.as_object() {
                    let found = obj
                        .iter()
                        .find(|(k, _)| k.to_lowercase() == part.to_lowercase());
                    if let Some((_, v)) = found {
                        current = v;
                        continue;
                    }
                }
                return None;
            }
        }
    }
    value_to_string(current)
}

fn value_to_string(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => Some(val.to_string()),
    }
}

/// Simple glob-style wildcard matching (* = any chars, ? = one char).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut p = pattern.chars().peekable();
    let mut t = text.chars().peekable();
    wildcard_match_inner(&mut p.collect::<Vec<_>>(), &mut t.collect::<Vec<_>>(), 0, 0)
}

fn wildcard_match_inner(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }

    if pattern[pi] == '*' {
        // Skip consecutive *
        let mut pi2 = pi;
        while pi2 < pattern.len() && pattern[pi2] == '*' {
            pi2 += 1;
        }
        if pi2 == pattern.len() {
            return true;
        } // trailing *

        for ti2 in ti..=text.len() {
            if wildcard_match_inner(pattern, text, pi2, ti2) {
                return true;
            }
        }
        false
    } else if ti < text.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
        wildcard_match_inner(pattern, text, pi + 1, ti + 1)
    } else {
        false
    }
}

// ── Public API ──

/// Load enabled sigma rules from DB and compile them.
pub async fn init(store: &dyn crate::db::Database) {
    let rules = load_and_compile(store).await;
    let count = rules.len();
    *SIGMA_RULES.write().await = rules;
    tracing::info!("SIGMA ENGINE: {} rules compiled and loaded", count);
}

/// Reload rules (after CRUD changes).
pub async fn reload(store: &dyn crate::db::Database) {
    let rules = load_and_compile(store).await;
    let count = rules.len();
    *SIGMA_RULES.write().await = rules;
    tracing::info!("SIGMA ENGINE: Reloaded — {} rules", count);
}

async fn load_and_compile(store: &dyn crate::db::Database) -> Vec<CompiledRule> {
    let rows = match store.list_sigma_rules_enabled().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("SIGMA ENGINE: Failed to load rules: {e}");
            return Vec::new();
        }
    };

    let mut compiled = Vec::new();
    for row in &rows {
        let id = row["id"].as_str().unwrap_or("").to_string();
        let title = row["title"].as_str().unwrap_or("").to_string();
        let level = row["level"].as_str().unwrap_or("medium").to_string();
        let detection = &row["detection_json"];

        if detection.is_null() {
            continue;
        }

        if let Some((matchers, condition)) = compile_detection(detection) {
            compiled.push(CompiledRule {
                id,
                title,
                level,
                logsource_category: row["logsource_category"].as_str().map(String::from),
                logsource_product: row["logsource_product"].as_str().map(String::from),
                logsource_service: row["logsource_service"].as_str().map(String::from),
                tags: row["tags"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                matchers,
                condition,
            });
        } else {
            tracing::debug!(
                "SIGMA ENGINE: Skipped rule {} — could not compile detection",
                row["id"]
            );
        }
    }

    compiled
}

/// Match a single log against all loaded rules.
pub async fn match_log(log: &Value, log_tag: Option<&str>) -> Vec<SigmaMatch> {
    let rules = SIGMA_RULES.read().await;
    let mut matches = Vec::new();
    for rule in rules.iter() {
        if let Some(m) = match_rule(rule, log, log_tag) {
            matches.push(m);
        }
    }
    matches
}

/// Run sigma matching on recent logs and create alerts. Called from IE cycle.
// See ADR-030: sigma dedup uses in-memory HashSet before DB fallback
pub async fn run_sigma_cycle(store: Arc<dyn crate::db::Database>, minutes_back: i64) {
    let rules = SIGMA_RULES.read().await;
    if rules.is_empty() {
        return;
    }

    let logs = match store.query_logs(minutes_back, None, None, 2000).await {
        Ok(l) => l,
        Err(_) => return,
    };

    let mut alerts_created = 0u32;
    let mut cycle_dedup: std::collections::HashSet<String> = std::collections::HashSet::new();

    for log in &logs {
        for rule in rules.iter() {
            if let Some(m) = match_rule(rule, &log.data, log.tag.as_deref()) {
                let hostname = log.hostname.as_deref().unwrap_or("unknown");
                let dedup_key = format!("{}_{}", m.rule_id, hostname);

                // Fast in-memory dedup (skip DB query for same rule+host within this cycle)
                if !cycle_dedup.insert(dedup_key.clone()) {
                    continue;
                }

                // DB dedup fallback (15 min window across cycles)
                if let Ok(Some(prev)) = store.get_setting("_sigma_dedup", &dedup_key).await {
                    if let Some(at) = prev["at"].as_str() {
                        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(at) {
                            if chrono::Utc::now().signed_duration_since(ts)
                                < chrono::Duration::minutes(15)
                            {
                                continue;
                            }
                        }
                    }
                }

                // Create alert
                let source_ip = m
                    .matched_fields
                    .iter()
                    .find(|(f, _)| f.contains("ip") || f.contains("addr") || f.contains("source"))
                    .map(|(_, v)| v.as_str());
                let username = m
                    .matched_fields
                    .iter()
                    .find(|(f, _)| f.contains("user") || f.contains("account"))
                    .map(|(_, v)| v.as_str());

                let _ = store
                    .insert_sigma_alert(
                        &m.rule_id,
                        &m.level,
                        &m.rule_title,
                        hostname,
                        source_ip,
                        username,
                    )
                    .await;

                // Dedup marker (expires in 15 min via settings cleanup)
                let _ = store
                    .set_setting(
                        "_sigma_dedup",
                        &format!("{}_{}", m.rule_id, hostname),
                        &serde_json::json!({
                            "at": chrono::Utc::now().to_rfc3339(),
                        }),
                    )
                    .await;

                alerts_created += 1;
            }
        }
    }

    if alerts_created > 0 {
        tracing::info!(
            "SIGMA ENGINE: {} alerts from {} logs ({} rules)",
            alerts_created,
            logs.len(),
            rules.len()
        );
    }
}

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
    Exact(String, String),            // field, value
    Contains(String, String),         // field, substring
    StartsWith(String, String),       // field, prefix
    EndsWith(String, String),         // field, suffix
    Wildcard(String, String),         // field, glob pattern
    AnyOf(String, Vec<String>),       // field, [values] — exact match OR
    ContainsAny(String, Vec<String>), // field|contains: [a,b,c] — substring OR
    StartsWithAny(String, Vec<String>),
    EndsWithAny(String, Vec<String>),
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
                        let values: Vec<String> = arr
                            .iter()
                            .filter_map(|v| {
                                v.as_str()
                                    .map(String::from)
                                    .or_else(|| v.as_i64().map(|n| n.to_string()))
                            })
                            .collect();
                        // The Sigma semantics for `field|<mod>: [a, b, c]` is "ANY
                        // of [a,b,c] matches with that modifier". Without the
                        // *Any variants below, a `line|contains: ["Failed
                        // password", "auth denied"]` was being compiled to
                        // exact-match AnyOf — silently never firing on real syslog
                        // content (which has prefixes / suffixes). The pre-fix
                        // bug took out our V58 / V59 / V60 rules until V61.
                        let lower: Vec<String> = values.iter().map(|v| v.to_lowercase()).collect();
                        match modifier {
                            "contains" => {
                                matchers.push(FieldMatcher::ContainsAny(field, lower));
                            }
                            "startswith" => {
                                matchers.push(FieldMatcher::StartsWithAny(field, lower));
                            }
                            "endswith" => {
                                matchers.push(FieldMatcher::EndsWithAny(field, lower));
                            }
                            _ => {
                                matchers.push(FieldMatcher::AnyOf(field, values));
                            }
                        }
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
        FieldMatcher::ContainsAny(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().any(|v| val_lower.contains(v.as_str())) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            // Defense in depth: also probe the whole log body — same semantics as
            // FieldMatcher::Contains so rules don't depend on whether the field
            // is exposed at top-level or nested.
            let text = log.to_string().to_lowercase();
            if values.iter().any(|v| text.contains(v.as_str())) {
                matched.push((field.clone(), "(found in log body)".into()));
                return true;
            }
            false
        }
        FieldMatcher::StartsWithAny(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().any(|v| val_lower.starts_with(v.as_str())) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::EndsWithAny(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().any(|v| val_lower.ends_with(v.as_str())) {
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

// ── Pipeline tunables (Phase A — refoundation 27/04) ──
// 15 min dedup was too short — same rule re-fires every Sigma cycle (5 min)
// because the lab's brute force keeps hitting the same window. 1 h is the
// SOC industry standard for "same alert, same asset, suppress."
const SIGMA_DEDUP_WINDOW_MIN: i64 = 60;
const FINDING_DEDUP_WINDOW_MIN: i64 = 60;
/// How long do we look for "another signal on the same asset" to decide
/// whether a `medium` sigma should promote to a finding. Longer than the
/// dedup window so a single brute-force burst (8 events in 30s, dedup'd
/// once) still corroborates a separate medium-level audit log.
const CORROBORATION_WINDOW_MIN: i64 = 60;

/// Run sigma matching on recent logs, create alerts AND auto-create
/// findings for high/critical matches (or corroborated medium ones).
///
/// Pipeline philosophy (Phase A) — an incident must equal a real threat,
/// so the sigma layer:
///   - always creates a `sigma_alert` row (raw signal, 30 d retention)
///   - resolves the `hostname` to a canonical asset (avoid raw IP / FQDN drift)
///   - decides whether the alert is signal-rich enough to deserve a `finding`:
///     * critical / high → always promote
///     * medium → promote ONLY if corroborated (≥ 1 other signal on the
///       same asset in the last hour: sigma alert, finding, or firewall event)
///     * low / informational → never auto-promote
///   - leaves escalation-to-incident to the Intelligence Engine which
///     reads findings, not raw alerts.
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
    let mut findings_created = 0u32;
    let mut cycle_dedup: std::collections::HashSet<String> = std::collections::HashSet::new();

    for log in &logs {
        for rule in rules.iter() {
            if let Some(m) = match_rule(rule, &log.data, log.tag.as_deref()) {
                // Phase 8b — Filtre FP IDS multi-vendor.
                //
                // Sur un parc client typique (10 srv + 50 postes), Windows
                // Update / antivirus update / app self-update génèrent des
                // centaines d'alertes IDS "informational" par jour, quel que
                // soit le vendor (Suricata, Fortinet, Stormshield, pfSense).
                // Sans filtre on crée ~1500 incidents/jour de FP — système
                // inutilisable.
                //
                // Le filtre est délégué au registre `ids_normalizer` qui
                // dispatch sur le vendor adapté via `try_normalize`. Si la
                // règle n'est pas un IDS générique (ex: tc-ssh-brute,
                // opnsense-001 auth failed), `try_normalize` retourne None
                // et le pipeline garde l'alerte intacte. Voir
                // `agent/ids_normalizer/mod.rs::is_benign` pour les critères.
                if let Some(normalized) =
                    crate::agent::ids_normalizer::try_normalize(&m.rule_id, &m.matched_fields)
                    && crate::agent::ids_normalizer::is_benign(&normalized)
                {
                    continue;
                }

                let raw_hostname = log.hostname.as_deref().unwrap_or("unknown");
                let canonical_asset = resolve_canonical_asset(store.as_ref(), raw_hostname).await;

                let dedup_key = format!("{}_{}", m.rule_id, canonical_asset);
                if !cycle_dedup.insert(dedup_key.clone()) {
                    continue;
                }
                if let Ok(Some(prev)) = store.get_setting("_sigma_dedup", &dedup_key).await {
                    if let Some(at) = prev["at"].as_str() {
                        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(at) {
                            if chrono::Utc::now().signed_duration_since(ts)
                                < chrono::Duration::minutes(SIGMA_DEDUP_WINDOW_MIN)
                            {
                                continue;
                            }
                        }
                    }
                }

                // First pass — direct lookup of common field names. Records
                // both source and destination so we can pick the side that
                // belongs to the customer infrastructure (see asset
                // re-attribution below).
                let mut source_ip = m
                    .matched_fields
                    .iter()
                    .find(|(f, _)| f.contains("ip") || f.contains("addr") || f.contains("source"))
                    .map(|(_, v)| v.as_str());
                let mut dest_ip: Option<&str> = m
                    .matched_fields
                    .iter()
                    .find(|(f, _)| f.contains("dst") || f.contains("dest"))
                    .map(|(_, v)| v.as_str());
                // Fallback — Suricata IDS connectors expose the raw eve.json
                // line under matched_fields[*].0 == "line" with src/dest
                // nested inside the JSON. Pull both out so the asset
                // re-attribution can work on either side.
                let mut suricata_src_ip_owned: Option<String> = None;
                let mut suricata_dst_ip_owned: Option<String> = None;
                if source_ip.is_none() || dest_ip.is_none() {
                    for (k, v) in m.matched_fields.iter() {
                        if k != "line" {
                            continue;
                        }
                        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(v.trim()) {
                            if source_ip.is_none()
                                && let Some(s) = payload.get("src_ip").and_then(|x| x.as_str())
                            {
                                suricata_src_ip_owned = Some(s.to_string());
                            }
                            if dest_ip.is_none()
                                && let Some(s) = payload.get("dest_ip").and_then(|x| x.as_str())
                            {
                                suricata_dst_ip_owned = Some(s.to_string());
                            }
                            break;
                        }
                    }
                    if source_ip.is_none() {
                        source_ip = suricata_src_ip_owned.as_deref();
                    }
                    if dest_ip.is_none() {
                        dest_ip = suricata_dst_ip_owned.as_deref();
                    }
                }
                let username = m
                    .matched_fields
                    .iter()
                    .find(|(f, _)| f.contains("user") || f.contains("account"))
                    .map(|(_, v)| v.as_str());

                // Asset re-attribution. The connector that emitted the log
                // typically records its own hostname as `raw_hostname` (e.g.
                // the firewall for pf / Suricata logs). We want the asset to
                // be the entity ThreatClaw is supposed to protect, so we
                // pick the IP that looks "internal" first:
                //   1. dest_ip if it's RFC1918 — likely an inbound attack
                //      against an internal target
                //   2. src_ip if it's RFC1918 — likely outbound from a
                //      compromised internal host
                //   3. Otherwise, leave the canonical_asset alone — the
                //      inventory gate downstream will decide whether to
                //      escalate.
                fn is_private_ipv4(s: &str) -> bool {
                    let p = match s.parse::<std::net::Ipv4Addr>() {
                        Ok(v) => v,
                        Err(_) => return false,
                    };
                    let o = p.octets();
                    o[0] == 10
                        || (o[0] == 172 && (16..=31).contains(&o[1]))
                        || (o[0] == 192 && o[1] == 168)
                }
                // For IDS findings the host that emitted the log (raw_hostname)
                // is NEVER the right asset — the alert is about observed
                // traffic, not about the firewall itself. We pick:
                //   1. dest_ip when private — inbound attack against internal
                //   2. src_ip when private — outbound exfil from a private host
                //   3. src_ip otherwise — perimeter-only traffic; the
                //      inventory gate downstream will classify the external
                //      IP as External and drop the incident (right answer:
                //      that's an Internet scanner hammering the WAN, not an
                //      attack on a monitored asset).
                //   4. dest_ip otherwise — same logic, last resort
                //   5. raw_hostname only when neither IP could be extracted
                let canonical_asset = if dest_ip.map(is_private_ipv4).unwrap_or(false) {
                    dest_ip.unwrap().to_string()
                } else if source_ip.map(is_private_ipv4).unwrap_or(false) {
                    source_ip.unwrap().to_string()
                } else if let Some(s) = source_ip {
                    s.to_string()
                } else if let Some(d) = dest_ip {
                    d.to_string()
                } else {
                    canonical_asset
                };

                // Phase 5 (Bug 8) — sérialise les `matched_fields` extraits par
                // l'engine sigma (ex: signature Suricata, dest_port, proto, action
                // firewall, bytes échangés) et les persiste en DB pour qu'ils
                // remontent dans le dossier passé au L2. Sans ça `matched_fields`
                // restait `{}` et le L2 inventait des détails plausibles
                // (88.88.88.88, EternalBlue, fail2ban...).
                let mut mf_obj = serde_json::Map::new();
                for (k, v) in &m.matched_fields {
                    mf_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
                }
                let mf_value = serde_json::Value::Object(mf_obj);

                let _ = store
                    .insert_sigma_alert_with_fields(
                        &m.rule_id,
                        &m.level,
                        &m.rule_title,
                        &canonical_asset,
                        source_ip,
                        username,
                        &mf_value,
                    )
                    .await;
                let _ = store
                    .set_setting(
                        "_sigma_dedup",
                        &dedup_key,
                        &serde_json::json!({ "at": chrono::Utc::now().to_rfc3339() }),
                    )
                    .await;
                alerts_created += 1;

                // ── Decide if this alert promotes to a finding ──
                let level_lc = m.level.to_lowercase();
                let promote = match level_lc.as_str() {
                    "critical" | "high" => true,
                    "medium" => {
                        // count_recent_signals_on_asset returns ≥ 1 because
                        // we just inserted our own sigma_alert. Need ≥ 2 for
                        // genuine corroboration (us + one other).
                        let n = store
                            .count_recent_signals_on_asset(
                                &canonical_asset,
                                CORROBORATION_WINDOW_MIN,
                            )
                            .await
                            .unwrap_or(0);
                        n >= 2
                    }
                    _ => false,
                };

                if promote {
                    let f_dedup_key = format!("{}_{}", m.rule_id, canonical_asset);
                    let recently_filed = store
                        .get_setting("_finding_dedup", &f_dedup_key)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|v| v["at"].as_str().map(String::from))
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|ts| {
                            chrono::Utc::now().signed_duration_since(ts)
                                < chrono::Duration::minutes(FINDING_DEDUP_WINDOW_MIN)
                        })
                        .unwrap_or(false);

                    if !recently_filed {
                        let metadata = serde_json::json!({
                            "rule_id": m.rule_id,
                            "matched_fields": m.matched_fields,
                            "source_ip": source_ip,
                            "username": username,
                            "raw_hostname": raw_hostname,
                        });
                        let f = crate::db::threatclaw_store::NewFinding {
                            skill_id: "sigma".into(),
                            title: m.rule_title.clone(),
                            description: Some(format!(
                                "Sigma rule {} matched on {} (level={})",
                                m.rule_id, canonical_asset, level_lc
                            )),
                            severity: level_lc.clone(),
                            category: Some("sigma".into()),
                            asset: Some(canonical_asset.clone()),
                            source: Some(format!("sigma:{}", m.rule_id)),
                            metadata: Some(metadata),
                        };
                        if store.insert_finding(&f).await.is_ok() {
                            let _ = store
                                .set_setting(
                                    "_finding_dedup",
                                    &f_dedup_key,
                                    &serde_json::json!({
                                        "at": chrono::Utc::now().to_rfc3339()
                                    }),
                                )
                                .await;
                            findings_created += 1;
                        }
                    }
                }
            }
        }
    }

    if alerts_created > 0 || findings_created > 0 {
        tracing::info!(
            "SIGMA ENGINE: {} alerts, {} findings from {} logs ({} rules)",
            alerts_created,
            findings_created,
            logs.len(),
            rules.len()
        );
    }
}

/// Resolve a raw `hostname` (could be IP, FQDN, NetBIOS, or short name)
/// against the assets table. Falls back to the raw value when the asset
/// is unknown so the pipeline still records something — but we prefer
/// the canonical hostname stored in `assets` so downstream aggregation
/// (Intelligence Engine) doesn't split signals between "10.77.0.1" and
/// "OPNsense.internal" and "opnsense-firewall".
async fn resolve_canonical_asset(store: &dyn crate::db::Database, raw: &str) -> String {
    if raw.is_empty() || raw == "unknown" {
        return raw.to_string();
    }
    let looks_like_ipv4 =
        raw.split('.').count() == 4 && raw.split('.').all(|p| p.parse::<u8>().is_ok());
    if looks_like_ipv4 {
        if let Ok(Some(asset)) = store.find_asset_by_ip(raw).await {
            return asset.hostname.unwrap_or_else(|| asset.name);
        }
    }
    if let Ok(Some(asset)) = store.find_asset_by_hostname(raw).await {
        return asset.hostname.unwrap_or_else(|| asset.name);
    }
    raw.to_string()
}

// Phase 8b — La logique IDS multi-vendor (Suricata + futurs Fortinet,
// Stormshield, pfSense, Cisco Firepower) vit dans
// `agent/ids_normalizer/`. Voir le trait `IdsAlertNormalizer` et la
// fonction `is_benign` côté module dédié pour la matrice complète des
// critères de drop. Le sigma_engine n'invoque que `try_normalize +
// is_benign` ; aucune logique vendor-specific ici.

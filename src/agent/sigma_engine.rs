//! Native Sigma rule matching engine. See ADR-020.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;

// ── Global compiled rules ──

pub static SIGMA_RULES: LazyLock<Arc<RwLock<Vec<CompiledRule>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(Vec::new())));

/// Active exception list, refreshed at the same cadence as the rules.
/// Indexed at lookup time on (rule_id, scope_field, scope_value) — the
/// cardinality is expected to stay below a few hundred so a linear scan
/// is fine.
pub static SIGMA_EXCEPTIONS: LazyLock<Arc<RwLock<Vec<ActiveException>>>> =
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
    /// Promotion ladder disposition controlling how matches are surfaced
    /// (monitor / detect / block). Default 'detect'.
    pub disposition: String,
    /// Alerting sphere (page / queue / rba_only). Default 'queue'. When
    /// `rba_only`, a match writes a `risk_event` (RBA) instead of a direct
    /// alert — see the routing in `run_sigma_cycle`. (Phase D1.)
    pub tier: String,
    /// Optional per-rule risk weight (0-100) for RBA. `None` → the score is
    /// derived from `level` at routing time. (Phase D1.)
    pub risk_score: Option<i32>,
}

/// Cached active exception. Comparison against alert fields happens
/// case-insensitively for textual scopes (hostname / username / tag)
/// and exact for source_ip.
#[derive(Debug, Clone)]
pub struct ActiveException {
    pub rule_id: String,
    pub scope_field: String,
    pub scope_value: String,
}

/// True if any active exception silences the rule for the given alert
/// context. Engine checks this AFTER `match_rule` returned a hit, but
/// BEFORE the alert is written to the DB — so excluded matches leave no
/// trace beyond a trace::debug line.
pub fn alert_is_excepted(
    exceptions: &[ActiveException],
    rule_id: &str,
    hostname: Option<&str>,
    source_ip: Option<&str>,
    username: Option<&str>,
    rule_tags: &[String],
) -> bool {
    for ex in exceptions {
        if ex.rule_id != rule_id {
            continue;
        }
        let scope_lower = ex.scope_value.to_lowercase();
        match ex.scope_field.as_str() {
            "hostname" => {
                if let Some(h) = hostname {
                    if h.eq_ignore_ascii_case(&ex.scope_value) {
                        return true;
                    }
                    // Allow a trailing wildcard so an operator can scope
                    // an exception to a host family (e.g. `srv-prod-*`).
                    if let Some(prefix) = ex.scope_value.strip_suffix('*') {
                        if h.to_lowercase().starts_with(&prefix.to_lowercase()) {
                            return true;
                        }
                    }
                }
            }
            "source_ip" => {
                if let Some(ip) = source_ip {
                    if ip == ex.scope_value {
                        return true;
                    }
                }
            }
            "username" => {
                if let Some(u) = username {
                    if u.eq_ignore_ascii_case(&ex.scope_value) {
                        return true;
                    }
                }
            }
            "tag" => {
                if rule_tags.iter().any(|t| t.to_lowercase() == scope_lower) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub enum FieldMatcher {
    Exact(String, String),            // field, value (case-insensitive)
    Contains(String, String),         // field, substring (case-insensitive)
    StartsWith(String, String),       // field, prefix (case-insensitive)
    EndsWith(String, String),         // field, suffix (case-insensitive)
    Wildcard(String, String),         // field, glob pattern
    AnyOf(String, Vec<String>),       // field, [values] — exact match OR
    ContainsAny(String, Vec<String>), // field|contains: [a,b,c] — substring OR
    StartsWithAny(String, Vec<String>),
    EndsWithAny(String, Vec<String>),
    // `|<mod>|all` variants — every value must match (AND semantics). Used by
    // SigmaHQ patterns like `CommandLine|contains|all: [' -hp', ' a ', ' -m']`
    // where a single command line must contain every fragment.
    ContainsAll(String, Vec<String>),
    StartsWithAll(String, Vec<String>),
    EndsWithAll(String, Vec<String>),

    // ── Sigma 2.0 modifiers ────────────────────────────────────────────
    // `|cased` — case-sensitive equivalents (the default in Sigma is
    // case-insensitive; the modifier opts back into byte-exact matching).
    ExactCased(String, String),
    ContainsCased(String, String),
    StartsWithCased(String, String),
    EndsWithCased(String, String),
    /// `|re` — PCRE-style regular expression. Compiled once at rule load.
    Regex(String, regex::Regex),
    /// `|cidr` — value handled as a CIDR network range. Supports IPv4/IPv6.
    Cidr(String, CidrNet),
    /// `|exists: true|false` — field presence check.
    Exists(String, bool),
    /// `|lt`/`|lte`/`|gt`/`|gte` — numeric comparison against an f64 value.
    NumericLt(String, f64),
    NumericLte(String, f64),
    NumericGt(String, f64),
    NumericGte(String, f64),
    /// `|fieldref` — compares the field's value against another field in the
    /// same event (case-insensitive). Used by anti-evasion rules where the
    /// expected token is itself in the event (e.g. ProcessId == ParentProcessId).
    FieldRef(String, String),
}

impl FieldMatcher {
    /// The primary event field this matcher reads, when the matcher requires the
    /// field's value to be present to ever match. Returns `None` for `Exists`,
    /// which deliberately tests presence/absence and is satisfiable without a
    /// resolvable value. Used by the per-cycle field-resolution health audit so
    /// a rule whose fields never resolve (a field-mapping error) is surfaced
    /// loudly instead of dying silently. Exhaustive on purpose: a new variant
    /// won't compile until it declares its audited field.
    fn audited_field(&self) -> Option<&str> {
        match self {
            FieldMatcher::Exists(_, _) => None,
            FieldMatcher::Exact(f, _)
            | FieldMatcher::Contains(f, _)
            | FieldMatcher::StartsWith(f, _)
            | FieldMatcher::EndsWith(f, _)
            | FieldMatcher::Wildcard(f, _)
            | FieldMatcher::AnyOf(f, _)
            | FieldMatcher::ContainsAny(f, _)
            | FieldMatcher::StartsWithAny(f, _)
            | FieldMatcher::EndsWithAny(f, _)
            | FieldMatcher::ContainsAll(f, _)
            | FieldMatcher::StartsWithAll(f, _)
            | FieldMatcher::EndsWithAll(f, _)
            | FieldMatcher::ExactCased(f, _)
            | FieldMatcher::ContainsCased(f, _)
            | FieldMatcher::StartsWithCased(f, _)
            | FieldMatcher::EndsWithCased(f, _)
            | FieldMatcher::Regex(f, _)
            | FieldMatcher::Cidr(f, _)
            | FieldMatcher::NumericLt(f, _)
            | FieldMatcher::NumericLte(f, _)
            | FieldMatcher::NumericGt(f, _)
            | FieldMatcher::NumericGte(f, _)
            | FieldMatcher::FieldRef(f, _) => Some(f.as_str()),
        }
    }
}

/// Lightweight CIDR network used by FieldMatcher::Cidr. We hand-roll the
/// match logic instead of pulling in `ipnet` because the operation is
/// trivial and Sigma rules carry at most a few hundred CIDR entries.
#[derive(Debug, Clone)]
pub struct CidrNet {
    addr: std::net::IpAddr,
    prefix: u8,
}

impl CidrNet {
    pub fn parse(spec: &str) -> Option<Self> {
        let (ip_str, prefix_str) = spec.split_once('/')?;
        let addr: std::net::IpAddr = ip_str.parse().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, candidate: &std::net::IpAddr) -> bool {
        match (self.addr, candidate) {
            (std::net::IpAddr::V4(net), std::net::IpAddr::V4(ip)) => {
                let net = u32::from(net);
                let ip = u32::from(*ip);
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix);
                (net & mask) == (ip & mask)
            }
            (std::net::IpAddr::V6(net), std::net::IpAddr::V6(ip)) => {
                let net = u128::from(net);
                let ip = u128::from(*ip);
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix);
                (net & mask) == (ip & mask)
            }
            _ => false,
        }
    }
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

/// RBA (Phase D1) — default risk weight derived from a rule's Sigma level when
/// the rule has no explicit `risk_score`. Aligns the 0-100 risk scale with the
/// severity ladder (cf. internal/PLAN_PHASE_D_RBA.md / Splunk RBA confidence 0-100).
pub fn risk_score_from_level(level: &str) -> i32 {
    match level.to_ascii_lowercase().as_str() {
        "critical" => 100,
        "high" => 50,
        "medium" => 25,
        "low" => 10,
        _ => 5, // informational / unknown
    }
}

/// RBA — extract the first MITRE tactic + technique from a rule's Sigma tags
/// (`attack.t1003.001`, `attack.credential_access`, …). Populates the "risk
/// annotations" used by the tactic-diversity Risk Incident Rule.
pub fn mitre_from_tags(tags: &[String]) -> (Option<String>, Option<String>) {
    let mut tactic = None;
    let mut technique = None;
    for t in tags {
        let lt = t.to_ascii_lowercase();
        let Some(rest) = lt.strip_prefix("attack.") else {
            continue;
        };
        let is_technique =
            rest.starts_with('t') && rest[1..].chars().next().is_some_and(|c| c.is_ascii_digit());
        if is_technique {
            if technique.is_none() {
                technique = Some(rest.to_ascii_uppercase()); // t1003.001 -> T1003.001
            }
        } else if tactic.is_none() {
            tactic = Some(rest.to_string()); // credential_access
        }
    }
    (tactic, technique)
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
                // Parse field|modifier(|all) syntax. SigmaHQ rules frequently
                // chain a second `|all` segment to require every list value
                // to be present in the field (vs the default ANY-of). We also
                // tolerate `|all` appearing before the matcher modifier.
                let parts: Vec<&str> = key.split('|').collect();
                let field = parts[0].to_string();
                let has_all = parts.iter().skip(1).any(|p| *p == "all");
                let modifier = parts
                    .iter()
                    .skip(1)
                    .find(|p| **p != "all")
                    .copied()
                    .unwrap_or("");

                // Expansion modifiers — `|windash`, `|base64`, `|base64offset`,
                // `|utf16le`/`|wide` — fan a single rule value out into several
                // substring variants. Compose any of them with `|contains` and
                // emit one ContainsAny per (field, variants) so the rest of the
                // engine stays uniform. If the rule already specified `|all`,
                // the expansion stays in OR semantics for the value variants
                // themselves (any encoded form is enough) — `|all` only forces
                // every list element to match when the YAML value is a list.
                if let Some(variants) = expand_value_modifier(modifier, val) {
                    if !variants.is_empty() {
                        matchers.push(FieldMatcher::ContainsAny(field.clone(), variants));
                        continue;
                    }
                }

                match val {
                    Value::String(s) => {
                        matchers.push(make_matcher(&field, modifier, s));
                    }
                    Value::Number(n) => {
                        matchers.push(FieldMatcher::Exact(field, n.to_string()));
                    }
                    Value::Bool(b) => {
                        matchers.push(FieldMatcher::Exact(field, b.to_string()));
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
                        match (modifier, has_all) {
                            ("contains", true) => {
                                matchers.push(FieldMatcher::ContainsAll(field, lower));
                            }
                            ("startswith", true) => {
                                matchers.push(FieldMatcher::StartsWithAll(field, lower));
                            }
                            ("endswith", true) => {
                                matchers.push(FieldMatcher::EndsWithAll(field, lower));
                            }
                            ("contains", false) => {
                                matchers.push(FieldMatcher::ContainsAny(field, lower));
                            }
                            ("startswith", false) => {
                                matchers.push(FieldMatcher::StartsWithAny(field, lower));
                            }
                            ("endswith", false) => {
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
    // The compile path passes one stripped modifier at a time. Multi-segment
    // syntax like `|contains|cased` is normalized at the caller into ordered
    // segments, but for simple two-token shapes we parse the trailing flag
    // here so callers don't have to special-case every combination.
    let (base, cased) = match modifier.split_once("|cased").or_else(|| {
        modifier
            .strip_suffix("cased")
            .map(|m| (m.trim_end_matches('|'), ""))
    }) {
        Some((m, _)) if !m.is_empty() => (m, true),
        _ if modifier == "cased" => ("", true),
        _ => (modifier, false),
    };

    match base {
        // ── case-insensitive (default Sigma) ─────────────────────────
        "contains" if !cased => FieldMatcher::Contains(field.to_string(), value.to_lowercase()),
        "startswith" if !cased => FieldMatcher::StartsWith(field.to_string(), value.to_lowercase()),
        "endswith" if !cased => FieldMatcher::EndsWith(field.to_string(), value.to_lowercase()),

        // ── case-sensitive (Sigma 2.0 `|cased`) ───────────────────────
        "contains" if cased => FieldMatcher::ContainsCased(field.to_string(), value.to_string()),
        "startswith" if cased => {
            FieldMatcher::StartsWithCased(field.to_string(), value.to_string())
        }
        "endswith" if cased => FieldMatcher::EndsWithCased(field.to_string(), value.to_string()),
        "" if cased => FieldMatcher::ExactCased(field.to_string(), value.to_string()),

        // ── regular expression ────────────────────────────────────────
        "re" | "re|i" => {
            let prefix = if base == "re|i" { "(?i)" } else { "" };
            match regex::Regex::new(&format!("{prefix}{value}")) {
                Ok(re) => FieldMatcher::Regex(field.to_string(), re),
                Err(_) => {
                    // Invalid regex — fall back to a literal substring so the
                    // rule still loads. A warning here would be nice but the
                    // loader logs the rule id elsewhere.
                    FieldMatcher::Contains(field.to_string(), value.to_lowercase())
                }
            }
        }

        // ── CIDR network ──────────────────────────────────────────────
        "cidr" => match CidrNet::parse(value) {
            Some(net) => FieldMatcher::Cidr(field.to_string(), net),
            None => FieldMatcher::Exact(field.to_string(), value.to_lowercase()),
        },

        // ── presence check ────────────────────────────────────────────
        "exists" => {
            let expected = matches!(value.to_lowercase().as_str(), "true" | "1" | "yes");
            FieldMatcher::Exists(field.to_string(), expected)
        }

        // ── numeric comparators ───────────────────────────────────────
        "lt" => parse_numeric(value)
            .map(|n| FieldMatcher::NumericLt(field.to_string(), n))
            .unwrap_or_else(|| FieldMatcher::Exact(field.to_string(), value.to_lowercase())),
        "lte" => parse_numeric(value)
            .map(|n| FieldMatcher::NumericLte(field.to_string(), n))
            .unwrap_or_else(|| FieldMatcher::Exact(field.to_string(), value.to_lowercase())),
        "gt" => parse_numeric(value)
            .map(|n| FieldMatcher::NumericGt(field.to_string(), n))
            .unwrap_or_else(|| FieldMatcher::Exact(field.to_string(), value.to_lowercase())),
        "gte" => parse_numeric(value)
            .map(|n| FieldMatcher::NumericGte(field.to_string(), n))
            .unwrap_or_else(|| FieldMatcher::Exact(field.to_string(), value.to_lowercase())),

        // ── field-to-field reference ──────────────────────────────────
        "fieldref" => FieldMatcher::FieldRef(field.to_string(), value.to_string()),

        // ── default (no modifier or unknown) ──────────────────────────
        _ => {
            if value.contains('*') || value.contains('?') {
                FieldMatcher::Wildcard(field.to_string(), value.to_lowercase())
            } else {
                FieldMatcher::Exact(field.to_string(), value.to_lowercase())
            }
        }
    }
}

fn parse_numeric(s: &str) -> Option<f64> {
    s.trim().parse::<f64>().ok()
}

/// Sigma 2.0 modifier shapes that expand a single rule value into several
/// substring variants (windash, base64, base64offset, utf16le/utf16be/wide).
/// Returns the variants if `modifier` is one of those — `None` for any other
/// modifier so the caller falls back to the normal compile path. Composing
/// with `|contains` is implicit: the substring is always searched anywhere
/// in the field. Composing with `|all` would change OR→AND across the
/// variants but we keep OR semantics here: any encoded form is enough.
fn expand_value_modifier(modifier: &str, val: &Value) -> Option<Vec<String>> {
    // Modifier may arrive as `windash|contains` / `contains|windash` / `windash`
    // — Sigma allows the order to vary.
    let segments: std::collections::HashSet<&str> = modifier.split('|').collect();

    let pick: &str = if segments.contains("windash") {
        "windash"
    } else if segments.contains("base64offset") {
        "base64offset"
    } else if segments.contains("base64") {
        "base64"
    } else if segments.contains("utf16le") || segments.contains("wide") {
        "utf16le"
    } else if segments.contains("utf16be") {
        "utf16be"
    } else if segments.contains("utf16") {
        "utf16"
    } else {
        return None;
    };

    let raw_values: Vec<String> = match val {
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return Some(Vec::new()),
    };

    let mut out: Vec<String> = Vec::new();
    for v in raw_values {
        match pick {
            "windash" => {
                for variant in windash_variants(&v) {
                    if !out.contains(&variant) {
                        out.push(variant);
                    }
                }
            }
            "base64" => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(v.as_bytes())
                    .to_lowercase();
                if !out.contains(&encoded) {
                    out.push(encoded);
                }
            }
            "base64offset" => {
                for variant in base64offset_variants(&v) {
                    if !out.contains(&variant) {
                        out.push(variant);
                    }
                }
            }
            "utf16le" => {
                let encoded = utf16le_string(&v);
                if !out.contains(&encoded) {
                    out.push(encoded);
                }
            }
            "utf16be" => {
                let bytes: Vec<u8> = v.encode_utf16().flat_map(|c| c.to_be_bytes()).collect();
                let s = String::from_utf8_lossy(&bytes).to_lowercase();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            "utf16" => {
                // Sigma `|utf16` — UTF-16 with a leading BOM. We emit both LE
                // and BE so the matcher fires whatever byte order the live
                // payload uses; logging upstream is unpredictable for these
                // encodings.
                let mut le_bytes = vec![0xFF, 0xFE];
                le_bytes.extend(v.encode_utf16().flat_map(|c| c.to_le_bytes()));
                let mut be_bytes = vec![0xFE, 0xFF];
                be_bytes.extend(v.encode_utf16().flat_map(|c| c.to_be_bytes()));
                let le = String::from_utf8_lossy(&le_bytes).to_lowercase();
                let be = String::from_utf8_lossy(&be_bytes).to_lowercase();
                if !out.contains(&le) {
                    out.push(le);
                }
                if !out.contains(&be) {
                    out.push(be);
                }
            }
            _ => {}
        }
    }
    Some(out)
}

/// Generate the set of substring variants Sigma's `|windash` modifier expects.
/// Sigma 2.0 spec: every `-flag` token is duplicated with `/flag`, `–flag`,
/// `—flag`, `―flag` (en/em/horizontal-bar dashes). Returns the original value
/// plus every dash permutation, deduped. Lowercased for use with Contains.
pub fn windash_variants(value: &str) -> Vec<String> {
    const DASHES: &[&str] = &["-", "/", "\u{2013}", "\u{2014}", "\u{2015}"];
    let lower = value.to_lowercase();
    let mut out = vec![lower.clone()];
    if let Some(rest) = lower.strip_prefix('-') {
        for d in DASHES {
            let candidate = format!("{d}{rest}");
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    } else if let Some(idx) = lower.find(" -") {
        // Token in the middle of a string: " -flag" or " /flag".
        let (prefix, tail) = lower.split_at(idx);
        let rest = tail.trim_start_matches(' ').trim_start_matches('-');
        for d in DASHES {
            let candidate = format!("{prefix} {d}{rest}");
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

/// Encode a string in all three Sigma `|base64offset` shifted byte positions.
/// The Sigma spec records that a substring's base64 representation depends on
/// its byte alignment, so the engine has to check three encodings to catch a
/// command-line fragment regardless of where it falls in the parent buffer.
pub fn base64offset_variants(value: &str) -> Vec<String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(3);
    for shift in 0..3 {
        let mut padded = vec![0u8; shift];
        padded.extend_from_slice(bytes);
        let encoded = engine.encode(&padded);
        // Strip the leading shift-padded characters so the substring search
        // matches whatever offset the live buffer has.
        let trim_start = ((shift * 8 + 5) / 6).min(encoded.len());
        let trim_end = (encoded.len()).saturating_sub(((shift * 8) % 3 + 2) / 3);
        if trim_start < trim_end {
            out.push(encoded[trim_start..trim_end].to_lowercase());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Encode a string as UTF-16 little-endian bytes rendered into a lossy
/// substring. Used by Sigma's `|utf16le` / `|wide` modifiers when the rule
/// expects to find UTF-16 text inside a UTF-8 log line (e.g. PowerShell
/// EncodedCommand payloads after decode-as-utf8 happened).
pub fn utf16le_string(value: &str) -> String {
    let bytes: Vec<u8> = value.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    String::from_utf8_lossy(&bytes).to_lowercase()
}

/// Parse a condition string into a Condition tree.
///
/// Supports:
///   - bare reference: `selection`
///   - binary: `X and Y`, `X or Y`, `X and not Y`
///   - unary:  `not X`
///   - quantifier: `1 of X`, `all of X` where `X` is a name pattern
///     (wildcard `*` or the literal `them`). Quantifiers fold to nested
///     And/Or so the rest of the engine stays unaware of them.
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

    // Handle "1 of <pattern>" and "all of <pattern>". Pattern matching is
    // intentionally simple (prefix*, *suffix, exact, or `them`) since this
    // is what SigmaHQ actually emits in practice — full glob is overkill.
    if let Some(pat) = cond.strip_prefix("1 of ") {
        let names = expand_selection_pattern(pat.trim(), selections);
        if names.is_empty() {
            return Condition::Ref(cond.to_string());
        }
        return fold_or(names);
    }
    if let Some(pat) = cond.strip_prefix("all of ") {
        let names = expand_selection_pattern(pat.trim(), selections);
        if names.is_empty() {
            return Condition::Ref(cond.to_string());
        }
        return fold_and(names);
    }

    // Simple reference
    Condition::Ref(cond.to_string())
}

/// Expand a `1 of X` / `all of X` pattern into the concrete selection names
/// defined in the detection block. Empty result means the pattern didn't
/// match anything — caller should fall back to a leaf Ref so the engine
/// returns false safely instead of panicking.
fn expand_selection_pattern(
    pat: &str,
    selections: &HashMap<String, Vec<FieldMatcher>>,
) -> Vec<String> {
    if pat == "them" {
        // `1 of them` / `all of them`: every named selection in the block.
        // SigmaHQ's spec excludes the `condition`/`timeframe` keys, which
        // we already stripped at compile time, so all keys remaining in
        // `selections` are valid candidates.
        let mut names: Vec<String> = selections.keys().cloned().collect();
        names.sort();
        return names;
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        let mut names: Vec<String> = selections
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        names.sort();
        return names;
    }
    if let Some(suffix) = pat.strip_prefix('*') {
        let mut names: Vec<String> = selections
            .keys()
            .filter(|k| k.ends_with(suffix))
            .cloned()
            .collect();
        names.sort();
        return names;
    }
    if selections.contains_key(pat) {
        return vec![pat.to_string()];
    }
    Vec::new()
}

fn fold_or(names: Vec<String>) -> Condition {
    let mut iter = names.into_iter().map(|n| Condition::Ref(n));
    let first = iter.next().expect("non-empty");
    iter.fold(first, |acc, c| Condition::Or(Box::new(acc), Box::new(c)))
}

fn fold_and(names: Vec<String>) -> Condition {
    let mut iter = names.into_iter().map(|n| Condition::Ref(n));
    let first = iter.next().expect("non-empty");
    iter.fold(first, |acc, c| Condition::And(Box::new(acc), Box::new(c)))
}

// ── Matching ──

/// Whether a rule's logsource (category / product) is compatible with a log's
/// `tag`. A missing tag is treated as compatible (the rule still evaluates) to
/// preserve the long-standing behaviour for logs ingested without a tag.
/// Shared by `match_rule` and the field-resolution health audit so both gate
/// rules identically.
fn logsource_matches(rule: &CompiledRule, log_tag: Option<&str>) -> bool {
    if let Some(ref cat) = rule.logsource_category {
        if let Some(tag) = log_tag {
            if !tag.contains(cat.as_str()) {
                return false;
            }
        }
    }
    if let Some(ref prod) = rule.logsource_product {
        if let Some(tag) = log_tag {
            if !tag.contains(prod.as_str()) {
                return false;
            }
        }
    }
    true
}

/// Match a log against a single compiled rule.
fn match_rule(rule: &CompiledRule, log: &Value, log_tag: Option<&str>) -> Option<SigmaMatch> {
    // Check logsource filter
    if !logsource_matches(rule, log_tag) {
        return None;
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
                // Field exists but does not contain the substring — strict miss.
                // We must NOT fall back to scanning the entire JSON body, or
                // unrelated fields silently satisfy the rule (e.g. a rule
                // targeting `commandline` matching a PID stored in `data.pid`).
                return false;
            }
            // Field not present. Symbolic aliases (`full_log`, `message`, ...)
            // intentionally collapse to a whole-event scan because legacy
            // syslog rules reference them as a stand-in for "the log body".
            // For every other field name a missing key means the rule is not
            // applicable to this event — return false.
            if is_symbolic_log_alias(field) {
                let text = log.to_string().to_lowercase();
                if text.contains(substring) {
                    matched.push((field.clone(), substring.clone()));
                    return true;
                }
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
                return false;
            }
            if is_symbolic_log_alias(field) {
                let text = log.to_string().to_lowercase();
                for v in values {
                    if text.contains(v.as_str()) {
                        matched.push((field.clone(), v.clone()));
                        return true;
                    }
                }
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
        FieldMatcher::ContainsAll(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().all(|v| val_lower.contains(v.as_str())) {
                    matched.push((field.clone(), val));
                    return true;
                }
                return false;
            }
            if is_symbolic_log_alias(field) {
                let text = log.to_string().to_lowercase();
                if values.iter().all(|v| text.contains(v.as_str())) {
                    matched.push((field.clone(), values.join(" + ")));
                    return true;
                }
            }
            false
        }
        FieldMatcher::StartsWithAll(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().all(|v| val_lower.starts_with(v.as_str())) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::EndsWithAll(field, values) => {
            if let Some(val) = find_field(log, field) {
                let val_lower = val.to_lowercase();
                if values.iter().all(|v| val_lower.ends_with(v.as_str())) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }

        // ── Sigma 2.0 modifier arms ─────────────────────────────────────
        FieldMatcher::ExactCased(field, expected) => {
            if let Some(val) = find_field(log, field) {
                if val == *expected {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::ContainsCased(field, substring) => {
            if let Some(val) = find_field(log, field) {
                if val.contains(substring.as_str()) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::StartsWithCased(field, prefix) => {
            if let Some(val) = find_field(log, field) {
                if val.starts_with(prefix.as_str()) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::EndsWithCased(field, suffix) => {
            if let Some(val) = find_field(log, field) {
                if val.ends_with(suffix.as_str()) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::Regex(field, re) => {
            if let Some(val) = find_field(log, field) {
                if re.is_match(&val) {
                    matched.push((field.clone(), val));
                    return true;
                }
            }
            false
        }
        FieldMatcher::Cidr(field, net) => {
            if let Some(val) = find_field(log, field) {
                if let Ok(ip) = val.parse::<std::net::IpAddr>() {
                    if net.contains(&ip) {
                        matched.push((field.clone(), val));
                        return true;
                    }
                }
            }
            false
        }
        FieldMatcher::Exists(field, expected) => {
            let present = find_field(log, field).is_some();
            if present == *expected {
                matched.push((field.clone(), present.to_string()));
                return true;
            }
            false
        }
        FieldMatcher::NumericLt(field, n) => numeric_cmp(field, log, |x| x < *n, matched),
        FieldMatcher::NumericLte(field, n) => numeric_cmp(field, log, |x| x <= *n, matched),
        FieldMatcher::NumericGt(field, n) => numeric_cmp(field, log, |x| x > *n, matched),
        FieldMatcher::NumericGte(field, n) => numeric_cmp(field, log, |x| x >= *n, matched),
        FieldMatcher::FieldRef(field, other) => {
            // Compare two fields in the same event. Used by anti-evasion
            // rules where the suspicious condition is equality between two
            // fields (e.g. ProcessId == ParentProcessId for a parent-child
            // self-spawn pattern). Case-insensitive on both sides.
            if let (Some(a), Some(b)) = (find_field(log, field), find_field(log, other)) {
                if a.to_lowercase() == b.to_lowercase() {
                    matched.push((field.clone(), a));
                    return true;
                }
            }
            false
        }
    }
}

fn numeric_cmp(
    field: &str,
    log: &Value,
    cmp: impl Fn(f64) -> bool,
    matched: &mut Vec<(String, String)>,
) -> bool {
    let Some(val) = find_field(log, field) else {
        return false;
    };
    let Ok(parsed) = val.parse::<f64>() else {
        return false;
    };
    if cmp(parsed) {
        matched.push((field.to_string(), val));
        return true;
    }
    false
}

/// True if the field name is a symbolic alias for the whole log body —
/// legacy syslog rules reference these as a stand-in for "the raw log
/// line". For these aliases (and only these), a missing key triggers a
/// fallback scan of the serialized event. Any other field reference is
/// honored strictly: missing = no match, present-but-different = no
/// match. Without this gate, a rule targeting `commandline` would
/// silently match unrelated tokens elsewhere in the event (e.g. a port
/// number stored in `data.SourcePort`), which is the root cause of the
/// false positives that surfaced during the 2026-06 audit.
/// Stable 16-character hex digest of the matched field values, used as
/// part of the per-rule dedup key. Different username / source IP /
/// command line produces a different fingerprint and therefore a
/// different dedup bucket, so a brand-new attack on the same host no
/// longer reuses the suppression window of an unrelated earlier match.
fn sigma_match_fingerprint(matched_fields: &[(String, String)]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    let mut pairs: Vec<&(String, String)> = matched_fields.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    for (f, v) in pairs {
        f.to_lowercase().hash(&mut h);
        v.to_lowercase().hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

/// Same as `sigma_match_fingerprint` but also folds in the common
/// discriminator fields from the log (target user, source / destination
/// address, process id). The Golden Ticket rule for instance only
/// captures `channel`, `eventid` and `TicketEncryptionType` in
/// `matched_fields` — every account being targeted hashes identically
/// from those three values, so two distinct compromises against
/// `alice` and `bobby` would never both surface without the extra
/// context. Discriminators we look at: top-level and `data.*` variants
/// of `TargetUserName`, `SubjectUserName`, `username`, `user`,
/// `Account`, `IpAddress`, `source_ip`, `src_ip`, `dst_ip`, `dest_ip`,
/// `ProcessId`, `CommandLine` — anything present is folded in.
fn sigma_match_fingerprint_with_log(
    matched_fields: &[(String, String)],
    log: &serde_json::Value,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    const DISCRIMINATORS: &[&str] = &[
        "TargetUserName",
        "SubjectUserName",
        "username",
        "user",
        "user_name",
        "Account",
        "IpAddress",
        "source_ip",
        "src_ip",
        "src",
        "source",
        "rhost",
        "dst_ip",
        "dest_ip",
        "dst",
        "destination",
        "ProcessId",
        "CommandLine",
    ];

    let mut h = DefaultHasher::new();
    let mut pairs: Vec<&(String, String)> = matched_fields.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    for (f, v) in pairs {
        f.to_lowercase().hash(&mut h);
        v.to_lowercase().hash(&mut h);
    }

    // Fold in any discriminator we can find — checked both at top level
    // and nested under `data` (Windows osquery shape).
    for d in DISCRIMINATORS {
        for path in [d.to_string(), format!("data.{d}")] {
            if let Some(v) = find_field(log, &path)
                && !v.is_empty()
            {
                path.to_lowercase().hash(&mut h);
                v.to_lowercase().hash(&mut h);
                break;
            }
        }
    }

    format!("{:016x}", h.finish())
}

fn is_symbolic_log_alias(field: &str) -> bool {
    matches!(
        field.to_lowercase().as_str(),
        "full_log" | "raw_log" | "raw_text" | "log_text" | "message" | "body" | "log"
    )
}

/// Find a field value in a JSONB log. Supports dot notation and flat search.
///
/// Windows osquery telemetry (sysmon / powershell / windows_security) nests the
/// event fields under a `data` envelope: `{eventid, channel, data:{CommandLine,…}}`.
/// Sigma rules authored with a bare field name (`commandline`) — as most of the
/// first-party Windows pack is — must still resolve against that shape. So when a
/// single-segment field is absent at the top level we transparently retry under
/// `data.<field>`. Without this, ~50 marquee rules (LSASS dump, NTDS, PowerShell
/// obfuscation, APT) silently never matched real telemetry (they only matched the
/// flat-field demo data). See detection-chain audit, 2026-06-20.
fn find_field(log: &Value, field: &str) -> Option<String> {
    if let Some(v) = resolve_path(log, field) {
        return Some(v);
    }
    // Fallback: a bare field nested under the osquery `data` envelope.
    // Only for single-segment names — dotted paths are taken as authoritative.
    if !field.contains('.') {
        if let Some(v) = resolve_path(log, &format!("data.{field}")) {
            return Some(v);
        }
    }
    None
}

/// Resolve a (possibly dotted) field path against the log JSONB, with
/// case-insensitive matching at each level.
fn resolve_path(log: &Value, field: &str) -> Option<String> {
    // Try direct field access (exact key, including literal dotted keys).
    if let Some(val) = log.get(field) {
        return value_to_string(val);
    }

    // Try dot notation (e.g., "source.ip", "data.CommandLine").
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
    let rule_count = rules.len();
    *SIGMA_RULES.write().await = rules;

    let exceptions = load_active_exceptions(store).await;
    let exc_count = exceptions.len();
    *SIGMA_EXCEPTIONS.write().await = exceptions;

    tracing::info!(
        "SIGMA ENGINE: {} rules compiled, {} active exceptions loaded",
        rule_count,
        exc_count
    );
}

/// Reload rules and exceptions (after CRUD changes).
pub async fn reload(store: &dyn crate::db::Database) {
    let rules = load_and_compile(store).await;
    let rule_count = rules.len();
    *SIGMA_RULES.write().await = rules;

    let exceptions = load_active_exceptions(store).await;
    let exc_count = exceptions.len();
    *SIGMA_EXCEPTIONS.write().await = exceptions;

    tracing::info!(
        "SIGMA ENGINE: Reloaded — {} rules, {} exceptions",
        rule_count,
        exc_count
    );
}

// ── Test-only re-exports ──────────────────────────────────────────
//
// The integration test runner under `tests/sigma_rules.rs` needs to
// compile a YAML detection block and match it against fixture events.
// We don't want to expose `compile_detection` / `match_rule` to the
// rest of the crate — those are engine internals — so we provide
// these thin wrappers behind a feature-less but opt-in name.

pub fn compile_detection_for_tests(
    detection: &serde_json::Value,
) -> Option<(HashMap<String, Vec<FieldMatcher>>, Condition)> {
    compile_detection(detection)
}

pub fn match_rule_for_tests(
    rule: &CompiledRule,
    log: &serde_json::Value,
    log_tag: Option<&str>,
) -> Option<SigmaMatch> {
    match_rule(rule, log, log_tag)
}

/// Test/CI access to the SIGMA HEALTH field-resolution oracle. Returns
/// `(rule_id, unresolved_fields)` for every rule that resolved NONE of its
/// fields across the sampled logs of its own logsource — i.e. silently dead.
pub fn detect_unresolved_field_rules_for_tests(
    rules: &[CompiledRule],
    logs: &[crate::db::threatclaw_store::LogRecord],
) -> Vec<(String, Vec<String>)> {
    detect_unresolved_field_rules(rules, logs)
        .into_iter()
        .map(|w| (w.rule_id, w.fields))
        .collect()
}

async fn load_active_exceptions(store: &dyn crate::db::Database) -> Vec<ActiveException> {
    match store.load_active_sigma_exceptions().await {
        Ok(rows) => rows
            .into_iter()
            .filter_map(|r| {
                Some(ActiveException {
                    rule_id: r.get("rule_id")?.as_str()?.to_string(),
                    scope_field: r.get("scope_field")?.as_str()?.to_string(),
                    scope_value: r.get("scope_value")?.as_str()?.to_string(),
                })
            })
            .collect(),
        Err(e) => {
            tracing::warn!("SIGMA ENGINE: Failed to load exceptions: {e}");
            Vec::new()
        }
    }
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
            let disposition = row["disposition"].as_str().unwrap_or("detect").to_string();
            let tier = row["tier"].as_str().unwrap_or("queue").to_string();
            let risk_score = row["risk_score"].as_i64().map(|v| v as i32);
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
                disposition,
                tier,
                risk_score,
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

    // Cursor-based forward read. Each cycle resumes from the (created_at, id)
    // of the last log it processed, so a fixed batch size that's too small for
    // the live rate no longer drops logs — the next cycle catches up. The
    // floor (minutes_back as a safety bound) keeps a stale cursor from
    // re-scanning hours of history after an outage: when we detect the cursor
    // would force a window wider than `minutes_back`, we accept the gap and
    // emit a `lag` warn so the operator knows some logs went past.
    //
    // The cursor advances on `created_at` (DB insert time), not the event
    // `time`, so an upstream clock-drifted source can never poison it. See
    // query_logs_after_cursor for the full rationale.
    //
    // Cursor format (persisted as a setting):
    //   { "created_at": "2026-06-15T14:30:00Z", "id": 123456 }
    // Cycle batch size. Pushed from 5000 to 10000 on 2026-06-15 after the
    // red-team simulation revealed a syslog burst of ~10 k rows per 5-min
    // tick drained too slowly under the old cap (cf. query_logs_after_cursor
    // for the per-tag fairness rationale).
    const SIGMA_LOG_BATCH: i64 = 10000;
    const SIGMA_CURSOR_KEY: &str = "sigma_log_cursor";

    let (cursor_created_at, cursor_id) = load_sigma_cursor(store.as_ref()).await;

    let logs = match store
        .query_logs_after_cursor(cursor_created_at, cursor_id, minutes_back, SIGMA_LOG_BATCH)
        .await
    {
        Ok(l) => l,
        Err(_) => return,
    };

    // Lag indicator. When the batch is full, the live rate exceeds our
    // throughput per cycle and the cursor lags reality. Surface it so the
    // operator can size the deployment (or we tune SIGMA_LOG_BATCH up). The
    // cursor still advances either way, so coverage is preserved across cycles.
    if logs.len() as i64 >= SIGMA_LOG_BATCH {
        tracing::warn!(
            "SIGMA: batch saturated at {} logs — cursor is lagging the live ingestion rate, next cycle will catch up",
            SIGMA_LOG_BATCH
        );
    }

    // Observe-and-enrol: any hostname appearing in the recent log batch that
    // is not yet in the assets table gets upserted with `source = "syslog"`
    // and `inventory_status` left at the default so the operator can promote
    // it from "observed" to "declared" later. Without this hook a customer
    // forwarding syslog from 10k hosts would see zero asset rows even though
    // the SOC console clearly shows traffic, which made triage and the
    // dashboard inventory unusable for the syslog-only use case.
    enrol_observed_hostnames(store.as_ref(), &logs).await;

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

                // Dedup key blends the matched fields with a handful of
                // log discriminators (target user, source / destination
                // address, process id) so the fingerprint changes when
                // the *target* of the attack changes, even if the rule
                // itself only ever captured the constant parts (event
                // id, encryption type, channel). Without the
                // discriminators a Golden Ticket rule fingerprints
                // identically for every user — the second compromised
                // account never makes it past the suppression window.
                let fp = sigma_match_fingerprint_with_log(&m.matched_fields, &log.data);
                let dedup_key = format!("{}_{}_{}", m.rule_id, canonical_asset, fp);
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

                // Phase B — active exception filter. Operator-scoped
                // allowlist that silences a rule for a hostname / source
                // IP / username / tag. Loaded at engine reload, expired
                // entries already dropped by the SQL `WHERE` clause.
                {
                    let exceptions = SIGMA_EXCEPTIONS.read().await;
                    if alert_is_excepted(
                        &exceptions,
                        &m.rule_id,
                        Some(&canonical_asset),
                        source_ip,
                        username,
                        &rule.tags,
                    ) {
                        tracing::debug!(
                            "SIGMA ENGINE: alert dropped by exception — rule={} asset={}",
                            m.rule_id,
                            canonical_asset
                        );
                        continue;
                    }
                }

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
                // Phase D1 — RBA routing. A rule tagged `tier='rba_only'`
                // does NOT raise a direct alert: each match writes a weighted
                // `risk_event` on the asset, and the aggregator surfaces an
                // incident only when accumulated risk crosses a threshold.
                // (cf. internal/PLAN_PHASE_D_RBA.md.)
                if rule.tier == "rba_only" {
                    let score = rule
                        .risk_score
                        .unwrap_or_else(|| risk_score_from_level(&m.level));
                    let (mitre_tactic, mitre_technique) = mitre_from_tags(&rule.tags);
                    let ev = crate::db::threatclaw_store::NewRiskEvent {
                        risk_object: canonical_asset.clone(),
                        object_type: "asset".into(),
                        score,
                        source_rule: m.rule_id.clone(),
                        mitre_tactic,
                        mitre_technique,
                        log_id: Some(log.id),
                        message: Some(m.rule_title.clone()),
                    };
                    if let Err(e) = store.insert_risk_event(&ev).await {
                        tracing::warn!(
                            "RBA: insert_risk_event failed for rule {} on {}: {e}",
                            m.rule_id,
                            canonical_asset
                        );
                    }
                    continue; // no direct alert for rba_only rules
                }

                // Phase B — promotion ladder disposition. `block` tags the
                // alert so the HITL panel surfaces an explicit "auto-action
                // recommended" pill. `monitor` forces the alert level down
                // to informational so it lands in audit-only mode and the
                // promotion-to-finding short-circuit below filters it out.
                let effective_level: String = match rule.disposition.as_str() {
                    "monitor" => "informational".to_string(),
                    other => {
                        if other == "block" {
                            mf_obj.insert(
                                "_disposition".into(),
                                serde_json::Value::String("block".into()),
                            );
                        }
                        m.level.clone()
                    }
                };
                let mf_value = serde_json::Value::Object(mf_obj);

                let _ = store
                    .insert_sigma_alert_with_fields(
                        &m.rule_id,
                        &effective_level,
                        &m.rule_title,
                        &canonical_asset,
                        source_ip,
                        username,
                        &mf_value,
                        Some(log.id),
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
                // Use the *effective* level so a rule in `monitor` mode
                // (which we just downgraded to informational) never
                // promotes — that's the entire point of audit-only.
                let level_lc = effective_level.to_lowercase();
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
                    // Apply the same junk-hostname filter the observe-and-enrol
                    // pass uses, otherwise findings land on assets that don't
                    // exist and never will (`kernel`, `dockerd`,
                    // `bc130c79e5dd`). Pre-fix cyb06 had findings keyed on
                    // sshd-session, lynis, and a Docker container id, plus a
                    // CRITICAL incident on a 12-hex container id — purely
                    // orphan rows the operator could not act on.
                    if looks_like_program_or_container_id(&canonical_asset) {
                        tracing::debug!(
                            "SIGMA: skip finding on junk hostname '{}' (rule={})",
                            canonical_asset,
                            m.rule_id
                        );
                        continue;
                    }

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

    // Field-resolution health audit (once per cycle, warn-once per rule): surface
    // any rule that is silently dead because its fields never resolve against its
    // own logsource — the failure class behind the 50 dead Windows rules.
    warn_unresolved_field_rules(&rules, &logs);

    if alerts_created > 0 || findings_created > 0 {
        tracing::info!(
            "SIGMA ENGINE: {} alerts, {} findings from {} logs ({} rules)",
            alerts_created,
            findings_created,
            logs.len(),
            rules.len()
        );
    }

    // Advance the cursor to the last (time, id) of the batch so the next
    // cycle resumes from there. We pin to the last record consumed (not the
    // theoretical end of the window) because some upstream connectors backfill
    // out of order — pinning to "the last one we *saw*" guarantees we don't
    // skip a late arrival on the next tick.
    if let (Some(last_created_at), Some(last_id)) = (
        logs.last().map(|l| l.created_at.clone()),
        logs.last().map(|l| l.id),
    ) {
        // Advance the cursor on `created_at` (DB insert time), NOT the event
        // `time`. `created_at` is assigned by Postgres (`DEFAULT now()`) at
        // INSERT, so it is monotonic and can never be in the future — no
        // clamp is needed and an upstream clock-drifted `time` can no longer
        // leap the cursor ahead of wall-clock and starve the engine (the
        // multi-hour blind window seen on cyb06 2026-06-20). The query orders
        // by (created_at ASC, id ASC), so the last row carries the max cursor.
        save_sigma_cursor(store.as_ref(), &last_created_at, last_id).await;
    }
    let _ = SIGMA_CURSOR_KEY; // referenced for clarity in tests/audit

    // Keep the sigma_rule_stats matview in lockstep with the cycle so the
    // dashboard never lags more than one tick. Cheap on ~75 rules; the
    // CONCURRENTLY refresh avoids blocking reads during the swap.
    if let Err(e) = store.refresh_sigma_rule_stats().await {
        tracing::warn!("SIGMA ENGINE: refresh_sigma_rule_stats failed: {e}");
    }
}

/// Read the persisted sigma cursor (created_at, id). Returns (None, 0) on first
/// boot or after the setting was cleared — the caller treats that as "start
/// from the floor of the safety window".
///
/// The cursor advances on `created_at` (DB insert time) now, not the event
/// `time` (see query_logs_after_cursor). We deliberately read the `created_at`
/// key only: a legacy cursor persisted under the old `time` key is treated as
/// absent (returns None), which makes the engine resume from the floor on the
/// first cycle after upgrade — that also self-heals an old `time`-cursor that
/// had been poisoned by a future-dated row.
async fn load_sigma_cursor(
    store: &dyn crate::db::Database,
) -> (Option<chrono::DateTime<chrono::Utc>>, i64) {
    let Ok(Some(val)) = store.get_setting("_system", "sigma_log_cursor").await else {
        return (None, 0);
    };
    let created_at = val
        .get("created_at")
        .and_then(|t| t.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    // A cursor with no parseable created_at (first boot, or a legacy time-only
    // cursor) must not carry over a stale id, or the keyset predicate
    // `created_at = floor AND id > $2` would silently skip rows at the floor.
    let id = if created_at.is_some() {
        val.get("id").and_then(|i| i.as_i64()).unwrap_or(0)
    } else {
        0
    };
    (created_at, id)
}

/// Persist the sigma cursor after a successful batch consume. Failures here
/// are non-fatal — on the next cycle we'd just re-read the last batch, which
/// is wasteful but not unsafe (dedup keys prevent double alerting).
async fn save_sigma_cursor(store: &dyn crate::db::Database, last_created_at: &str, last_id: i64) {
    let val = serde_json::json!({
        "created_at": last_created_at,
        "id": last_id,
    });
    if let Err(e) = store.set_setting("_system", "sigma_log_cursor", &val).await {
        tracing::warn!("SIGMA ENGINE: failed to persist cursor — {e}");
    }
}

/// For every distinct, non-empty hostname appearing in the recent log
/// batch, upsert a syslog-sourced asset row if one does not already
/// exist. This is the auto-enrolment hook for the "customer forwards
/// raw syslog from N hosts" use case — without it the assets table
/// stays empty until the operator manually declares each device, even
/// though the SOC console shows live traffic from them.
///
/// Idempotent: subsequent cycles re-upsert the same id and skip rows
/// where `find_asset_by_hostname` already returns Some. We only enrol
/// when the raw hostname is neither empty nor literally "unknown",
/// and we never overwrite a hostname that already maps to a declared
/// asset (the auto-row uses a deterministic `syslog-observed-<host>`
/// id distinct from any operator-created id).
async fn enrol_observed_hostnames(
    store: &dyn crate::db::Database,
    logs: &[crate::db::threatclaw_store::LogRecord],
) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Declared internal networks — used to keep public scanner IPs out of the
    // inventory (see the IP guard below). Loaded once for the whole batch.
    let networks: Vec<crate::agent::ip_classifier::NetworkRange> = store
        .list_internal_networks()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|n| {
            crate::agent::ip_classifier::NetworkRange::from_cidr(
                &n.cidr,
                n.label.as_deref().unwrap_or(""),
                &n.zone,
            )
        })
        .collect();
    for log in logs {
        let Some(h) = log.hostname.as_deref() else {
            continue;
        };
        if h.is_empty() || h == "unknown" {
            continue;
        }
        if looks_like_program_or_container_id(h) {
            continue;
        }
        // A WAN-facing firewall logs every Internet scanner that hits it; when
        // such an IP lands in the syslog `host` slot, enrolling it creates a
        // billable junk asset that reappears every cycle. Only enrol an IP-shaped
        // host when it classifies as internal (declared network / RFC1918 / ULA);
        // drop External and special addresses. Real (non-IP) hostnames pass through.
        if h.parse::<std::net::IpAddr>().is_ok()
            && !crate::agent::ip_classifier::ip_is_enrollable(h, &networks, &[])
        {
            continue;
        }
        // A syslog `host` value that still carries key=value / quoted fragments
        // (e.g. Stormshield's `fw="VMSNS…"` when fluent-bit's RFC3164 parser
        // mis-splits its non-standard "Legacy" line) is not a real hostname.
        // Enrolling it both creates a garbage asset and — lacking an IP —
        // dodges dedup, duplicating a device already enrolled by its connector.
        if h.contains('=') || h.contains('"') {
            continue;
        }
        if !seen.insert(h.to_string()) {
            continue;
        }
        if let Ok(Some(_)) = store.find_asset_by_hostname(h).await {
            continue;
        }
        // Enrol through the single resolver so a host seen via syslog and via
        // the agent collapses to one canonical id instead of a private
        // `syslog-observed-*` id. The syslog-source subtype + tags come from
        // classification_for_source.
        let discovered = crate::graph::asset_resolution::DiscoveredAsset {
            mac: None,
            hostname: Some(h.to_string()),
            fqdn: None,
            ip: None,
            os: None,
            ports: None,
            services: serde_json::json!([]),
            ou: None,
            vlan: None,
            vm_id: None,
            criticality: None,
            source: "syslog".into(),
        };
        let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
        tracing::info!(
            target: "asset_enrolment",
            "auto-enrolled asset from syslog source: {}",
            h
        );
    }
}

/// Heuristic to filter out values that look like a syslog program name or
/// a Docker container id rather than a real hostname. Without this filter
/// the observe-and-enrol pass creates noise assets like
/// "syslog-observed-kernel" or "syslog-observed-dockerd" whenever a sender
/// emits a RFC3164 line that omits the hostname field (the program then
/// lands in the parsed host slot). Real hostnames almost always carry a
/// `.` (FQDN), a `-` (host-NN convention), or a digit, while program
/// names are short lowercase tokens. The blocklist catches the rest.
fn looks_like_program_or_container_id(s: &str) -> bool {
    // Common syslog program names that leak into the host slot when the
    // sender omits the hostname header.
    const PROGRAM_BLOCKLIST: &[&str] = &[
        "kernel",
        "systemd",
        "rsyslogd",
        "syslog-ng",
        "dockerd",
        "containerd",
        "containerd-shim",
        "cron",
        "crond",
        "sshd",
        "audit",
        "auditd",
        "sudo",
        "su",
        "login",
        "init",
        "dhclient",
        "NetworkManager",
        "wpa_supplicant",
        "agetty",
        "polkitd",
        "snapd",
        "chronyd",
        "ntpd",
        "named",
        "postfix",
        "nginx",
        "apache2",
        "httpd",
        "haproxy",
        "kubelet",
        "kube-proxy",
    ];
    let lower = s.to_ascii_lowercase();
    if PROGRAM_BLOCKLIST.contains(&lower.as_str()) {
        return true;
    }
    // Internal noise from the ThreatClaw stack itself
    if s.starts_with("threatclaw-") {
        return true;
    }
    // Docker container ids are 12 or 64 hex chars with no dot, no dash
    let is_hex = !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
    let no_separator = !s.contains('.') && !s.contains('-') && !s.contains('_');
    if is_hex && no_separator && (s.len() == 12 || s.len() == 64) {
        return true;
    }
    false
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

// ── Field-resolution health audit ───────────────────────────────────────────
// The 2026-06-20 detection-chain audit found ~50 marquee Windows rules silently
// dead: they referenced a bare field (`commandline`) that did not resolve against
// the nested osquery telemetry shape, with no warning anywhere. Fix #1 resolves
// the bare field; this audit makes the *class* of failure loud so it can never
// silently recur — a rule whose fields never resolve against its own logsource is
// flagged in the logs.

/// Rules already flagged this process lifetime, so we warn once per rule instead
/// of every 5-minute cycle.
static SIGMA_HEALTH_WARNED: LazyLock<std::sync::RwLock<std::collections::HashSet<String>>> =
    LazyLock::new(|| std::sync::RwLock::new(std::collections::HashSet::new()));

/// A rule whose referenced fields never resolved against any log of its own
/// logsource in the sampled batch — almost always a field-mapping error.
#[derive(Debug, Clone, PartialEq)]
struct RuleFieldWarning {
    rule_id: String,
    logsource: String,
    fields: Vec<String>,
    sampled: usize,
}

/// Detect enabled rules that are silently dead because none of their referenced
/// fields resolve against the log shape of their own logsource. Bounded and
/// sampled: it early-exits on the first resolving log, so working rules cost ~one
/// lookup and only suspect rules pay the sampling cost.
fn detect_unresolved_field_rules(
    rules: &[CompiledRule],
    logs: &[crate::db::threatclaw_store::LogRecord],
) -> Vec<RuleFieldWarning> {
    const MAX_SAMPLE_PER_RULE: usize = 25;
    const MIN_SAMPLE_TO_JUDGE: usize = 5;
    let mut warnings = Vec::new();
    for rule in rules {
        // Auditable fields: skip presence-only (`exists`) matchers and symbolic
        // aliases (`message`/`full_log`, which resolve via the whole-event body
        // scan in eval_matcher, not via find_field — auditing them would
        // false-positive).
        let mut fields: Vec<&str> = rule
            .matchers
            .values()
            .flatten()
            .filter_map(|m| m.audited_field())
            .filter(|f| !is_symbolic_log_alias(f))
            .collect();
        if fields.is_empty() {
            continue;
        }
        fields.sort_unstable();
        fields.dedup();

        let mut sampled = 0usize;
        let mut resolved_any = false;
        for log in logs {
            if !logsource_matches(rule, log.tag.as_deref()) {
                continue;
            }
            if fields.iter().any(|f| find_field(&log.data, f).is_some()) {
                resolved_any = true;
                break;
            }
            sampled += 1;
            if sampled >= MAX_SAMPLE_PER_RULE {
                break;
            }
        }
        if !resolved_any && sampled >= MIN_SAMPLE_TO_JUDGE {
            warnings.push(RuleFieldWarning {
                rule_id: rule.id.clone(),
                logsource: rule
                    .logsource_category
                    .as_deref()
                    .or(rule.logsource_product.as_deref())
                    .unwrap_or("?")
                    .to_string(),
                fields: fields.iter().map(|s| s.to_string()).collect(),
                sampled,
            });
        }
    }
    warnings
}

/// Run the field-resolution audit on the current batch and warn once per rule.
fn warn_unresolved_field_rules(
    rules: &[CompiledRule],
    logs: &[crate::db::threatclaw_store::LogRecord],
) {
    let warnings = detect_unresolved_field_rules(rules, logs);
    if warnings.is_empty() {
        return;
    }
    let mut seen = SIGMA_HEALTH_WARNED
        .write()
        .unwrap_or_else(|e| e.into_inner());
    for w in warnings {
        if seen.insert(w.rule_id.clone()) {
            tracing::warn!(
                target: "sigma_health",
                rule_id = %w.rule_id,
                logsource = %w.logsource,
                sampled = w.sampled,
                "SIGMA HEALTH: rule '{}' resolved NONE of its fields {:?} across {} '{}' logs — likely a field-mapping error (the rule is silently dead)",
                w.rule_id, w.fields, w.sampled, w.logsource
            );
        }
    }
}

// Phase 8b — La logique IDS multi-vendor (Suricata + futurs Fortinet,
// Stormshield, pfSense, Cisco Firepower) vit dans
// `agent/ids_normalizer/`. Voir le trait `IdsAlertNormalizer` et la
// fonction `is_benign` côté module dédié pour la matrice complète des
// critères de drop. Le sigma_engine n'invoque que `try_normalize +
// is_benign` ; aucune logique vendor-specific ici.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── wildcard_match ─────────────────────────────────────────────

    #[test]
    fn wildcard_exact_match() {
        assert!(wildcard_match("hello", "hello"));
        assert!(!wildcard_match("hello", "world"));
    }

    #[test]
    fn wildcard_star_matches_anything() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("hello*", "helloworld"));
        assert!(wildcard_match("*world", "helloworld"));
        assert!(wildcard_match("hello*world", "helloANYworld"));
    }

    #[test]
    fn wildcard_question_matches_one_char() {
        assert!(wildcard_match("h?llo", "hello"));
        assert!(wildcard_match("h?llo", "hxllo"));
        assert!(!wildcard_match("h?llo", "hllo"));
    }

    #[test]
    fn wildcard_consecutive_stars_collapse() {
        assert!(wildcard_match("***", "anything"));
        assert!(wildcard_match("a**b", "axxb"));
    }

    // ── find_field ─────────────────────────────────────────────────

    #[test]
    fn find_field_top_level() {
        let log = json!({ "username": "alice", "src_ip": "10.0.0.1" });
        assert_eq!(find_field(&log, "username"), Some("alice".into()));
        assert_eq!(find_field(&log, "src_ip"), Some("10.0.0.1".into()));
    }

    #[test]
    fn find_field_case_insensitive() {
        let log = json!({ "UserName": "alice" });
        assert_eq!(find_field(&log, "username"), Some("alice".into()));
        assert_eq!(find_field(&log, "USERNAME"), Some("alice".into()));
    }

    #[test]
    fn find_field_dot_notation_nested() {
        let log = json!({ "data": { "host": { "name": "srv-01" } } });
        assert_eq!(find_field(&log, "data.host.name"), Some("srv-01".into()));
    }

    #[test]
    fn find_field_missing_returns_none() {
        let log = json!({ "username": "alice" });
        assert_eq!(find_field(&log, "missing"), None);
    }

    #[test]
    fn find_field_handles_numeric_values() {
        let log = json!({ "port": 22, "score": 9.5 });
        assert_eq!(find_field(&log, "port"), Some("22".into()));
        assert_eq!(find_field(&log, "score"), Some("9.5".into()));
    }

    // ── eval_matcher ───────────────────────────────────────────────

    fn run_matcher(m: &FieldMatcher, log: &serde_json::Value) -> bool {
        let mut buf = Vec::new();
        eval_matcher(m, log, &mut buf)
    }

    // NOTE on matcher invariants: `make_matcher` lowercases the pattern
    // value at compile time, then `eval_matcher` lowercases the log value
    // at run time. So when constructing a FieldMatcher directly in a test,
    // its second argument is assumed to be ALREADY lowercased. The case
    // insensitivity is enforced at compile time, not in the matcher body.
    // The `matcher_via_make_matcher` test below verifies the end-to-end
    // case insensitivity chain that real users see.

    #[test]
    fn matcher_exact_lowercase_pattern() {
        let log = json!({ "username": "Alice" });
        assert!(run_matcher(
            &FieldMatcher::Exact("username".into(), "alice".into()),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::Exact("username".into(), "bob".into()),
            &log
        ));
    }

    #[test]
    fn matcher_via_make_matcher_is_case_insensitive_end_to_end() {
        // What a user writes in YAML: value with arbitrary casing.
        let m = make_matcher("username", "", "ALICE");
        let log_upper = json!({ "username": "Alice" });
        let log_lower = json!({ "username": "alice" });
        let log_mixed = json!({ "username": "aLiCe" });
        let mut buf = Vec::new();
        assert!(eval_matcher(&m, &log_upper, &mut buf));
        assert!(eval_matcher(&m, &log_lower, &mut buf));
        assert!(eval_matcher(&m, &log_mixed, &mut buf));
    }

    #[test]
    fn matcher_contains_substring() {
        let log = json!({ "message": "Failed login from 10.0.0.1" });
        // Pattern stored lowercased per make_matcher invariant.
        assert!(run_matcher(
            &FieldMatcher::Contains("message".into(), "failed login".into()),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::Contains("message".into(), "success".into()),
            &log
        ));
    }

    #[test]
    fn matcher_contains_falls_back_to_body_scan() {
        // Symbolic alias (`message`) absent at top level — fallback to whole body.
        let log = json!({ "data": { "raw": "Failed login from 10.0.0.1" } });
        assert!(run_matcher(
            &FieldMatcher::Contains("message".into(), "failed login".into()),
            &log
        ));
    }

    #[test]
    fn matcher_contains_strict_for_non_symbolic_field() {
        // Regression for the 2026-06 FP storm: a rule targeting `commandline`
        // must NOT silently match unrelated fields just because the substring
        // appears somewhere else in the event. Before the fix, `commandline`
        // would fall back to scanning the whole JSON, so an event without a
        // commandline field — but with "23" stored in a port number elsewhere
        // — would falsely satisfy a rule looking for the literal "23" in a
        // command line. Now the matcher is strict: missing field = no match.
        let log = json!({
            "data": { "TargetPort": 23, "Image": "powershell.exe" }
        });
        assert!(!run_matcher(
            &FieldMatcher::Contains("commandline".into(), "23".into()),
            &log
        ));
    }

    // ── Sigma 2.0 modifier coverage ─────────────────────────────────

    #[test]
    fn modifier_cased_distinguishes_case() {
        let log = json!({ "User": "Administrator" });
        // Default Sigma is case-insensitive — should match.
        assert!(run_matcher(
            &FieldMatcher::Exact("User".into(), "administrator".into()),
            &log
        ));
        // |cased — exact byte match, case matters.
        assert!(run_matcher(
            &FieldMatcher::ExactCased("User".into(), "Administrator".into()),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::ExactCased("User".into(), "administrator".into()),
            &log
        ));
    }

    #[test]
    fn modifier_regex_matches_pattern() {
        let log = json!({ "commandline": "powershell.exe -EncodedCommand AAAA" });
        let re = regex::Regex::new(r"(?i)powershell.*-encodedcommand").unwrap();
        assert!(run_matcher(
            &FieldMatcher::Regex("commandline".into(), re),
            &log
        ));
    }

    #[test]
    fn modifier_regex_fails_on_no_match() {
        let log = json!({ "commandline": "cmd.exe /c dir" });
        let re = regex::Regex::new(r"powershell").unwrap();
        assert!(!run_matcher(
            &FieldMatcher::Regex("commandline".into(), re),
            &log
        ));
    }

    #[test]
    fn modifier_cidr_v4_in_range() {
        let log = json!({ "src_ip": "10.0.0.42" });
        let net = CidrNet::parse("10.0.0.0/24").unwrap();
        assert!(run_matcher(&FieldMatcher::Cidr("src_ip".into(), net), &log));
    }

    #[test]
    fn modifier_cidr_v4_out_of_range() {
        let log = json!({ "src_ip": "10.0.1.42" });
        let net = CidrNet::parse("10.0.0.0/24").unwrap();
        assert!(!run_matcher(
            &FieldMatcher::Cidr("src_ip".into(), net),
            &log
        ));
    }

    #[test]
    fn modifier_cidr_v6_in_range() {
        let log = json!({ "src_ip": "2001:db8::1" });
        let net = CidrNet::parse("2001:db8::/32").unwrap();
        assert!(run_matcher(&FieldMatcher::Cidr("src_ip".into(), net), &log));
    }

    #[test]
    fn modifier_exists_true_when_present() {
        let log = json!({ "EventID": 4624 });
        assert!(run_matcher(
            &FieldMatcher::Exists("EventID".into(), true),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::Exists("EventID".into(), false),
            &log
        ));
    }

    #[test]
    fn modifier_exists_false_when_absent() {
        let log = json!({ "EventID": 4624 });
        assert!(run_matcher(
            &FieldMatcher::Exists("Missing".into(), false),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::Exists("Missing".into(), true),
            &log
        ));
    }

    #[test]
    fn modifier_numeric_lt_gt() {
        let log = json!({ "score": "85" });
        assert!(run_matcher(
            &FieldMatcher::NumericGt("score".into(), 80.0),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::NumericLt("score".into(), 80.0),
            &log
        ));
        assert!(run_matcher(
            &FieldMatcher::NumericLte("score".into(), 85.0),
            &log
        ));
        assert!(run_matcher(
            &FieldMatcher::NumericGte("score".into(), 85.0),
            &log
        ));
    }

    #[test]
    fn modifier_fieldref_matches_when_fields_equal() {
        let log = json!({ "ProcessId": "1234", "ParentProcessId": "1234" });
        assert!(run_matcher(
            &FieldMatcher::FieldRef("ProcessId".into(), "ParentProcessId".into()),
            &log
        ));
    }

    #[test]
    fn modifier_fieldref_no_match_when_different() {
        let log = json!({ "ProcessId": "1234", "ParentProcessId": "5678" });
        assert!(!run_matcher(
            &FieldMatcher::FieldRef("ProcessId".into(), "ParentProcessId".into()),
            &log
        ));
    }

    #[test]
    fn windash_variants_replaces_leading_dash() {
        let vs = windash_variants("-hp");
        assert!(vs.contains(&"-hp".to_string()));
        assert!(vs.contains(&"/hp".to_string()));
        assert!(vs.contains(&"\u{2013}hp".to_string())); // en dash
        assert!(vs.contains(&"\u{2014}hp".to_string())); // em dash
    }

    #[test]
    fn base64offset_variants_emits_three_shifts() {
        let vs = base64offset_variants("admin");
        assert!(
            vs.len() >= 3,
            "expected at least 3 shift variants, got {vs:?}"
        );
    }

    #[test]
    fn make_matcher_re_compiles_regex() {
        let m = make_matcher("commandline", "re", r"powershell.*-EncodedCommand");
        assert!(matches!(m, FieldMatcher::Regex(_, _)));
    }

    #[test]
    fn make_matcher_cidr_parses_value() {
        let m = make_matcher("src_ip", "cidr", "192.168.0.0/16");
        assert!(matches!(m, FieldMatcher::Cidr(_, _)));
    }

    #[test]
    fn make_matcher_cased_modifier() {
        let m = make_matcher("User", "cased", "Administrator");
        assert!(matches!(m, FieldMatcher::ExactCased(_, _)));
        let m = make_matcher("User", "contains|cased", "Admin");
        assert!(matches!(m, FieldMatcher::ContainsCased(_, _)));
    }

    // ── End-to-end integration tests with real SigmaHQ rule shapes ──

    #[test]
    fn sigmahq_real_regex_rule_compiles_to_regex_matcher() {
        // Powershell Token Obfuscation, deb9b646-… real SigmaHQ rule.
        let detection = json!({
            "selection": [
                { "CommandLine|re": r"\w+`(?:\w+|-|.)`[\w+|\s]" },
                { "CommandLine|re": r#""(?:\{\d\})+"\s*-f"# }
            ],
            "filter_main_envpath": {
                "data.CommandLine|contains": "${env:path}"
            },
            "condition": "selection and not 1 of filter_main_*"
        });
        let (selections, _cond) = compile_detection_for_tests(&detection).unwrap();
        let sel = selections.get("selection").expect("selection must compile");
        let regex_count = sel
            .iter()
            .filter(|m| matches!(m, FieldMatcher::Regex(_, _)))
            .count();
        assert!(
            regex_count >= 1,
            "Expected at least one Regex matcher in compiled selection"
        );
    }

    #[test]
    fn sigmahq_real_base64offset_rule_expands_to_contains_any() {
        // PowerShell Base64 Encoded IEX Cmdlet, 88f680b8-… real SigmaHQ rule.
        let detection = json!({
            "selection": [
                {
                    "CommandLine|base64offset|contains": [
                        "IEX ([",
                        "iex (New",
                        "IEX(New"
                    ]
                }
            ],
            "condition": "selection"
        });
        let (selections, _cond) = compile_detection_for_tests(&detection).unwrap();
        let sel = selections.get("selection").expect("selection must compile");
        // base64offset must expand into a ContainsAny with at least 3*3=9 variants
        // (3 values × 3 shift positions), give or take dedup.
        let contains_any = sel
            .iter()
            .find_map(|m| match m {
                FieldMatcher::ContainsAny(_, vs) => Some(vs.clone()),
                _ => None,
            })
            .expect("Expected a ContainsAny matcher after base64offset expansion");
        assert!(
            contains_any.len() >= 6,
            "Expected base64offset to emit several variants per value, got {}",
            contains_any.len()
        );
    }

    #[test]
    fn sigmahq_cidr_rule_compiles_to_cidr_matcher() {
        let detection = json!({
            "selection": {
                "src_ip|cidr": "10.0.0.0/8"
            },
            "condition": "selection"
        });
        let (selections, _cond) = compile_detection_for_tests(&detection).unwrap();
        let sel = selections.get("selection").unwrap();
        assert!(matches!(sel.first(), Some(FieldMatcher::Cidr(_, _))));

        // End-to-end match against a live log.
        let log_inside = json!({ "src_ip": "10.5.1.42" });
        let log_outside = json!({ "src_ip": "192.168.1.1" });
        let m = sel.first().unwrap();
        assert!(run_matcher(m, &log_inside));
        assert!(!run_matcher(m, &log_outside));
    }

    #[test]
    fn sigmahq_windash_rule_expands_to_dash_variants() {
        let detection = json!({
            "selection": {
                "data.CommandLine|windash|contains": " -hp"
            },
            "condition": "selection"
        });
        let (selections, _cond) = compile_detection_for_tests(&detection).unwrap();
        let sel = selections.get("selection").unwrap();
        let contains_any = sel
            .iter()
            .find_map(|m| match m {
                FieldMatcher::ContainsAny(_, vs) => Some(vs.clone()),
                _ => None,
            })
            .expect("windash must compile to ContainsAny");
        // At least the original + the / variant + the en-dash variant.
        assert!(
            contains_any.len() >= 3,
            "windash expansion thin: got {:?}",
            contains_any
        );

        // E2E: live log with the slash variant must match.
        let log = json!({ "data": { "CommandLine": "7z.exe a /hp:secret archive.7z" } });
        let m = sel.first().unwrap();
        assert!(run_matcher(m, &log), "windash slash variant should match");
    }

    #[test]
    fn matcher_contains_present_but_no_substring_is_strict() {
        // Field exists and does NOT contain the substring — must NOT fall
        // back to whole-body scan even though the substring is present in a
        // different field of the same event.
        let log = json!({
            "commandline": "powershell.exe",
            "host": "23-RDP-server"
        });
        assert!(!run_matcher(
            &FieldMatcher::Contains("commandline".into(), "rdp".into()),
            &log
        ));
    }

    #[test]
    fn matcher_startswith_endswith() {
        let log = json!({ "command": "powershell.exe -EncodedCommand abc" });
        assert!(run_matcher(
            &FieldMatcher::StartsWith("command".into(), "powershell".into()),
            &log
        ));
        assert!(run_matcher(
            &FieldMatcher::EndsWith("command".into(), "abc".into()),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::StartsWith("command".into(), "cmd".into()),
            &log
        ));
    }

    #[test]
    fn matcher_wildcard_uses_glob() {
        let log = json!({ "path": "C:\\Users\\admin\\Documents\\file.exe" });
        // Pattern + log value both lowercased before glob compare.
        assert!(run_matcher(
            &FieldMatcher::Wildcard("path".into(), "c:\\users\\*\\file.exe".into()),
            &log
        ));
        assert!(!run_matcher(
            &FieldMatcher::Wildcard("path".into(), "c:\\windows\\*".into()),
            &log
        ));
    }

    #[test]
    fn matcher_any_of_or() {
        let log = json!({ "event_id": "4625" });
        let m = FieldMatcher::AnyOf(
            "event_id".into(),
            vec!["4624".into(), "4625".into(), "4768".into()],
        );
        assert!(run_matcher(&m, &log));
        let m_miss = FieldMatcher::AnyOf("event_id".into(), vec!["4624".into(), "4768".into()]);
        assert!(!run_matcher(&m_miss, &log));
    }

    #[test]
    fn matcher_contains_any_or() {
        let log = json!({ "command": "Invoke-Mimikatz" });
        let m = FieldMatcher::ContainsAny(
            "command".into(),
            vec!["mimikatz".into(), "bloodhound".into()],
        );
        assert!(run_matcher(&m, &log));
    }

    #[test]
    fn matcher_startswith_any() {
        let log = json!({ "binary": "powershell.exe" });
        let m = FieldMatcher::StartsWithAny(
            "binary".into(),
            vec!["cmd".into(), "powershell".into(), "wscript".into()],
        );
        assert!(run_matcher(&m, &log));
    }

    #[test]
    fn matcher_endswith_any() {
        let log = json!({ "file": "evil.exe" });
        let m = FieldMatcher::EndsWithAny(
            "file".into(),
            vec![".exe".into(), ".dll".into(), ".bat".into()],
        );
        assert!(run_matcher(&m, &log));
    }

    // ── compile_detection / parse_condition ────────────────────────

    #[test]
    fn compile_simple_selection() {
        let det = json!({
            "selection": { "username": "admin" },
            "condition": "selection"
        });
        let (sel, _cond) = compile_detection(&det).expect("compile");
        assert!(sel.contains_key("selection"));
        assert_eq!(sel["selection"].len(), 1);
    }

    #[test]
    fn compile_selection_with_modifier() {
        let det = json!({
            "selection": { "command|contains": "Mimikatz" },
            "condition": "selection"
        });
        let (sel, _) = compile_detection(&det).expect("compile");
        assert!(matches!(sel["selection"][0], FieldMatcher::Contains(_, _)));
    }

    #[test]
    fn condition_and_not_filter() {
        let det = json!({
            "selection": { "event_id": "4625" },
            "filter":    { "username": "test" },
            "condition": "selection and not filter"
        });
        let (sel, cond) = compile_detection(&det).expect("compile");

        // True positive: matches selection, not filter.
        let log = json!({ "event_id": "4625", "username": "alice" });
        let mut buf = Vec::new();
        assert!(eval_condition(&cond, &sel, &log, &mut buf));

        // False: matches the filter too → should NOT fire.
        let filtered = json!({ "event_id": "4625", "username": "test" });
        let mut buf2 = Vec::new();
        assert!(!eval_condition(&cond, &sel, &filtered, &mut buf2));
    }

    #[test]
    fn condition_or_alternative() {
        let det = json!({
            "selection_a": { "event_id": "4625" },
            "selection_b": { "event_id": "4768" },
            "condition": "selection_a or selection_b"
        });
        let (sel, cond) = compile_detection(&det).expect("compile");

        let log_a = json!({ "event_id": "4625" });
        let log_b = json!({ "event_id": "4768" });
        let log_c = json!({ "event_id": "4624" });
        let mut buf = Vec::new();
        assert!(eval_condition(&cond, &sel, &log_a, &mut buf));
        assert!(eval_condition(&cond, &sel, &log_b, &mut buf));
        assert!(!eval_condition(&cond, &sel, &log_c, &mut buf));
    }

    #[test]
    fn condition_default_is_selection() {
        // No condition string → defaults to "selection".
        let det = json!({
            "selection": { "username": "root" }
        });
        let (sel, cond) = compile_detection(&det).expect("compile");
        let log = json!({ "username": "root" });
        let mut buf = Vec::new();
        assert!(eval_condition(&cond, &sel, &log, &mut buf));
    }

    // ── match_rule (end-to-end) ────────────────────────────────────

    fn rule(
        id: &str,
        selections: HashMap<String, Vec<FieldMatcher>>,
        cond: Condition,
    ) -> CompiledRule {
        CompiledRule {
            id: id.into(),
            title: id.into(),
            level: "high".into(),
            logsource_category: None,
            logsource_product: None,
            logsource_service: None,
            tags: vec![],
            matchers: selections,
            condition: cond,
            disposition: "detect".into(),
            tier: "queue".into(),
            risk_score: None,
        }
    }

    #[test]
    fn match_rule_returns_match_on_hit() {
        let mut sels = HashMap::new();
        sels.insert(
            "selection".into(),
            vec![FieldMatcher::Exact("username".into(), "root".into())],
        );
        let r = rule("rid", sels, Condition::Ref("selection".into()));
        let log = json!({ "username": "root" });
        let m = match_rule(&r, &log, None);
        assert!(m.is_some());
        assert_eq!(m.unwrap().rule_id, "rid");
    }

    #[test]
    fn match_rule_returns_none_on_miss() {
        let mut sels = HashMap::new();
        sels.insert(
            "selection".into(),
            vec![FieldMatcher::Exact("username".into(), "root".into())],
        );
        let r = rule("rid", sels, Condition::Ref("selection".into()));
        let log = json!({ "username": "alice" });
        assert!(match_rule(&r, &log, None).is_none());
    }

    #[test]
    fn match_rule_respects_logsource_category_via_tag() {
        let mut sels = HashMap::new();
        sels.insert(
            "selection".into(),
            vec![FieldMatcher::Exact("event_id".into(), "4625".into())],
        );
        let mut r = rule("rid", sels, Condition::Ref("selection".into()));
        r.logsource_category = Some("windows".into());

        let log = json!({ "event_id": "4625" });
        // Tag matches category — fires.
        assert!(match_rule(&r, &log, Some("windows.security")).is_some());
        // Tag does not match — drops.
        assert!(match_rule(&r, &log, Some("linux.syslog")).is_none());
    }

    /// Regression (detection-chain audit 2026-06-20): first-party Windows rules
    /// use a bare field (`commandline`) while real osquery.sysmon telemetry nests
    /// it under `data.CommandLine`. `find_field` must resolve the bare field through
    /// the `data` envelope, or the marquee rules (LSASS dump, NTDS extraction,
    /// PowerShell obfuscation, APT) silently never match real telemetry — they only
    /// fired on the flat-field demo data, which hid the bug for weeks.
    #[test]
    fn bare_field_resolves_under_data_envelope() {
        // Real osquery.sysmon shape: {eventid, channel, data:{CommandLine}}.
        let log = json!({
            "eventid": "1",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "data": { "CommandLine": "ntdsutil.exe ac i ntds ifm create full C:\\temp" }
        });
        // find_field resolves the bare field through the data envelope...
        assert_eq!(
            find_field(&log, "commandline").as_deref(),
            Some("ntdsutil.exe ac i ntds ifm create full C:\\temp")
        );
        // ...so a rule authored with a bare `commandline|contains` now fires.
        let mut sels = HashMap::new();
        sels.insert(
            "selection".into(),
            vec![FieldMatcher::Contains(
                "commandline".into(),
                "ntdsutil.exe".into(),
            )],
        );
        let mut r = rule(
            "sysmon-ntds-extraction",
            sels,
            Condition::Ref("selection".into()),
        );
        r.logsource_category = Some("osquery".into());
        r.logsource_product = Some("sysmon".into());
        assert!(match_rule(&r, &log, Some("osquery.sysmon")).is_some());
    }

    /// A flat top-level field must still win over the `data` envelope, so syslog /
    /// osquery.process flat shapes (and the demo data) keep working unchanged.
    #[test]
    fn flat_field_takes_precedence_over_data_envelope() {
        let log = json!({
            "commandline": "flat-value",
            "data": { "CommandLine": "nested-value" }
        });
        assert_eq!(
            find_field(&log, "commandline").as_deref(),
            Some("flat-value")
        );
    }

    // ── field-resolution health audit ──────────────────────────────

    fn log_rec(tag: &str, data: serde_json::Value) -> crate::db::threatclaw_store::LogRecord {
        crate::db::threatclaw_store::LogRecord {
            id: 0,
            tag: Some(tag.into()),
            time: String::new(),
            created_at: String::new(),
            hostname: None,
            data,
        }
    }

    #[test]
    fn health_audit_flags_dead_rule_but_not_resolving_one() {
        // 6 real-shaped osquery.sysmon logs (nested under `data`).
        let logs: Vec<_> = (0..6)
            .map(|_| {
                log_rec(
                    "osquery.sysmon",
                    json!({"eventid":"1","channel":"x","data":{"CommandLine":"powershell.exe -enc AAA"}}),
                )
            })
            .collect();

        // Dead: references a field present in NO sysmon log.
        let mut s1 = HashMap::new();
        s1.insert(
            "selection".into(),
            vec![FieldMatcher::Contains(
                "nonexistent_field".into(),
                "x".into(),
            )],
        );
        let mut broken = rule("broken-rule", s1, Condition::Ref("selection".into()));
        broken.logsource_product = Some("sysmon".into());

        // Healthy: bare `commandline` resolves under the data envelope (fix #1).
        let mut s2 = HashMap::new();
        s2.insert(
            "selection".into(),
            vec![FieldMatcher::Contains(
                "commandline".into(),
                "powershell".into(),
            )],
        );
        let mut good = rule("good-rule", s2, Condition::Ref("selection".into()));
        good.logsource_product = Some("sysmon".into());

        let ids: Vec<String> = detect_unresolved_field_rules(&[broken, good], &logs)
            .into_iter()
            .map(|w| w.rule_id)
            .collect();
        assert!(
            ids.contains(&"broken-rule".to_string()),
            "dead rule must be flagged"
        );
        assert!(
            !ids.contains(&"good-rule".to_string()),
            "a rule whose fields resolve must NOT be flagged"
        );
    }

    #[test]
    fn health_audit_requires_minimum_sample() {
        // Only 3 matching logs (< MIN_SAMPLE_TO_JUDGE) → not enough evidence.
        let logs: Vec<_> = (0..3)
            .map(|_| {
                log_rec(
                    "osquery.sysmon",
                    json!({"eventid":"1","data":{"CommandLine":"x"}}),
                )
            })
            .collect();
        let mut s = HashMap::new();
        s.insert(
            "selection".into(),
            vec![FieldMatcher::Contains("nonexistent".into(), "x".into())],
        );
        let mut r = rule("r", s, Condition::Ref("selection".into()));
        r.logsource_product = Some("sysmon".into());
        assert!(detect_unresolved_field_rules(&[r], &logs).is_empty());
    }

    #[test]
    fn health_audit_ignores_symbolic_alias_fields() {
        // `message` resolves via the whole-event body scan, not find_field, so it
        // must be excluded from the audit (else legitimate syslog rules false-flag).
        let logs: Vec<_> = (0..6)
            .map(|_| log_rec("linux.syslog", json!({"program":"sshd","raw":"…"})))
            .collect();
        let mut s = HashMap::new();
        s.insert(
            "selection".into(),
            vec![FieldMatcher::Contains("message".into(), "failed".into())],
        );
        let mut r = rule("syslog-rule", s, Condition::Ref("selection".into()));
        r.logsource_category = Some("syslog".into());
        assert!(detect_unresolved_field_rules(&[r], &logs).is_empty());
    }

    #[test]
    fn audited_field_skips_exists_matcher() {
        assert_eq!(
            FieldMatcher::Contains("CommandLine".into(), "x".into()).audited_field(),
            Some("CommandLine")
        );
        assert_eq!(
            FieldMatcher::Exists("CommandLine".into(), true).audited_field(),
            None
        );
    }

    /// E2E anti-regression: load the real marquee Windows rule FILES, compile them
    /// through the production path, and assert each fires on representative attack
    /// telemetry in the REAL nested osquery.sysmon shape ({data:{CommandLine}}).
    /// Locks fix #1 against future regressions in BOTH the engine and the rule
    /// files — the exact silent-death class the detection-chain audit found. If a
    /// marquee rule ever stops matching real telemetry, this fails the build.
    #[test]
    fn marquee_windows_rules_fire_on_real_shape_telemetry() {
        let cases: &[(&str, &str)] = &[
            (
                "rules/windows/sysmon-ntds-extraction.yaml",
                r"ntdsutil.exe ac i ntds ifm create full C:\temp",
            ),
            (
                "rules/windows/sysmon-lsass-comsvcs.yaml",
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1234 C:\lsass.dmp full",
            ),
            (
                "rules/windows/ps-obfusc-001.yaml",
                "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAA",
            ),
        ];
        for (path, cmdline) in cases {
            let full = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path);
            let raw = std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {path}: {e}"));
            let rule_json: serde_json::Value =
                serde_yaml_ng::from_str(&raw).unwrap_or_else(|e| panic!("yaml {path}: {e}"));
            let (matchers, condition) = compile_detection_for_tests(&rule_json["detection"])
                .unwrap_or_else(|| panic!("compile {path}"));
            let rule = CompiledRule {
                id: rule_json["id"].as_str().unwrap_or("").to_string(),
                title: rule_json["title"].as_str().unwrap_or("").to_string(),
                level: rule_json["level"].as_str().unwrap_or("high").to_string(),
                logsource_category: rule_json["logsource"]["category"]
                    .as_str()
                    .map(String::from),
                logsource_product: rule_json["logsource"]["product"].as_str().map(String::from),
                logsource_service: rule_json["logsource"]["service"].as_str().map(String::from),
                tags: vec![],
                matchers,
                condition,
                disposition: "detect".into(),
                tier: "queue".into(),
                risk_score: None,
            };
            // Real osquery.sysmon shape: the command line is nested under `data`.
            let log = json!({
                "eventid": "1",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "data": { "CommandLine": cmdline }
            });
            assert!(
                match_rule_for_tests(&rule, &log, Some("osquery.sysmon")).is_some(),
                "marquee rule {} must fire on real nested telemetry: {cmdline}",
                rule.id
            );
        }
    }

    // ── alert_is_excepted (Phase B exceptions) ─────────────────────

    fn exc(rule_id: &str, scope: &str, value: &str) -> ActiveException {
        ActiveException {
            rule_id: rule_id.into(),
            scope_field: scope.into(),
            scope_value: value.into(),
        }
    }

    #[test]
    fn exception_hostname_exact() {
        let list = vec![exc("rid", "hostname", "srv-prod-01")];
        assert!(alert_is_excepted(
            &list,
            "rid",
            Some("srv-prod-01"),
            None,
            None,
            &[]
        ));
        assert!(!alert_is_excepted(
            &list,
            "rid",
            Some("srv-prod-02"),
            None,
            None,
            &[]
        ));
    }

    #[test]
    fn exception_hostname_case_insensitive() {
        let list = vec![exc("rid", "hostname", "Srv-Prod-01")];
        assert!(alert_is_excepted(
            &list,
            "rid",
            Some("srv-PROD-01"),
            None,
            None,
            &[]
        ));
    }

    #[test]
    fn exception_hostname_trailing_wildcard() {
        let list = vec![exc("rid", "hostname", "srv-prod-*")];
        assert!(alert_is_excepted(
            &list,
            "rid",
            Some("srv-prod-01"),
            None,
            None,
            &[]
        ));
        assert!(alert_is_excepted(
            &list,
            "rid",
            Some("srv-prod-42"),
            None,
            None,
            &[]
        ));
        assert!(!alert_is_excepted(
            &list,
            "rid",
            Some("srv-staging-01"),
            None,
            None,
            &[]
        ));
    }

    #[test]
    fn exception_source_ip_exact() {
        let list = vec![exc("rid", "source_ip", "10.0.0.5")];
        assert!(alert_is_excepted(
            &list,
            "rid",
            None,
            Some("10.0.0.5"),
            None,
            &[]
        ));
        assert!(!alert_is_excepted(
            &list,
            "rid",
            None,
            Some("10.0.0.6"),
            None,
            &[]
        ));
    }

    #[test]
    fn exception_username() {
        let list = vec![exc("rid", "username", "svc-backup")];
        assert!(alert_is_excepted(
            &list,
            "rid",
            None,
            None,
            Some("svc-backup"),
            &[]
        ));
        assert!(alert_is_excepted(
            &list,
            "rid",
            None,
            None,
            Some("SVC-BACKUP"),
            &[]
        ));
    }

    #[test]
    fn exception_tag_match() {
        let list = vec![exc("rid", "tag", "attack.t1110")];
        let tags = vec![
            "attack.t1110".to_string(),
            "attack.credential_access".into(),
        ];
        assert!(alert_is_excepted(&list, "rid", None, None, None, &tags));
        let other_tags = vec!["attack.t1059".to_string()];
        assert!(!alert_is_excepted(
            &list,
            "rid",
            None,
            None,
            None,
            &other_tags
        ));
    }

    #[test]
    fn exception_other_rule_not_silenced() {
        let list = vec![exc("rule-a", "hostname", "srv-prod-01")];
        // Exception belongs to a different rule — should not trip.
        assert!(!alert_is_excepted(
            &list,
            "rule-b",
            Some("srv-prod-01"),
            None,
            None,
            &[]
        ));
    }

    // ── looks_like_program_or_container_id (existing tests) ────────

    #[test]
    fn program_blocklist_filters_common_daemons() {
        for prog in [
            "kernel",
            "systemd",
            "dockerd",
            "containerd",
            "rsyslogd",
            "sshd",
            "cron",
            "nginx",
        ] {
            assert!(
                looks_like_program_or_container_id(prog),
                "{prog} should be filtered"
            );
        }
    }

    #[test]
    fn case_insensitive_blocklist() {
        assert!(looks_like_program_or_container_id("Kernel"));
        assert!(looks_like_program_or_container_id("SYSTEMD"));
    }

    #[test]
    fn threatclaw_internal_filtered() {
        assert!(looks_like_program_or_container_id("threatclaw-agent-sync"));
        assert!(looks_like_program_or_container_id("threatclaw-core"));
    }

    #[test]
    fn docker_short_container_id_filtered() {
        assert!(looks_like_program_or_container_id("bc130c79e5dd"));
        assert!(looks_like_program_or_container_id("a1b2c3d4e5f6"));
    }

    #[test]
    fn docker_long_container_id_filtered() {
        let long = "a".repeat(64);
        assert!(looks_like_program_or_container_id(&long));
    }

    #[test]
    fn real_hostnames_pass_through() {
        for host in [
            "client-prod-01",
            "webserver-london",
            "sd-98664",
            "host01.client.local",
            "SHIR-Hive",
            "interstellar-dc01",
            "192.168.1.10",
        ] {
            assert!(
                !looks_like_program_or_container_id(host),
                "{host} should NOT be filtered"
            );
        }
    }

    #[test]
    fn edge_short_hex_not_container_size() {
        // 11-char hex doesn't look like a container id (12 or 64)
        assert!(!looks_like_program_or_container_id("abcdef12345"));
        // 13-char hex same
        assert!(!looks_like_program_or_container_id("abcdef1234567"));
    }
}

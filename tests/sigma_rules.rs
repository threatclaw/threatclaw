//! Integration test runner for on-disk Sigma rules — Phase C.3.
//!
//! Walks `rules/**/*.test.yaml`, finds the matching `<rule-id>.yaml`,
//! compiles both, and asserts that every `positive` event triggers
//! `match_rule` while no `negative` event does. Rules without a
//! sibling fixture are reported as warnings (will become errors in a
//! follow-up sprint).
//!
//! Run with: `cargo test --test sigma_rules`.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use threatclaw::agent::sigma_engine::{self, CompiledRule, Condition};

#[derive(Debug, Deserialize)]
struct RuleYaml {
    id: String,
    title: String,
    level: String,
    logsource: LogSource,
    detection: serde_yaml_ng::Value,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LogSource {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    service: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    rule: String,
    #[serde(default)]
    positive: Vec<Case>,
    #[serde(default)]
    negative: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    #[serde(default)]
    description: Option<String>,
    event: serde_yaml_ng::Value,
    #[serde(default)]
    tag: Option<String>,
}

fn rules_dir() -> PathBuf {
    // Override so an out-of-tree caller (e.g. the premium maison firing test)
    // can point the real engine at a converted rule set + its fixtures.
    if let Ok(dir) = std::env::var("TC_RULES_TEST_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("rules")
}

fn walk(dir: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, suffix, out);
        } else if path.to_string_lossy().ends_with(suffix) {
            out.push(path);
        }
    }
}

fn yaml_to_json(v: serde_yaml_ng::Value) -> serde_json::Value {
    match v {
        serde_yaml_ng::Value::Null => serde_json::Value::Null,
        serde_yaml_ng::Value::Bool(b) => serde_json::Value::Bool(b),
        serde_yaml_ng::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml_ng::Value::String(s) => serde_json::Value::String(s),
        serde_yaml_ng::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.into_iter().map(yaml_to_json).collect())
        }
        serde_yaml_ng::Value::Mapping(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if let Some(key) = k.as_str() {
                    out.insert(key.to_string(), yaml_to_json(v));
                }
            }
            serde_json::Value::Object(out)
        }
        _ => serde_json::Value::Null,
    }
}

/// Compile a rule the same way the engine does at boot.
fn compile_rule(rule: &RuleYaml) -> CompiledRule {
    let detection = yaml_to_json(rule.detection.clone());
    // We deliberately reach through a thin re-export rather than
    // duplicating the compile logic — see lib.rs for the pub use.
    let (matchers, condition) = sigma_engine::compile_detection_for_tests(&detection)
        .unwrap_or_else(|| (HashMap::new(), Condition::Ref("selection".into())));
    CompiledRule {
        id: rule.id.clone(),
        title: rule.title.clone(),
        level: rule.level.clone(),
        logsource_category: rule.logsource.category.clone(),
        logsource_product: rule.logsource.product.clone(),
        logsource_service: rule.logsource.service.clone(),
        tags: rule.tags.clone(),
        matchers,
        condition,
        disposition: "detect".into(),
        tier: "queue".into(),
        risk_score: None,
    }
}

fn load_rule_for_fixture(fixture_path: &Path, rule_id: &str) -> Option<RuleYaml> {
    // The rule lives in the same directory as the fixture, with the same
    // basename minus the `.test` suffix. Fall back to a recursive scan
    // when the convention is broken — the runner stays lenient.
    let mut candidate = fixture_path.to_path_buf();
    if let Some(stem) = fixture_path.file_stem().and_then(|s| s.to_str()) {
        let bare = stem.trim_end_matches(".test");
        candidate.set_file_name(format!("{bare}.yaml"));
        if candidate.exists() {
            let raw = std::fs::read_to_string(&candidate).ok()?;
            return serde_yaml_ng::from_str::<RuleYaml>(&raw).ok();
        }
    }
    // Lenient scan — find any file with the right `id:`.
    let mut all = Vec::new();
    walk(&rules_dir(), ".yaml", &mut all);
    for p in all {
        if p.to_string_lossy().contains(".test.") {
            continue;
        }
        let raw = match std::fs::read_to_string(&p) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Ok(r) = serde_yaml_ng::from_str::<RuleYaml>(&raw) {
            if r.id == rule_id {
                return Some(r);
            }
        }
    }
    None
}

#[test]
fn all_test_fixtures_pass() {
    let mut fixtures = Vec::new();
    walk(&rules_dir(), ".test.yaml", &mut fixtures);

    if fixtures.is_empty() {
        eprintln!(
            "WARN: no test fixtures found under {:?}; runner is idle",
            rules_dir()
        );
        return;
    }

    let mut failures: Vec<String> = Vec::new();
    let mut total_positive = 0usize;
    let mut total_negative = 0usize;

    for fixture_path in &fixtures {
        let raw = match std::fs::read_to_string(fixture_path) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("{:?}: cannot read fixture: {e}", fixture_path));
                continue;
            }
        };
        let fixture: FixtureFile = match serde_yaml_ng::from_str(&raw) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("{:?}: invalid fixture YAML: {e}", fixture_path));
                continue;
            }
        };
        let rule_yaml = match load_rule_for_fixture(fixture_path, &fixture.rule) {
            Some(r) => r,
            None => {
                failures.push(format!(
                    "{:?}: cannot locate rule '{}' for fixture",
                    fixture_path, fixture.rule
                ));
                continue;
            }
        };
        let rule = compile_rule(&rule_yaml);

        for (i, case) in fixture.positive.iter().enumerate() {
            total_positive += 1;
            let event = yaml_to_json(case.event.clone());
            let tag = case.tag.as_deref();
            if sigma_engine::match_rule_for_tests(&rule, &event, tag).is_none() {
                failures.push(format!(
                    "{:?}: positive[{}] '{}' did not match",
                    fixture_path,
                    i,
                    case.description.as_deref().unwrap_or("(no description)")
                ));
            }
        }
        for (i, case) in fixture.negative.iter().enumerate() {
            total_negative += 1;
            let event = yaml_to_json(case.event.clone());
            let tag = case.tag.as_deref();
            if sigma_engine::match_rule_for_tests(&rule, &event, tag).is_some() {
                failures.push(format!(
                    "{:?}: negative[{}] '{}' matched but should not",
                    fixture_path,
                    i,
                    case.description.as_deref().unwrap_or("(no description)")
                ));
            }
        }
    }

    println!(
        "Sigma rule runner: {} fixture(s), {} positive case(s), {} negative case(s) — {} failure(s)",
        fixtures.len(),
        total_positive,
        total_negative,
        failures.len()
    );

    if !failures.is_empty() {
        panic!(
            "{} fixture failure(s):\n  - {}",
            failures.len(),
            failures.join("\n  - ")
        );
    }
}

#[test]
fn every_rule_has_a_test_fixture() {
    // Warning-grade today; will become a hard error in a follow-up.
    let mut rules = Vec::new();
    walk(&rules_dir(), ".yaml", &mut rules);
    rules.retain(|p| !p.to_string_lossy().contains(".test."));

    let mut fixtures = Vec::new();
    walk(&rules_dir(), ".test.yaml", &mut fixtures);
    let covered: std::collections::HashSet<String> = fixtures
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .filter_map(|raw| serde_yaml_ng::from_str::<FixtureFile>(&raw).ok())
        .map(|f| f.rule)
        .collect();

    let mut missing = Vec::new();
    for path in &rules {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rule: RuleYaml = match serde_yaml_ng::from_str(&raw) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !covered.contains(&rule.id) {
            missing.push(rule.id);
        }
    }
    if !missing.is_empty() {
        eprintln!(
            "WARN: {} rule(s) ship without a test fixture: {}",
            missing.len(),
            missing.join(", ")
        );
    }
}

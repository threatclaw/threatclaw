//! D4 validation harness — compile every converted Sigma rule in a directory
//! through the real TC engine and report how many compile / fire.
//!
//! Run against the pySigma-converted output:
//!   TC_VALIDATE_DIR=/path/to/converted cargo test --test sigma_pysigma_validate -- --nocapture --ignored
//!
//! Ignored by default (needs an external dir). This is the "compiles in the
//! Rust engine" gate from PLAN_SIGMA_PYSIGMA_PIPELINE.md D4.

use serde_json::json;
use std::path::Path;
use threatclaw::agent::sigma_engine::{
    compile_detection_for_tests, detect_unresolved_field_rules_for_tests, match_rule_for_tests,
    CompiledRule,
};
use threatclaw::db::threatclaw_store::LogRecord;

/// Compile every rule in a dir into CompiledRule (skipping ones that don't
/// compile). Shared by the firing + health tests.
fn compile_all(dir: &str) -> Vec<CompiledRule> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).expect("read dir").flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("yml") {
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let doc: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let rule_json = yaml_to_json(&doc);
        let det = &rule_json["detection"];
        let (matchers, condition) = match compile_detection_for_tests(det) {
            Some(c) => c,
            None => continue,
        };
        out.push(CompiledRule {
            id: rule_json["id"].as_str().unwrap_or("").to_string(),
            title: String::new(),
            level: "high".into(),
            logsource_category: rule_json["logsource"]["category"].as_str().map(String::from),
            logsource_product: rule_json["logsource"]["product"].as_str().map(String::from),
            logsource_service: rule_json["logsource"]["service"].as_str().map(String::from),
            tags: vec![],
            matchers,
            condition,
            disposition: "monitor".into(),
            tier: "queue".into(),
            risk_score: None,
        });
    }
    out
}

fn yaml_to_json(y: &serde_yaml_ng::Value) -> serde_json::Value {
    serde_json::to_value(y).unwrap_or(serde_json::Value::Null)
}

#[test]
#[ignore]
fn validate_converted_rules_compile() {
    let dir = std::env::var("TC_VALIDATE_DIR")
        .expect("set TC_VALIDATE_DIR to the converted-rules directory");
    let dir = Path::new(&dir);
    let mut total = 0usize;
    let mut compiled = 0usize;
    let mut failed: Vec<String> = Vec::new();

    let entries = std::fs::read_dir(dir).expect("read dir");
    for e in entries.flatten() {
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        total += 1;
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(_) => {
                failed.push(format!("{}: unreadable", p.display()));
                continue;
            }
        };
        let doc: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
            Ok(d) => d,
            Err(err) => {
                failed.push(format!("{}: yaml {err}", p.display()));
                continue;
            }
        };
        let det = match doc.get("detection") {
            Some(d) => yaml_to_json(d),
            None => {
                failed.push(format!("{}: no detection", p.display()));
                continue;
            }
        };
        match compile_detection_for_tests(&det) {
            Some(_) => compiled += 1,
            None => failed.push(format!(
                "{}: compile_detection returned None",
                p.file_name().and_then(|x| x.to_str()).unwrap_or("?")
            )),
        }
    }

    println!("\n=== pySigma-converted rule validation ===");
    println!("  total    : {total}");
    println!("  compiled : {compiled}");
    println!("  failed   : {}", failed.len());
    if !failed.is_empty() {
        println!("\n  first 20 failures:");
        for f in failed.iter().take(20) {
            println!("    {f}");
        }
    }
    let rate = if total > 0 { compiled * 100 / total } else { 0 };
    println!("\n  compile rate: {rate}%");
    assert!(total > 0, "no rules found in {}", dir.display());
}

/// Firing smoke test — proves the convert→compile→fire chain mechanically.
/// For each converted rule with a single selection of plain `data.X: "literal"`
/// (or `|contains`) matches, auto-build a positive log and confirm it fires.
/// Reports the fire rate over the testable subset (rules with complex
/// conditions are skipped — those are validated on the lab, not synthetically).
#[test]
#[ignore]
fn converted_rules_fire_on_synthetic_log() {
    let dir = std::env::var("TC_VALIDATE_DIR")
        .expect("set TC_VALIDATE_DIR to the converted-rules directory");
    let mut testable = 0usize;
    let mut fired = 0usize;

    for e in std::fs::read_dir(&dir).expect("read dir").flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("yml") {
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let doc: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&text) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let rule_json = yaml_to_json(&doc);
        let det = &rule_json["detection"];
        // Only single-selection rules with a plain object of string fields.
        let cond = det.get("condition").and_then(|c| c.as_str()).unwrap_or("");
        let sel_names: Vec<&String> = det
            .as_object()
            .map(|o| o.keys().filter(|k| *k != "condition").collect())
            .unwrap_or_default();
        if sel_names.len() != 1 || cond.trim() != sel_names[0] {
            continue; // complex condition → lab-validated, skip here
        }
        let sel = &det[sel_names[0]];
        let obj = match sel.as_object() {
            Some(o) => o,
            None => continue,
        };
        // Build a log that satisfies every `data.X[|contains]: "literal"` field.
        let mut data = serde_json::Map::new();
        let mut ok = true;
        for (k, v) in obj {
            let parts: Vec<&str> = k.split('|').collect();
            let field = parts[0].strip_prefix("data.").unwrap_or(parts[0]);
            let modifier = parts.get(1).copied().unwrap_or("");
            // Only handle plain string single values + contains/startswith/endswith.
            let lit = match v.as_str() {
                Some(s) if matches!(modifier, "" | "contains" | "startswith" | "endswith") => s,
                _ => {
                    ok = false;
                    break;
                }
            };
            // Build a value that satisfies THIS modifier exactly.
            let log_val = match modifier {
                "contains" => format!("PRE{lit}POST"),
                "startswith" => format!("{lit}POST"),
                "endswith" => format!("PRE{lit}"),
                _ => lit.to_string(), // plain equals
            };
            data.insert(field.to_string(), json!(log_val));
        }
        if !ok || data.is_empty() {
            continue;
        }
        testable += 1;
        let (matchers, condition) = match compile_detection_for_tests(det) {
            Some(c) => c,
            None => continue,
        };
        let rule = CompiledRule {
            id: rule_json["id"].as_str().unwrap_or("").to_string(),
            title: String::new(),
            level: "high".into(),
            logsource_category: None,
            logsource_product: rule_json["logsource"]["product"].as_str().map(String::from),
            logsource_service: rule_json["logsource"]["service"].as_str().map(String::from),
            tags: vec![],
            matchers,
            condition,
            disposition: "detect".into(),
            tier: "queue".into(),
            risk_score: None,
        };
        let log = json!({ "data": data });
        if match_rule_for_tests(&rule, &log, Some("osquery.sysmon")).is_some() {
            fired += 1;
        }
    }

    println!("\n=== firing smoke test (single-selection subset) ===");
    println!("  testable : {testable}");
    println!("  fired    : {fired}");
    let rate = if testable > 0 { fired * 100 / testable } else { 0 };
    println!("  fire rate: {rate}%");
    assert!(testable > 0, "no testable single-selection rules found");
}

/// SIGMA HEALTH oracle on the converted set: which rules are "silently dead"
/// because none of their fields exist in the telemetry TC actually produces
/// (tests/fixtures/sigma_telemetry_schema.json). This is the field-map
/// completeness gate — a rule referencing an unmapped field can never fire.
/// (Telemetry *availability* — whether the EventID is collected — is measured
/// at runtime on a live instance by the same engine check.)
#[test]
#[ignore]
fn health_check_field_resolution() {
    let dir = std::env::var("TC_VALIDATE_DIR").expect("set TC_VALIDATE_DIR");
    let rules = compile_all(&dir);

    // Representative telemetry: one log per tag carrying every field TC produces.
    let schema_path = format!(
        "{}/tests/fixtures/sigma_telemetry_schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&schema_path).expect("schema"))
            .expect("schema json");
    let mut logs: Vec<LogRecord> = Vec::new();
    for (tag, fields) in schema.as_object().expect("obj") {
        // Real osquery log shape: {eventid, channel, data: {<fields>}}. Rule
        // fields are `data.X`, resolved as log.data["data"]["X"], so the
        // telemetry fields nest under a "data" key. ≥ MIN_SAMPLE_TO_JUDGE (5).
        let payload = json!({ "eventid": "1", "channel": "synthetic", "data": fields.clone() });
        for _ in 0..6 {
            logs.push(LogRecord {
                id: 0,
                tag: Some(tag.clone()),
                time: String::new(),
                created_at: String::new(),
                hostname: None,
                data: payload.clone(),
            });
        }
    }

    let dead = detect_unresolved_field_rules_for_tests(&rules, &logs);
    let total = rules.len();
    let fireable = total - dead.len();
    println!("\n=== SIGMA HEALTH — field-map completeness on converted set ===");
    println!("  compiled rules : {total}");
    println!("  silently dead  : {} (reference fields TC doesn't produce)", dead.len());
    println!(
        "  field-resolvable: {fireable} ({}%)",
        if total > 0 { fireable * 100 / total } else { 0 }
    );
    if !dead.is_empty() {
        println!("\n  first 15 silently-dead rules (rule_id → unresolved fields):");
        for (id, fields) in dead.iter().take(20) {
            println!("    {id}  {fields:?}");
        }
    }
    assert!(total > 0);
}

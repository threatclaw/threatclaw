//! On-disk Sigma rule sync — Phase C of the Sigma roadmap.
//!
//! At core boot, walks `rules/**/*.yaml` (excluding `*.test.yaml`
//! fixtures) and upserts each rule into the `sigma_rules` table. The
//! YAML file is the source of truth for the content-derived fields
//! (title, detection, tags, level, ...); the operator-managed columns
//! (enabled, disposition, tier, owner, promoted_at) are preserved
//! across syncs so a tuning done via the dashboard is not undone by
//! the next boot.
//!
//! Files are NEVER deleted from the DB by this loader. A rule
//! retirement still requires either an explicit migration or
//! flipping `enabled` to false from the dashboard. That keeps the
//! sync idempotent and safe against accidental file removal during
//! a deploy.

use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::db::Database;

/// Top-level shape of a rule file. Mirrors the SigmaHQ rule convention
/// but only deserialises the fields we actually persist — anything
/// extra in the YAML is silently ignored, which keeps the loader
/// forward-compatible with rule files that adopt newer Sigma spec
/// fields before we wire them through.
#[derive(Debug, Deserialize)]
struct RuleFile {
    id: String,
    title: String,
    #[serde(default)]
    description: Option<String>,
    level: String,
    #[serde(default)]
    status: Option<String>,
    logsource: LogSource,
    detection: serde_yaml_ng::Value,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    author: Option<String>,
    // Initial promotion disposition (monitor/detect/block). Applied ON INSERT
    // only — operator promotions are preserved on re-sync. pySigma-converted
    // SigmaHQ rules ship as `monitor` (shadow); proprietary rules omit it and
    // default to `detect`.
    #[serde(default)]
    disposition: Option<String>,
    // The following are accepted but not stored on the DB row yet.
    // They flow into rule_yaml verbatim for documentation purposes.
    #[serde(default)]
    #[allow(dead_code)]
    references: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    falsepositives: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    date: Option<String>,
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

#[derive(Debug, Default)]
pub struct SyncReport {
    pub files_seen: usize,
    pub rules_upserted: usize,
    pub rules_pruned: usize,
    pub parse_errors: Vec<(PathBuf, String)>,
    pub db_errors: Vec<(String, String)>,
}

/// Below this many total rule files, the `rules/` tree is treated as broken
/// (empty or partial deploy) and NO reconcile runs — a bad sync must never be
/// able to wipe the DB. The bundle alone ships well over this.
const RECONCILE_MIN_FILES: usize = 100;
/// Below this many `_managed` files the pulled pack is treated as unhealthy
/// (failed or partial pull) and managed rules are NOT pruned, so a broken pull
/// cannot delete the pulled rule set. A healthy pack ships thousands.
const MANAGED_HEALTHY_MIN: usize = 100;

/// Walk `rules_dir` recursively and upsert every rule file.
pub async fn sync_rules_from_disk(store: &dyn Database, rules_dir: &Path) -> SyncReport {
    let mut report = SyncReport::default();
    if !rules_dir.is_dir() {
        tracing::info!(
            "SIGMA FILE LOADER: rules directory not found at {:?} — skipping sync",
            rules_dir
        );
        return report;
    }

    // Every rule id seen this sync (for the reconcile) + how many came from the
    // pulled `_managed` pack (to gate managed pruning).
    let mut seen: Vec<String> = Vec::new();
    let mut managed_seen = 0usize;

    let mut stack: Vec<PathBuf> = vec![rules_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("SIGMA FILE LOADER: cannot read {:?}: {}", dir, e);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = match path.file_name().and_then(|s| s.to_str()) {
                Some(n) => n,
                None => continue,
            };
            // Test fixtures live alongside rules — skip them, they go
            // through the test runner instead.
            if name.ends_with(".test.yaml") || name.ends_with(".test.yml") {
                continue;
            }
            if !(name.ends_with(".yaml") || name.ends_with(".yml")) {
                continue;
            }
            report.files_seen += 1;
            // A file under a `_managed/` component came from the pulled R2 pack;
            // anything else is baked into the image bundle.
            let is_managed = path.components().any(|c| c.as_os_str() == "_managed");
            let source = if is_managed { "managed" } else { "bundle" };
            match sync_one_file(store, &path, source, &mut report).await {
                Ok(id) => {
                    seen.push(id);
                    if is_managed {
                        managed_seen += 1;
                    }
                }
                Err(e) => report.parse_errors.push((path.clone(), e)),
            }
        }
    }

    // Reconcile (prune) rules that vanished from disk. Skipped entirely if the
    // sync looks broken (too few files) so an empty/partial deploy can never
    // wipe the DB. Managed rules are pruned only when the pulled pack synced
    // healthy — a failed pull (empty `_managed`) leaves them untouched.
    if report.files_seen >= RECONCILE_MIN_FILES {
        let prune_managed = managed_seen >= MANAGED_HEALTHY_MIN;
        match store.reconcile_sigma_rules(&seen, prune_managed).await {
            Ok(n) => {
                report.rules_pruned = n as usize;
                tracing::info!(
                    "SIGMA FILE LOADER: reconcile pruned {} stale rules (managed_seen={}, prune_managed={})",
                    n,
                    managed_seen,
                    prune_managed
                );
            }
            Err(e) => tracing::warn!("SIGMA FILE LOADER: reconcile failed: {}", e),
        }
    } else {
        tracing::warn!(
            "SIGMA FILE LOADER: only {} files seen (< {}), skipping reconcile to avoid wiping the DB on a broken sync",
            report.files_seen,
            RECONCILE_MIN_FILES
        );
    }

    tracing::info!(
        "SIGMA FILE LOADER: synced {}/{} files, pruned {} ({} parse err, {} DB err)",
        report.rules_upserted,
        report.files_seen,
        report.rules_pruned,
        report.parse_errors.len(),
        report.db_errors.len()
    );
    report
}

async fn sync_one_file(
    store: &dyn Database,
    path: &Path,
    source: &str,
    report: &mut SyncReport,
) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let rule: RuleFile = serde_yaml_ng::from_str(&raw).map_err(|e| format!("yaml: {e}"))?;

    // Convert the detection YAML value into our JSONB shape. The
    // existing compile pipeline only consumes serde_json::Value so we
    // round-trip through serde_yaml_ng → serde_json.
    let detection_json = yaml_to_json(rule.detection.clone());

    let res = store
        .upsert_sigma_rule_from_file(
            &rule.id,
            &rule.title,
            rule.description.as_deref(),
            &rule.level,
            rule.status.as_deref(),
            rule.logsource.category.as_deref(),
            rule.logsource.product.as_deref(),
            rule.logsource.service.as_deref(),
            &rule.tags,
            rule.author.as_deref(),
            &raw,
            &detection_json,
            rule.disposition.as_deref(),
            source,
        )
        .await;

    match res {
        Ok(_) => {
            report.rules_upserted += 1;
            Ok(rule.id)
        }
        Err(e) => {
            report.db_errors.push((rule.id.clone(), e.to_string()));
            Err(format!("db: {e}"))
        }
    }
}

/// Convert a `serde_yaml_ng::Value` into a `serde_json::Value`. Used at
/// the file boundary so the rest of the engine keeps consuming JSON
/// without any awareness of YAML.
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
        // Tagged and other YAML-only constructs are flattened to null —
        // we never authored Sigma rules use them.
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_rule() {
        let yaml = r#"
title: Test rule
id: test-001
status: experimental
description: |
  A minimal rule used by the loader tests.
author: ThreatClaw
date: 2026-06-14
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process
detection:
  selection:
    image|endswith: 'powershell.exe'
  condition: selection
falsepositives:
  - Legitimate scripted admin task.
level: high
"#;
        let r: RuleFile = serde_yaml_ng::from_str(yaml).expect("parse");
        assert_eq!(r.id, "test-001");
        assert_eq!(r.level, "high");
        assert_eq!(r.tags.len(), 2);
        let det = yaml_to_json(r.detection);
        assert!(det.get("selection").is_some());
        assert_eq!(det["condition"], "selection");
    }

    #[test]
    fn ignores_extra_fields_gracefully() {
        let yaml = r#"
title: Test
id: test-extra
level: low
logsource:
  product: windows
detection:
  selection: { event_id: '4625' }
  condition: selection
extra_field_we_dont_know: 42
"#;
        let r: RuleFile = serde_yaml_ng::from_str(yaml).expect("parse with extras");
        assert_eq!(r.id, "test-extra");
    }
}

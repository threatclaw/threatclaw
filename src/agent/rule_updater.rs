//! Agent-side Sigma rule auto-update (support plan).
//!
//! A FREE ThreatClaw agent that holds an active **support plan** pulls fresh,
//! validated Sigma rules from the license worker straight into its own engine.
//! It reuses the existing disk→DB→compile pipeline: fetched rules are written
//! under the rules dir, then [`sigma_file_loader::sync_rules_from_disk`] +
//! [`sigma_engine::reload`] pick them up.
//!
//! Off by default: without `TC_SUPPORT_KEY` the agent runs its bundled-at-
//! release rules unchanged ([`RuleUpdateConfig::from_env`] returns `None`).
//!
//! When configured, the intelligence loop spawns [`run_update_cycle`]
//! periodically (every ~6h) so a supported agent keeps its detection set fresh
//! between releases.

use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_WORKER_BASE: &str = "https://license.threatclaw.io";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// Where the last successfully-applied pack version is persisted, so the updater
// skips a download when already current — across restarts too.
const VERSION_NS: &str = "_sigma_rules";
const VERSION_KEY: &str = "managed_version";

/// Resolved configuration for one update run.
pub struct RuleUpdateConfig {
    pub worker_base: String,
    pub support_key: String,
    pub rules_dir: PathBuf,
    /// This server's stable install UUID — sent so the worker can bind the
    /// support plan to one server (anti-sharing seat). Empty if unreadable.
    pub install_id: String,
}

impl RuleUpdateConfig {
    /// Build from the environment. Returns `None` when no support key is
    /// configured (free agents / no plan) so the updater is a clean no-op.
    pub fn from_env() -> Option<Self> {
        let support_key = std::env::var("TC_SUPPORT_KEY")
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())?;
        let worker_base = std::env::var("TC_LICENSE_API_URL")
            .unwrap_or_else(|_| DEFAULT_WORKER_BASE.to_string());
        let rules_dir = PathBuf::from(
            std::env::var("TC_SIGMA_RULES_DIR").unwrap_or_else(|_| "/app/rules".to_string()),
        );
        let install_id =
            crate::licensing::storage::load_or_create_install_id().unwrap_or_default();
        Some(Self {
            worker_base: worker_base.trim_end_matches('/').to_string(),
            support_key,
            rules_dir,
            install_id,
        })
    }

    fn manifest_url(&self) -> String {
        format!("{}/api/agent/rules/manifest", self.worker_base)
    }
    fn download_url(&self) -> String {
        format!("{}/api/agent/rules/download", self.worker_base)
    }
    /// Fetched rules land in a dedicated subdir so an update can replace them
    /// wholesale without disturbing the agent's bundled rules.
    pub fn managed_dir(&self) -> PathBuf {
        self.rules_dir.join("_managed")
    }
}

/// What a single update cycle did.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Manifest version matched `last_version` — nothing fetched.
    UpToDate,
    /// New rules fetched and applied.
    Applied { version: String, rules: usize },
}

/// Extract the `version` field from a `MANIFEST.json` body. Pure.
pub fn parse_manifest_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("version")?.as_str().map(|s| s.to_string())
}

/// Extract a gzipped tar of rule files into `dest`, which is wiped and
/// recreated first so removed-upstream files don't linger on disk. Returns the
/// number of `*.yml` / `*.yaml` files written. The `tar` crate refuses entries
/// that would escape `dest`, so a hostile archive can't path-traverse.
pub fn extract_rules_targz(gz_bytes: &[u8], dest: &Path) -> std::io::Result<usize> {
    if dest.exists() {
        std::fs::remove_dir_all(dest)?;
    }
    std::fs::create_dir_all(dest)?;
    let dec = flate2::read::GzDecoder::new(gz_bytes);
    let mut archive = tar::Archive::new(dec);
    archive.unpack(dest)?;
    Ok(count_rule_files(dest))
}

/// Recursively count Sigma rule files under `dir`.
fn count_rule_files(dir: &Path) -> usize {
    let mut count = 0;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count += count_rule_files(&path);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml") {
                count += 1;
            }
        }
    }
    count
}

/// Run one update cycle: check the published version against the last applied
/// one (persisted in a setting), and if it changed, download + extract the
/// Sigma pack and refresh the engine. Network failures return `Err` and leave
/// the running rules untouched.
pub async fn run_update_cycle(
    store: &dyn crate::db::Database,
    cfg: &RuleUpdateConfig,
) -> Result<UpdateOutcome, String> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    // 1. Manifest — cheap version check so we only download on a real change.
    let manifest = client
        .get(cfg.manifest_url())
        .bearer_auth(&cfg.support_key)
        .header("X-Install-Id", &cfg.install_id)
        .send()
        .await
        .map_err(|e| format!("manifest fetch: {e}"))?;
    if !manifest.status().is_success() {
        return Err(format!("manifest http {}", manifest.status()));
    }
    let manifest_body = manifest
        .text()
        .await
        .map_err(|e| format!("manifest body: {e}"))?;
    let version = parse_manifest_version(&manifest_body)
        .ok_or_else(|| "manifest has no version".to_string())?;
    let last_version = store
        .get_setting(VERSION_NS, VERSION_KEY)
        .await
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(|s| s.to_string()));
    if last_version.as_deref() == Some(version.as_str()) {
        return Ok(UpdateOutcome::UpToDate);
    }

    // 2. Download the Sigma pack.
    let dl = client
        .get(cfg.download_url())
        .bearer_auth(&cfg.support_key)
        .header("X-Install-Id", &cfg.install_id)
        .send()
        .await
        .map_err(|e| format!("pack fetch: {e}"))?;
    if !dl.status().is_success() {
        return Err(format!("pack http {}", dl.status()));
    }
    let bytes = dl.bytes().await.map_err(|e| format!("pack body: {e}"))?;

    // 3. Extract into the managed subdir.
    let n = extract_rules_targz(&bytes, &cfg.managed_dir())
        .map_err(|e| format!("extract: {e}"))?;

    // 4. Apply through the existing pipeline (disk → DB upsert → recompile).
    crate::agent::sigma_file_loader::sync_rules_from_disk(store, &cfg.rules_dir).await;
    crate::agent::sigma_engine::reload(store).await;

    // Remember the applied version so the next cycle no-ops until it changes.
    let _ = store
        .set_setting(VERSION_NS, VERSION_KEY, &serde_json::json!(version))
        .await;

    Ok(UpdateOutcome::Applied { version, rules: n })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut b = tar::Builder::new(&mut gz);
            for (path, data) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, *data).unwrap();
            }
            b.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn parse_manifest_version_reads_field() {
        assert_eq!(
            parse_manifest_version(r#"{"version":"2026.06.25","packs":[]}"#),
            Some("2026.06.25".to_string())
        );
        assert_eq!(parse_manifest_version("not json"), None);
        assert_eq!(parse_manifest_version(r#"{"packs":[]}"#), None);
    }

    #[test]
    fn extract_writes_rule_files_and_counts_yaml() {
        let dest = std::env::temp_dir().join("tc_rule_updater_test_extract");
        let gz = make_targz(&[
            ("sigma/rules/standard/foo.yml", b"title: Foo"),
            ("sigma/rules/exclusive/bar.yaml", b"title: Bar"),
            ("sigma/LICENSES/NOTICE.txt", b"notice"),
        ]);
        let n = extract_rules_targz(&gz, &dest).unwrap();
        assert_eq!(n, 2, "only the two yml/yaml files count, not NOTICE.txt");
        assert!(dest.join("sigma/rules/standard/foo.yml").exists());
        assert_eq!(
            std::fs::read_to_string(dest.join("sigma/rules/standard/foo.yml")).unwrap(),
            "title: Foo"
        );
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn extract_wipes_stale_files_first() {
        let dest = std::env::temp_dir().join("tc_rule_updater_test_wipe");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("stale.yml"), b"old").unwrap();
        let gz = make_targz(&[("fresh.yml", b"new")]);
        let n = extract_rules_targz(&gz, &dest).unwrap();
        assert_eq!(n, 1);
        assert!(!dest.join("stale.yml").exists(), "stale rule must be wiped");
        assert!(dest.join("fresh.yml").exists());
        std::fs::remove_dir_all(&dest).ok();
    }

    #[test]
    fn urls_and_managed_dir() {
        let cfg = RuleUpdateConfig {
            worker_base: "https://license.threatclaw.io".to_string(),
            support_key: "TC-XXXX".to_string(),
            rules_dir: PathBuf::from("/app/rules"),
            install_id: "00000000-0000-4000-8000-000000000000".to_string(),
        };
        assert_eq!(
            cfg.manifest_url(),
            "https://license.threatclaw.io/api/agent/rules/manifest"
        );
        assert_eq!(
            cfg.download_url(),
            "https://license.threatclaw.io/api/agent/rules/download"
        );
        assert_eq!(cfg.managed_dir(), PathBuf::from("/app/rules/_managed"));
    }
}

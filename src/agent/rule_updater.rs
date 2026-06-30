//! Agent-side threat-intel pack auto-update (support plan).
//!
//! A FREE ThreatClaw agent that holds an active **support plan** pulls fresh,
//! validated data packs from the license worker straight into its own engines.
//! Historically this synced one pack — the Sigma rule set — reusing the existing
//! disk→DB→compile pipeline. It is now a generic **multi-pack sync**: an
//! orchestrator ([`run_update_cycle`]) walks a registry of [`PackInstaller`]s,
//! and each installer knows how to land its pack (Sigma rules, and — as the
//! hub-R2 chantier lands — KEV/MITRE/EPSS/IOC/grype-db). One MANIFEST lists every
//! pack with its own version; a pack is only downloaded when *its* version moved,
//! and one pack failing never blocks the others.
//!
//! Off by default: without `TC_SUPPORT_KEY` (or a dashboard-stored support key)
//! the agent runs its bundled-at-release data unchanged
//! ([`RuleUpdateConfig::from_env`] returns `None`).
//!
//! When configured, the intelligence loop spawns [`run_update_cycle`]
//! periodically (every ~6h) so a supported agent keeps its detection set fresh
//! between releases.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_WORKER_BASE: &str = "https://license.threatclaw.io";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// Where the Sigma pack's last successfully-applied version is persisted, so the
// updater skips a download when already current — across restarts too. Kept on
// the original namespace/key so an agent upgraded into the multi-pack world does
// not forget it already runs the current Sigma pack (no spurious re-download).
const VERSION_NS: &str = "_sigma_rules";
const VERSION_KEY: &str = "managed_version";

// Support key persisted via the dashboard (premium-key activation) rather than
// the TC_SUPPORT_KEY env var. The env var wins when both are present.
const SUPPORT_KEY_NS: &str = "_system";
const SUPPORT_KEY_SETTING: &str = "tc_support_key";

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
    /// Resolve the effective support key. The env var wins; the dashboard-stored
    /// setting is the fallback. Empty / whitespace values count as absent.
    fn resolve_support_key(from_env: Option<String>, from_store: Option<String>) -> Option<String> {
        let clean = |k: String| -> Option<String> {
            let t = k.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        };
        from_env.and_then(clean).or_else(|| from_store.and_then(clean))
    }

    /// Build a config around an already-resolved support key. Non-key fields
    /// (worker base, rules dir, install id) come from the environment / disk.
    fn with_key(support_key: String) -> Self {
        let worker_base = std::env::var("TC_LICENSE_API_URL")
            .unwrap_or_else(|_| DEFAULT_WORKER_BASE.to_string());
        let rules_dir = PathBuf::from(
            std::env::var("TC_SIGMA_RULES_DIR").unwrap_or_else(|_| "/app/rules".to_string()),
        );
        let install_id =
            crate::licensing::storage::load_or_create_install_id().unwrap_or_default();
        Self {
            worker_base: worker_base.trim_end_matches('/').to_string(),
            support_key,
            rules_dir,
            install_id,
        }
    }

    /// Build from the environment only. Returns `None` when no support key is
    /// configured (free agents / no plan) so the updater is a clean no-op.
    pub fn from_env() -> Option<Self> {
        Self::resolve_support_key(std::env::var("TC_SUPPORT_KEY").ok(), None).map(Self::with_key)
    }

    /// Build from the environment, falling back to the dashboard-stored support
    /// key (`_system`/`tc_support_key`) when the env var is unset — so an
    /// operator can activate premium auto-update from the UI, not just via env.
    pub async fn from_env_or_store(store: &dyn crate::db::Database) -> Option<Self> {
        let from_store = store
            .get_setting(SUPPORT_KEY_NS, SUPPORT_KEY_SETTING)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(str::to_string));
        Self::resolve_support_key(std::env::var("TC_SUPPORT_KEY").ok(), from_store)
            .map(Self::with_key)
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

/// One pack listed in the worker MANIFEST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackEntry {
    /// Pack name (matches `PackInstaller::pack_name`), e.g. `sigma-agent`.
    pub name: String,
    /// The pack's published version. Per-pack `version` if the manifest carries
    /// one; otherwise the manifest's top-level `version` (today every pack is
    /// built together under one version).
    pub version: String,
    /// Optional content hash for integrity verification of the downloaded pack.
    pub sha256: Option<String>,
}

/// What a single pack did within one update cycle.
#[derive(Debug, PartialEq, Eq)]
pub enum PackOutcome {
    /// Manifest version matched the last applied one — nothing fetched.
    UpToDate,
    /// New pack fetched and applied.
    Applied { version: String, items: usize },
    /// No installer registered offered this pack name — or the manifest didn't
    /// list a registered installer's pack.
    Skipped,
    /// This pack's download/verify/install failed; the running data is untouched
    /// and the version is NOT persisted, so the next cycle retries it. Other
    /// packs in the same cycle are unaffected.
    Failed(String),
}

/// What an update cycle did, per registered pack.
#[derive(Debug, PartialEq, Eq)]
pub struct UpdateOutcome {
    pub packs: Vec<(String, PackOutcome)>,
}

/// A consumer of one R2 pack: it knows the pack's name, where to download it,
/// where its applied version is persisted, and how to land its bytes into the
/// right place in the agent (rules dir, DB table, on-disk DB, …).
#[async_trait]
pub trait PackInstaller: Send + Sync {
    /// The MANIFEST `pack` name this installer consumes.
    fn pack_name(&self) -> &'static str;
    /// Absolute worker URL to download this pack's bytes.
    fn download_url(&self, cfg: &RuleUpdateConfig) -> String;
    /// `(namespace, key)` under which this pack's applied version is persisted in
    /// `settings`. Per-pack so independent cadences don't collide.
    fn version_key(&self) -> (&'static str, String);
    /// Land already-downloaded (and integrity-checked) pack bytes. Returns the
    /// number of items applied (rules, IoC, techniques…). On `Err` the cycle
    /// records [`PackOutcome::Failed`] and leaves the version unpersisted.
    async fn install(
        &self,
        store: &dyn crate::db::Database,
        cfg: &RuleUpdateConfig,
        bytes: &[u8],
    ) -> Result<usize, String>;
}

/// The Sigma rule pack — the original (and, for now, only) installer. Reuses the
/// existing disk→DB→compile pipeline unchanged.
pub struct SigmaInstaller;

#[async_trait]
impl PackInstaller for SigmaInstaller {
    fn pack_name(&self) -> &'static str {
        "sigma-agent"
    }
    fn download_url(&self, cfg: &RuleUpdateConfig) -> String {
        cfg.download_url()
    }
    fn version_key(&self) -> (&'static str, String) {
        (VERSION_NS, VERSION_KEY.to_string())
    }
    async fn install(
        &self,
        store: &dyn crate::db::Database,
        cfg: &RuleUpdateConfig,
        bytes: &[u8],
    ) -> Result<usize, String> {
        // Extract into the managed subdir, then apply through the existing
        // pipeline (disk → DB upsert → recompile).
        let n = extract_rules_targz(bytes, &cfg.managed_dir())
            .map_err(|e| format!("extract: {e}"))?;
        crate::agent::sigma_file_loader::sync_rules_from_disk(store, &cfg.rules_dir).await;
        crate::agent::sigma_engine::reload(store).await;
        Ok(n)
    }
}

/// The installers a normal agent runs. One entry today (Sigma); the hub-R2
/// chantier appends KEV/MITRE/EPSS/IOC/grype-db here as each lands.
pub fn default_installers() -> Vec<Box<dyn PackInstaller>> {
    vec![Box::new(SigmaInstaller)]
}

/// Extract the `version` field from a `MANIFEST.json` body. Pure.
pub fn parse_manifest_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("version")?.as_str().map(|s| s.to_string())
}

/// Parse the `packs` array of a `MANIFEST.json` into [`PackEntry`]s. Pure.
///
/// A pack's version is its own `version` field when present, else the manifest's
/// top-level `version` (today every pack is built under one global version, so
/// the fallback is the normal path). A pack with neither a usable name nor any
/// version is skipped. Returns `[]` on non-JSON or a manifest with no usable
/// pack entries.
pub fn parse_manifest_packs(body: &str) -> Vec<PackEntry> {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let top_version = v.get("version").and_then(|x| x.as_str()).map(str::to_string);
    let mut out = Vec::new();
    let Some(arr) = v.get("packs").and_then(|p| p.as_array()) else {
        return out;
    };
    for p in arr {
        let Some(name) = p.get("pack").and_then(|x| x.as_str()) else {
            continue;
        };
        let version = p
            .get("version")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .or_else(|| top_version.clone());
        let Some(version) = version else {
            continue;
        };
        let sha256 = p.get("sha256").and_then(|x| x.as_str()).map(str::to_string);
        out.push(PackEntry {
            name: name.to_string(),
            version,
            sha256,
        });
    }
    out
}

/// Verify that `bytes` hashes to `expected_hex` (SHA-256, case-insensitive). Pure.
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> bool {
    use sha2::{Digest, Sha256};
    let got = format!("{:x}", Sha256::digest(bytes));
    got.eq_ignore_ascii_case(expected_hex.trim())
}

/// Extract a gzipped tar of rule files into `dest`, whose CONTENTS are wiped
/// first so removed-upstream files don't linger on disk. Returns the number of
/// `*.yml` / `*.yaml` files written. The `tar` crate refuses entries that would
/// escape `dest`, so a hostile archive can't path-traverse.
pub fn extract_rules_targz(gz_bytes: &[u8], dest: &Path) -> std::io::Result<usize> {
    // Clear `dest`'s CONTENTS in place rather than removing and recreating the
    // directory itself. On the hardened image `dest` (/app/rules/_managed) is a
    // mount point: the rootfs is read_only and a writable volume is mounted here,
    // so rmdir-ing it fails (EBUSY) and recreating it under the read-only parent
    // fails (EROFS, os error 30) — which silently broke every premium rule
    // auto-update. Wiping the contents keeps the mount point intact.
    if dest.exists() {
        for entry in std::fs::read_dir(dest)? {
            let path = entry?.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
        }
    } else {
        std::fs::create_dir_all(dest)?;
    }
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
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
        {
            count += 1;
        }
    }
    count
}

/// Outcome of validating a support key against the license worker.
#[derive(Debug, PartialEq)]
pub enum SupportKeyCheck {
    /// Key maps to an active support plan — premium auto-update is available.
    Active,
    /// Key known but the plan is not active (past_due / cancelled / expired).
    Inactive,
    /// Key rejected/malformed, or the worker is unreachable.
    Rejected(String),
}

/// Validate a support key by calling the worker manifest endpoint with the key
/// plus this server's install id. Persists nothing — used by the dashboard's
/// premium-key activation to give immediate, honest feedback.
pub async fn check_support_key(key: &str) -> SupportKeyCheck {
    let key = key.trim();
    if key.is_empty() {
        return SupportKeyCheck::Rejected("clé vide".into());
    }
    let cfg = RuleUpdateConfig::with_key(key.to_string());
    let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => return SupportKeyCheck::Rejected(format!("client http: {e}")),
    };
    match client
        .get(cfg.manifest_url())
        .bearer_auth(&cfg.support_key)
        .header("X-Install-Id", &cfg.install_id)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => SupportKeyCheck::Active,
        Ok(r) if r.status().as_u16() == 402 => SupportKeyCheck::Inactive,
        Ok(r) => SupportKeyCheck::Rejected(format!("worker http {}", r.status())),
        Err(e) => SupportKeyCheck::Rejected(format!("serveur de licence injoignable: {e}")),
    }
}

/// Run one update cycle with the default installer registry. See
/// [`run_update_cycle_with`].
pub async fn run_update_cycle(
    store: &dyn crate::db::Database,
    cfg: &RuleUpdateConfig,
) -> Result<UpdateOutcome, String> {
    run_update_cycle_with(store, cfg, &default_installers()).await
}

/// Run one update cycle over `installers`: fetch the shared MANIFEST, then for
/// each registered installer, compare the published version against the last
/// applied one (persisted per-pack) and on a change download, integrity-check
/// and install that pack. A manifest-fetch failure dooms the whole cycle
/// (`Err`); a single pack's failure is isolated to [`PackOutcome::Failed`] and
/// never blocks the others.
pub async fn run_update_cycle_with(
    store: &dyn crate::db::Database,
    cfg: &RuleUpdateConfig,
    installers: &[Box<dyn PackInstaller>],
) -> Result<UpdateOutcome, String> {
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    // 1. Manifest — shared across packs, so a failure dooms the cycle.
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
    let entries = parse_manifest_packs(&manifest_body);
    if entries.is_empty() {
        return Err("manifest lists no packs".to_string());
    }

    // 2. Each registered installer syncs its pack independently.
    let mut results = Vec::new();
    for installer in installers {
        let name = installer.pack_name();
        let Some(entry) = entries.iter().find(|e| e.name == name) else {
            results.push((name.to_string(), PackOutcome::Skipped));
            continue;
        };
        let (ns, key) = installer.version_key();
        let last = store
            .get_setting(ns, &key)
            .await
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        if last.as_deref() == Some(entry.version.as_str()) {
            results.push((name.to_string(), PackOutcome::UpToDate));
            continue;
        }
        match sync_one_pack(&client, store, cfg, installer.as_ref(), entry).await {
            Ok(items) => {
                // Remember the applied version so the next cycle no-ops until it
                // changes. Only after a successful install.
                let _ = store
                    .set_setting(ns, &key, &serde_json::json!(entry.version))
                    .await;
                results.push((
                    name.to_string(),
                    PackOutcome::Applied {
                        version: entry.version.clone(),
                        items,
                    },
                ));
            }
            Err(e) => results.push((name.to_string(), PackOutcome::Failed(e))),
        }
    }

    Ok(UpdateOutcome { packs: results })
}

/// Download one pack, verify its hash, and hand the bytes to its installer.
async fn sync_one_pack(
    client: &reqwest::Client,
    store: &dyn crate::db::Database,
    cfg: &RuleUpdateConfig,
    installer: &dyn PackInstaller,
    entry: &PackEntry,
) -> Result<usize, String> {
    let dl = client
        .get(installer.download_url(cfg))
        .bearer_auth(&cfg.support_key)
        .header("X-Install-Id", &cfg.install_id)
        .send()
        .await
        .map_err(|e| format!("pack fetch: {e}"))?;
    if !dl.status().is_success() {
        return Err(format!("pack http {}", dl.status()));
    }
    let bytes = dl.bytes().await.map_err(|e| format!("pack body: {e}"))?;
    if entry
        .sha256
        .as_deref()
        .is_some_and(|expected| !verify_sha256(&bytes, expected))
    {
        return Err(format!("sha256 mismatch for pack {}", entry.name));
    }
    installer.install(store, cfg, &bytes).await
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
    fn parse_manifest_packs_uses_top_level_version_as_fallback() {
        // The real worker manifest: one global `version`, packs without their
        // own `version` field — every pack inherits the top-level one.
        let body = r#"{
          "version": "2099.09.09",
          "packs": [
            {"pack":"sigma","bytes":1,"sha256":"aa"},
            {"pack":"sigma-agent","bytes":2,"sha256":"ff634ac0"},
            {"pack":"yara","bytes":3}
          ]
        }"#;
        let packs = parse_manifest_packs(body);
        assert_eq!(packs.len(), 3);
        let agent = packs.iter().find(|p| p.name == "sigma-agent").unwrap();
        assert_eq!(agent.version, "2099.09.09");
        assert_eq!(agent.sha256.as_deref(), Some("ff634ac0"));
        // sha256 is optional
        assert_eq!(packs.iter().find(|p| p.name == "yara").unwrap().sha256, None);
    }

    #[test]
    fn parse_manifest_packs_prefers_per_pack_version() {
        // Forward-compatible: when packs carry their own version (independent
        // cadences), it wins over the global one.
        let body = r#"{
          "version": "2099.09.09",
          "packs": [
            {"pack":"sigma-agent","sha256":"aa"},
            {"pack":"kev","version":"2026.06.30","sha256":"bb"}
          ]
        }"#;
        let packs = parse_manifest_packs(body);
        assert_eq!(packs.iter().find(|p| p.name == "sigma-agent").unwrap().version, "2099.09.09");
        assert_eq!(packs.iter().find(|p| p.name == "kev").unwrap().version, "2026.06.30");
    }

    #[test]
    fn parse_manifest_packs_empty_on_garbage_or_no_packs() {
        assert!(parse_manifest_packs("not json").is_empty());
        assert!(parse_manifest_packs(r#"{"version":"1"}"#).is_empty());
        // pack entries with no name and no resolvable version are dropped
        assert!(parse_manifest_packs(r#"{"packs":[{"bytes":1}]}"#).is_empty());
    }

    #[test]
    fn verify_sha256_matches_case_insensitively() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let empty = b"";
        assert!(verify_sha256(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(verify_sha256(
            empty,
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
        assert!(!verify_sha256(empty, "deadbeef"));
    }

    #[test]
    fn default_registry_has_sigma_only() {
        let reg = default_installers();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0].pack_name(), "sigma-agent");
    }

    #[test]
    fn sigma_installer_keeps_legacy_version_key() {
        // The Sigma pack must keep persisting under the original namespace/key so
        // an upgraded agent doesn't re-download a pack it already has.
        let (ns, key) = SigmaInstaller.version_key();
        assert_eq!(ns, "_sigma_rules");
        assert_eq!(key, "managed_version");
    }

    #[test]
    fn resolve_support_key_env_wins_then_store_then_none() {
        let r = RuleUpdateConfig::resolve_support_key;
        // env wins when both present
        assert_eq!(r(Some("env".into()), Some("store".into())).as_deref(), Some("env"));
        // empty/whitespace env falls back to the stored key
        assert_eq!(r(Some("   ".into()), Some("store".into())).as_deref(), Some("store"));
        // store-only
        assert_eq!(r(None, Some("store".into())).as_deref(), Some("store"));
        // trimmed
        assert_eq!(r(Some("  k  ".into()), None).as_deref(), Some("k"));
        // nothing
        assert_eq!(r(None, None), None);
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
        // the Sigma installer downloads from the legacy rules endpoint
        assert_eq!(SigmaInstaller.download_url(&cfg), cfg.download_url());
        assert_eq!(cfg.managed_dir(), PathBuf::from("/app/rules/_managed"));
    }
}

//! Backup manager — creates, lists, and rotates ThreatClaw backups.
//!
//! Backups are JSON files written to /app/data/backups/ inside the core
//! container (mounted as Docker volume `core-data`). For external storage,
//! the operator can either remap the volume to a host path or sync the
//! directory to a NAS via standard tools (rsync, rclone).
//!
//! Backup format: gzip-compressed JSON containing all critical tables
//! (config, settings, assets, networks, incidents, findings, alerts,
//! ml_scores, etc.). Filename pattern: `tc-backup-YYYY-MM-DD-HHMMSS.json.gz`.

use crate::db::Database;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};

const BACKUP_DIR: &str = "/app/data/backups";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSettings {
    /// Whether automatic daily backups are enabled.
    pub auto_enabled: bool,
    /// Time of day for the daily backup (HH:MM, UTC).
    pub auto_time: String,
    /// Number of backups to keep before rotation.
    pub retention_count: usize,
    /// Optional external path (must be a directory accessible inside the container).
    /// Empty = use the default /app/data/backups.
    pub external_path: String,
}

impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            auto_enabled: true,
            auto_time: "02:00".into(),
            retention_count: 7,
            external_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub name: String,
    pub size_bytes: u64,
    pub created_at: String,
}

const BACKUP_SETTINGS_KEY: &str = "tc_config_backup_settings";

/// Load backup settings from DB.
pub async fn load_settings(store: &dyn Database) -> BackupSettings {
    if let Ok(Some(val)) = store.get_setting("_system", BACKUP_SETTINGS_KEY).await {
        if let Ok(s) = serde_json::from_value(val) {
            return s;
        }
    }
    BackupSettings::default()
}

/// Save backup settings to DB.
pub async fn save_settings(store: &dyn Database, settings: &BackupSettings) -> Result<(), String> {
    let val = serde_json::to_value(settings).map_err(|e| e.to_string())?;
    store
        .set_setting("_system", BACKUP_SETTINGS_KEY, &val)
        .await
        .map_err(|e| e.to_string())
}

/// Resolve the backup directory: external_path if set, otherwise default.
fn backup_dir(settings: &BackupSettings) -> PathBuf {
    if settings.external_path.is_empty() {
        PathBuf::from(BACKUP_DIR)
    } else {
        PathBuf::from(&settings.external_path)
    }
}

/// Ensure the backup directory exists.
fn ensure_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create_dir_all: {e}"))?;
    }
    Ok(())
}

/// Build the in-memory backup payload from the database.
async fn build_backup_payload(store: &dyn Database) -> serde_json::Value {
    let mut backup = json!({
        "version": "2.2.0",
        "format": "tc-full-v1",
        "exported_at": chrono::Utc::now().to_rfc3339(),
    });

    // Company profile + networks + categories
    backup["company_profile"] = json!(store.get_company_profile().await.unwrap_or_default());
    backup["internal_networks"] = json!(store.list_internal_networks().await.unwrap_or_default());
    backup["asset_categories"] = json!(store.list_asset_categories().await.unwrap_or_default());

    // Assets
    backup["assets"] = json!(
        store
            .list_assets(None, None, 10000, 0)
            .await
            .unwrap_or_default()
    );

    // All settings (system config, channels, anonymizer, notification, etc.)
    let mut all_settings: Vec<serde_json::Value> = vec![];
    for owner in &["_system", "_audit", "_targets"] {
        let rows = store.list_settings(owner).await.unwrap_or_default();
        for s in rows {
            all_settings.push(json!({"owner": owner, "key": s.key, "value": s.value}));
        }
    }
    backup["settings"] = json!(all_settings);

    // Incidents (everything — not many rows)
    backup["incidents"] = json!(
        store
            .list_incidents(None, 10000, 0)
            .await
            .unwrap_or_default()
    );

    // Findings (open + recent resolved)
    backup["findings"] = json!(
        store
            .list_findings(None, None, None, 10000, 0)
            .await
            .unwrap_or_default()
    );

    // Recent alerts (cap to keep file size sane — full sigma_alerts can be 1M+ rows)
    backup["alerts"] = json!(
        store
            .list_alerts(None, None, 5000, 0)
            .await
            .unwrap_or_default()
    );

    // ML scores
    backup["ml_scores"] = json!(store.get_all_ml_scores().await.unwrap_or_default());

    backup
}

/// Create a backup file on disk and return its info.
pub async fn create_backup(store: &dyn Database) -> Result<BackupInfo, String> {
    let settings = load_settings(store).await;
    let dir = backup_dir(&settings);
    ensure_dir(&dir)?;

    let payload = build_backup_payload(store).await;
    let json_bytes = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y-%m-%d-%H%M%S").to_string();
    let name = format!("tc-backup-{}.json.gz", timestamp);
    let path = dir.join(&name);

    // Gzip compress
    let file = std::fs::File::create(&path).map_err(|e| format!("create file: {e}"))?;
    let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    encoder
        .write_all(&json_bytes)
        .map_err(|e| format!("gzip write: {e}"))?;
    encoder.finish().map_err(|e| format!("gzip finish: {e}"))?;

    let size_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    tracing::info!("BACKUP: Created {} ({} bytes)", name, size_bytes);

    // Apply retention immediately after a fresh backup
    let _ = apply_retention(&settings).await;

    Ok(BackupInfo {
        name,
        size_bytes,
        created_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// List available backups in the configured directory.
pub async fn list_backups(store: &dyn Database) -> Vec<BackupInfo> {
    let settings = load_settings(store).await;
    let dir = backup_dir(&settings);
    if !dir.exists() {
        return vec![];
    }

    let mut out = vec![];
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("tc-backup-") || !name.ends_with(".json.gz") {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let created_at = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0))
                .flatten()
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();
            out.push(BackupInfo {
                name,
                size_bytes: metadata.len(),
                created_at,
            });
        }
    }
    // Sort newest first
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    out
}

/// Read a backup file's bytes for download. Validates the name to prevent path traversal.
pub async fn read_backup(store: &dyn Database, name: &str) -> Result<Vec<u8>, String> {
    if !is_safe_name(name) {
        return Err("invalid backup name".into());
    }
    let settings = load_settings(store).await;
    let path = backup_dir(&settings).join(name);
    std::fs::read(&path).map_err(|e| format!("read: {e}"))
}

/// Delete a backup file. Validates the name to prevent path traversal.
pub async fn delete_backup(store: &dyn Database, name: &str) -> Result<(), String> {
    if !is_safe_name(name) {
        return Err("invalid backup name".into());
    }
    let settings = load_settings(store).await;
    let path = backup_dir(&settings).join(name);
    std::fs::remove_file(&path).map_err(|e| format!("delete: {e}"))?;
    tracing::info!("BACKUP: Deleted {}", name);
    Ok(())
}

/// Validate a backup filename: only the expected pattern, no path components.
fn is_safe_name(name: &str) -> bool {
    !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && name.starts_with("tc-backup-")
        && name.ends_with(".json.gz")
        && name.len() < 200
}

/// Apply retention policy: keep only the N most recent backups.
async fn apply_retention(settings: &BackupSettings) -> Result<(), String> {
    let dir = backup_dir(settings);
    if !dir.exists() {
        return Ok(());
    }

    let mut files: Vec<(String, std::time::SystemTime)> = vec![];
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("tc-backup-") || !name.ends_with(".json.gz") {
                continue;
            }
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    files.push((name, modified));
                }
            }
        }
    }

    // Sort newest first, then drop everything beyond retention_count
    files.sort_by(|a, b| b.1.cmp(&a.1));
    for (name, _) in files.into_iter().skip(settings.retention_count) {
        let path = dir.join(&name);
        if std::fs::remove_file(&path).is_ok() {
            tracing::info!("BACKUP: Rotated out {}", name);
        }
    }
    Ok(())
}

/// Daily backup check — fires once per day at the configured time.
/// Called from the IE cycle.
pub async fn check_daily_backup(store: &dyn Database) {
    let settings = load_settings(store).await;
    if !settings.auto_enabled {
        return;
    }

    // Parse target time
    let parts: Vec<&str> = settings.auto_time.split(':').collect();
    let target_h = parts
        .first()
        .and_then(|h| h.parse::<u32>().ok())
        .unwrap_or(2);
    let target_m = parts
        .get(1)
        .and_then(|m| m.parse::<u32>().ok())
        .unwrap_or(0);

    let now = chrono::Utc::now();
    let cur_h = now.format("%H").to_string().parse::<u32>().unwrap_or(0);
    let cur_m = now.format("%M").to_string().parse::<u32>().unwrap_or(0);
    let target_min = target_h * 60 + target_m;
    let cur_min = cur_h * 60 + cur_m;

    // Fire within a 10-min window
    if cur_min < target_min || cur_min > target_min + 10 {
        return;
    }

    // Already done today?
    let today = now.format("%Y-%m-%d").to_string();
    if let Ok(Some(last)) = store.get_setting("_system", "last_daily_backup").await {
        if last.as_str() == Some(today.as_str()) {
            return;
        }
    }

    match create_backup(store).await {
        Ok(info) => {
            tracing::info!(
                "DAILY_BACKUP: {} created ({} KB)",
                info.name,
                info.size_bytes / 1024
            );
            let _ = store
                .set_setting("_system", "last_daily_backup", &json!(today))
                .await;
        }
        Err(e) => {
            tracing::error!("DAILY_BACKUP: Failed — {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_name() {
        assert!(is_safe_name("tc-backup-2026-04-12-020000.json.gz"));
        assert!(!is_safe_name("../etc/passwd"));
        assert!(!is_safe_name("tc-backup-/foo.json.gz"));
        assert!(!is_safe_name("foo.json.gz"));
        assert!(!is_safe_name("tc-backup-foo.txt"));
        assert!(!is_safe_name(&"tc-backup-".repeat(50)));
    }

    #[test]
    fn test_default_settings() {
        let s = BackupSettings::default();
        assert!(s.auto_enabled);
        assert_eq!(s.auto_time, "02:00");
        assert_eq!(s.retention_count, 7);
        assert!(s.external_path.is_empty());
    }
}

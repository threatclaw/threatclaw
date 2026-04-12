//! Ransomware SMB detection via heuristic analysis.
//!
//! Detects ransomware activity by analyzing file operations on SMB shares:
//! - High rename/create ratio (mass file renaming = encryption)
//! - Known ransomware extensions (.lockbit, .ryuk, .conti, .encrypted, etc.)
//! - Ransom note filenames (README, DECRYPT, HOW_TO_RECOVER, etc.)
//! - High file modification volume per minute
//! - High entropy in new filenames (encrypted filenames)
//!
//! Sources: Zeek smb_files.log, Wazuh Windows file events, osquery file_events.
//! Inspired by Gatewatcher ML semi-supervised ransomware detection.
//! MITRE: T1486 (Data Encrypted for Impact)

use std::collections::HashMap;
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Detection thresholds — conservative to avoid false positives.
const RENAME_RATIO_THRESHOLD: f64 = 0.5;     // >50% of ops are renames
const MIN_OPERATIONS: usize = 10;             // Need enough ops to detect pattern
const VOLUME_THRESHOLD: usize = 50;           // >50 file ops in analysis window
const ENTROPY_THRESHOLD: f64 = 4.0;           // High entropy = encrypted filenames
const RANSOM_EXT_SCORE: u32 = 60;             // Known ransomware extension
const RANSOM_NOTE_SCORE: u32 = 40;            // Known ransom note filename
const RENAME_RATIO_SCORE: u32 = 40;           // High rename ratio
const VOLUME_SCORE: u32 = 20;                 // High volume modifier
const ENTROPY_SCORE: u32 = 25;                // High filename entropy
const SCORE_HIGH: u32 = 50;
const SCORE_CRITICAL: u32 = 80;

/// Known ransomware file extensions.
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    // Major ransomware families
    "lockbit", "lockbit3", "encrypted", "enc", "locked",
    "crypt", "crypto", "crypted", "cryptolocker",
    "ryuk", "conti", "hive", "blackcat", "alphv",
    "blackbasta", "royal", "akira", "play",
    "medusa", "clop", "cl0p", "revil", "sodinokibi",
    "maze", "egregor", "darkside", "blackmatter",
    "phobos", "dharma", "stop", "djvu",
    "wannacry", "wncry", "wcry", "wncryt",
    "locky", "zepto", "odin", "osiris",
    "cerber", "cerber3", "cerber2",
    "gandcrab", "krab",
    "petya", "notpetya", "hermes",
    "ransom", "pay", "decrypt", "recover",
    // Generic suspicious
    "aes256", "rsa2048", "rsa4096",
];

/// Ransom note filename patterns (case-insensitive).
const RANSOM_NOTE_PATTERNS: &[&str] = &[
    "readme", "read_me", "read-me",
    "decrypt", "decryption", "how_to_decrypt",
    "how_to_recover", "recovery", "restore",
    "ransom", "warning", "attention",
    "unlock", "help_decrypt", "help_recover",
    "your_files", "files_encrypted",
    "important", "!!!",
];

/// Result of a ransomware scan cycle.
#[derive(Debug)]
pub struct RansomwareScanResult {
    pub logs_checked: usize,
    pub suspects_found: usize,
    pub findings_created: usize,
}

/// Scan recent file operation logs for ransomware indicators.
pub async fn scan_ransomware(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> RansomwareScanResult {
    let mut result = RansomwareScanResult {
        logs_checked: 0, suspects_found: 0, findings_created: 0,
    };

    // Collect file operation events from all sources
    let mut all_ops: Vec<FileOp> = Vec::new();

    // Source 1: Zeek smb_files.log
    let smb_logs = store.query_logs(minutes_back, None, Some("zeek.smb_files"), 5000)
        .await.unwrap_or_default();
    result.logs_checked += smb_logs.len();

    for log in &smb_logs {
        let action = log.data["action"].as_str().unwrap_or("");
        let name = log.data["name"].as_str().unwrap_or("");
        let path = log.data["path"].as_str().unwrap_or("");
        let src = log.data["id.orig_h"].as_str().unwrap_or("");
        let dst = log.data["id.resp_h"].as_str().unwrap_or("");
        let size = log.data["size"].as_u64().unwrap_or(0);
        let hostname = log.hostname.as_deref().unwrap_or(src);

        if action.is_empty() && name.is_empty() { continue; }

        all_ops.push(FileOp {
            action: normalize_action(action),
            filename: name.to_string(),
            path: path.to_string(),
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            hostname: hostname.to_string(),
            size,
            source: "zeek.smb",
        });
    }

    // Source 2: Wazuh file integrity events (stored as wazuh.alert in logs)
    let wazuh_logs = store.query_logs(minutes_back, None, Some("wazuh.alert"), 3000)
        .await.unwrap_or_default();
    result.logs_checked += wazuh_logs.len();

    for log in &wazuh_logs {
        // Wazuh FIM (syscheck) events have data.path and data.changed_attributes
        let path = log.data["data"]["path"].as_str()
            .or_else(|| log.data["syscheck"]["path"].as_str())
            .unwrap_or("");
        if path.is_empty() { continue; }

        let event_type = log.data["syscheck"]["event"].as_str().unwrap_or("");
        let hostname = log.data["agent"]["name"].as_str()
            .or(log.hostname.as_deref())
            .unwrap_or("unknown");

        let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);

        all_ops.push(FileOp {
            action: normalize_action(event_type),
            filename: filename.to_string(),
            path: path.to_string(),
            src_ip: String::new(),
            dst_ip: String::new(),
            hostname: hostname.to_string(),
            size: 0,
            source: "wazuh.fim",
        });
    }

    // Source 3: osquery file_events
    let osquery_logs = store.query_logs(minutes_back, None, Some("osquery.file"), 3000)
        .await.unwrap_or_default();
    result.logs_checked += osquery_logs.len();

    for log in &osquery_logs {
        let action = log.data["action"].as_str().unwrap_or("");
        let target_path = log.data["target_path"].as_str().unwrap_or("");
        let hostname = log.hostname.as_deref().unwrap_or("unknown");

        if target_path.is_empty() { continue; }

        let filename = target_path.rsplit(['/', '\\']).next().unwrap_or(target_path);

        all_ops.push(FileOp {
            action: normalize_action(action),
            filename: filename.to_string(),
            path: target_path.to_string(),
            src_ip: String::new(),
            dst_ip: String::new(),
            hostname: hostname.to_string(),
            size: 0,
            source: "osquery.file",
        });
    }

    if all_ops.len() < MIN_OPERATIONS { return result; }

    // Aggregate by hostname (each machine analyzed independently)
    let mut host_ops: HashMap<String, Vec<&FileOp>> = HashMap::new();
    for op in &all_ops {
        host_ops.entry(op.hostname.clone()).or_default().push(op);
    }

    for (hostname, ops) in &host_ops {
        if ops.len() < MIN_OPERATIONS { continue; }

        let mut evidence: Vec<String> = Vec::new();
        let mut score: u32 = 0;

        // 1. Rename/create ratio (mass encryption = many renames)
        let renames = ops.iter().filter(|o| o.action == "rename").count();
        let total = ops.len();
        let rename_ratio = renames as f64 / total as f64;
        if rename_ratio > RENAME_RATIO_THRESHOLD && renames >= 5 {
            evidence.push(format!(
                "Ratio renommage élevé: {:.0}% ({}/{} opérations)",
                rename_ratio * 100.0, renames, total
            ));
            score += RENAME_RATIO_SCORE;
        }

        // 2. Known ransomware extensions
        let ransom_ext_count = ops.iter().filter(|o| has_ransomware_extension(&o.filename)).count();
        if ransom_ext_count > 0 {
            let ext_examples: Vec<String> = ops.iter()
                .filter(|o| has_ransomware_extension(&o.filename))
                .take(3)
                .map(|o| o.filename.clone())
                .collect();
            evidence.push(format!(
                "{} fichiers avec extension ransomware: {}",
                ransom_ext_count, ext_examples.join(", ")
            ));
            score += RANSOM_EXT_SCORE;
            if ransom_ext_count > 10 { score += 20; } // Bonus for mass encryption
        }

        // 3. Ransom note filenames
        let notes: Vec<String> = ops.iter()
            .filter(|o| is_ransom_note(&o.filename))
            .map(|o| o.filename.clone())
            .collect();
        if !notes.is_empty() {
            let unique_notes: std::collections::HashSet<_> = notes.iter().collect();
            evidence.push(format!(
                "Note de rançon détectée: {}",
                unique_notes.iter().take(3).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
            score += RANSOM_NOTE_SCORE;
        }

        // 4. High volume of file operations
        if total >= VOLUME_THRESHOLD {
            evidence.push(format!("{} opérations fichier en {} min (seuil: {})",
                total, minutes_back, VOLUME_THRESHOLD));
            score += VOLUME_SCORE;
        }

        // 5. High entropy in new filenames (encrypted names)
        let entropies: Vec<f64> = ops.iter()
            .filter(|o| o.action == "create" || o.action == "rename")
            .map(|o| {
                let name_part = o.filename.rsplit('.').last().unwrap_or(&o.filename);
                shannon_entropy(name_part)
            })
            .collect();
        if !entropies.is_empty() {
            let avg = entropies.iter().sum::<f64>() / entropies.len() as f64;
            let high_count = entropies.iter().filter(|&&e| e > ENTROPY_THRESHOLD).count();
            if high_count > 3 {
                evidence.push(format!(
                    "{} fichiers avec noms haute entropie (moy: {:.2})",
                    high_count, avg
                ));
                score += ENTROPY_SCORE;
            }
        }

        // Need at least 2 indicators or 1 very strong one
        if evidence.is_empty() || (evidence.len() < 2 && score < SCORE_HIGH) { continue; }

        result.suspects_found += 1;
        let severity = if score >= SCORE_CRITICAL { "CRITICAL" } else { "HIGH" };

        // Identify source IPs (SMB attackers)
        let src_ips: Vec<String> = ops.iter()
            .filter(|o| !o.src_ip.is_empty())
            .map(|o| o.src_ip.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter().collect();

        let title = format!(
            "Ransomware suspect: {} ({} opérations, score {})",
            hostname, total, score
        );

        let evidence_text = evidence.join("\n- ");
        let description = format!(
            "Activité suspecte de ransomware détectée sur {}.\n\n\
             Indicateurs:\n- {}\n\n\
             Sources SMB: {}\n\n\
             Le chiffrement de masse se caractérise par un volume élevé de \
             renommages de fichiers avec des extensions connues de ransomware. \
             Les notes de rançon confirment l'attaque.\n\n\
             ACTION URGENTE: Isoler la machine immédiatement, \
             couper les accès SMB, vérifier les backups.",
            hostname, evidence_text,
            if src_ips.is_empty() { "local".to_string() } else { src_ips.join(", ") },
        );

        let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
            skill_id: "ndr-ransomware".into(),
            title,
            description: Some(description),
            severity: severity.into(),
            category: Some("malware-detection".into()),
            asset: Some(hostname.clone()),
            source: Some("Ransomware heuristic analysis".into()),
            metadata: Some(serde_json::json!({
                "hostname": hostname,
                "total_operations": total,
                "renames": renames,
                "rename_ratio": rename_ratio,
                "ransomware_extensions_found": ransom_ext_count,
                "ransom_notes": notes,
                "score": score,
                "source_ips": src_ips,
                "evidence": evidence,
                "detection": "ransomware-heuristic",
                "mitre": ["T1486", "T1021.002"]
            })),
        }).await;
        result.findings_created += 1;
    }

    if result.suspects_found > 0 {
        tracing::warn!(
            "NDR-RANSOMWARE: {} file ops analyzed, {} hosts with ransomware indicators",
            result.logs_checked, result.suspects_found
        );
    }

    result
}

// ── Helpers ──

struct FileOp<'a> {
    action: String,
    filename: String,
    path: String,
    src_ip: String,
    dst_ip: String,
    hostname: String,
    size: u64,
    source: &'a str,
}

/// Normalize action names across sources.
fn normalize_action(action: &str) -> String {
    let lower = action.to_lowercase();
    if lower.contains("rename") || lower.contains("moved") { return "rename".into(); }
    if lower.contains("creat") || lower.contains("added") || lower.contains("write") { return "create".into(); }
    if lower.contains("delet") || lower.contains("remov") { return "delete".into(); }
    if lower.contains("modif") || lower.contains("chang") || lower.contains("updat") { return "modify".into(); }
    lower
}

/// Check if filename has a known ransomware extension.
fn has_ransomware_extension(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        RANSOMWARE_EXTENSIONS.contains(&ext)
    } else {
        false
    }
}

/// Check if filename looks like a ransom note.
fn is_ransom_note(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    // Strip extension for matching
    let name = lower.rsplit('.').last().unwrap_or(&lower);
    RANSOM_NOTE_PATTERNS.iter().any(|pattern| name.contains(pattern))
}

/// Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() { freq[b as usize] += 1; }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ransomware_extensions() {
        assert!(has_ransomware_extension("document.lockbit"));
        assert!(has_ransomware_extension("photo.encrypted"));
        assert!(has_ransomware_extension("data.ryuk"));
        assert!(has_ransomware_extension("file.WANNACRY"));
        assert!(!has_ransomware_extension("normal.docx"));
        assert!(!has_ransomware_extension("image.jpg"));
    }

    #[test]
    fn test_ransom_note() {
        assert!(is_ransom_note("README.txt"));
        assert!(is_ransom_note("HOW_TO_DECRYPT.html"));
        assert!(is_ransom_note("!!!IMPORTANT!!!.txt"));
        assert!(is_ransom_note("DECRYPT_YOUR_FILES.txt"));
        assert!(!is_ransom_note("report.pdf"));
        assert!(!is_ransom_note("config.yml"));
    }

    #[test]
    fn test_normalize_action() {
        assert_eq!(normalize_action("SMBRename"), "rename");
        assert_eq!(normalize_action("CREATED"), "create");
        assert_eq!(normalize_action("deleted"), "delete");
        assert_eq!(normalize_action("modified"), "modify");
        assert_eq!(normalize_action("WriteTo"), "create");
    }
}

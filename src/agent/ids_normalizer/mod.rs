//! IDS alert normalization layer (Phase 8b).
//!
//! Different IDS/IPS vendors emit alerts with wildly different schemas
//! (Suricata `eve.json`, Fortinet `attack`/`attackid`, Stormshield SNS
//! `class`, pfSense+Snort `classification`...). The sigma engine matches
//! all of them under generic rules like `opnsense-004 OPNsense IDS alert`,
//! `fortinet-ips-001`, etc. To decide if a given alert is a *benign update*
//! (Windows Update, Defender signature download, browser auto-update) we
//! need to inspect vendor-specific fields — but the *rule* (informational
//! severity + benign category + update flowbit → drop) is identical
//! across vendors.
//!
//! The trait abstracts the parsing-step away from the decision-step:
//!   1. Each vendor implements [`IdsAlertNormalizer`] to extract a common
//!      [`NormalizedAlert`] from its raw `matched_fields`.
//!   2. [`is_benign`] takes a `NormalizedAlert` and applies the same
//!      conservative drop rules to all vendors.
//!
//! Adding Fortinet / Stormshield / pfSense / Cisco Firepower etc. is one
//! file per vendor and one entry in [`registry`].
//!
//! See `roadmap-mai.md` Phase 8b. Originally motivated by SRV-01-DOM
//! Windows Update outbound generating spurious incident #1581 on cyb06.

use serde::{Deserialize, Serialize};

pub mod suricata;

/// Canonical severity ladder used across vendors. Internal mapping is
/// done by each [`IdsAlertNormalizer`] from its native scale (Suricata
/// 1-3, Fortinet "informational"…"critical", etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Direction of the flow as seen by the IDS at the perimeter. Most
/// vendors expose at least src/dst IPs; the normalizer decides which
/// side is internal vs external (RFC1918 heuristic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// External → internal (potential attack against an asset)
    Inbound,
    /// Internal → external (asset reaching out — update, exfil, C2…)
    Outbound,
    /// Both endpoints private (lateral movement candidate)
    Internal,
    /// Both endpoints public (perimeter scan, IDS observing transit)
    External,
    /// IPs missing or unparseable — fail open (don't drop just because we
    /// couldn't classify direction).
    Unknown,
}

/// Normalized view of an IDS alert. Vendor-specific quirks live in the
/// normalizer; everything downstream (FP filter, narrative builder)
/// works against this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedAlert {
    pub vendor: String,
    pub severity: SeverityLevel,
    /// Canonicalized category string (e.g. "Misc activity",
    /// "Trojan Activity"). Comparison is done case-insensitive.
    pub category: String,
    pub signature: String,
    /// Lowercase flowbits / tags. Suricata calls these flowbits;
    /// Fortinet has `app`+`appcat`; Stormshield has `srcname`/`dstname`.
    /// All collapsed into the same Vec for uniform allowlist matching.
    pub flowbits: Vec<String>,
    pub direction: Direction,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
}

/// Raw matched fields from the sigma matcher. Each vendor sees a
/// different shape; the most common is `("line", "<raw eve.json>")` for
/// Suricata, `("payload", "<csv kvp>")` for Fortinet, etc.
pub type RawFields<'a> = &'a [(String, String)];

/// Vendor adapter. Each impl is responsible for:
///   - knowing which sigma `rule_id` it is the canonical normalizer for
///   - parsing the raw matched fields into a [`NormalizedAlert`]
///
/// Returning `None` from `normalize` means "I don't recognize this
/// payload". The pipeline will then not apply Phase 8 filtering — the
/// alert flows through normally.
pub trait IdsAlertNormalizer: Send + Sync {
    fn vendor_id(&self) -> &'static str;
    /// True if this normalizer is responsible for a given sigma rule_id.
    /// Allows multiple normalizers to coexist for the same vendor (e.g.
    /// `fortinet-ips-001` vs `fortinet-app-001`).
    fn matches_rule(&self, rule_id: &str) -> bool;
    fn normalize(&self, raw: RawFields<'_>) -> Option<NormalizedAlert>;
}

/// Static registry of all available normalizers. Order matters only when
/// a single rule_id could be claimed by multiple vendors — first match
/// wins, so put the more specific impls earlier.
pub fn registry() -> Vec<Box<dyn IdsAlertNormalizer>> {
    vec![Box::new(suricata::SuricataNormalizer::default())]
}

/// Try to normalize an alert via the first registered normalizer that
/// recognizes the rule_id. Returns `None` when no vendor adapter claims
/// the rule (e.g. tc-ssh-brute, opnsense-001 auth failed) — those rules
/// are not IDS alerts and should not be filtered as such.
pub fn try_normalize(rule_id: &str, raw: RawFields<'_>) -> Option<NormalizedAlert> {
    for normalizer in registry() {
        if normalizer.matches_rule(rule_id) {
            if let Some(n) = normalizer.normalize(raw) {
                return Some(n);
            }
        }
    }
    None
}

// ── Phase 8 — drop rules ────────────────────────────────────────────

/// Categories that historically map to *informational* / *policy*
/// observations across vendors. Comparison is case-insensitive.
const BENIGN_CATEGORIES: &[&str] = &[
    "Misc activity",
    "Generic Protocol Command Decode",
    "Not Suspicious Traffic",
    "Potential Corporate Privacy Violation",
    // Fortinet "appctrl" / Stormshield equivalents are added when those
    // normalizers land — keep one strict source of truth here.
];

/// Flowbit / tag patterns that mark legitimate auto-updaters. Matched
/// case-insensitively as substring (a flowbit `ET.INFO.WindowsUpdate`
/// matches the pattern `et.info.windowsupdate`).
const BENIGN_FLOWBITS: &[&str] = &[
    "et.info.windowsupdate",
    "et.policy.googleupdate",
    "et.policy.adobeupdate",
    "et.info.javaupdate",
    "policy.windowsupdate",
];

/// Signature prefixes (case-insensitive) that strongly correlate with
/// non-attack traffic. Conservative — does NOT touch ET TROJAN, ET
/// MALWARE, ET CURRENT_EVENTS, ET EXPLOIT prefixes.
const BENIGN_SIG_PREFIXES: &[&str] = &[
    "et info windowsupdate",
    "et info packed executable download",
    "et policy ",
    "et info microsoft",
    "et info adobe",
    "et info google",
    "et info mozilla",
    "et info dropbox",
    "et info windows defender",
    "et info windows update",
    "et chat ",
];

/// Decide whether a normalized alert should be dropped before it
/// becomes a sigma_alert (and therefore an incident). Conservative —
/// always defaults to NOT dropping when the signal is ambiguous, so
/// real attacks never get masked.
pub fn is_benign(alert: &NormalizedAlert) -> bool {
    // (1) low/info severity + a known benign category
    if matches!(alert.severity, SeverityLevel::Info | SeverityLevel::Low)
        && BENIGN_CATEGORIES
            .iter()
            .any(|c| alert.category.eq_ignore_ascii_case(c))
    {
        return true;
    }

    // (2) explicit benign flowbit / tag
    let fb_lower = alert
        .flowbits
        .iter()
        .map(|s| s.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    if !fb_lower.is_empty() && BENIGN_FLOWBITS.iter().any(|fb| fb_lower.contains(fb)) {
        return true;
    }

    // (3) signature prefix denoting policy / update traffic
    let sig_lower = alert.signature.to_lowercase();
    if !sig_lower.is_empty() && BENIGN_SIG_PREFIXES.iter().any(|p| sig_lower.starts_with(p)) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn na(
        severity: SeverityLevel,
        category: &str,
        sig: &str,
        flowbits: &[&str],
    ) -> NormalizedAlert {
        NormalizedAlert {
            vendor: "test".into(),
            severity,
            category: category.into(),
            signature: sig.into(),
            flowbits: flowbits.iter().map(|s| s.to_string()).collect(),
            direction: Direction::Unknown,
            source_ip: None,
            dest_ip: None,
        }
    }

    #[test]
    fn high_severity_trojan_kept() {
        let a = na(
            SeverityLevel::High,
            "A Network Trojan was Detected",
            "ET TROJAN Win32/Emotet CnC",
            &[],
        );
        assert!(!is_benign(&a));
    }

    #[test]
    fn info_misc_activity_dropped() {
        let a = na(
            SeverityLevel::Info,
            "Misc activity",
            "ET INFO Packed Executable Download",
            &[],
        );
        assert!(is_benign(&a));
    }

    #[test]
    fn windows_update_flowbit_dropped() {
        let a = na(
            SeverityLevel::Medium,
            "Whatever",
            "Generic",
            &["ET.INFO.WindowsUpdate"],
        );
        assert!(is_benign(&a));
    }

    #[test]
    fn high_severity_with_benign_category_kept() {
        // Defensive: even if category looks benign, high severity wins.
        let a = na(SeverityLevel::High, "Misc activity", "ET TROJAN", &[]);
        assert!(!is_benign(&a));
    }

    #[test]
    fn et_policy_signature_prefix_dropped() {
        let a = na(
            SeverityLevel::Medium,
            "Other",
            "ET POLICY GoogleUpdate poll",
            &[],
        );
        assert!(is_benign(&a));
    }

    #[test]
    fn unknown_alert_kept() {
        let a = na(SeverityLevel::Medium, "Unknown", "Custom rule", &[]);
        assert!(!is_benign(&a));
    }
}

//! Self-event provenance registry — the single source of truth for "is this one
//! of ThreatClaw's own published artifacts?", consulted by every detector that
//! could otherwise flag us attacking ourselves.
//!
//! The first artifact is the agent installer (`installer/install-agent.ps1`): it
//! legitimately downloads the agent and embeds an lsass-monitoring Sysmon config,
//! so generic detectors (`is_suspicious_powershell`, Sigma reflective-loader
//! rules) match it. Without an exemption, ThreatClaw raises an incident against
//! its own rollout on every monitored host.
//!
//! ## Provenance, not content heuristic
//! Recognition is by the **exact SHA-256** of the artifact, never a substring.
//! It is non-forgeable (reproducing the hash means reproducing our exact bytes,
//! which are benign) and non-guessable (a hash cannot be guessed). The default is
//! always "not ours" — a single differing byte falls through to normal detection,
//! so a real attack is never masked.
//!
//! ## Why per-channel
//! Different ingestion channels carry the *same* artifact as *different* bytes:
//! osquery Script Block Logging re-encodes the 4104 under the host ANSI codepage
//! and splits it into parts; syslog wraps and truncates it. There is no single
//! channel-invariant hash, so each [`Channel`] keeps its own hash set.
//!
//! ## Captured, and guarded against drift
//! The hashes are CAPTURED, not derived — PowerShell re-encodes the script, so
//! they cannot be reproduced from the UTF-8 source (verified: reassembled 4104 =
//! 30876 bytes vs 27204 in the file). `scripts/check-consistency.sh` pins
//! `installer/install-agent.ps1` to its capture and fails the build whenever the
//! installer changes, signalling a re-capture (procedure on the const below).

use sha2::{Digest, Sha256};

/// Ingestion channel a piece of content arrived through. Each channel has its own
/// byte representation of the same artifact, hence its own hash set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// osquery `powershell_events` — Windows Script Block Logging (event 4104).
    OsqueryPowershell,
    // `Syslog` is intentionally absent. On a standard deployment PowerShell reaches
    // ThreatClaw only via the osquery agent; a host that ALSO forwards PowerShell
    // Operational over syslog is double-ingesting the same event, and the clean fix
    // is to stop that redundant forward — not to hash a truncated, locale-encoded
    // syslog line. Add a `Syslog` arm only for genuinely syslog-only Windows estates.
}

/// SHA-256 of the installer's **fully reassembled** Script Block Logging text in
/// the osquery channel — i.e. all 4104 parts of a block concatenated in
/// MessageNumber order.
///
/// Why the whole, not the parts: PowerShell splits a large script across several
/// 4104 events and the split boundary **varies between runs** (we observed part 1
/// at 12756 / 22434 / 22464 bytes on three installs of the *same* script). Per-part
/// hashes are therefore not stable; the reassembled whole is (all three reassembled
/// to the identical 32187-byte text). The caller must reassemble before calling
/// [`is_self_generated`].
///
/// RE-CAPTURE when `install-agent.ps1` changes (check-consistency.sh enforces it):
/// run the new installer on a host with Script Block Logging on, then in the DB
/// reassemble per block and hash the whole:
///   WITH p AS (SELECT DISTINCT data->'data'->>'ScriptBlockId' sbid,
///       (data->'data'->>'MessageNumber')::int n, data->'data'->>'ScriptBlockText' t
///     FROM logs WHERE tag='osquery.powershell' AND data->>'eventid'='4104'
///       AND data->'data'->>'ScriptBlockId' IN (SELECT DISTINCT data->'data'->>'ScriptBlockId'
///         FROM logs WHERE tag='osquery.powershell' AND data->>'eventid'='4104'
///         AND data->'data'->>'ScriptBlockText' LIKE '%ThreatClaw Agent Installer%'))
///   SELECT encode(digest(string_agg(t,'' ORDER BY n),'sha256'),'hex')
///   FROM p GROUP BY sbid LIMIT 1;
/// Replace the value below, and update EXPECTED_INSTALLER_SHA in check-consistency.sh.
///
/// Captured 2026-06-22 on cyb06 (stable across 3 installs), for install-agent.ps1
/// at file sha bc80f50b… (the Expand-ZipCompat build).
const INSTALLER_OSQUERY_PS_SHA256: &[&str] =
    &["6b41888aa3c8873c675c52d15bf5e309fc0bb90d3ec7d6e4e63e3e8d17377d5f"];

fn installer_hashes(channel: Channel) -> &'static [&'static str] {
    match channel {
        Channel::OsqueryPowershell => INSTALLER_OSQUERY_PS_SHA256,
    }
}

/// `true` iff `content`'s SHA-256 is registered for `channel` — i.e. it is one of
/// our own published artifacts in that channel's exact byte representation.
/// Conservative: empty or any non-match returns `false`.
fn matches_registered(content: &str, hashes: &[&str]) -> bool {
    if content.is_empty() {
        return false;
    }
    let sha = hex::encode(Sha256::digest(content.as_bytes()));
    hashes.contains(&sha.as_str())
}

/// `true` iff `content` is one of ThreatClaw's own published artifacts (today: the
/// agent installer) in the exact byte representation of `channel`. Provenance by
/// exact hash — non-forgeable, non-guessable, conservative.
pub fn is_self_generated(content: &str, channel: Channel) -> bool {
    matches_registered(content, installer_hashes(channel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_never_self() {
        assert!(!is_self_generated("", Channel::OsqueryPowershell));
        assert!(!matches_registered("", &["whatever"]));
    }

    #[test]
    fn non_matching_content_is_not_self() {
        assert!(!is_self_generated(
            "Invoke-Mimikatz -DumpCreds",
            Channel::OsqueryPowershell
        ));
    }

    #[test]
    fn exact_byte_match_is_recognized() {
        // Proves the hash+compare mechanism independently of the captured
        // installer bytes: a string matches iff its own SHA-256 is registered.
        let content = "exact published bytes";
        let h = hex::encode(Sha256::digest(content.as_bytes()));
        assert!(matches_registered(content, &[h.as_str()]));
        // One byte different → no match.
        assert!(!matches_registered("exact published byteS", &[h.as_str()]));
    }
}

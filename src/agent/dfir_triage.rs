//! Native DFIR triage (Phase 1) — turn already-ingested endpoint telemetry into a
//! forensic **timeline** labelled with MITRE ATT&CK, and surface a few
//! high-precision **standalone findings** worth raising on their own.
//!
//! The core here is **pure** (no clock, no I/O) so it is fully unit-tested: it
//! maps a list of [`RawObservation`] (extracted at the edge from osquery/sysmon
//! logs) into [`NewTimelineEvent`]s and [`StandaloneFinding`]s. The collector
//! (reading logs) and the IE-cycle wiring live at the edges and are added in the
//! next Phase-1 increment.
//!
//! Design principles (RFC 3227 / NIST 800-86 / MITRE): order chronologically in
//! **UTC**, label on the **trigger** (not the artifact path), and keep the
//! standalone-finding set to **low-false-positive** signals only.
//!
//! See internal/PLAN_NATIVE_DFIR.md / PLAN_NATIVE_DFIR_BUILD.md.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::db::Database;
use crate::db::threatclaw_store::{NewRiskEvent, NewTimelineEvent, TimelineEvent};

/// Poll cadence of the background DFIR collector.
const DFIR_POLL_INTERVAL: Duration = Duration::from_secs(180);
/// Lookback window for assembling an incident's timeline (24h).
const DFIR_WINDOW_MIN: i64 = 1440;

/// Category of a raw forensic observation pulled from ingested telemetry.
/// Each kind maps to a typed edge in the attack graph — high-signal events make
/// an edge; edgeless self-references (e.g. signed DLL loads) are not collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObsKind {
    ProcessCreate,
    NetworkConnect,
    /// Per-process DNS query (Sysmon 22) → `RESOLVED` edge.
    DnsQuery,
    /// Cross-process injection (Sysmon 8 CreateRemoteThread) → `INJECTED_INTO`.
    Injection,
    /// Handle opened to LSASS (Sysmon 10, scoped) → `ACCESSED_LSASS` (T1003).
    CredentialAccess,
    /// Run key, service, scheduled task, cron, systemd unit, authorized_keys, …
    Persistence,
    Logon,
    FileEvent,
    /// New user, group add, UID-0 creation, sudoers change.
    AccountChange,
    /// Added to a privileged group (4732/4756), SUID, sudoers NOPASSWD.
    PrivilegeEscalation,
    /// Log clear, history wipe, AV/EDR disable, timestomp.
    DefenseEvasion,
}

/// A minimal, source-agnostic observation. The pure timeline/labelling logic
/// works on this so it never touches a DB or a clock. The `*_guid` / `related_to`
/// keys carry the **causal** structure (process tree + typed edges) so the
/// attack graph is a provenance graph, not a flat list.
#[derive(Debug, Clone)]
pub struct RawObservation {
    pub ts: DateTime<Utc>,
    pub kind: ObsKind,
    pub asset: String,
    /// User / parent process / source IP (display).
    pub actor: Option<String>,
    /// Cmdline / "Run\\X = Y" / "authorized_keys += <key>" / …
    pub detail: String,
    /// Hash / IP / domain / path, when present.
    pub ioc: Option<String>,
    /// "osquery.sysmon", "osquery.windows_security", "osquery.process", …
    pub source: String,
    /// Stable identity of the process this event belongs to (Sysmon ProcessGuid).
    pub proc_guid: Option<String>,
    /// Parent process GUID — the `SPAWNED` edge (process-tree spine).
    pub parent_guid: Option<String>,
    /// Target of a non-spawn edge: injected process / lsass / dest IP / domain /
    /// file path, depending on `kind`.
    pub related_to: Option<String>,
}

impl RawObservation {
    /// Base observation with all causal/optional fields empty — keeps the mappers
    /// terse (set only the fields a given source provides).
    pub(crate) fn base(ts: DateTime<Utc>, kind: ObsKind, asset: &str, source: &str) -> Self {
        RawObservation {
            ts,
            kind,
            asset: asset.into(),
            actor: None,
            detail: String::new(),
            ioc: None,
            source: source.into(),
            proc_guid: None,
            parent_guid: None,
            related_to: None,
        }
    }
}

/// A high-precision finding worth raising as its own incident (low FP rate).
#[derive(Debug, Clone, PartialEq)]
pub struct StandaloneFinding {
    pub title: String,
    pub severity: &'static str,
    pub mitre_technique: &'static str,
    pub detail: String,
}

/// Stable `event_type` string for the timeline row.
pub fn event_type_str(kind: &ObsKind) -> &'static str {
    match kind {
        ObsKind::ProcessCreate => "process_spawn",
        ObsKind::NetworkConnect => "net_connect",
        ObsKind::DnsQuery => "dns_query",
        ObsKind::Injection => "injection",
        ObsKind::CredentialAccess => "credential_access",
        ObsKind::Persistence => "persistence_install",
        ObsKind::Logon => "logon",
        ObsKind::FileEvent => "file_event",
        ObsKind::AccountChange => "account_change",
        ObsKind::PrivilegeEscalation => "privilege_escalation",
        ObsKind::DefenseEvasion => "defense_evasion",
    }
}

/// Default severity by category. The "active intrusion" signals (injection,
/// credential theft, persistence, evasion, privesc, account change) are high;
/// process/network/logon are contextual timeline (medium); DNS/file are info.
pub fn severity_for(kind: &ObsKind) -> &'static str {
    match kind {
        ObsKind::Injection
        | ObsKind::CredentialAccess
        | ObsKind::Persistence
        | ObsKind::DefenseEvasion
        | ObsKind::PrivilegeEscalation
        | ObsKind::AccountChange => "high",
        ObsKind::ProcessCreate | ObsKind::NetworkConnect | ObsKind::Logon => "medium",
        ObsKind::DnsQuery | ObsKind::FileEvent => "info",
    }
}

/// Pure: map an observation to `(tactic, technique)` by **trigger** (keyword on
/// the detail), not by source. Conservative — a coarse default per category when
/// no specific trigger matches.
pub fn label_mitre(obs: &RawObservation) -> (Option<String>, Option<String>) {
    let d = obs.detail.to_lowercase();
    let (tactic, technique): (&str, &str) = match obs.kind {
        ObsKind::ProcessCreate => {
            if d.contains("-enc") || d.contains("encodedcommand") {
                ("execution", "T1059.001")
            } else {
                ("execution", "T1059")
            }
        }
        ObsKind::Persistence => {
            if d.contains("authorized_keys") {
                ("persistence", "T1098.004")
            } else if d.contains("ld.so.preload") {
                ("persistence", "T1574.006")
            } else if d.contains("psexesvc") || d.contains("7045") || d.contains("service") {
                ("persistence", "T1543.003")
            } else if d.contains("schtask") || d.contains("scheduled task") {
                ("persistence", "T1053.005")
            } else if d.contains("cron") {
                ("persistence", "T1053.003")
            } else if d.contains("systemd") {
                ("persistence", "T1543.002")
            } else if d.contains("\\run") || d.contains("runonce") {
                ("persistence", "T1547.001")
            } else {
                ("persistence", "T1547")
            }
        }
        ObsKind::NetworkConnect => ("command-and-control", "T1071"),
        ObsKind::DnsQuery => ("command-and-control", "T1071.004"),
        ObsKind::Injection => ("defense-evasion", "T1055"),
        ObsKind::CredentialAccess => ("credential-access", "T1003.001"),
        ObsKind::Logon => ("lateral-movement", "T1021"),
        ObsKind::AccountChange => {
            if d.contains("sudoers") || d.contains("nopasswd") {
                ("privilege-escalation", "T1548.003")
            } else {
                ("persistence", "T1136")
            }
        }
        ObsKind::PrivilegeEscalation => {
            if d.contains("group") || d.contains("4732") || d.contains("4756") {
                ("privilege-escalation", "T1098")
            } else {
                ("privilege-escalation", "T1548")
            }
        }
        ObsKind::DefenseEvasion => {
            if d.contains("1102") || d.contains("104") || d.contains("clear") {
                ("defense-evasion", "T1070.001")
            } else {
                ("defense-evasion", "T1070")
            }
        }
        ObsKind::FileEvent => ("collection", "T1005"),
    };
    (Some(tactic.to_string()), Some(technique.to_string()))
}

/// Pure: convert one observation into a persistable timeline event.
pub fn to_timeline_event(obs: &RawObservation) -> NewTimelineEvent {
    let (mitre_tactic, mitre_technique) = label_mitre(obs);
    NewTimelineEvent {
        ts: obs.ts.to_rfc3339(),
        tz_origin: Some("UTC".into()),
        event_type: event_type_str(&obs.kind).into(),
        asset: obs.asset.clone(),
        actor: obs.actor.clone(),
        description: obs.detail.clone(),
        severity: severity_for(&obs.kind).into(),
        mitre_tactic,
        mitre_technique,
        ioc: obs.ioc.clone(),
        related_artifacts: Vec::new(),
        source_artifact: Some(obs.source.clone()),
        collected_hash: None,
        proc_guid: obs.proc_guid.clone(),
        parent_guid: obs.parent_guid.clone(),
        related_to: obs.related_to.clone(),
    }
}

/// Pure: order observations chronologically (UTC) and map them to timeline
/// events. Stable sort → equal timestamps keep input order.
pub fn assemble_timeline(mut obs: Vec<RawObservation>) -> Vec<NewTimelineEvent> {
    obs.sort_by(|a, b| a.ts.cmp(&b.ts));
    obs.iter().map(to_timeline_event).collect()
}

/// Pure (2b-bis): assess the kill-chain breadth of an incident's timeline and,
/// if the DFIR evidence reveals a more serious multi-stage intrusion than the
/// base alert implied, recommend a severity to **escalate** to. Returns
/// `(SEVERITY, reason)` or None. DFIR only ever escalates UP — it corroborates,
/// it never downgrades (that stays the L2 verdict's job for false positives).
pub fn assess_killchain(events: &[NewTimelineEvent]) -> Option<(&'static str, String)> {
    use std::collections::BTreeSet;
    let mut stages: BTreeSet<&'static str> = BTreeSet::new();
    for ev in events {
        let stage = match ev.event_type.as_str() {
            "process_spawn" => "exécution",
            "persistence_install" => "persistance",
            "net_connect" => "C2",
            "injection" => "injection",
            "credential_access" => "vol de creds",
            "privilege_escalation" => "escalade priv",
            "logon" => "accès/latéral",
            "defense_evasion" => "évasion",
            "account_change" => "manipulation de compte",
            // dns_query / file_event = contexte timeline, pas un déclencheur.
            _ => continue,
        };
        stages.insert(stage);
    }
    if stages.is_empty() {
        return None;
    }
    let has = |s: &str| stages.contains(s);
    // "Strong" stages signal an active intrusion on their own (a logon + a process
    // spawn is not enough). Injection / credential theft / persistence / evasion /
    // privesc are all individually strong.
    let strong = has("persistance")
        || has("C2")
        || has("évasion")
        || has("injection")
        || has("vol de creds")
        || has("escalade priv");
    let n = stages.len();
    let reason = format!(
        "Chaîne d'attaque DFIR multi-étapes confirmée : {}",
        stages.iter().copied().collect::<Vec<_>>().join(" + ")
    );
    if (has("persistance") && has("C2")) || n >= 3 {
        Some(("CRITICAL", reason))
    } else if n >= 2 && strong {
        Some(("HIGH", reason))
    } else {
        None
    }
}

/// Pure: extract high-precision standalone findings (the create-an-incident-on-
/// its-own set). Deliberately narrow to keep the false-positive rate near zero.
pub fn detect_standalone_findings(obs: &[RawObservation]) -> Vec<StandaloneFinding> {
    let mut out = Vec::new();
    for o in obs {
        let d = o.detail.to_lowercase();
        let f = match o.kind {
            ObsKind::Persistence if d.contains("authorized_keys") => Some((
                "Clé SSH ajoutée à authorized_keys (backdoor probable)",
                "high",
                "T1098.004",
            )),
            ObsKind::Persistence if d.contains("ld.so.preload") => Some((
                "ld.so.preload modifié (rootkit userland probable)",
                "high",
                "T1574.006",
            )),
            ObsKind::Persistence if d.contains("psexesvc") && d.contains("7045") => Some((
                "Service PSEXESVC installé (mouvement latéral PsExec)",
                "high",
                "T1021.002",
            )),
            ObsKind::AccountChange if d.contains("nopasswd") || d.contains("sudoers") => Some((
                "Entrée sudoers NOPASSWD ajoutée (escalade de privilèges)",
                "high",
                "T1548.003",
            )),
            ObsKind::AccountChange if d.contains("uid=0") || d.contains("uid 0") => Some((
                "Nouveau compte UID 0 créé (backdoor root)",
                "high",
                "T1136.001",
            )),
            ObsKind::ProcessCreate if d.contains("/dev/shm") => Some((
                "Exécution depuis /dev/shm (malware résidant en mémoire)",
                "high",
                "T1059",
            )),
            ObsKind::DefenseEvasion
                if d.contains("1102") || d.contains("104") || d.contains("clear") =>
            {
                Some((
                    "Journal d'événements effacé (anti-forensique)",
                    "high",
                    "T1070.001",
                ))
            }
            _ => None,
        };
        if let Some((title, severity, mitre_technique)) = f {
            out.push(StandaloneFinding {
                title: title.into(),
                severity,
                mitre_technique,
                detail: o.detail.clone(),
            });
        }
    }
    out
}

// ── Edge: collect observations from already-ingested telemetry ──────────────

/// Non-empty string field on a JSON object.
fn jstr<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
}

/// Parse an integer that osquery may emit as a JSON number OR a string
/// (uid, port, … — osquery serialises most columns as strings).
fn jint(v: Option<&Value>) -> Option<i64> {
    let v = v?;
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Parse a log timestamp into UTC. Handles the formats `query_logs` actually
/// yields: PostgreSQL `timestamptz::text` ("2026-06-22 19:20:00[.ffffff]+00",
/// space separator, short "+00" offset) as well as RFC 3339. A naive form
/// (assumed UTC) is the last resort. Getting this right is what keeps the
/// timeline chronological — a parse miss falls back to "now" and flattens it.
fn parse_log_ts(s: &str) -> Option<DateTime<Utc>> {
    // RFC 3339 ("...T...+00:00").
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    // PostgreSQL timestamptz::text — space separator, "%#z" accepts "+00".
    if let Ok(d) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%#z") {
        return Some(d.with_timezone(&Utc));
    }
    // Naive (no offset) — assume UTC.
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
        .map(|n| n.and_utc())
        .ok()
}

/// Pure: map a Sysmon event to an observation, carrying the causal keys
/// (ProcessGuid spine). Covers the must-have attack-map set: 1 ProcessCreate,
/// 3 NetworkConnect, 8 CreateRemoteThread (injection), 10 ProcessAccess (scoped
/// to LSASS = credential theft), 11 FileCreate, 22 DnsQuery. EID 7 (ImageLoad)
/// is intentionally NOT mapped — it's a volume bomb with no useful edge.
pub fn obs_from_sysmon(
    eventid: &str,
    inner: &Value,
    asset: &str,
    ts: DateTime<Utc>,
) -> Option<RawObservation> {
    let mut o = RawObservation::base(ts, ObsKind::ProcessCreate, asset, "osquery.sysmon");
    match eventid {
        "1" => {
            let cmd = jstr(inner, "CommandLine").or_else(|| jstr(inner, "Image"))?;
            o.kind = ObsKind::ProcessCreate;
            o.actor = jstr(inner, "ParentImage").map(String::from);
            o.detail = cmd.into();
            o.ioc = jstr(inner, "Hashes").map(String::from);
            o.proc_guid = jstr(inner, "ProcessGuid").map(String::from);
            o.parent_guid = jstr(inner, "ParentProcessGuid").map(String::from);
        }
        "3" => {
            let dip = jstr(inner, "DestinationIp")?;
            let dport = jstr(inner, "DestinationPort").unwrap_or("");
            o.kind = ObsKind::NetworkConnect;
            o.actor = jstr(inner, "Image").map(String::from);
            o.detail = format!("{dip}:{dport}");
            o.ioc = Some(dip.into());
            o.proc_guid = jstr(inner, "ProcessGuid").map(String::from);
            o.related_to = Some(dip.into());
        }
        "8" => {
            // CreateRemoteThread → cross-process injection (rare, high-signal).
            let src = jstr(inner, "SourceImage").unwrap_or("?");
            let tgt = jstr(inner, "TargetImage").unwrap_or("?");
            o.kind = ObsKind::Injection;
            o.actor = Some(src.into());
            o.detail = format!("Injection {src} → {tgt}");
            o.proc_guid = jstr(inner, "SourceProcessGuid").map(String::from);
            o.related_to = jstr(inner, "TargetProcessGuid")
                .or(Some(tgt))
                .map(String::from);
        }
        "10" => {
            // ProcessAccess: only LSASS handle opens are high-signal (cred theft).
            let tgt = jstr(inner, "TargetImage").unwrap_or("");
            if !tgt.to_ascii_lowercase().contains("lsass") {
                return None;
            }
            let src = jstr(inner, "SourceImage").unwrap_or("?");
            let access = jstr(inner, "GrantedAccess").unwrap_or("");
            o.kind = ObsKind::CredentialAccess;
            o.actor = Some(src.into());
            o.detail = format!("Accès LSASS par {src} (GrantedAccess {access})");
            o.proc_guid = jstr(inner, "SourceProcessGuid").map(String::from);
            o.related_to = Some("lsass.exe".into());
        }
        "11" => {
            let f = jstr(inner, "TargetFilename")?;
            o.kind = ObsKind::FileEvent;
            o.actor = jstr(inner, "Image").map(String::from);
            o.detail = format!("Fichier créé : {f}");
            o.ioc = Some(f.into());
            o.proc_guid = jstr(inner, "ProcessGuid").map(String::from);
            o.related_to = Some(f.into());
        }
        "22" => {
            let q = jstr(inner, "QueryName")?;
            o.kind = ObsKind::DnsQuery;
            o.actor = jstr(inner, "Image").map(String::from);
            o.detail = format!("DNS : {q}");
            o.ioc = Some(q.into());
            o.proc_guid = jstr(inner, "ProcessGuid").map(String::from);
            o.related_to = Some(q.into());
        }
        _ => return None,
    }
    Some(o)
}

/// Pure: map a PowerShell/Operational event. EID 4104 (ScriptBlock logging)
/// carries the **deobfuscated** script text — the highest-value PowerShell
/// artifact. Only the first part of a multi-part script is kept (dedup by
/// `MessageNumber`) so one script = one timeline entry.
pub fn obs_from_powershell(
    eventid: &str,
    inner: &Value,
    asset: &str,
    ts: DateTime<Utc>,
) -> Option<RawObservation> {
    if eventid != "4104" {
        return None;
    }
    // Skip continuation parts of a chunked script block.
    if let Some(n) = jstr(inner, "MessageNumber")
        && n != "1"
    {
        return None;
    }
    let script = jstr(inner, "ScriptBlockText")?;
    let mut o = RawObservation::base(ts, ObsKind::ProcessCreate, asset, "osquery.powershell");
    o.actor = jstr(inner, "Path").map(String::from);
    o.detail = format!("PowerShell ScriptBlock: {script}");
    Some(o)
}

/// Pure: map a Security event to an observation. Covers the attack-map set:
/// logon (4624 success / 4625 failure — kept only for **lateral** types 3/9/10
/// and failures; interactive/service/machine logons are dropped as noise),
/// account changes (4720/4726), privileged group adds (4732/4756), and audit-log
/// clearing (1102, the near-zero-FP defense-evasion signal).
pub fn obs_from_winsec(
    eventid: &str,
    inner: &Value,
    asset: &str,
    ts: DateTime<Utc>,
) -> Option<RawObservation> {
    let user = || jstr(inner, "TargetUserName").or_else(|| jstr(inner, "SubjectUserName"));
    match eventid {
        "4624" | "4625" => {
            let u = user()?;
            let ulow = u.to_ascii_lowercase();
            if u.ends_with('$') || ulow == "system" || ulow == "anonymous logon" {
                return None;
            }
            let logon_type = jstr(inner, "LogonType").unwrap_or("?");
            // Keep only lateral-relevant logons (3 network, 9 runas/netonly,
            // 10 RDP) and all failures; drop interactive/service baseline noise.
            if eventid == "4624" && !matches!(logon_type, "3" | "9" | "10") {
                return None;
            }
            let src_ip = jstr(inner, "IpAddress").filter(|s| *s != "-");
            let outcome = if eventid == "4625" {
                "échec"
            } else {
                "succès"
            };
            let from = src_ip.map(|ip| format!(" depuis {ip}")).unwrap_or_default();
            let mut o = RawObservation::base(ts, ObsKind::Logon, asset, "osquery.windows_security");
            o.actor = Some(u.to_string());
            o.detail = format!("Logon {outcome} type {logon_type} — {u}{from}");
            o.ioc = src_ip.map(String::from);
            Some(o)
        }
        "4720" | "4726" => {
            let u = jstr(inner, "TargetUserName").unwrap_or("?");
            let verb = if eventid == "4720" {
                "créé"
            } else {
                "supprimé"
            };
            let mut o = RawObservation::base(
                ts,
                ObsKind::AccountChange,
                asset,
                "osquery.windows_security",
            );
            o.actor = jstr(inner, "SubjectUserName").map(String::from);
            o.detail = format!("Compte {verb} : {u}");
            Some(o)
        }
        "4732" | "4756" => {
            let grp = jstr(inner, "TargetUserName")
                .or_else(|| jstr(inner, "GroupName"))
                .unwrap_or("?");
            let mut o = RawObservation::base(
                ts,
                ObsKind::PrivilegeEscalation,
                asset,
                "osquery.windows_security",
            );
            o.actor = jstr(inner, "SubjectUserName").map(String::from);
            o.detail = format!("Ajout au groupe privilégié : {grp} (4732/4756)");
            Some(o)
        }
        "1102" => {
            let mut o = RawObservation::base(
                ts,
                ObsKind::DefenseEvasion,
                asset,
                "osquery.windows_security",
            );
            o.actor = jstr(inner, "SubjectUserName").map(String::from);
            o.detail = "Journal de sécurité effacé (1102)".into();
            Some(o)
        }
        _ => None,
    }
}

/// Known reverse-shell / backdoor listener ports. A LISTEN on one of these is
/// high-signal regardless of the owning process (low FP), so we surface it even
/// without a per-host baseline.
// Superset of the connector's alert list (check_listening_ports) so anything it
// alerts on also lands on the timeline, plus a few more reverse-shell defaults.
const SUSPICIOUS_LISTEN_PORTS: &[i64] = &[
    1234, 1337, 4444, 4445, 5554, 5555, 6666, 7777, 8888, 9001, 9002, 9999, 12345, 31337, 54321,
];

/// Pure: map a "snapshot" log (the whole `data` object IS the artifact, no
/// eventid) to **0..N** observations. These sources are list-shaped and
/// re-emitted every sync, so the caller dedups by `detail`. High-precision
/// filters only — we deliberately surface the low-FP subset, not the full list:
/// - scheduled tasks / startup / authorized_keys → Persistence (mid/late chain),
/// - uid-0 non-root accounts → AccountChange (backdoor root, T1136),
/// - known reverse-shell listener ports → NetworkConnect (C2 channel ready).
///
/// `osquery.dns` (dns_cache) is intentionally NOT mapped: the whole cache is
/// noise without a DGA verdict (which lives in the connector/ML, not the log),
/// and Sysmon 22 already gives per-process DNS with attribution.
pub fn obs_from_snapshot_log(
    tag: &str,
    data: &Value,
    asset: &str,
    ts: DateTime<Utc>,
) -> Vec<RawObservation> {
    let mut out = Vec::new();
    match tag {
        "osquery.scheduled_tasks" => {
            let name = jstr(data, "name").unwrap_or("?");
            let path = jstr(data, "path").unwrap_or("?");
            let mut o = RawObservation::base(ts, ObsKind::Persistence, asset, tag);
            // English token so label_mitre maps it to T1053.005.
            o.detail = format!("Tâche planifiée (scheduled task) : {name} → {path}");
            o.related_to = Some(path.into());
            out.push(o);
        }
        "osquery.startup" => {
            let name = jstr(data, "name").unwrap_or("?");
            let path = jstr(data, "path").unwrap_or("?");
            let mut o = RawObservation::base(ts, ObsKind::Persistence, asset, tag);
            o.detail = format!("Élément de démarrage (startup) : {name} → {path}");
            o.related_to = Some(path.into());
            out.push(o);
        }
        "osquery.ssh_keys" => {
            if let Some(keys) = data.get("keys").and_then(|k| k.as_array())
                && !keys.is_empty()
            {
                let files: Vec<&str> = keys
                    .iter()
                    .filter_map(|k| k.get("key_file").and_then(|v| v.as_str()))
                    .collect();
                let mut o = RawObservation::base(ts, ObsKind::Persistence, asset, tag);
                o.detail = format!(
                    "authorized_keys ({} clé(s)) : {}",
                    keys.len(),
                    files.join(", ")
                );
                o.related_to = files.first().map(|s| (*s).to_string());
                out.push(o);
            }
        }
        "osquery.users" => {
            // Backdoor root: any account with uid 0 that isn't `root`.
            if let Some(users) = data.get("users").and_then(|u| u.as_array()) {
                for u in users {
                    let name = jstr(u, "username").unwrap_or("?");
                    if jint(u.get("uid")) == Some(0) && !name.eq_ignore_ascii_case("root") {
                        let mut o = RawObservation::base(ts, ObsKind::AccountChange, asset, tag);
                        o.actor = Some(name.to_string());
                        o.detail = format!("Compte UID 0 non-root : {name} (backdoor root)");
                        out.push(o);
                    }
                }
            }
        }
        "osquery.ports" => {
            if let Some(ports) = data.get("ports").and_then(|p| p.as_array()) {
                for p in ports {
                    let Some(port) = jint(p.get("port")) else {
                        continue;
                    };
                    if SUSPICIOUS_LISTEN_PORTS.contains(&port) {
                        let name = jstr(p, "name").unwrap_or("?");
                        let addr = jstr(p, "address").unwrap_or("0.0.0.0");
                        let mut o = RawObservation::base(ts, ObsKind::NetworkConnect, asset, tag);
                        o.detail = format!("Port en écoute suspect : {addr}:{port} ({name})");
                        o.ioc = Some(port.to_string());
                        out.push(o);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Edge (I/O): read recent osquery telemetry for an asset across the relevant
/// tags and map each event to an observation. Server-side parsing — only rows,
/// never raw artifacts, cross the wire.
pub async fn collect_observations_from_logs(
    store: &dyn Database,
    asset: &str,
    minutes_back: i64,
) -> Vec<RawObservation> {
    type Mapper = fn(&str, &Value, &str, DateTime<Utc>) -> Option<RawObservation>;
    // Event sources: one log row = one event, keyed on `eventid` + nested `data`.
    let event_sources: [(&str, Mapper); 3] = [
        ("osquery.sysmon", obs_from_sysmon),
        ("osquery.powershell", obs_from_powershell),
        ("osquery.windows_security", obs_from_winsec),
    ];
    let mut out = Vec::new();
    for (tag, map) in event_sources {
        let logs = store
            .query_logs(minutes_back, Some(asset), Some(tag), 5000)
            .await
            .unwrap_or_default();
        for l in &logs {
            let eventid = l.data.get("eventid").and_then(|v| v.as_str()).unwrap_or("");
            let Some(inner) = l.data.get("data") else {
                continue;
            };
            let ts = parse_log_ts(&l.time)
                .or_else(|| parse_log_ts(&l.created_at))
                .unwrap_or_else(Utc::now);
            if let Some(o) = map(eventid, inner, asset, ts) {
                out.push(o);
            }
        }
    }

    // Snapshot sources: the whole `data` is the artifact, re-logged every sync,
    // so DEDUP by detail (one entry per distinct finding) to avoid flooding the
    // timeline with the same task/key/account/port every 5 minutes. Each source
    // can yield several findings (a users/ports list), hence the Vec mapper.
    let snapshot_tags = [
        "osquery.scheduled_tasks",
        "osquery.startup",
        "osquery.ssh_keys",
        "osquery.users",
        "osquery.ports",
    ];
    let mut seen = std::collections::HashSet::new();
    for tag in snapshot_tags {
        let logs = store
            .query_logs(minutes_back, Some(asset), Some(tag), 5000)
            .await
            .unwrap_or_default();
        for l in &logs {
            let ts = parse_log_ts(&l.time)
                .or_else(|| parse_log_ts(&l.created_at))
                .unwrap_or_else(Utc::now);
            for o in obs_from_snapshot_log(tag, &l.data, asset, ts) {
                if seen.insert(o.detail.clone()) {
                    out.push(o);
                }
            }
        }
    }
    out
}

/// Run DFIR triage for one incident: assemble the forensic timeline from ingested
/// telemetry and persist it. Idempotent — stamps `dfir_collected_at` so it runs
/// once per incident. Non-fatal (never breaks the caller).
/// Map a kill-chain severity to a CAPPED RBA score. Deliberately below RBA's
/// single-fire score threshold (100) so ONE investigation can never raise a risk
/// notable on its own — only repeated DFIR-confirmed activity on the same asset
/// (or accumulation with other risk sources) crosses it. That's the slow-APT /
/// sustained-attack signal, and it is re-fire-safe by construction.
fn dfir_risk_score(severity: &str) -> i32 {
    match severity {
        "CRITICAL" => 50,
        "HIGH" => 25,
        _ => 0,
    }
}

/// Pick a representative `(tactic, technique)` for the investigation: the most
/// advanced / most severe stage present, so the risk_event feeds RBA's tactic
/// diversity rule (RIR-b) meaningfully when several incidents stack on an asset.
fn dominant_tactic(events: &[NewTimelineEvent]) -> (Option<String>, Option<String>) {
    const PRIORITY: &[&str] = &[
        "credential_access",
        "persistence_install",
        "account_change",
        "privilege_escalation",
        "injection",
        "defense_evasion",
        "net_connect",
        "logon",
        "process_spawn",
    ];
    for want in PRIORITY {
        if let Some(ev) = events.iter().find(|e| e.event_type == *want) {
            return (ev.mitre_tactic.clone(), ev.mitre_technique.clone());
        }
    }
    (None, None)
}

/// Edge (I/O): feed the RBA engine from a completed DFIR triage. Two producers,
/// both non-fatal and both capped below the single-fire threshold:
/// - **own asset**: a kill-chain-scored event → sustained, multi-incident
///   activity on one asset accumulates into a "under sustained attack" notable;
/// - **lateral targets** (the incident's `related_assets`): a modest event each
///   → a campaign spreading across machines accumulates on hosts that don't yet
///   have their own incident.
async fn feed_rba_from_dfir(
    store: &dyn Database,
    incident_id: i32,
    asset: &str,
    events: &[NewTimelineEvent],
    killchain: Option<&(&'static str, String)>,
) {
    if let Some((sev, reason)) = killchain {
        let score = dfir_risk_score(sev);
        if score > 0 {
            let (mitre_tactic, mitre_technique) = dominant_tactic(events);
            let ev = NewRiskEvent {
                risk_object: asset.to_string(),
                object_type: "asset".into(),
                score,
                source_rule: "dfir:killchain".into(),
                mitre_tactic,
                mitre_technique,
                log_id: None,
                message: Some(format!("DFIR #{incident_id} : {reason}")),
            };
            if let Err(e) = store.insert_risk_event(&ev).await {
                tracing::debug!(
                    "DFIR: insert_risk_event (killchain) failed for #{incident_id}: {e}"
                );
            }
        }
    }

    // Cross-asset: the graph-derived lateral targets carried on the incident.
    if let Ok(Some(inc)) = store.get_incident(incident_id).await
        && let Some(related) = inc.get("related_assets").and_then(|v| v.as_array())
    {
        for r in related {
            let Some(target) = r.as_str() else { continue };
            if target.is_empty() || target.eq_ignore_ascii_case(asset) {
                continue;
            }
            let ev = NewRiskEvent {
                risk_object: target.to_string(),
                object_type: "asset".into(),
                score: 25,
                source_rule: "dfir:lateral".into(),
                mitre_tactic: Some("lateral-movement".into()),
                mitre_technique: Some("T1021".into()),
                log_id: None,
                message: Some(format!(
                    "Cible de mouvement latéral depuis {asset} (incident #{incident_id})"
                )),
            };
            if let Err(e) = store.insert_risk_event(&ev).await {
                tracing::debug!("DFIR: insert_risk_event (lateral) failed for #{incident_id}: {e}");
            }
        }
    }
}

pub async fn run_dfir_triage(store: Arc<dyn Database>, incident_id: i32, asset: &str) {
    let obs = collect_observations_from_logs(store.as_ref(), asset, DFIR_WINDOW_MIN).await;
    if !obs.is_empty() {
        let events = assemble_timeline(obs);
        match store.insert_timeline_events(incident_id, &events).await {
            Ok(n) => tracing::info!(
                "DFIR: incident #{incident_id} — {n} timeline events assembled for {asset}"
            ),
            Err(e) => {
                tracing::warn!("DFIR: insert_timeline_events failed for #{incident_id}: {e}")
            }
        }

        let killchain = assess_killchain(&events);

        // 2b-bis — corroboration: if the timeline reveals a multi-stage intrusion,
        // escalate the incident severity (upgrade-only, audited). No new incident,
        // no second alert — it strengthens the one the detection layer created.
        if let Some((sev, reason)) = &killchain {
            match store
                .escalate_incident_severity(incident_id, sev, reason)
                .await
            {
                Ok(n) if n > 0 => {
                    tracing::info!("DFIR: incident #{incident_id} escalated to {sev} — {reason}")
                }
                Ok(_) => {} // already at or above this severity — no change
                Err(e) => {
                    tracing::warn!(
                        "DFIR: escalate_incident_severity failed for #{incident_id}: {e}"
                    )
                }
            }
        }

        // 2b-bis (a) — feed RBA so DFIR-confirmed activity accumulates ACROSS
        // incidents and ACROSS assets: the low-and-slow / lateral campaigns a
        // single incident can't see. Each emission is capped below RBA's
        // single-fire threshold, so one investigation never raises a notable on
        // its own — only sustained accumulation does (re-fire-safe by design).
        feed_rba_from_dfir(
            store.as_ref(),
            incident_id,
            asset,
            &events,
            killchain.as_ref(),
        )
        .await;
    }
    // Stamp even when empty so the incident isn't re-polled forever (the
    // triggering telemetry is already ingested by the time we run).
    if let Err(e) = store.mark_dfir_collected(incident_id).await {
        tracing::warn!("DFIR: mark_dfir_collected failed for #{incident_id}: {e}");
    }
}

/// Background loop: assemble a forensic timeline for incidents that don't have
/// one yet. Mirrors the `forensic_enricher` poll pattern. Enriches every
/// incident (IE, RBA notable, graph) without touching each create site.
pub async fn run_dfir_collector(store: Arc<dyn Database>) {
    loop {
        tokio::time::sleep(DFIR_POLL_INTERVAL).await;
        let pending = match store.list_incidents_needing_dfir(20).await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("DFIR collector: list failed (or unsupported): {e}");
                continue;
            }
        };
        for (id, asset) in pending {
            run_dfir_triage(store.clone(), id, &asset).await;
        }
    }
}

// ── Per-incident attack graph (Phase 3 / option C) ─────────────────────────

/// A node in the per-incident attack graph.
#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    /// host | process_spawn | net_connect | logon | …
    pub kind: String,
    pub severity: String,
    pub mitre: Option<String>,
}

/// A directed edge in the per-incident attack graph.
#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub label: String,
}

/// Focused attack graph for ONE incident: the affected host at the root, its
/// forensic timeline as a chronological chain (the attack story), and lateral
/// edges to related assets.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AttackGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}

/// Edge type for an event kind (the relationship the event represents).
fn edge_type(event_type: &str) -> &'static str {
    match event_type {
        "process_spawn" => "SPAWNED",
        "net_connect" => "CONNECTED_TO",
        "dns_query" => "RESOLVED",
        "injection" => "INJECTED_INTO",
        "credential_access" => "ACCESSED_LSASS",
        "file_event" => "CREATED_FILE",
        "logon" => "AUTHENTICATED",
        "persistence_install" => "PERSISTS_VIA",
        "account_change" => "ACCOUNT_CHANGE",
        "privilege_escalation" => "PRIVESC",
        "defense_evasion" => "EVASION",
        _ => "RELATED",
    }
}

/// Pure: build the per-incident **provenance graph** from its forensic timeline.
/// The spine is the **process tree keyed on ProcessGuid** (never PID): each
/// `process_spawn` is a process node, wired parent→child via `parent_guid`.
/// Every other event hangs off its owning process (by `proc_guid`) as a typed
/// edge (CONNECTED_TO / INJECTED_INTO / ACCESSED_LSASS / CREATED_FILE / …) so the
/// graph reconstructs *causality* (who did what to what), not a flat chain.
/// Related assets attach as lateral-movement branches. Events with no GUID fall
/// back to the host root so nothing is lost.
pub fn build_attack_graph(
    asset: &str,
    timeline: &[TimelineEvent],
    related: &[String],
) -> AttackGraph {
    use std::collections::HashMap;
    let mut g = AttackGraph::default();
    let host_id = format!("host:{asset}");
    g.nodes.push(GraphNode {
        id: host_id.clone(),
        label: asset.to_string(),
        kind: "host".into(),
        severity: "info".into(),
        mitre: None,
    });

    // Pass 1 — process nodes, keyed by ProcessGuid (the spine).
    let mut proc_node: HashMap<&str, String> = HashMap::new();
    for ev in timeline {
        if ev.event_type == "process_spawn"
            && let Some(guid) = ev.proc_guid.as_deref()
            && !proc_node.contains_key(guid)
        {
            let nid = format!("proc:{guid}");
            proc_node.insert(guid, nid.clone());
            g.nodes.push(GraphNode {
                id: nid,
                label: truncate(&ev.description, 60),
                kind: "process".into(),
                severity: ev.severity.clone(),
                mitre: ev.mitre_technique.clone(),
            });
        }
    }

    // The node that "owns" an event: its process (by proc_guid) else the host.
    let owner = |ev: &TimelineEvent| -> String {
        ev.proc_guid
            .as_deref()
            .and_then(|gd| proc_node.get(gd).cloned())
            .unwrap_or_else(|| host_id.clone())
    };

    // Pass 2 — edges (+ action/artifact nodes for non-process events).
    for ev in timeline {
        let etype = edge_type(&ev.event_type);
        if ev.event_type == "process_spawn" {
            // SPAWNED: parent process (by parent_guid) → this process; root at host.
            let child = ev
                .proc_guid
                .as_deref()
                .and_then(|gd| proc_node.get(gd).cloned())
                .unwrap_or_else(|| format!("ev:{}", ev.id));
            let parent = ev
                .parent_guid
                .as_deref()
                .and_then(|gd| proc_node.get(gd).cloned())
                .unwrap_or_else(|| host_id.clone());
            // Guid-less process: still materialise a node so it's not lost.
            if !ev
                .proc_guid
                .as_deref()
                .is_some_and(|gd| proc_node.contains_key(gd))
            {
                g.nodes.push(GraphNode {
                    id: child.clone(),
                    label: truncate(&ev.description, 60),
                    kind: "process".into(),
                    severity: ev.severity.clone(),
                    mitre: ev.mitre_technique.clone(),
                });
            }
            g.edges.push(GraphEdge {
                source: parent,
                target: child,
                label: etype.into(),
            });
        } else {
            // Action node hanging off the owning process (or host).
            let nid = format!("ev:{}", ev.id);
            g.nodes.push(GraphNode {
                id: nid.clone(),
                label: truncate(&ev.description, 60),
                kind: ev.event_type.clone(),
                severity: ev.severity.clone(),
                mitre: ev.mitre_technique.clone(),
            });
            g.edges.push(GraphEdge {
                source: owner(ev),
                target: nid,
                label: etype.into(),
            });
        }
    }

    // Lateral movement to related assets.
    for r in related {
        if r == asset {
            continue;
        }
        let rid = format!("host:{r}");
        g.nodes.push(GraphNode {
            id: rid.clone(),
            label: r.clone(),
            kind: "host".into(),
            severity: "info".into(),
            mitre: None,
        });
        g.edges.push(GraphEdge {
            source: host_id.clone(),
            target: rid,
            label: "LATERAL".into(),
        });
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(kind: ObsKind, detail: &str, age_secs: i64) -> RawObservation {
        let base = DateTime::parse_from_rfc3339("2026-06-22T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let mut o = RawObservation::base(
            base - chrono::Duration::seconds(age_secs),
            kind,
            "WIN-01",
            "osquery.sysmon",
        );
        o.detail = detail.into();
        o
    }

    #[test]
    fn timeline_is_chronological() {
        // Fed out of order; must come back oldest-first.
        let events = assemble_timeline(vec![
            obs(ObsKind::NetworkConnect, "185.1.2.3:443", 10), // newer
            obs(ObsKind::ProcessCreate, "powershell -enc AAA", 100), // oldest
            obs(ObsKind::Persistence, "schtask Updater", 50),  // middle
        ]);
        let descs: Vec<&str> = events.iter().map(|e| e.description.as_str()).collect();
        assert_eq!(
            descs,
            vec!["powershell -enc AAA", "schtask Updater", "185.1.2.3:443"],
            "events must be ordered oldest-first"
        );
        // UTC RFC3339 stamps preserved
        assert!(events[0].ts.ends_with("+00:00"));
    }

    #[test]
    fn labels_encoded_powershell_as_t1059_001() {
        let (tac, tech) = label_mitre(&obs(
            ObsKind::ProcessCreate,
            "powershell.exe -EncodedCommand X",
            1,
        ));
        assert_eq!(tac.as_deref(), Some("execution"));
        assert_eq!(tech.as_deref(), Some("T1059.001"));
    }

    #[test]
    fn labels_persistence_triggers() {
        let cases = [
            ("authorized_keys += ssh-rsa AAA", "T1098.004"),
            ("schtask /create Updater", "T1053.005"),
            ("new service 7045 PSEXESVC", "T1543.003"),
            ("/etc/cron.d/evil", "T1053.003"),
        ];
        for (detail, tech) in cases {
            let (_, t) = label_mitre(&obs(ObsKind::Persistence, detail, 1));
            assert_eq!(t.as_deref(), Some(tech), "detail={detail}");
        }
    }

    #[test]
    fn standalone_findings_fire_on_high_precision_triggers_only() {
        let observations = vec![
            obs(ObsKind::Persistence, "authorized_keys += ssh-rsa AAA", 5),
            obs(ObsKind::AccountChange, "useradd backdoor uid=0", 4),
            obs(ObsKind::Persistence, "ld.so.preload = /tmp/x.so", 3),
            obs(ObsKind::DefenseEvasion, "Security log cleared (1102)", 2),
            // benign — must NOT produce a finding
            obs(ObsKind::ProcessCreate, "C:\\Windows\\explorer.exe", 1),
            obs(ObsKind::NetworkConnect, "10.0.0.5:445", 1),
        ];
        let findings = detect_standalone_findings(&observations);
        assert_eq!(findings.len(), 4, "exactly the 4 high-precision triggers");
        assert!(findings.iter().all(|f| f.severity == "high"));
        assert!(findings.iter().any(|f| f.mitre_technique == "T1098.004"));
        assert!(findings.iter().any(|f| f.mitre_technique == "T1136.001"));
    }

    fn tev(id: i64, etype: &str, tech: &str) -> TimelineEvent {
        TimelineEvent {
            id,
            incident_id: 1,
            ts: "2026-06-22T19:20:00+00:00".into(),
            event_type: etype.into(),
            asset: "WIN-01".into(),
            actor: None,
            description: format!("{etype} detail"),
            severity: "high".into(),
            mitre_tactic: None,
            mitre_technique: Some(tech.into()),
            ioc: None,
            source_artifact: Some("osquery.sysmon".into()),
            created_at: "2026-06-22T19:26:00+00:00".into(),
            proc_guid: None,
            parent_guid: None,
            related_to: None,
        }
    }

    #[test]
    fn attack_graph_hangs_events_off_host_when_guidless_with_lateral() {
        let tl = vec![
            tev(1, "logon", "T1021"),
            tev(2, "process_spawn", "T1059.001"),
            tev(3, "net_connect", "T1071"),
        ];
        let g = build_attack_graph("WIN-01", &tl, &["WIN-01".into(), "WIN-02".into()]);
        // host + 3 event nodes + 1 lateral peer (self skipped) = 5 nodes
        assert_eq!(g.nodes.len(), 5);
        assert_eq!(g.nodes[0].kind, "host");
        // no proc_guid → every event hangs off the host; +1 lateral = 4 edges
        assert_eq!(g.edges.len(), 4);
        assert!(g.edges.iter().all(|e| e.source == "host:WIN-01"));
        assert!(
            g.edges
                .iter()
                .any(|e| e.label == "LATERAL" && e.target == "host:WIN-02")
        );
    }

    #[test]
    fn attack_graph_builds_causal_process_tree() {
        // Outlook(guid A) → powershell(guid B) which connects out and touches lsass.
        let mut p_outlook = tev(1, "process_spawn", "T1566");
        p_outlook.proc_guid = Some("A".into());
        let mut p_ps = tev(2, "process_spawn", "T1059.001");
        p_ps.proc_guid = Some("B".into());
        p_ps.parent_guid = Some("A".into());
        let mut net = tev(3, "net_connect", "T1071");
        net.proc_guid = Some("B".into());
        let mut cred = tev(4, "credential_access", "T1003.001");
        cred.proc_guid = Some("B".into());

        let g = build_attack_graph("WIN-01", &[p_outlook, p_ps, net, cred], &[]);
        // 2 process nodes (proc:A, proc:B) deduped by guid
        assert!(g.nodes.iter().any(|n| n.id == "proc:A"));
        assert!(g.nodes.iter().any(|n| n.id == "proc:B"));
        // SPAWNED edge A → B (causal parent→child, NOT host→child)
        assert!(
            g.edges
                .iter()
                .any(|e| e.source == "proc:A" && e.target == "proc:B" && e.label == "SPAWNED")
        );
        // the network + lsass actions hang off powershell (proc:B), not the host
        assert!(
            g.edges
                .iter()
                .any(|e| e.source == "proc:B" && e.label == "CONNECTED_TO")
        );
        assert!(
            g.edges
                .iter()
                .any(|e| e.source == "proc:B" && e.label == "ACCESSED_LSASS")
        );
    }

    fn nte(event_type: &str) -> NewTimelineEvent {
        NewTimelineEvent {
            ts: "2026-06-22T19:20:00+00:00".into(),
            tz_origin: Some("UTC".into()),
            event_type: event_type.into(),
            asset: "WIN-01".into(),
            actor: None,
            description: format!("{event_type} detail"),
            severity: "medium".into(),
            mitre_tactic: None,
            mitre_technique: None,
            ioc: None,
            related_artifacts: vec![],
            source_artifact: None,
            collected_hash: None,
            proc_guid: None,
            parent_guid: None,
            related_to: None,
        }
    }

    fn nte_t(event_type: &str, tactic: &str, tech: &str) -> NewTimelineEvent {
        let mut e = nte(event_type);
        e.mitre_tactic = Some(tactic.into());
        e.mitre_technique = Some(tech.into());
        e
    }

    #[test]
    fn dfir_risk_score_is_capped_below_single_fire_threshold() {
        assert_eq!(dfir_risk_score("CRITICAL"), 50);
        assert_eq!(dfir_risk_score("HIGH"), 25);
        assert_eq!(dfir_risk_score("MEDIUM"), 0);
        // one investigation must NEVER alone cross RBA's score threshold (100)
        assert!(dfir_risk_score("CRITICAL") < 100);
    }

    #[test]
    fn dominant_tactic_prefers_most_advanced_stage() {
        // exec + C2 + credential theft present → credential theft wins (highest priority)
        let evs = vec![
            nte_t("process_spawn", "execution", "T1059"),
            nte_t("net_connect", "command-and-control", "T1071"),
            nte_t("credential_access", "credential-access", "T1003.001"),
        ];
        let (tac, tech) = dominant_tactic(&evs);
        assert_eq!(tac.as_deref(), Some("credential-access"));
        assert_eq!(tech.as_deref(), Some("T1003.001"));
        // nothing recognised → no tactic
        assert_eq!(
            dominant_tactic(&[nte_t("file_event", "x", "y")]),
            (None, None)
        );
    }

    #[test]
    fn killchain_persistence_plus_c2_is_critical() {
        let r = assess_killchain(&[nte("persistence_install"), nte("net_connect")]);
        assert_eq!(r.map(|(s, _)| s), Some("CRITICAL"));
    }

    #[test]
    fn killchain_three_distinct_stages_is_critical() {
        let r = assess_killchain(&[nte("logon"), nte("process_spawn"), nte("net_connect")]);
        assert_eq!(r.map(|(s, _)| s), Some("CRITICAL"));
    }

    #[test]
    fn killchain_two_stages_with_a_strong_one_is_high() {
        // exécution + persistance (2 distinctes, persistance = forte) → HIGH
        let r = assess_killchain(&[nte("process_spawn"), nte("persistence_install")]);
        assert_eq!(r.map(|(s, _)| s), Some("HIGH"));
    }

    #[test]
    fn killchain_weak_combos_do_not_escalate() {
        // une seule étape (exécution)
        assert!(assess_killchain(&[nte("process_spawn"), nte("process_spawn")]).is_none());
        // deux étapes faibles (logon + exécution, aucune forte)
        assert!(assess_killchain(&[nte("logon"), nte("process_spawn")]).is_none());
        // vide
        assert!(assess_killchain(&[]).is_none());
    }

    #[test]
    fn benign_telemetry_yields_no_findings() {
        let observations = vec![
            obs(ObsKind::ProcessCreate, "powershell Get-Service", 2),
            obs(ObsKind::Logon, "logon type 2 alice", 1),
        ];
        assert!(detect_standalone_findings(&observations).is_empty());
    }

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-22T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn sysmon_process_create_maps_with_parent_and_cmdline() {
        let inner = serde_json::json!({
            "CommandLine": "powershell.exe -EncodedCommand AAA",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage": "C:\\Program Files\\Office\\outlook.exe"
        });
        let o = obs_from_sysmon("1", &inner, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::ProcessCreate);
        assert_eq!(
            o.actor.as_deref(),
            Some("C:\\Program Files\\Office\\outlook.exe")
        );
        assert!(o.detail.contains("-EncodedCommand"));
        // and it labels as T1059.001 downstream
        let ev = to_timeline_event(&o);
        assert_eq!(ev.mitre_technique.as_deref(), Some("T1059.001"));
    }

    #[test]
    fn sysmon_network_connect_carries_ip_ioc() {
        let inner = serde_json::json!({
            "DestinationIp": "185.1.2.3", "DestinationPort": "443", "Image": "x.exe"
        });
        let o = obs_from_sysmon("3", &inner, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::NetworkConnect);
        assert_eq!(o.ioc.as_deref(), Some("185.1.2.3"));
        assert_eq!(o.detail, "185.1.2.3:443");
    }

    #[test]
    fn sysmon_unhandled_eventid_is_skipped() {
        // EID 2 (FileCreateTime) / 12 (registry) are not in the attack-map set.
        assert!(obs_from_sysmon("2", &serde_json::json!({"x": "y"}), "WIN-01", ts()).is_none());
        assert!(obs_from_sysmon("12", &serde_json::json!({"x": "y"}), "WIN-01", ts()).is_none());
        // eventid 1 with no cmdline/image → skipped (no usable detail)
        assert!(obs_from_sysmon("1", &serde_json::json!({"User": "x"}), "WIN-01", ts()).is_none());
    }

    #[test]
    fn sysmon_injection_credaccess_dns_file_mapped_with_guids() {
        // EID 8 CreateRemoteThread → injection, carries source guid + target.
        let inj = serde_json::json!({
            "SourceImage": "a.exe", "TargetImage": "lsass.exe",
            "SourceProcessGuid": "G1", "TargetProcessGuid": "G2"
        });
        let o = obs_from_sysmon("8", &inj, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::Injection);
        assert_eq!(o.proc_guid.as_deref(), Some("G1"));
        assert_eq!(o.related_to.as_deref(), Some("G2"));
        // EID 10 → only LSASS access is kept (credential theft).
        let lsass = serde_json::json!({"SourceImage":"mimi.exe","TargetImage":"C:\\...\\lsass.exe","SourceProcessGuid":"G3"});
        let o = obs_from_sysmon("10", &lsass, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::CredentialAccess);
        // non-lsass ProcessAccess is dropped as noise
        assert!(
            obs_from_sysmon(
                "10",
                &serde_json::json!({"TargetImage":"chrome.exe"}),
                "WIN-01",
                ts()
            )
            .is_none()
        );
        // EID 22 DNS → DnsQuery, domain as ioc
        let dns = serde_json::json!({"QueryName":"evil.com","Image":"ps.exe","ProcessGuid":"G4"});
        let o = obs_from_sysmon("22", &dns, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::DnsQuery);
        assert_eq!(o.ioc.as_deref(), Some("evil.com"));
        // EID 11 FileCreate → FileEvent
        let fc = serde_json::json!({"TargetFilename":"C:\\Temp\\evil.exe","Image":"ps.exe"});
        assert_eq!(
            obs_from_sysmon("11", &fc, "WIN-01", ts()).unwrap().kind,
            ObsKind::FileEvent
        );
    }

    #[test]
    fn winsec_account_group_and_logclear_mapped() {
        // 4720 account created
        let o = obs_from_winsec(
            "4720",
            &serde_json::json!({"TargetUserName":"backdoor","SubjectUserName":"adm"}),
            "WIN-01",
            ts(),
        )
        .unwrap();
        assert_eq!(o.kind, ObsKind::AccountChange);
        // 4732 privileged group add → PrivilegeEscalation
        let o = obs_from_winsec(
            "4732",
            &serde_json::json!({"TargetUserName":"Administrators","SubjectUserName":"adm"}),
            "WIN-01",
            ts(),
        )
        .unwrap();
        assert_eq!(o.kind, ObsKind::PrivilegeEscalation);
        // 1102 log cleared → DefenseEvasion
        let o = obs_from_winsec("1102", &serde_json::json!({}), "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::DefenseEvasion);
        // 4624 interactive (type 2) is dropped; only lateral types 3/9/10 kept
        assert!(
            obs_from_winsec(
                "4624",
                &serde_json::json!({"TargetUserName":"alice","LogonType":"2"}),
                "WIN-01",
                ts()
            )
            .is_none()
        );
    }

    #[test]
    fn powershell_4104_maps_first_part_only() {
        let p1 = serde_json::json!({"ScriptBlockText": "IEX (New-Object Net.WebClient)...", "MessageNumber": "1"});
        let o = obs_from_powershell("4104", &p1, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::ProcessCreate);
        assert_eq!(o.source, "osquery.powershell");
        assert!(o.detail.contains("ScriptBlock"));
        // continuation part is skipped
        let p2 = serde_json::json!({"ScriptBlockText": "...rest", "MessageNumber": "2"});
        assert!(obs_from_powershell("4104", &p2, "WIN-01", ts()).is_none());
        // other PS event ids ignored
        assert!(obs_from_powershell("4103", &p1, "WIN-01", ts()).is_none());
    }

    #[test]
    fn winsec_logon_maps_and_filters_noise() {
        let rdp =
            serde_json::json!({"TargetUserName":"alice","LogonType":"10","IpAddress":"10.0.0.9"});
        let o = obs_from_winsec("4624", &rdp, "WIN-01", ts()).unwrap();
        assert_eq!(o.kind, ObsKind::Logon);
        assert_eq!(o.ioc.as_deref(), Some("10.0.0.9"));
        assert!(o.detail.contains("type 10"));
        // machine/service/system logons are noise → skipped
        assert!(
            obs_from_winsec(
                "4624",
                &serde_json::json!({"TargetUserName":"WIN-01$"}),
                "WIN-01",
                ts()
            )
            .is_none()
        );
        assert!(
            obs_from_winsec(
                "4624",
                &serde_json::json!({"TargetUserName":"SYSTEM"}),
                "WIN-01",
                ts()
            )
            .is_none()
        );
        // non-logon event ignored
        assert!(obs_from_winsec("4688", &rdp, "WIN-01", ts()).is_none());
    }

    fn one(tag: &str, data: serde_json::Value) -> RawObservation {
        obs_from_snapshot_log(tag, &data, "WIN-01", ts())
            .into_iter()
            .next()
            .expect("expected one observation")
    }

    #[test]
    fn snapshot_persistence_logs_map_and_label() {
        // scheduled task → Persistence, labelled T1053.005
        let o = one(
            "osquery.scheduled_tasks",
            serde_json::json!({"name":"Updater","path":"C:\\Temp\\evil.exe"}),
        );
        assert_eq!(o.kind, ObsKind::Persistence);
        assert_eq!(o.related_to.as_deref(), Some("C:\\Temp\\evil.exe"));
        assert_eq!(label_mitre(&o).1.as_deref(), Some("T1053.005"));
        // authorized_keys → Persistence T1098.004
        let o = one(
            "osquery.ssh_keys",
            serde_json::json!({"keys_count":1,"keys":[{"key_file":"/root/.ssh/authorized_keys"}]}),
        );
        assert!(o.detail.contains("authorized_keys"));
        assert_eq!(label_mitre(&o).1.as_deref(), Some("T1098.004"));
        // startup → Persistence
        assert_eq!(
            one(
                "osquery.startup",
                serde_json::json!({"name":"x","path":"C:\\Temp\\x.exe","source":"Registry"})
            )
            .kind,
            ObsKind::Persistence
        );
        // empty key list → no observation
        assert!(
            obs_from_snapshot_log(
                "osquery.ssh_keys",
                &serde_json::json!({"keys":[]}),
                "WIN-01",
                ts()
            )
            .is_empty()
        );
    }

    #[test]
    fn snapshot_users_and_ports_high_precision_only() {
        // uid-0 non-root → AccountChange (backdoor root, T1136); root + normal skipped.
        let obs = obs_from_snapshot_log(
            "osquery.users",
            &serde_json::json!({"users":[
                {"username":"root","uid":"0"},
                {"username":"backdoor","uid":"0"},
                {"username":"alice","uid":"1000"}
            ]}),
            "WIN-01",
            ts(),
        );
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].kind, ObsKind::AccountChange);
        assert_eq!(obs[0].actor.as_deref(), Some("backdoor"));
        assert_eq!(label_mitre(&obs[0]).1.as_deref(), Some("T1136"));
        // ports: only known reverse-shell ports surface; 443/22 are ignored.
        let obs = obs_from_snapshot_log(
            "osquery.ports",
            &serde_json::json!({"ports":[
                {"port":"443","name":"nginx","address":"0.0.0.0"},
                {"port":4444,"name":"nc","address":"0.0.0.0"},
                {"port":"22","name":"sshd","address":"0.0.0.0"}
            ]}),
            "WIN-01",
            ts(),
        );
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].kind, ObsKind::NetworkConnect);
        assert_eq!(obs[0].ioc.as_deref(), Some("4444"));
        assert!(obs[0].detail.contains("4444"));
    }

    #[test]
    fn parse_log_ts_handles_pg_timestamptz_text_and_rfc3339() {
        // The real format query_logs yields (time::text) — regression for the
        // e2e bug where this fell back to now() and flattened the timeline.
        let a = parse_log_ts("2026-06-22 19:20:00+00").expect("PG ::text");
        assert_eq!(a.to_rfc3339(), "2026-06-22T19:20:00+00:00");
        let b = parse_log_ts("2026-06-22 19:20:00.123456+00").expect("PG ::text w/ micros");
        assert_eq!(b.to_rfc3339(), "2026-06-22T19:20:00.123456+00:00");
        // RFC 3339 and naive (assumed UTC) still work; junk is rejected.
        assert!(parse_log_ts("2026-06-22T12:00:00+00:00").is_some());
        assert!(parse_log_ts("2026-06-22 12:00:00").is_some());
        assert!(parse_log_ts("not-a-date").is_none());
    }
}

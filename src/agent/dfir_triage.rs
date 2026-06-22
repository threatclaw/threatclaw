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
use serde_json::Value;

use crate::db::Database;
use crate::db::threatclaw_store::NewTimelineEvent;

/// Poll cadence of the background DFIR collector.
const DFIR_POLL_INTERVAL: Duration = Duration::from_secs(180);
/// Lookback window for assembling an incident's timeline (24h).
const DFIR_WINDOW_MIN: i64 = 1440;

/// Category of a raw forensic observation pulled from ingested telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObsKind {
    ProcessCreate,
    NetworkConnect,
    /// Run key, service, scheduled task, cron, systemd unit, authorized_keys, …
    Persistence,
    Logon,
    FileEvent,
    /// New user, group add, UID-0 creation, sudoers change.
    AccountChange,
    /// Log clear, history wipe, AV/EDR disable, timestomp.
    DefenseEvasion,
}

/// A minimal, source-agnostic observation. The pure timeline/labelling logic
/// works on this so it never touches a DB or a clock.
#[derive(Debug, Clone)]
pub struct RawObservation {
    pub ts: DateTime<Utc>,
    pub kind: ObsKind,
    pub asset: String,
    /// User / parent process / source IP.
    pub actor: Option<String>,
    /// Cmdline / "Run\\X = Y" / "authorized_keys += <key>" / …
    pub detail: String,
    /// Hash / IP / domain / path, when present.
    pub ioc: Option<String>,
    /// "osquery.sysmon", "osquery.windows_security", "osquery.process", …
    pub source: String,
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
        ObsKind::Persistence => "persistence_install",
        ObsKind::Logon => "logon",
        ObsKind::FileEvent => "file_event",
        ObsKind::AccountChange => "account_change",
        ObsKind::DefenseEvasion => "defense_evasion",
    }
}

/// Default severity by category (persistence / evasion / account changes are the
/// load-bearing signals → high; the rest is contextual timeline → medium/info).
pub fn severity_for(kind: &ObsKind) -> &'static str {
    match kind {
        ObsKind::Persistence | ObsKind::DefenseEvasion | ObsKind::AccountChange => "high",
        ObsKind::ProcessCreate | ObsKind::NetworkConnect | ObsKind::Logon => "medium",
        ObsKind::FileEvent => "info",
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
        ObsKind::Logon => ("lateral-movement", "T1021"),
        ObsKind::AccountChange => {
            if d.contains("sudoers") || d.contains("nopasswd") {
                ("privilege-escalation", "T1548.003")
            } else {
                ("persistence", "T1136")
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
    }
}

/// Pure: order observations chronologically (UTC) and map them to timeline
/// events. Stable sort → equal timestamps keep input order.
pub fn assemble_timeline(mut obs: Vec<RawObservation>) -> Vec<NewTimelineEvent> {
    obs.sort_by(|a, b| a.ts.cmp(&b.ts));
    obs.iter().map(to_timeline_event).collect()
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

/// Pure: map a Sysmon event (EventData object `inner`) to an observation.
/// Covers ProcessCreate (1) and NetworkConnect (3) — the timeline backbone.
pub fn obs_from_sysmon(
    eventid: &str,
    inner: &Value,
    asset: &str,
    ts: DateTime<Utc>,
) -> Option<RawObservation> {
    match eventid {
        "1" => {
            let cmd = jstr(inner, "CommandLine").or_else(|| jstr(inner, "Image"))?;
            Some(RawObservation {
                ts,
                kind: ObsKind::ProcessCreate,
                asset: asset.into(),
                actor: jstr(inner, "ParentImage").map(String::from),
                detail: cmd.into(),
                ioc: jstr(inner, "Hashes").map(String::from),
                source: "osquery.sysmon".into(),
            })
        }
        "3" => {
            let dip = jstr(inner, "DestinationIp")?;
            let dport = jstr(inner, "DestinationPort").unwrap_or("");
            Some(RawObservation {
                ts,
                kind: ObsKind::NetworkConnect,
                asset: asset.into(),
                actor: jstr(inner, "Image").map(String::from),
                detail: format!("{dip}:{dport}"),
                ioc: Some(dip.into()),
                source: "osquery.sysmon".into(),
            })
        }
        _ => None,
    }
}

/// Edge (I/O): read recent osquery/sysmon logs for an asset and map them to
/// observations. Server-side parsing — only rows, never raw artifacts.
pub async fn collect_observations_from_logs(
    store: &dyn Database,
    asset: &str,
    minutes_back: i64,
) -> Vec<RawObservation> {
    let mut out = Vec::new();
    let logs = store
        .query_logs(minutes_back, Some(asset), Some("osquery.sysmon"), 5000)
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
        if let Some(o) = obs_from_sysmon(eventid, inner, asset, ts) {
            out.push(o);
        }
    }
    out
}

/// Run DFIR triage for one incident: assemble the forensic timeline from ingested
/// telemetry and persist it. Idempotent — stamps `dfir_collected_at` so it runs
/// once per incident. Non-fatal (never breaks the caller).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(kind: ObsKind, detail: &str, age_secs: i64) -> RawObservation {
        let base = DateTime::parse_from_rfc3339("2026-06-22T12:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        RawObservation {
            ts: base - chrono::Duration::seconds(age_secs),
            kind,
            asset: "WIN-01".into(),
            actor: None,
            detail: detail.into(),
            ioc: None,
            source: "osquery.sysmon".into(),
        }
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
        let inner = serde_json::json!({"TargetFilename": "C:\\x"});
        assert!(obs_from_sysmon("11", &inner, "WIN-01", ts()).is_none());
        // eventid 1 with no cmdline/image → also skipped (no usable detail)
        assert!(obs_from_sysmon("1", &serde_json::json!({"User": "x"}), "WIN-01", ts()).is_none());
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

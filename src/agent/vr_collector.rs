//! DFIR Velociraptor auto-collect (Chantier 2).
//!
//! Two background workers that race the destruction of an endpoint after an
//! incident fires, then fold the preserved evidence into the SAME DFIR pipeline
//! as native telemetry (timeline / attack graph / kill-chain):
//!
//! - [`run_vr_preservation_trigger`] — at T0 (fast poll), for each open HIGH+
//!   incident on a Velociraptor-enrolled host, schedule a small set of
//!   **volatile** read-only collections (process list, network, persistence).
//!   The host may be wiped/encrypted minutes later — we grab the volatile state
//!   while the client still answers.
//! - [`run_vr_collection_ingest`] — poll the scheduled flows; when a flow is
//!   FINISHED, read its rows, map the **high-signal** subset to
//!   [`RawObservation`]s (source-tagged `velociraptor:*`), persist them into the
//!   incident's `forensic_timeline`, and re-assess the kill-chain (upgrade-only
//!   severity escalation). The attack graph rebuilds from the timeline on read.
//!
//! Everything goes through the **skill connector** (gRPC, investigator role,
//! read-only). No new config, no new dependency. Heavy collections (full triage,
//! RAM image, fleet hunts) stay manual (analyst buttons, Chantier 2 incr 5).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;

use crate::agent::dfir_triage::{ObsKind, RawObservation, assemble_timeline, assess_killchain};
use crate::connectors::velociraptor;
use crate::db::Database;

/// T0 trigger cadence — ~20s is effectively immediate against a wipe that takes
/// minutes, without touching every incident-create site.
const TRIGGER_INTERVAL: Duration = Duration::from_secs(20);
/// Ingest cadence — VR collections finish in seconds to a couple of minutes.
const INGEST_INTERVAL: Duration = Duration::from_secs(30);
/// A collection stuck beyond this is declared failed (client offline / wiped).
const COLLECTION_TIMEOUT: chrono::Duration = chrono::Duration::minutes(10);
/// Global rate-limit: never schedule more than this many collections per minute
/// (a mass-incident event must not trigger a collection storm across the fleet).
const MAX_COLLECTIONS_PER_MIN: i64 = 60;

/// Volatile, read-only artifacts to grab at T0, by OS family. These disappear on
/// reboot/wipe, are cheap, and need only the `investigator` role.
fn volatile_artifacts(os: &str) -> &'static [&'static str] {
    if os.contains("windows") {
        &[
            "Windows.System.Pslist",
            "Windows.Network.Netstat",
            "Windows.Sysinternals.Autoruns",
        ]
    } else {
        // linux / darwin
        &[
            "Linux.Sys.Pslist",
            "Linux.Network.NetstatEnriched",
            "Linux.Sys.Crontab",
        ]
    }
}

// ── Trigger (T0 preservation) ───────────────────────────────────────────────

pub async fn run_vr_preservation_trigger(store: Arc<dyn Database>) {
    loop {
        tokio::time::sleep(TRIGGER_INTERVAL).await;

        // Cheap SQL first — nothing to do if no HIGH+ incident is awaiting VR.
        let pending = match store.list_incidents_needing_vr_preservation(20).await {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!("VR trigger: list failed (or unsupported): {e}");
                continue;
            }
        };
        // Only now hit the connector: is Velociraptor actually configured?
        if !velociraptor::is_configured(store.as_ref()).await {
            continue; // skill not set up — leave incidents unmarked, retry later
        }
        // Storm guard.
        if store.count_recent_dfir_collections(60).await.unwrap_or(0) >= MAX_COLLECTIONS_PER_MIN {
            tracing::warn!("VR trigger: rate limit hit, deferring preservation this cycle");
            continue;
        }

        for (incident_id, asset, _sev) in pending {
            preserve_incident(store.as_ref(), incident_id, &asset).await;
        }
    }
}

/// Schedule the volatile collection set for one incident's host (once).
async fn preserve_incident(store: &dyn Database, incident_id: i32, asset: &str) {
    match velociraptor::resolve_client(store, asset).await {
        Ok(Some((client_id, os))) => {
            for artifact in volatile_artifacts(&os) {
                match velociraptor::tool_collect(store, &client_id, artifact).await {
                    Ok(resp) => {
                        let flow_id = resp.get("flow_id").and_then(|v| v.as_str());
                        let _ = store
                            .insert_dfir_collection(
                                incident_id,
                                Some(&client_id),
                                artifact,
                                flow_id,
                                "collecting",
                                "auto",
                            )
                            .await;
                        tracing::info!(
                            "VR preserve: incident #{incident_id} {asset} → {artifact} ({flow_id:?})"
                        );
                    }
                    Err(e) => {
                        let _ = store
                            .insert_dfir_collection(
                                incident_id,
                                Some(&client_id),
                                artifact,
                                None,
                                "failed",
                                "auto",
                            )
                            .await;
                        tracing::warn!("VR preserve: collect {artifact} failed: {e}");
                    }
                }
            }
        }
        Ok(None) => {
            // Not a Velociraptor client — mark once so we don't re-scan it forever.
            let _ = store
                .insert_dfir_collection(incident_id, None, "-", None, "no_client", "auto")
                .await;
        }
        Err(e) => tracing::debug!("VR preserve: resolve_client({asset}) failed: {e}"),
    }
}

// ── Ingest (fold finished flows into the timeline) ──────────────────────────

pub async fn run_vr_collection_ingest(store: Arc<dyn Database>) {
    loop {
        tokio::time::sleep(INGEST_INTERVAL).await;

        let collecting = match store.list_dfir_collections_collecting(50).await {
            Ok(c) if !c.is_empty() => c,
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!("VR ingest: list failed (or unsupported): {e}");
                continue;
            }
        };
        if !velociraptor::is_configured(store.as_ref()).await {
            continue;
        }

        for c in collecting {
            let (Some(client_id), Some(flow_id)) = (c.client_id.clone(), c.flow_id.clone()) else {
                let _ = store
                    .mark_dfir_collection(c.id, "failed", None, Some("missing client/flow id"))
                    .await;
                continue;
            };
            ingest_one(store.as_ref(), &c, &client_id, &flow_id).await;
        }
    }
}

async fn ingest_one(
    store: &dyn Database,
    c: &crate::db::threatclaw_store::DfirCollection,
    client_id: &str,
    flow_id: &str,
) {
    let state = velociraptor::flow_state(store, client_id, flow_id)
        .await
        .unwrap_or_else(|_| "UNKNOWN".to_string());
    match state.as_str() {
        "FINISHED" => {}
        "ERROR" => {
            let _ = store
                .mark_dfir_collection(c.id, "failed", None, Some("flow ERROR"))
                .await;
            return;
        }
        _ => {
            // Still RUNNING. Give up if the host has gone dark past the timeout
            // (wiped/offline → the flow will never finish), else retry next cycle.
            let stuck = chrono::DateTime::parse_from_rfc3339(&c.requested_at)
                .map(|t| {
                    Utc::now().signed_duration_since(t.with_timezone(&Utc)) > COLLECTION_TIMEOUT
                })
                .unwrap_or(false);
            if stuck {
                let _ = store
                    .mark_dfir_collection(c.id, "failed", None, Some("timeout (host offline?)"))
                    .await;
            }
            return;
        }
    }

    let rows = match velociraptor::read_flow_source(store, client_id, flow_id, &c.artifact).await {
        Ok(r) => r,
        Err(e) => {
            let _ = store
                .mark_dfir_collection(c.id, "failed", None, Some(&format!("read source: {e}")))
                .await;
            return;
        }
    };

    // Resolve the incident's asset for the observation label.
    let asset = store
        .get_incident(c.incident_id)
        .await
        .ok()
        .flatten()
        .and_then(|i| i.get("asset").and_then(|v| v.as_str()).map(String::from))
        .unwrap_or_default();

    let obs = map_collection(&c.artifact, &rows, &asset);
    let n = obs.len() as i32;
    if !obs.is_empty() {
        let events = assemble_timeline(obs);
        if let Err(e) = store.insert_timeline_events(c.incident_id, &events).await {
            let _ = store
                .mark_dfir_collection(c.id, "failed", None, Some(&format!("insert: {e}")))
                .await;
            return;
        }
        // Re-assess the kill-chain on the FULL (telemetry + VR) timeline — VR may
        // reveal a stage the ingested telemetry missed. Upgrade-only, audited.
        reassess_killchain(store, c.incident_id).await;
    }
    let _ = store
        .mark_dfir_collection(c.id, "done", Some(n), None)
        .await;
    tracing::info!(
        "VR ingest: incident #{} {} → {n} event(s) from {}",
        c.incident_id,
        asset,
        c.artifact
    );
}

/// Re-run the kill-chain assessment over the incident's full timeline and escalate
/// severity if warranted. Reuses the same machinery as the native DFIR collector.
async fn reassess_killchain(store: &dyn Database, incident_id: i32) {
    let Ok(events) = store.list_timeline_for_incident(incident_id).await else {
        return;
    };
    // assess_killchain works on NewTimelineEvent; rebuild the minimal shape it reads.
    let as_new: Vec<crate::db::threatclaw_store::NewTimelineEvent> = events
        .iter()
        .map(|e| crate::db::threatclaw_store::NewTimelineEvent {
            ts: e.ts.clone(),
            tz_origin: None,
            event_type: e.event_type.clone(),
            asset: e.asset.clone(),
            actor: e.actor.clone(),
            description: e.description.clone(),
            severity: e.severity.clone(),
            mitre_tactic: e.mitre_tactic.clone(),
            mitre_technique: e.mitre_technique.clone(),
            ioc: e.ioc.clone(),
            related_artifacts: vec![],
            source_artifact: e.source_artifact.clone(),
            collected_hash: None,
            proc_guid: e.proc_guid.clone(),
            parent_guid: e.parent_guid.clone(),
            related_to: e.related_to.clone(),
        })
        .collect();
    if let Some((sev, reason)) = assess_killchain(&as_new) {
        match store
            .escalate_incident_severity(incident_id, sev, &reason)
            .await
        {
            Ok(n) if n > 0 => tracing::info!(
                "VR ingest: incident #{incident_id} escalated to {sev} (VR evidence) — {reason}"
            ),
            _ => {}
        }
    }
}

// ── Pure mappers: VR rows → high-signal RawObservations ─────────────────────

/// Dispatch a finished collection's rows to the right mapper.
pub fn map_collection(artifact: &str, rows: &[Value], asset: &str) -> Vec<RawObservation> {
    match artifact {
        "Linux.Sys.Pslist" | "Windows.System.Pslist" => obs_from_pslist(rows, asset, artifact),
        "Linux.Network.NetstatEnriched" | "Windows.Network.Netstat" => {
            obs_from_netstat(rows, asset, artifact)
        }
        "Linux.Sys.Crontab" => obs_from_crontab(rows, asset, artifact),
        "Windows.Sysinternals.Autoruns" => obs_from_autoruns(rows, asset, artifact),
        _ => Vec::new(),
    }
}

/// True for paths attackers favour for dropped payloads (world-writable / temp /
/// hidden). Mirrors the connector's `is_suspicious_path` philosophy.
fn is_suspicious_path(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    l.starts_with("/tmp/")
        || l.starts_with("/var/tmp/")
        || l.starts_with("/dev/shm/")
        || l.contains("\\temp\\")
        || l.contains("\\appdata\\local\\temp\\")
        || l.contains("\\users\\public\\")
        || (l.starts_with("/home/") && l.contains("/."))
}

/// Routable remote peer (not loopback / unspecified / RFC1918 / link-local).
/// Conservative: only clearly-external peers are surfaced as C2-shaped events.
fn is_external_ip(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return !(v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_multicast()
            || v4.is_broadcast());
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        return !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast());
    }
    false
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty())
}

/// Pslist → ProcessCreate, but ONLY for processes running from a suspicious path
/// (we don't flood the timeline with the full process table — the raw collection
/// stays in Velociraptor for drill-down).
fn obs_from_pslist(rows: &[Value], asset: &str, artifact: &str) -> Vec<RawObservation> {
    let src = format!("velociraptor:{artifact}");
    let mut out = Vec::new();
    for r in rows {
        let exe = s(r, "Exe").unwrap_or("");
        let cmd = s(r, "CommandLine").unwrap_or("");
        let name = s(r, "Name").unwrap_or("?");
        if !is_suspicious_path(exe) && !is_suspicious_path(cmd) {
            continue;
        }
        let mut o = RawObservation::base(Utc::now(), ObsKind::ProcessCreate, asset, &src);
        o.actor = s(r, "Username").map(String::from);
        o.detail = if cmd.is_empty() {
            format!("Process en chemin suspect : {name} ({exe})")
        } else {
            cmd.to_string()
        };
        o.ioc = r
            .get("Hash")
            .and_then(|h| h.get("SHA256"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        out.push(o);
    }
    out
}

/// Netstat → NetworkConnect for ESTABLISHED sessions to an external peer, plus
/// LISTEN on known reverse-shell ports.
fn obs_from_netstat(rows: &[Value], asset: &str, artifact: &str) -> Vec<RawObservation> {
    const REV_SHELL_PORTS: &[i64] = &[
        1234, 1337, 4444, 4445, 5554, 5555, 6666, 7777, 8888, 9001, 9002, 9999, 12345, 31337, 54321,
    ];
    let src = format!("velociraptor:{artifact}");
    let mut out = Vec::new();
    for r in rows {
        let status = s(r, "Status").unwrap_or("");
        let raddr = s(r, "Raddr").unwrap_or("");
        let rport = r.get("Rport").and_then(|v| v.as_i64()).unwrap_or(0);
        let lport = r.get("Lport").and_then(|v| v.as_i64()).unwrap_or(0);
        let pname = r
            .get("ProcInfo")
            .and_then(|p| p.get("Name"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        if status.eq_ignore_ascii_case("ESTABLISHED") && is_external_ip(raddr) {
            let mut o = RawObservation::base(Utc::now(), ObsKind::NetworkConnect, asset, &src);
            o.detail = format!("Connexion sortante établie : {raddr}:{rport} ({pname})");
            o.ioc = Some(raddr.to_string());
            o.related_to = Some(raddr.to_string());
            out.push(o);
        } else if status.eq_ignore_ascii_case("LISTEN") && REV_SHELL_PORTS.contains(&lport) {
            let laddr = s(r, "Laddr").unwrap_or("0.0.0.0");
            let mut o = RawObservation::base(Utc::now(), ObsKind::NetworkConnect, asset, &src);
            o.detail = format!("Port en écoute suspect : {laddr}:{lport} ({pname})");
            o.ioc = Some(lport.to_string());
            out.push(o);
        }
    }
    out
}

/// Crontab → Persistence (all entries; the artifact is already curated/low-volume).
fn obs_from_crontab(rows: &[Value], asset: &str, artifact: &str) -> Vec<RawObservation> {
    let src = format!("velociraptor:{artifact}");
    rows.iter()
        .filter_map(|r| {
            let cmd = s(r, "Command")
                .or_else(|| s(r, "Line"))
                .or_else(|| s(r, "Raw"))?;
            let mut o = RawObservation::base(Utc::now(), ObsKind::Persistence, asset, &src);
            // "cron" token → label_mitre maps to T1053.003.
            o.detail = format!("Tâche cron : {cmd}");
            o.related_to = s(r, "Path").map(String::from);
            Some(o)
        })
        .collect()
}

/// Autoruns (Windows) → Persistence. The artifact already enumerates only
/// autostart entries, so we surface them all and let label_mitre classify.
fn obs_from_autoruns(rows: &[Value], asset: &str, artifact: &str) -> Vec<RawObservation> {
    let src = format!("velociraptor:{artifact}");
    rows.iter()
        .filter_map(|r| {
            let entry = s(r, "Entry")
                .or_else(|| s(r, "ImagePath"))
                .or_else(|| s(r, "Image"))?;
            let location = s(r, "EntryLocation")
                .or_else(|| s(r, "Category"))
                .unwrap_or("autorun");
            let mut o = RawObservation::base(Utc::now(), ObsKind::Persistence, asset, &src);
            o.detail = format!("Autorun ({location}) : {entry}");
            o.related_to = s(r, "ImagePath").map(String::from);
            Some(o)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pslist_maps_only_suspicious_paths() {
        let rows = vec![
            serde_json::json!({"Name":"systemd","Exe":"/usr/lib/systemd/systemd","CommandLine":"/sbin/init","Username":"root"}),
            serde_json::json!({"Name":"evil","Exe":"/tmp/evil","CommandLine":"/tmp/evil 600","Username":"root","Hash":{"SHA256":"abc123"}}),
        ];
        let obs = obs_from_pslist(&rows, "H", "Linux.Sys.Pslist");
        assert_eq!(obs.len(), 1, "only the /tmp process is surfaced");
        assert_eq!(obs[0].kind, ObsKind::ProcessCreate);
        assert_eq!(obs[0].ioc.as_deref(), Some("abc123"));
        assert!(obs[0].source.starts_with("velociraptor:"));
    }

    #[test]
    fn netstat_maps_external_established_and_revshell_listen() {
        let rows = vec![
            // loopback established — ignored
            serde_json::json!({"Status":"ESTABLISHED","Raddr":"127.0.0.1","Rport":443,"ProcInfo":{"Name":"x"}}),
            // RFC1918 established — ignored
            serde_json::json!({"Status":"ESTABLISHED","Raddr":"10.0.0.5","Rport":443,"ProcInfo":{"Name":"y"}}),
            // external established — mapped
            serde_json::json!({"Status":"ESTABLISHED","Raddr":"185.199.108.153","Rport":443,"ProcInfo":{"Name":"curl"}}),
            // reverse-shell listener — mapped
            serde_json::json!({"Status":"LISTEN","Laddr":"0.0.0.0","Lport":4444,"ProcInfo":{"Name":"nc"}}),
            // benign listener — ignored
            serde_json::json!({"Status":"LISTEN","Laddr":"0.0.0.0","Lport":443,"ProcInfo":{"Name":"nginx"}}),
        ];
        let obs = obs_from_netstat(&rows, "H", "Linux.Network.NetstatEnriched");
        assert_eq!(obs.len(), 2);
        assert!(obs.iter().all(|o| o.kind == ObsKind::NetworkConnect));
        assert!(
            obs.iter()
                .any(|o| o.ioc.as_deref() == Some("185.199.108.153"))
        );
        assert!(obs.iter().any(|o| o.ioc.as_deref() == Some("4444")));
    }

    #[test]
    fn crontab_maps_to_persistence() {
        let rows = vec![serde_json::json!({"Command":"/tmp/backdoor.sh","Path":"/etc/cron.d/x"})];
        let obs = obs_from_crontab(&rows, "H", "Linux.Sys.Crontab");
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].kind, ObsKind::Persistence);
        assert!(obs[0].detail.to_lowercase().contains("cron"));
    }

    #[test]
    fn external_ip_classification() {
        assert!(is_external_ip("185.199.108.153"));
        assert!(!is_external_ip("10.0.0.5"));
        assert!(!is_external_ip("192.168.1.1"));
        assert!(!is_external_ip("127.0.0.1"));
        assert!(!is_external_ip(""));
    }
}

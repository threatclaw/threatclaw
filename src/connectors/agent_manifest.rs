//! Agent manifest — server-pushed list of extra osquery queries that the
//! endpoint agent should run each sync cycle.
//!
//! ## Why
//!
//! The agent installer ships with a baked-in set of "core" queries
//! (software inventory, sockets, etc.). For everything that needs to
//! evolve faster than the agent itself (new event channels, tweaked
//! filters, additional tables exposed by osquery), we don't want to
//! re-deploy the installer on every endpoint. Instead, the agent fetches
//! this manifest from the server at the start of each sync cycle and
//! runs the queries it lists. Adding a new query becomes a server
//! deploy, not a fleet re-install.
//!
//! ## Contract
//!
//! - The agent calls `GET /api/tc/agent/manifest?platform={windows,linux}`
//!   authenticated by the standard webhook token (`X-Webhook-Token`
//!   header or `?token=`).
//! - The server returns a JSON manifest with a `version` (so the agent
//!   can log it) and a `queries` array.
//! - Each query is `{name, query, platforms[]}`. The agent runs only the
//!   queries whose `platforms` includes its own platform.
//! - The agent keys the JSON result under `query.name` in its payload, so
//!   the receiving side (osquery.rs handlers) can dispatch by name.
//!
//! If the manifest fetch fails (network, server down), the agent falls
//! back to its baked-in queries — a manifest-driven new query is
//! "best effort" until the agent observes it once.

use serde::Serialize;

#[derive(Serialize)]
pub struct ManifestQuery {
    pub name: &'static str,
    pub query: &'static str,
    pub platforms: &'static [&'static str],
}

#[derive(Serialize)]
pub struct AgentManifest {
    pub version: &'static str,
    pub queries: &'static [ManifestQuery],
}

/// Bump the version any time the manifest changes — the agent logs it so
/// you can confirm propagation across the fleet without inspecting every
/// host.
pub const MANIFEST_VERSION: &str = "2026-06-12-01";

/// Extra queries pushed to agents.
///
/// Keep the baked-in installer query set MINIMAL (inventory + sockets + core
/// events) and add anything that may evolve here. The receiver in
/// `osquery.rs::process_osquery_webhook` must have a branch for the
/// matching `name` key — otherwise the data is silently dropped.
pub const MANIFEST_QUERIES: &[ManifestQuery] = &[
    ManifestQuery {
        name: "sysmon_events",
        // Channel only exists when Sysmon is installed; osquery just
        // returns an empty array on hosts without Sysmon, so no harm.
        // Sysmon EIDs ingested: 1 (ProcessCreate), 3 (NetworkConnect),
        // 7 (ImageLoad), 8 (CreateRemoteThread), 10 (ProcessAccess),
        // 11 (FileCreate), 22 (DnsQuery). Limit kept generous because
        // Sysmon EID 1 alone can hit 50/min on a busy host.
        query: "SELECT datetime, eventid, data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (1,3,7,8,10,11,22) AND datetime > datetime('now', '-6 minutes') LIMIT 300;",
        platforms: &["windows"],
    },
    ManifestQuery {
        name: "windows_firewall_events",
        // Channel "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
        // — rule add/modify/delete, profile change, blocked connections.
        query: "SELECT datetime, eventid, data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' AND datetime > datetime('now', '-6 minutes') LIMIT 100;",
        platforms: &["windows"],
    },
];

pub fn manifest_json(platform: &str) -> serde_json::Value {
    let filtered: Vec<_> = MANIFEST_QUERIES
        .iter()
        .filter(|q| q.platforms.iter().any(|p| *p == platform))
        .map(|q| {
            serde_json::json!({
                "name": q.name,
                "query": q.query,
                "platforms": q.platforms,
            })
        })
        .collect();

    serde_json::json!({
        "version": MANIFEST_VERSION,
        "queries": filtered,
    })
}

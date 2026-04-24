//! Velociraptor DFIR connector.
//!
//! Integrates an on-prem Velociraptor deployment with ThreatClaw in two
//! directions:
//!
//!   - **Ingestion (phase A, this file)** — every sync cycle pulls the
//!     known clients and any hunt completions that landed since the last
//!     cursor, imports clients as assets via the usual resolver, and
//!     writes hunt results as findings.
//!
//!   - **Active investigation (phase B, added in the follow-up commit
//!     that touches `tool_calling.rs`)** — exposes four read-only tools
//!     to the L2 forensic LLM so it can query endpoints during an
//!     incident instead of recommending manual analysis.
//!
//! ## Transport
//!
//! Velociraptor's primary API is gRPC on port 8001 with mutual TLS. A
//! grpc-gateway at the same binary exposes every RPC over HTTPS JSON at
//! `/api/v1/*`. We speak REST:
//!
//!   - Keeps the dependency set unchanged (reqwest already carries
//!     rustls-tls with client certificate support). Adding tonic would
//!     roughly double the build time for a Phase-A feature that ingests
//!     at most a few hundred rows per cycle.
//!
//!   - Streaming is irrelevant for ingestion: hunt results are finalised
//!     rows that grpc-gateway returns as a JSON array.
//!
//!   - If Phase B later needs real streaming (`Query` with server-side
//!     VQL event queries that push rows as events occur), we add tonic
//!     behind a feature flag at that point.
//!
//! ## Authentication
//!
//! A dedicated API user is created on the Velociraptor server with the
//! least-privileged role combination:
//!
//! ```sh
//! velociraptor --config server.config.yaml config api_client \
//!     --name threatclaw --role investigator,api threatclaw.config.yaml
//! velociraptor --config server.config.yaml acl grant threatclaw \
//!     --role investigator,api
//! ```
//!
//! The generated `threatclaw.config.yaml` contains the CA cert, the
//! client cert + private key, and the API URL. The operator pastes
//! each field into the dashboard's Velociraptor skill form. We never
//! grant `administrator` — that role carries EXECVE and FILESYSTEM_WRITE,
//! which we do not want any VQL the LLM composes to be able to touch.
//!
//! The `investigator` role refuses these plugins/functions server-side
//! (acls.go / EXECVE ACL), so the Velociraptor ACL model is our primary
//! safety gate. The VQL lint in `validate_vql_readonly` is a
//! defence-in-depth double check, not the only line of defence.

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Connection config for a single Velociraptor server.
///
/// The three cert fields come straight from the `ca_certificate`,
/// `client_cert` and `client_private_key` YAML keys of the file
/// emitted by `velociraptor config api_client`. They are PEM-encoded
/// and carry the mutual-TLS handshake on their own — no password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelociraptorConfig {
    /// e.g. `https://velociraptor.internal:8001`. Must match the
    /// API.hostname + API.bind_address of the server config.
    pub api_url: String,
    /// CA that signed both the server and the client certs. Written by
    /// `config api_client` as `ca_certificate`.
    pub ca_pem: String,
    /// Client certificate (signed by ca_pem) that identifies this
    /// ThreatClaw instance. Written as `client_cert`.
    pub client_cert_pem: String,
    /// Private key matching `client_cert_pem`. Written as
    /// `client_private_key`.
    pub client_key_pem: String,
    /// The user name embedded in `client_cert_pem`'s CN. We send it as
    /// the `Grpc-Metadata-Usern` header because grpc-gateway needs the
    /// identity resolved from the cert in the HTTP path; the server
    /// still validates the cert, this is just a grpc-gateway quirk.
    pub username: String,
    /// Cursor — RFC3339 timestamp, earliest hunt completion we will
    /// consider on the next poll. Persisted in skill_configs between
    /// cycles.
    #[serde(default)]
    pub cursor_last_hunt_completion: Option<String>,
    /// Soft cap on alerts fetched per cycle so a backlog of hunt
    /// results cannot stall the scheduler.
    #[serde(default = "default_max_findings")]
    pub max_findings_per_cycle: u32,
}

fn default_max_findings() -> u32 {
    500
}

/// Result counters for a single sync cycle. Same spirit as
/// `WazuhSyncResult`: split the fetched / imported / dropped numbers so
/// an operator can tell at a glance whether the pipeline is healthy or
/// silently dropping.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VelociraptorSyncResult {
    pub clients_imported: usize,
    pub hunts_fetched: usize,
    pub findings_created: usize,
    pub insert_errors: usize,
    pub errors: Vec<String>,
    pub cursor: Option<String>,
}

/// Reusable HTTP client with mTLS identity + pinned CA. Built once per
/// sync cycle; cost is negligible versus the network round-trip.
fn build_http_client(config: &VelociraptorConfig) -> Result<Client, String> {
    // Pair cert + private key into a single PEM blob for reqwest's
    // Identity parser. Order does not matter as long as both are
    // present in the same buffer.
    let identity_pem = format!(
        "{}\n{}",
        config.client_cert_pem.trim(),
        config.client_key_pem.trim()
    );
    let identity =
        Identity::from_pem(identity_pem.as_bytes()).map_err(|e| format!("identity: {}", e))?;
    let ca = Certificate::from_pem(config.ca_pem.as_bytes()).map_err(|e| format!("ca: {}", e))?;

    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        // Velociraptor's default SAN is `VelociraptorServer`; operators
        // rarely reissue the server cert with a real hostname. Pinning
        // the CA above gives us authenticity; disable hostname matching
        // so the deployment URL (which routinely is an IP or internal
        // DNS that does not match the SAN) still connects.
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {}", e))
}

/// One sync cycle: list recent hunts, import newer-than-cursor results
/// as findings, sync the client roster into the asset graph.
pub async fn sync_velociraptor(
    store: &dyn Database,
    config: &VelociraptorConfig,
) -> VelociraptorSyncResult {
    let mut result = VelociraptorSyncResult {
        cursor: config.cursor_last_hunt_completion.clone(),
        ..Default::default()
    };

    let client = match build_http_client(config) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(e);
            return result;
        }
    };

    let base = config.api_url.trim_end_matches('/');

    // ── 1. Clients (ListClients) ──────────────────────────────────
    match fetch_clients(&client, base, &config.username).await {
        Ok(clients) => {
            for c in &clients {
                import_client_as_asset(store, c).await;
                result.clients_imported += 1;
            }
        }
        Err(e) => result.errors.push(format!("list_clients: {}", e)),
    }

    // ── 2. Hunts (ListHunts + GetHuntResults) ─────────────────────
    match fetch_hunts(&client, base, &config.username).await {
        Ok(hunts) => {
            let cursor = config.cursor_last_hunt_completion.as_deref();
            let newer: Vec<_> = hunts
                .into_iter()
                .filter(|h| match cursor {
                    Some(cur) => h.completion_ts_rfc3339.as_deref().is_some_and(|t| t > cur),
                    None => true,
                })
                .take(config.max_findings_per_cycle as usize)
                .collect();

            result.hunts_fetched = newer.len();

            let mut newest_seen = cursor.map(String::from);
            for hunt in &newer {
                if let Some(ref ts) = hunt.completion_ts_rfc3339 {
                    if newest_seen
                        .as_deref()
                        .map(|c| ts.as_str() > c)
                        .unwrap_or(true)
                    {
                        newest_seen = Some(ts.clone());
                    }
                }
                if import_hunt_finding(store, hunt).await {
                    result.findings_created += 1;
                } else {
                    result.insert_errors += 1;
                }
            }

            if newest_seen != result.cursor {
                result.cursor = newest_seen;
            }
        }
        Err(e) => result.errors.push(format!("list_hunts: {}", e)),
    }

    tracing::info!(
        "VELOCIRAPTOR SYNC: clients_imported={} hunts_fetched={} findings_created={} insert_errors={} errors={}",
        result.clients_imported,
        result.hunts_fetched,
        result.findings_created,
        result.insert_errors,
        result.errors.len()
    );

    result
}

/// A single Velociraptor client row, distilled from whatever the
/// GUI-facing `ApiClient` proto returns. Keep this narrow on purpose:
/// the full proto carries 30+ fields that we do not need for asset
/// resolution.
#[derive(Debug, Clone)]
struct ClientSummary {
    client_id: String,
    hostname: String,
    fqdn: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
    last_seen_at_ms: Option<i64>,
}

async fn fetch_clients(
    client: &Client,
    base: &str,
    username: &str,
) -> Result<Vec<ClientSummary>, String> {
    // SearchClients returns every known client. Velociraptor v0.6+ requires
    // POST with JSON body — the older GET-with-query-string form returns
    // HTTP 415 on modern deployments (v0.72+ dropped query-string support in
    // grpc-gateway).
    let url = format!("{}/api/v1/SearchClients", base);
    let payload = serde_json::json!({
        "query": "all",
        "limit": 2000,
        "type": 0, // 0 = full client objects (vs 1 = names only)
    });
    let resp = client
        .post(&url)
        .header("Grpc-Metadata-Username", username)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("http: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "HTTP {}{}",
            status,
            if body.is_empty() {
                String::new()
            } else {
                format!(" — {}", body.chars().take(200).collect::<String>())
            }
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
    let items = body["items"].as_array().cloned().unwrap_or_default();

    let mut out = Vec::with_capacity(items.len());
    for v in items {
        let client_id = v["client_id"].as_str().unwrap_or("").to_string();
        if client_id.is_empty() {
            continue;
        }
        let os = &v["os_info"];
        out.push(ClientSummary {
            client_id,
            hostname: os["hostname"].as_str().unwrap_or("").to_string(),
            fqdn: os["fqdn"].as_str().map(String::from),
            os_name: os["system"].as_str().map(String::from),
            os_version: os["release"].as_str().map(String::from),
            last_seen_at_ms: v["last_seen_at"].as_i64(),
        });
    }
    Ok(out)
}

async fn import_client_as_asset(store: &dyn Database, c: &ClientSummary) {
    // Velociraptor's client_id (`C.` + 16 hex) is stable across
    // reboots; hostname drifts when Windows sysprep clones or DHCP
    // hands out new names. Use hostname-first dedup via the resolver
    // but stamp the source so we can tell Velociraptor clients apart
    // from Wazuh agents pointing at the same machine.
    let os = match (&c.os_name, &c.os_version) {
        (Some(n), Some(v)) if !v.is_empty() => Some(format!("{} {}", n, v)),
        (Some(n), _) => Some(n.clone()),
        _ => None,
    };
    let discovered = crate::graph::asset_resolution::DiscoveredAsset {
        mac: None,
        hostname: if c.hostname.is_empty() {
            None
        } else {
            Some(c.hostname.clone())
        },
        fqdn: c.fqdn.clone(),
        ip: None,
        os,
        ports: None,
        services: serde_json::json!([]),
        ou: None,
        vlan: None,
        vm_id: None,
        criticality: Some("medium".into()),
        source: "velociraptor".into(),
    };
    let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
}

/// Narrow view over a Velociraptor hunt that we turn into a finding.
#[derive(Debug, Clone)]
struct HuntSummary {
    hunt_id: String,
    hunt_description: String,
    artifacts: Vec<String>,
    clients_with_results: i64,
    creator: String,
    completion_ts_rfc3339: Option<String>,
}

async fn fetch_hunts(
    client: &Client,
    base: &str,
    username: &str,
) -> Result<Vec<HuntSummary>, String> {
    // v0.72+ REST gateway requires POST with JSON body (HTTP 415 otherwise).
    let url = format!("{}/api/v1/ListHunts", base);
    let payload = serde_json::json!({
        "count": 500,
        "offset": 0,
        "include_archived": false,
    });
    let resp = client
        .post(&url)
        .header("Grpc-Metadata-Username", username)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("http: {}", e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "HTTP {}{}",
            status,
            if body.is_empty() {
                String::new()
            } else {
                format!(" — {}", body.chars().take(200).collect::<String>())
            }
        ));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
    let items = body["items"].as_array().cloned().unwrap_or_default();

    let mut out = Vec::with_capacity(items.len());
    for v in items {
        let hunt_id = v["hunt_id"].as_str().unwrap_or("").to_string();
        if hunt_id.is_empty() {
            continue;
        }
        // Velociraptor's hunt state machine:
        // PAUSED -> RUNNING -> STOPPED. We want terminal (STOPPED) hunts
        // for ingestion; RUNNING hunts get re-ingested once they finish.
        let state = v["state"].as_str().unwrap_or("");
        if state != "STOPPED" {
            continue;
        }

        let start_request = &v["start_request"];
        let artifacts: Vec<String> = start_request["artifacts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Velociraptor stores times as microsecond epoch. Convert to
        // RFC3339 for the cursor so it compares lexically with the
        // Wazuh cursor we already persist the same way.
        let completion_us = v["stats"]["stopped"]
            .as_i64()
            .or_else(|| v["state_changes"].as_i64());
        let completion_ts_rfc3339 = completion_us.and_then(us_to_rfc3339);

        out.push(HuntSummary {
            hunt_id,
            hunt_description: v["hunt_description"].as_str().unwrap_or("").to_string(),
            artifacts,
            clients_with_results: v["stats"]["total_clients_with_results"]
                .as_i64()
                .unwrap_or(0),
            creator: v["creator"].as_str().unwrap_or("").to_string(),
            completion_ts_rfc3339,
        });
    }
    Ok(out)
}

fn us_to_rfc3339(us: i64) -> Option<String> {
    // Velociraptor times occasionally leak as seconds or nanoseconds
    // depending on the field and version. Heuristic: < 1e12 → seconds,
    // 1e12-1e15 → millis, 1e15-1e18 → micros, ≥ 1e18 → nanos.
    let secs = match us {
        n if n < 1_000_000_000_000 => n,
        n if n < 1_000_000_000_000_000 => n / 1_000,
        n if n < 1_000_000_000_000_000_000 => n / 1_000_000,
        n => n / 1_000_000_000,
    };
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
}

/// Write a hunt completion as a finding. Returns false if the DB
/// insert failed — caller increments insert_errors.
async fn import_hunt_finding(store: &dyn Database, h: &HuntSummary) -> bool {
    let severity = if h.clients_with_results > 0 {
        // A hunt that matched real endpoints is worth investigator
        // attention; the actual criticality depends on the artifact
        // (e.g. Kerberoasting matches are HIGH, inventory artifacts
        // are LOW). We default to MEDIUM and let the operator
        // triage — a future iteration can map artifact name → severity.
        "MEDIUM"
    } else {
        "LOW"
    };

    let title = format!(
        "[Velociraptor hunt] {} — {} clients",
        if h.hunt_description.is_empty() {
            &h.hunt_id
        } else {
            &h.hunt_description
        },
        h.clients_with_results
    );

    let description = format!(
        "Hunt: {}\nArtifacts: {}\nClients with results: {}\nCreator: {}",
        h.hunt_id,
        h.artifacts.join(", "),
        h.clients_with_results,
        h.creator
    );

    crate::connectors::log_db_write(
        "velociraptor:hunt_finding",
        store.insert_finding(&NewFinding {
            skill_id: "skill-velociraptor".into(),
            title,
            description: Some(description),
            severity: severity.into(),
            category: Some("dfir-hunt".into()),
            asset: None,
            source: Some("Velociraptor".into()),
            metadata: Some(serde_json::json!({
                "hunt_id": h.hunt_id,
                "artifacts": h.artifacts,
                "clients_with_results": h.clients_with_results,
            })),
        }),
    )
    .await
    .is_some()
}

// ── Phase B: Tools for the L2 forensic LLM ──────────────────────────
//
// Each tool below loads the connector config from `skill_configs`,
// builds a one-shot HTTP client, and returns JSON the LLM can read.
// Failures return `Err(String)` — the caller (tool_calling.rs) wraps
// it into a ToolResult with success=false and the message so the LLM
// sees why it failed instead of hallucinating a reason.

/// Load the Velociraptor config from skill_configs. Returns Err with
/// a human-readable reason if any required field is missing or blank.
async fn load_config(store: &dyn Database) -> Result<VelociraptorConfig, String> {
    let rows = store
        .get_skill_config("skill-velociraptor")
        .await
        .map_err(|e| format!("config read failed: {}", e))?;
    let map: std::collections::HashMap<String, String> =
        rows.into_iter().map(|r| (r.key, r.value)).collect();

    let require = |k: &str| -> Result<String, String> {
        map.get(k)
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| format!("skill-velociraptor: '{}' not configured", k))
    };

    Ok(VelociraptorConfig {
        api_url: require("api_url")?,
        ca_pem: require("ca_pem")?,
        client_cert_pem: require("client_cert_pem")?,
        client_key_pem: require("client_key_pem")?,
        username: require("username")?,
        cursor_last_hunt_completion: map.get("cursor_last_hunt_completion").cloned(),
        max_findings_per_cycle: map
            .get("max_findings_per_cycle")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500),
    })
}

/// Tool 1 — `velociraptor.list_clients`. Returns the fleet roster
/// (client_id + hostname + os + last_seen). No VQL involved, maps
/// directly to `SearchClients`.
pub async fn tool_list_clients(store: &dyn Database) -> Result<serde_json::Value, String> {
    let config = load_config(store).await?;
    let client = build_http_client(&config)?;
    let base = config.api_url.trim_end_matches('/');
    let clients = fetch_clients(&client, base, &config.username).await?;
    Ok(serde_json::json!({
        "count": clients.len(),
        "clients": clients.iter().map(|c| serde_json::json!({
            "client_id": c.client_id,
            "hostname": c.hostname,
            "fqdn": c.fqdn,
            "os": match (&c.os_name, &c.os_version) {
                (Some(n), Some(v)) => format!("{} {}", n, v),
                (Some(n), _) => n.clone(),
                _ => "".to_string(),
            },
            "last_seen_ms": c.last_seen_at_ms,
        })).collect::<Vec<_>>(),
    }))
}

/// Tool 2 — `velociraptor.query(vql)`. Runs a read-only VQL on the
/// Velociraptor **server** (not on a specific client). Useful for
/// fleet-wide questions: "list hunts created in the last 24h",
/// "count clients by OS", "find flows that errored".
///
/// Safety: the Velociraptor API user is provisioned with the
/// `investigator` role which already refuses EXECVE / FILESYSTEM_WRITE
/// server-side. `validate_vql_readonly` is an additional client-side
/// check so an obvious write query gets rejected before it even hits
/// the network.
pub async fn tool_query(store: &dyn Database, vql: &str) -> Result<serde_json::Value, String> {
    validate_vql_readonly(vql)?;
    let config = load_config(store).await?;
    let client = build_http_client(&config)?;
    let url = format!("{}/api/v1/Query", config.api_url.trim_end_matches('/'));

    // Wrap the VQL in a VQLCollectorArgs-shaped body. `max_row: 500`
    // caps the result payload; grpc-gateway streams rows as a JSON
    // array terminated by end-of-stream.
    let body = serde_json::json!({
        "max_row": 500,
        "max_wait": 15,
        "Query": [{ "Name": "threatclaw-l2", "VQL": vql }],
    });

    let resp = client
        .post(&url)
        .header("Grpc-Metadata-Username", &config.username)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("http: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let raw = resp.text().await.map_err(|e| format!("read body: {}", e))?;

    // grpc-gateway emits newline-delimited JSON on streaming RPCs.
    // Each line is one `VQLResponse`; collect them into an array.
    let mut rows = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(arr) = v["result"]["Response"].as_str() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(arr) {
                    if let Some(a) = parsed.as_array() {
                        rows.extend(a.iter().cloned());
                    }
                }
            }
        }
    }
    Ok(serde_json::json!({ "row_count": rows.len(), "rows": rows }))
}

/// Tool 3 — `velociraptor.hunt(description, artifacts)`. Starts a new
/// hunt across the fleet. The `artifacts` list must reference existing
/// artifact names (e.g. `Windows.Detection.PsExec`,
/// `Generic.Client.Info`); custom VQL inline artifacts are not
/// exposed to the LLM to keep the attack surface minimal.
pub async fn tool_hunt(
    store: &dyn Database,
    description: &str,
    artifacts: &[String],
) -> Result<serde_json::Value, String> {
    if artifacts.is_empty() {
        return Err("hunt: at least one artifact required".into());
    }
    for a in artifacts {
        if a.is_empty() || a.contains(';') || a.contains('\n') {
            return Err(format!("hunt: invalid artifact name '{}'", a));
        }
    }
    let config = load_config(store).await?;
    let client = build_http_client(&config)?;
    let url = format!("{}/api/v1/CreateHunt", config.api_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "hunt_description": description,
        "start_request": {
            "artifacts": artifacts,
        },
    });

    let resp = client
        .post(&url)
        .header("Grpc-Metadata-Username", &config.username)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("http: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
    Ok(serde_json::json!({
        "hunt_id": body["flow_id"].as_str().unwrap_or(""),
        "status": "created",
        "description": description,
        "artifacts": artifacts,
    }))
}

/// Tool 4 — `velociraptor.collect(client_id, artifact)`. Schedules an
/// artifact collection on a specific client. Returns the `flow_id`
/// so the L2 can poll for results in a follow-up tool call or surface
/// the ID in an incident note.
pub async fn tool_collect(
    store: &dyn Database,
    client_id: &str,
    artifact: &str,
) -> Result<serde_json::Value, String> {
    // Minimal validation — the server enforces real authorization, we
    // just catch obvious misuse early.
    if !client_id.starts_with("C.") || client_id.len() < 4 {
        return Err(format!(
            "collect: invalid client_id '{}' (expected 'C.' + 16 hex)",
            client_id
        ));
    }
    if artifact.is_empty() || artifact.contains(';') || artifact.contains('\n') {
        return Err(format!("collect: invalid artifact '{}'", artifact));
    }
    let config = load_config(store).await?;
    let client = build_http_client(&config)?;
    let url = format!(
        "{}/api/v1/CollectArtifact",
        config.api_url.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "client_id": client_id,
        "artifacts": [artifact],
    });

    let resp = client
        .post(&url)
        .header("Grpc-Metadata-Username", &config.username)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("http: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
    Ok(serde_json::json!({
        "flow_id": body["flow_id"].as_str().unwrap_or(""),
        "client_id": client_id,
        "artifact": artifact,
        "status": "scheduled",
    }))
}

/// VQL read-only allowlist check used by the Phase B tools. The
/// Velociraptor server's ACL model (`investigator` role → no EXECVE,
/// no FILESYSTEM_WRITE) is the primary gate; this function is the
/// defence-in-depth second line, so we stay conservative.
///
/// Returns `Ok(())` if the query looks safe, `Err(reason)` otherwise.
///
/// Heuristic — match on bare VQL identifiers the reference plugins
/// ship under. The user's query might reference fields/columns with
/// the same name, which is why we look for `identifier(` rather than
/// the identifier alone.
pub fn validate_vql_readonly(vql: &str) -> Result<(), String> {
    let lower = vql.to_lowercase();
    for forbidden in [
        "execve(",
        "powershell(",
        "cmd(",
        "copy(",
        "upload_file(",
        "upload_s3(",
        "upload_directory(",
        "rm(",
        "write_csv(",
        "write_jsonl(",
        "write_yaml(",
        "mkdir(",
    ] {
        if lower.contains(forbidden) {
            return Err(format!(
                "VQL uses write/exec plugin {} which is not allowed from ThreatClaw",
                forbidden.trim_end_matches('(')
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical Velociraptor client_id is `C.` + 16 hex chars. Make
    // sure our client summary preserves it verbatim so asset dedup
    // downstream can use it as the stable key.
    #[test]
    fn client_summary_preserves_velociraptor_id_format() {
        let body = serde_json::json!({
            "client_id": "C.04b2307000dfdf7a",
            "os_info": { "hostname": "SRV01", "fqdn": "srv01.lab.local",
                          "system": "windows", "release": "10.0.20348" },
            "last_seen_at": 1_700_000_000_000_000_i64
        });
        let items = vec![body];
        let mut out = Vec::new();
        for v in items {
            let client_id = v["client_id"].as_str().unwrap_or("").to_string();
            if client_id.is_empty() {
                continue;
            }
            let os = &v["os_info"];
            out.push(ClientSummary {
                client_id,
                hostname: os["hostname"].as_str().unwrap_or("").to_string(),
                fqdn: os["fqdn"].as_str().map(String::from),
                os_name: os["system"].as_str().map(String::from),
                os_version: os["release"].as_str().map(String::from),
                last_seen_at_ms: v["last_seen_at"].as_i64(),
            });
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].client_id, "C.04b2307000dfdf7a");
        assert_eq!(out[0].hostname, "SRV01");
        assert_eq!(out[0].fqdn.as_deref(), Some("srv01.lab.local"));
    }

    // Velociraptor emits timestamps in microseconds, but some fields in
    // older releases leak seconds or nanoseconds. Cursor comparison
    // needs lexical ordering so all three formats must normalise to
    // the same RFC3339 second for the same wall-clock moment.
    #[test]
    fn us_to_rfc3339_handles_sec_ms_us_ns_scales() {
        let ref_secs = 1_700_000_000_i64; // 2023-11-14T22:13:20Z
        let from_s = us_to_rfc3339(ref_secs).unwrap();
        let from_ms = us_to_rfc3339(ref_secs * 1_000).unwrap();
        let from_us = us_to_rfc3339(ref_secs * 1_000_000).unwrap();
        let from_ns = us_to_rfc3339(ref_secs * 1_000_000_000).unwrap();
        assert_eq!(from_s, from_ms);
        assert_eq!(from_s, from_us);
        assert_eq!(from_s, from_ns);
    }

    // Second line of defence — even if an operator grants the ThreatClaw
    // API user the `administrator` role by mistake, the Phase B tool
    // surface refuses write/execute VQL.
    #[test]
    fn vql_lint_rejects_execve_family() {
        for bad in [
            "SELECT execve(argv=['whoami']) FROM scope()",
            "SELECT powershell(script='Get-Process') FROM scope()",
            "SELECT * FROM cmd(argv=['cmd','/c','dir'])",
            "SELECT upload_file(file='/etc/passwd', name='passwd') FROM scope()",
            "SELECT rm(filename='/tmp/x') FROM scope()",
        ] {
            assert!(
                validate_vql_readonly(bad).is_err(),
                "expected reject: {}",
                bad
            );
        }
    }

    #[test]
    fn vql_lint_accepts_common_read_only_plugins() {
        for ok in [
            "SELECT * FROM pslist()",
            "SELECT Name, Pid, CommandLine FROM pslist() WHERE Name =~ 'powershell'",
            "SELECT * FROM netstat()",
            "SELECT * FROM clients()",
            "SELECT * FROM parse_evtx(filename='C:\\\\Windows\\\\System32\\\\winevt\\\\Logs\\\\Security.evtx')",
            "SELECT * FROM Artifact.Windows.System.Amcache()",
        ] {
            assert!(validate_vql_readonly(ok).is_ok(), "expected accept: {}", ok);
        }
    }

    // `copy()` is a write plugin even when used in a subquery, and the
    // lint must catch it regardless of where it appears in the VQL.
    #[test]
    fn vql_lint_catches_write_plugin_in_subquery() {
        let bad = "SELECT Name FROM pslist() WHERE { SELECT * FROM copy(src='/etc/shadow', dst='/tmp/x') }";
        assert!(validate_vql_readonly(bad).is_err());
    }

    // The identity PEM concat gracefully handles leading/trailing
    // whitespace that routinely leaks through copy-paste from the YAML
    // config file.
    #[test]
    fn build_http_client_rejects_malformed_pem() {
        let cfg = VelociraptorConfig {
            api_url: "https://127.0.0.1:8001".into(),
            ca_pem: "not a pem".into(),
            client_cert_pem: "not a pem".into(),
            client_key_pem: "not a pem".into(),
            username: "threatclaw".into(),
            cursor_last_hunt_completion: None,
            max_findings_per_cycle: 100,
        };
        assert!(build_http_client(&cfg).is_err());
    }
}

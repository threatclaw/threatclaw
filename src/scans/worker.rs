//! Scan worker pool.
//!
//! Spawns N workers at startup. Each worker polls the scan_queue table
//! (`SELECT FOR UPDATE SKIP LOCKED` so they don't trample each other),
//! runs the appropriate scan, writes the structured result back to the
//! row, and loops.
//!
//! Configuration:
//!   - `TC_SCAN_WORKERS` env var, default 3
//!   - poll interval 5s when queue is empty
//!
//! Side effects of a successful scan:
//!   - `nmap_fingerprint`: result_json contains hosts/ports/services.
//!     The nmap_discovery::run_discovery call already feeds assets into
//!     the resolver, so the asset properties are updated as a side
//!     effect.
//!   - `trivy_image`: result_json contains the Trivy JSON report.
//!     execute_skill already inserts findings via the parser, so the
//!     /findings page shows the CVEs.
//!
//! On error: row.status = 'error', error_msg populated. Future polls
//! don't retry automatically — the orchestrator either re-enqueues
//! manually (RSSI clic) or the auto-trigger hook fires again next time
//! the source observation is ingested.

use crate::db::Database;
use crate::db::threatclaw_store::ScanJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

/// Default worker count. Override with TC_SCAN_WORKERS.
const DEFAULT_WORKERS: usize = 3;

/// Spawn the scan worker pool. Call once at startup, after migrations
/// and after the connector sync scheduler.
pub fn spawn_scan_workers(store: Arc<dyn Database>) {
    let n = std::env::var("TC_SCAN_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_WORKERS);

    tracing::info!("SCAN WORKERS: spawning {} workers", n);
    for i in 0..n {
        let store_clone = store.clone();
        let worker_id = format!("scan-w{}", i);
        tokio::spawn(async move {
            run_worker(worker_id, store_clone).await;
        });
    }
}

async fn run_worker(worker_id: String, store: Arc<dyn Database>) {
    tracing::info!("SCAN WORKER {}: started", worker_id);
    loop {
        match store.claim_next_scan(&worker_id).await {
            Ok(Some(job)) => {
                let job_id = job.id;
                let job_type = job.scan_type.clone();
                let job_target = job.target.clone();
                tracing::info!(
                    "SCAN WORKER {}: claimed job #{} {} target={}",
                    worker_id,
                    job_id,
                    job_type,
                    job_target
                );
                let started = std::time::Instant::now();
                match dispatch(store.as_ref(), &job).await {
                    Ok(result_json) => {
                        let duration_ms = started.elapsed().as_millis() as i32;
                        if let Err(e) = store.complete_scan(job_id, &result_json, duration_ms).await
                        {
                            tracing::error!(
                                "SCAN WORKER {}: failed to mark job #{} done: {}",
                                worker_id,
                                job_id,
                                e
                            );
                        } else {
                            tracing::info!(
                                "SCAN WORKER {}: job #{} {} done in {}ms",
                                worker_id,
                                job_id,
                                job_type,
                                duration_ms
                            );
                        }
                    }
                    Err(err) => {
                        let duration_ms = started.elapsed().as_millis() as i32;
                        tracing::warn!(
                            "SCAN WORKER {}: job #{} {} failed: {}",
                            worker_id,
                            job_id,
                            job_type,
                            err
                        );
                        let _ = store.fail_scan(job_id, &err, duration_ms).await;
                    }
                }
                // No sleep — pull the next one immediately if available.
            }
            Ok(None) => {
                // Queue empty. Backoff.
                sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                tracing::error!("SCAN WORKER {}: claim failed: {}", worker_id, e);
                sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

/// Dispatch a job to the right runner. Returns the structured result
/// (will be stored in scan_queue.result_json).
async fn dispatch(store: &dyn Database, job: &ScanJob) -> Result<serde_json::Value, String> {
    use crate::connectors::docker_executor::*;
    match job.scan_type.as_str() {
        // Native binary
        "nmap_fingerprint" => run_nmap(store, &job.target).await,
        // Ephemeral docker — each maps to a (config_fn, parser_fn) pair
        // already shipped with the catalog manifests.
        "trivy_image" => run_docker(store, trivy_image_config(&job.target), parse_trivy).await,
        "lynis_audit" => run_docker(store, lynis_config(&job.target), parse_lynis).await,
        "docker_bench" => run_docker(store, docker_bench_config(), parse_docker_bench).await,
        "syft_sbom" => run_docker(store, syft_config(&job.target), parse_syft).await,
        "semgrep_scan" => run_docker(store, semgrep_config(&job.target), parse_semgrep).await,
        "checkov_scan" => run_docker(store, checkov_config(&job.target), parse_checkov).await,
        "trufflehog_scan" => {
            run_docker(store, trufflehog_config(&job.target), parse_trufflehog).await
        }
        "zap_scan" => run_zap(store, &job.target).await,
        other => Err(format!("unknown scan_type '{}'", other)),
    }
}

async fn run_nmap(store: &dyn Database, target: &str) -> Result<serde_json::Value, String> {
    use crate::connectors::nmap_discovery::{NmapConfig, run_discovery};
    let config = NmapConfig {
        targets: target.to_string(),
        top_ports: 100,
        timing: "T3".into(),
        use_docker: false,
    };
    let result = run_discovery(store, &config).await;
    if !result.errors.is_empty() {
        return Err(result.errors.join("; "));
    }
    Ok(serde_json::json!({
        "hosts_discovered": result.hosts_discovered,
        "assets_resolved": result.assets_resolved,
        "open_ports_total": result.open_ports_total,
        "scan_duration_secs": result.scan_duration_secs,
    }))
}

/// Generic ephemeral-docker runner. Used for every scan_type that
/// already has a (config, parser) pair defined in docker_executor.
async fn run_docker(
    store: &dyn Database,
    config: crate::connectors::docker_executor::DockerSkillConfig,
    parser: fn(&str) -> Vec<crate::connectors::docker_executor::ParsedFinding>,
) -> Result<serde_json::Value, String> {
    let result = crate::connectors::docker_executor::execute_skill(store, &config, parser).await;
    if !result.success {
        return Err(result
            .error
            .unwrap_or_else(|| format!("{} failed", result.skill_id)));
    }
    Ok(serde_json::json!({
        "skill": result.skill_id,
        "findings_created": result.findings_created,
        "stdout_lines": result.stdout_lines,
        "duration_secs": result.duration_secs,
        "exit_code": result.exit_code,
    }))
}

/// ZAP needs a custom DockerSkillConfig (host network, mount point for
/// the work dir). The handler in threatclaw_api.rs already builds this
/// inline; replicate the same shape here.
async fn run_zap(store: &dyn Database, target: &str) -> Result<serde_json::Value, String> {
    use crate::connectors::docker_executor::{DockerSkillConfig, execute_skill, parse_zap};
    let config = DockerSkillConfig {
        image: "zaproxy/zap-stable:latest".into(),
        command: vec![
            "zap-baseline.py".into(),
            "-t".into(),
            target.into(),
            "-I".into(),
        ],
        mount_path: Some("/tmp/zap-work".into()),
        mount_target: "/zap/wrk".into(),
        network: "host".into(),
        memory_limit: "1g".into(),
        timeout_seconds: 600,
        skill_id: "skill-zap".into(),
        skill_name: "OWASP ZAP".into(),
        asset_label: None,
    };
    run_docker_inner(store, config, parse_zap).await
}

// Same body as run_docker — pulled out so run_zap can call without
// trying to copy a non-Copy config into the closure.
async fn run_docker_inner(
    store: &dyn Database,
    config: crate::connectors::docker_executor::DockerSkillConfig,
    parser: fn(&str) -> Vec<crate::connectors::docker_executor::ParsedFinding>,
) -> Result<serde_json::Value, String> {
    let result = crate::connectors::docker_executor::execute_skill(store, &config, parser).await;
    if !result.success {
        return Err(result
            .error
            .unwrap_or_else(|| format!("{} failed", result.skill_id)));
    }
    Ok(serde_json::json!({
        "skill": result.skill_id,
        "findings_created": result.findings_created,
        "stdout_lines": result.stdout_lines,
        "duration_secs": result.duration_secs,
        "exit_code": result.exit_code,
    }))
}

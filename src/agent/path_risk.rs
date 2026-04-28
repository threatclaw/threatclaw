//! Phase G2 — Predictive attack-path batch.
//!
//! Calcule les Top-N attack paths les plus probables sur le graph
//! d'assets, persistés en `attack_paths_predicted` (V63).
//!
//! Pipeline :
//! 1. Lister les nœuds source (exposed: internet, dmz, vlan_dev) et
//!    cible (criticality: high/critical) via Cypher AGE.
//! 2. Pour chaque (src, dst), Cypher MATCH path le plus court (BFS sur
//!    LATERAL_PATH/ATTACKS edges, max 5 hops) — c'est petit à notre
//!    échelle SMB, pas besoin de Dijkstra externe.
//! 3. Pour chaque path, agréger les CVE des assets traversés, lookup
//!    EPSS+KEV, calculer un score composite.
//! 4. Garder Top-N (default 50), persister.
//!
//! Score formula :
//!   base = clamp(epss_max + kev_boost, 0, 1)
//!   penalty per hop = 0.85^hops
//!   final = base * penalty
//!
//! kev_boost = +0.2 si au moins une CVE traversée est dans CISA KEV.
//! epss_max  = max EPSS sur les CVE traversées (0 si aucune connue).
//!
//! Le run complet doit tenir en < 10 s pour 500 nœuds (cf seuil
//! combinatoire MulVAL/CAULDRON dans la recherche). À notre échelle SMB
//! on est très en dessous.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::Database;

// ── Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub run_id: Uuid,
    pub src_asset: String,
    pub dst_asset: String,
    pub path_assets: Vec<String>,
    pub hops: i16,
    pub score: f64,
    pub epss_max: Option<f64>,
    pub has_kev: bool,
    pub cves_chain: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub explanation: Option<String>,
    pub computed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PathRiskConfig {
    pub max_hops: usize,
    pub min_score: f64,
    pub top_n: usize,
}

impl Default for PathRiskConfig {
    fn default() -> Self {
        Self {
            max_hops: 5,
            min_score: 0.05,
            top_n: 50,
        }
    }
}

// ── Score primitive (pure, testable sans DB) ──

/// Calcule le score d'un path à partir des inputs agrégés.
///
/// Inputs :
/// - `epss_max` : max EPSS (0..1) sur les CVE traversées, `None` si aucune CVE connue
/// - `has_kev` : true si au moins une CVE traversée est dans CISA KEV
/// - `hops` : nombre de hops dans le path (0 = src == dst, 1 = direct, etc.)
///
/// Sortie : 0.0 (impossible) à 1.0 (très probable).
///
/// Formule :
/// - base = clamp(epss_max + kev_boost, 0, 1) — ou 0.1 si aucune EPSS
/// - hop_penalty = 0.85^hops (plus c'est long, moins c'est probable)
/// - score = base * hop_penalty
pub fn compute_path_score(epss_max: Option<f64>, has_kev: bool, hops: i16) -> f64 {
    let kev_boost = if has_kev { 0.2 } else { 0.0 };
    let base = match epss_max {
        Some(e) => (e + kev_boost).clamp(0.0, 1.0),
        // Pas de CVE connue mais KEV présent (rare) : on garde le boost.
        // Sinon score plancher 0.05 — il y a un path mais on n'a aucune
        // info exploitabilité.
        None => {
            if has_kev {
                kev_boost
            } else {
                0.05
            }
        }
    };
    let hop_penalty = 0.85_f64.powi(hops as i32);
    (base * hop_penalty).clamp(0.0, 1.0)
}

// ── Batch driver ──

/// Lance un batch de calcul. À appeler par le scheduler (cron 4-6h).
/// Renvoie le run_id généré + le nombre de paths persistés.
pub async fn run_attack_path_batch(
    store: &Arc<dyn Database>,
    config: &PathRiskConfig,
) -> Result<(Uuid, usize), String> {
    let run_id = Uuid::new_v4();
    let started = std::time::Instant::now();
    info!(
        "PATH RISK BATCH: starting run_id={} (max_hops={}, top_n={})",
        run_id, config.max_hops, config.top_n
    );

    let sources = list_exposed_sources(store.as_ref()).await?;
    let targets = list_critical_targets(store.as_ref()).await?;
    info!(
        "PATH RISK BATCH: {} sources, {} targets",
        sources.len(),
        targets.len()
    );

    if sources.is_empty() || targets.is_empty() {
        info!("PATH RISK BATCH: rien à calculer (graph vide ou pas tagué)");
        return Ok((run_id, 0));
    }

    let mut all_paths: Vec<AttackPath> = Vec::new();

    for src in &sources {
        for dst in &targets {
            if src == dst {
                continue;
            }
            if let Some(path) = find_shortest_path(store.as_ref(), src, dst, config.max_hops).await
            {
                if let Some(scored) = enrich_and_score(store, run_id, src, dst, path).await {
                    if scored.score >= config.min_score {
                        all_paths.push(scored);
                    }
                }
            }
        }
    }

    // Trier décroissant et garder Top-N
    all_paths.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    all_paths.truncate(config.top_n);

    let count = all_paths.len();
    if count > 0 {
        if let Err(e) = store.insert_attack_paths(&all_paths).await {
            warn!("PATH RISK BATCH: persist failed: {}", e);
            return Err(format!("persist: {}", e));
        }
    }

    info!(
        "PATH RISK BATCH: run_id={} done — {} paths persisted in {}ms",
        run_id,
        count,
        started.elapsed().as_millis()
    );
    Ok((run_id, count))
}

// ── Scheduler hook ──

/// Spawn une tokio task qui lance `run_attack_path_batch` toutes les
/// `interval_hours` heures. À appeler une fois au boot (AUTO-START).
/// Premier batch staggered de 30 s pour éviter de slammer la DB au boot.
pub fn spawn_attack_path_scheduler(store: Arc<dyn Database>, interval_hours: u64) {
    let interval = std::time::Duration::from_secs(interval_hours * 3600);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        info!(
            "PATH RISK SCHEDULER: started (every {} hours)",
            interval_hours
        );
        let mut ticker = tokio::time::interval(interval);
        let cfg = PathRiskConfig::default();
        loop {
            ticker.tick().await;
            if let Err(e) = run_attack_path_batch(&store, &cfg).await {
                warn!("PATH RISK SCHEDULER: batch failed: {}", e);
            }
        }
    });
}

// ── Cypher helpers ──

async fn list_exposed_sources(store: &dyn Database) -> Result<Vec<String>, String> {
    let cypher = "MATCH (a:Asset) \
                  WHERE a.exposure_class IN ['internet', 'dmz', 'vlan_dev'] \
                  RETURN a.id AS id";
    let rows = store
        .execute_cypher(cypher)
        .await
        .map_err(|e| format!("cypher sources: {}", e))?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            r.get("id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect())
}

async fn list_critical_targets(store: &dyn Database) -> Result<Vec<String>, String> {
    let cypher = "MATCH (a:Asset) \
                  WHERE a.criticality IN ['high', 'critical'] \
                  RETURN a.id AS id";
    let rows = store
        .execute_cypher(cypher)
        .await
        .map_err(|e| format!("cypher targets: {}", e))?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            r.get("id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect())
}

/// Plus court path entre deux assets via les edges latéraux.
async fn find_shortest_path(
    store: &dyn Database,
    src: &str,
    dst: &str,
    max_hops: usize,
) -> Option<Vec<String>> {
    let src_esc = src.replace('\'', "\\'");
    let dst_esc = dst.replace('\'', "\\'");
    let cypher = format!(
        "MATCH path = shortestPath( \
           (s:Asset {{id: '{src}'}})-[:LATERAL_PATH|ATTACKS*1..{hops}]->(d:Asset {{id: '{dst}'}}) \
         ) \
         RETURN [n IN nodes(path) | n.id] AS assets",
        src = src_esc,
        dst = dst_esc,
        hops = max_hops
    );
    let rows = store.execute_cypher(&cypher).await.ok()?;
    let row = rows.first()?;
    let assets = row.get("assets")?.as_array()?;
    Some(
        assets
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
    )
}

/// Pour un path brut, agrège CVE+EPSS+KEV et calcule le score final.
async fn enrich_and_score(
    store: &Arc<dyn Database>,
    run_id: Uuid,
    src: &str,
    dst: &str,
    path: Vec<String>,
) -> Option<AttackPath> {
    let hops = (path.len().saturating_sub(1)) as i16;
    let cves = collect_cves_on_path(store.as_ref(), &path).await;

    // Lookup EPSS pour chaque CVE — on prend le max.
    let mut epss_max: Option<f64> = None;
    for cve in &cves {
        if let Ok(Some(score)) =
            crate::enrichment::epss::lookup_epss_cached(cve, store.as_ref()).await
        {
            epss_max = Some(epss_max.map_or(score.epss, |m| m.max(score.epss)));
        }
    }

    // KEV check — au moins une CVE dans CISA KEV ?
    let mut has_kev = false;
    for cve in &cves {
        if crate::enrichment::cisa_kev::is_exploited(store.as_ref(), cve)
            .await
            .is_some()
        {
            has_kev = true;
            break;
        }
    }

    let score = compute_path_score(epss_max, has_kev, hops);
    if score < 0.001 {
        return None;
    }

    let explanation = build_explanation(&path, &cves, epss_max, has_kev);

    Some(AttackPath {
        run_id,
        src_asset: src.to_string(),
        dst_asset: dst.to_string(),
        path_assets: path,
        hops,
        score,
        epss_max,
        has_kev,
        cves_chain: cves,
        mitre_techniques: vec![], // G5 — corrélation ATT&CK Flow
        explanation: Some(explanation),
        computed_at: Utc::now(),
    })
}

async fn collect_cves_on_path(store: &dyn Database, path: &[String]) -> Vec<String> {
    if path.is_empty() {
        return Vec::new();
    }
    let escaped: Vec<String> = path
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "\\'")))
        .collect();
    let cypher = format!(
        "MATCH (a:Asset)-[:AFFECTED_BY]->(c:CVE) \
         WHERE a.id IN [{}] \
         RETURN DISTINCT c.cve_id AS cve",
        escaped.join(",")
    );
    let rows = store.execute_cypher(&cypher).await.unwrap_or_default();
    rows.into_iter()
        .filter_map(|r| {
            r.get("cve")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect()
}

fn build_explanation(
    path: &[String],
    cves: &[String],
    epss_max: Option<f64>,
    has_kev: bool,
) -> String {
    let path_str = path.join(" → ");
    let cve_str = if cves.is_empty() {
        "aucune CVE liée connue".to_string()
    } else {
        format!(
            "via {}{}{}",
            cves[..cves.len().min(3)].join(", "),
            if cves.len() > 3 {
                format!(" + {} autres", cves.len() - 3)
            } else {
                String::new()
            },
            match epss_max {
                Some(e) => format!(" (EPSS max {:.2})", e),
                None => String::new(),
            }
        )
    };
    let kev_str = if has_kev {
        ", KEV ✓".to_string()
    } else {
        String::new()
    };
    format!("{path_str} — {cve_str}{kev_str}")
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_kev_high_epss_short_path() {
        // KEV + EPSS 0.87 + 1 hop direct → score = clamp(1.07,1) * 0.85 = 0.85
        let s = compute_path_score(Some(0.87), true, 1);
        assert!(s >= 0.85 - 1e-9, "expected ~0.85, got {}", s);
    }

    #[test]
    fn score_no_cve_no_kev_low() {
        // Pas de CVE, pas de KEV : floor minuscule
        let s = compute_path_score(None, false, 1);
        assert!(s < 0.1, "expected low floor, got {}", s);
    }

    #[test]
    fn score_kev_only_no_epss() {
        // CVE inconnue mais KEV présent : 0.2 * 0.85 ≈ 0.17
        let s = compute_path_score(None, true, 1);
        assert!(s > 0.15 && s < 0.20, "got {}", s);
    }

    #[test]
    fn score_decays_with_hops() {
        let one_hop = compute_path_score(Some(0.5), false, 1);
        let three_hops = compute_path_score(Some(0.5), false, 3);
        assert!(one_hop > three_hops);
        assert!(three_hops < one_hop * 0.85_f64.powi(2) + 0.001);
    }

    #[test]
    fn score_clamped_to_one() {
        // EPSS 0.99 + KEV → 1.19 clampé à 1.0 avant pénalité
        let s = compute_path_score(Some(0.99), true, 0);
        assert!(s <= 1.0);
        assert!(s > 0.99);
    }

    #[test]
    fn explanation_is_human_readable() {
        let exp = build_explanation(
            &["a".to_string(), "b".to_string(), "c".to_string()],
            &[
                "CVE-2024-1234".to_string(),
                "CVE-2023-9999".to_string(),
            ],
            Some(0.87),
            true,
        );
        assert!(exp.contains("a → b → c"));
        assert!(exp.contains("CVE-2024-1234"));
        assert!(exp.contains("EPSS"));
        assert!(exp.contains("KEV"));
    }
}

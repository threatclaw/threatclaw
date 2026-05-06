//! Pré-enrichissement déterministe opportuniste du dossier d'incident.
//!
//! Voir `internal/roadmap-mai.md` Phase 1d pour le design détaillé.
//!
//! ## Principe
//!
//! Avant que le L1/L2 LLM voie un dossier, on remplit son `EnrichmentBundle`
//! avec des données factuelles provenant de :
//! - **Cache local** (`enrichment_cache`) — déjà peuplé par le cycle IE qui
//!   tourne en parallèle
//! - **Sources gratuites sans clé API** (Spamhaus DROP/EDROP, ThreatFox,
//!   URLhaus, MalwareBazaar via abuse.ch ; CISA KEV / NVD / EPSS via cache)
//!
//! Le LLM reçoit ainsi un dossier riche en faits et a moins de marge pour
//! "broder" en hallucinant des éléments familiers (88.88.88.88, EternalBlue,
//! fail2ban, etc.). Combiné avec un prompt strict + reconciler narrative
//! (Phase 2), c'est l'arme principale contre les hallucinations.
//!
//! ## Tolérance aux pannes
//!
//! Chaque lookup externe est dans un `tokio::time::timeout` court. Une source
//! qui échoue (réseau, rate limit, parse error) ne bloque jamais les autres.
//! Le résultat d'enrichment est toujours un `EnrichmentBundle` valide, même
//! partiel.
//!
//! ## Caps de performance
//!
//! - Max 10 CVEs enrichis par dossier
//! - Max 5 IPs sources distinctes par dossier
//! - Timeouts 3-5s par lookup externe

use std::collections::HashSet;

use crate::agent::incident_dossier::{CveDetail, IncidentDossier, IpReputation, ThreatIntelMatch};
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

const MAX_CVES_PER_DOSSIER: usize = 10;
const MAX_IPS_PER_DOSSIER: usize = 5;

/// Pré-enrichit le dossier en consommant le cache + les sources gratuites
/// + les skills connectés (firewall, SIEM, EDR — Phase 3).
///
/// À appeler à la fin de `build_dossier_from_situation`, juste avant le retour
/// du dossier construit. Modifie `dossier.enrichment` en place.
pub async fn pre_enrich_dossier(store: &dyn Database, dossier: &mut IncidentDossier) {
    // Phase 3 — registry des skills connectés chez le client. Vide chez les
    // déploiements sans firewall/SIEM/EDR configuré, et c'est OK.
    let registry = crate::agent::skills::registry::SkillRegistry::from_db(store).await;

    enrich_cves(store, dossier).await;
    enrich_ip_reputations(store, dossier).await;
    enrich_threat_intel(store, dossier).await;
    enrich_firewall_logs(&registry, dossier).await;

    tracing::debug!(
        cve_count = dossier.enrichment.cve_details.len(),
        ip_count = dossier.enrichment.ip_reputations.len(),
        ti_count = dossier.enrichment.threat_intel.len(),
        line_count = dossier.enrichment.enrichment_lines.len(),
        "DOSSIER_ENRICHMENT: completed"
    );
}

/// Pour chaque finding du dossier qui mentionne une CVE dans son metadata,
/// récupérer EPSS (cache), KEV (cache local), et CVSS si dispo.
async fn enrich_cves(store: &dyn Database, dossier: &mut IncidentDossier) {
    let cve_ids = collect_unique_cves(dossier);
    let mut details = Vec::with_capacity(cve_ids.len());

    for cve_id in cve_ids.iter().take(MAX_CVES_PER_DOSSIER) {
        let mut detail = CveDetail {
            cve_id: cve_id.clone(),
            cvss_score: None,
            epss_score: None,
            is_kev: false,
            description: String::new(),
        };

        // EPSS — déjà en cache si le cycle IE l'a fetché récemment
        if let Some(cached) =
            crate::agent::production_safeguards::get_cached_ioc(store, "epss", cve_id).await
        {
            detail.epss_score = cached["epss"].as_f64();
        }

        // KEV — lookup local (DB CISA KEV mirror), très rapide
        if let Some(kev) = crate::enrichment::cisa_kev::is_exploited(store, cve_id).await {
            detail.is_kev = true;
            // KEV donne une description de la CVE et la due_date
            detail.description = format!(
                "Exploitation active confirmée (CISA KEV, due {})",
                kev.due_date
            );
        }

        // CVSS depuis cache NVD (si fetché par cve_lookup ailleurs)
        if let Some(cached) =
            crate::agent::production_safeguards::get_cached_ioc(store, "nvd", cve_id).await
        {
            detail.cvss_score = cached["cvss"].as_f64();
            if detail.description.is_empty() {
                if let Some(desc) = cached["description"].as_str() {
                    detail.description = desc.to_string();
                }
            }
        }

        details.push(detail);
    }

    dossier.enrichment.cve_details = details;
}

/// Pour chaque sigma_alert du dossier avec un `source_ip` routable, récupérer
/// la réputation depuis 3 sources **en live** :
///
/// 1. **GreyNoise Community** — gratuit, sans clé. Détecte les IPs scanners
///    (noise=true → bénin, deprioritise) vs targeted (classification=malicious).
///    Si le client a configuré une clé GreyNoise dans `skill_configs`, on
///    bascule sur l'API authentifiée (quotas plus généreux). Le résultat
///    est mis en cache 24h.
/// 2. **Spamhaus DROP/EDROP** — gratuit, sans clé. Liste l'IP comme
///    hostile-connue (botnet, hijack).
/// 3. **ThreatFox abuse.ch** — gratuit, sans clé. Match d'IOC threat intel
///    (C2, malware-bridge).
///
/// Phase 9g — Avant ce refactor, GreyNoise n'était lu que depuis le cache
/// (jamais peuplé pour les IPs sigma_alerts), et aucune source ne loguait
/// → l'opérateur voyait `ip_reputations: []` sans savoir si on avait
/// cherché ou pas. Le pipeline live + logs `info!` rend la transparence.
async fn enrich_ip_reputations(store: &dyn Database, dossier: &mut IncidentDossier) {
    use crate::agent::investigation_log::StepBuilder;
    use crate::db::threatclaw_store::{StepKind, StepStatus};

    let ips = collect_unique_routable_source_ips(dossier);
    if ips.is_empty() {
        tracing::debug!(
            "DOSSIER_ENRICHMENT: 0 routable source IPs in dossier — skipping IP reputation"
        );
        return;
    }

    let greynoise_key = load_skill_api_key(store, "skill-enrichment-greynoise").await;
    if greynoise_key.is_some() {
        tracing::debug!("DOSSIER_ENRICHMENT: GreyNoise API key found in skill_configs");
    }

    let mut reputations = Vec::new();
    for ip in ips.iter().take(MAX_IPS_PER_DOSSIER) {
        let mut matches = 0u32;

        // Phase 9o — chaque skill call est instrumenté pour la timeline
        // d'investigation : durée, résultat, status. Buffered tant que
        // l'incident n'a pas d'id (drainé par l'IE après create_incident).

        let t0 = std::time::Instant::now();
        if let Some(rep) = lookup_greynoise(store, ip, greynoise_key.as_deref()).await {
            tracing::info!(
                "DOSSIER_ENRICHMENT: ip={ip} source=greynoise classification={} ({})",
                rep.classification,
                rep.details
            );
            StepBuilder::new(
                StepKind::SkillCall,
                format!(
                    "GreyNoise · {ip} → {} ({})",
                    rep.classification, rep.details
                ),
            )
            .skill("skill-enrichment-greynoise")
            .duration_from(t0)
            .payload(serde_json::json!({
                "ip": ip,
                "classification": rep.classification,
                "details": rep.details,
                "is_malicious": rep.is_malicious,
            }))
            .enqueue(&mut dossier.investigation_log);
            matches += 1;
            reputations.push(rep);
        } else {
            tracing::debug!("DOSSIER_ENRICHMENT: ip={ip} source=greynoise no_result");
            StepBuilder::new(
                StepKind::SkillCall,
                format!("GreyNoise · {ip} → aucun signal"),
            )
            .skill("skill-enrichment-greynoise")
            .duration_from(t0)
            .status(StepStatus::NoMatch)
            .payload(serde_json::json!({"ip": ip}))
            .enqueue(&mut dossier.investigation_log);
        }

        let t0 = std::time::Instant::now();
        if let Some(rep) = lookup_spamhaus(ip).await {
            tracing::info!(
                "DOSSIER_ENRICHMENT: ip={ip} source=spamhaus classification={} ({})",
                rep.classification,
                rep.details
            );
            StepBuilder::new(
                StepKind::SkillCall,
                format!("Spamhaus · {ip} → {} ({})", rep.classification, rep.details),
            )
            .skill("skill-enrichment-spamhaus")
            .duration_from(t0)
            .payload(serde_json::json!({
                "ip": ip,
                "classification": rep.classification,
                "details": rep.details,
            }))
            .enqueue(&mut dossier.investigation_log);
            matches += 1;
            reputations.push(rep);
        } else {
            tracing::debug!("DOSSIER_ENRICHMENT: ip={ip} source=spamhaus not_listed");
            StepBuilder::new(StepKind::SkillCall, format!("Spamhaus · {ip} → non listé"))
                .skill("skill-enrichment-spamhaus")
                .duration_from(t0)
                .status(StepStatus::NoMatch)
                .payload(serde_json::json!({"ip": ip}))
                .enqueue(&mut dossier.investigation_log);
        }

        let t0 = std::time::Instant::now();
        if let Some(rep) = lookup_threatfox(ip).await {
            tracing::info!(
                "DOSSIER_ENRICHMENT: ip={ip} source=threatfox classification={} ({})",
                rep.classification,
                rep.details
            );
            StepBuilder::new(
                StepKind::SkillCall,
                format!(
                    "ThreatFox · {ip} → {} ({})",
                    rep.classification, rep.details
                ),
            )
            .skill("skill-enrichment-threatfox")
            .duration_from(t0)
            .payload(serde_json::json!({
                "ip": ip,
                "classification": rep.classification,
                "details": rep.details,
            }))
            .enqueue(&mut dossier.investigation_log);
            matches += 1;
            reputations.push(rep);
        } else {
            tracing::debug!("DOSSIER_ENRICHMENT: ip={ip} source=threatfox no_match");
            StepBuilder::new(
                StepKind::SkillCall,
                format!("ThreatFox · {ip} → aucun match"),
            )
            .skill("skill-enrichment-threatfox")
            .duration_from(t0)
            .status(StepStatus::NoMatch)
            .payload(serde_json::json!({"ip": ip}))
            .enqueue(&mut dossier.investigation_log);
        }

        tracing::info!("DOSSIER_ENRICHMENT: ip={ip} — {matches} reputation source(s) matched");
    }

    tracing::info!(
        "DOSSIER_ENRICHMENT: ip_reputations populated with {} entries from {} IP(s)",
        reputations.len(),
        ips.len()
    );
    dossier.enrichment.ip_reputations = reputations;
}

/// Lookup GreyNoise — cache hit returns immediately, otherwise live fetch
/// against the Community endpoint (or authenticated when a key is provided).
/// Result is cached 24h on success.
///
/// Returns `None` when the IP is unknown (`classification=unknown` AND no
/// noise/riot signal) so we don't pollute the dossier with empty entries
/// — the caller logs the miss.
async fn lookup_greynoise(
    store: &dyn Database,
    ip: &str,
    api_key: Option<&str>,
) -> Option<IpReputation> {
    // (1) Cache — hit if the IE cycle or a prior dossier touched the IP.
    if let Some(cached) =
        crate::agent::production_safeguards::get_cached_ioc(store, "greynoise", ip).await
    {
        let classification = cached["classification"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let noise = cached["noise"].as_bool().unwrap_or(false);
        let riot = cached["riot"].as_bool().unwrap_or(false);
        if classification != "unknown" || noise || riot {
            return Some(IpReputation {
                ip: ip.into(),
                is_malicious: classification == "malicious",
                classification,
                source: "greynoise".into(),
                details: format!("noise={noise} riot={riot} (cache)"),
            });
        }
    }

    // (2) Live fetch — Community endpoint, with optional auth key.
    let result = match tokio::time::timeout(
        std::time::Duration::from_secs(8),
        crate::enrichment::greynoise::lookup_ip(ip, api_key),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!("DOSSIER_ENRICHMENT: greynoise live fetch for {ip} failed: {e}");
            return None;
        }
        Err(_) => {
            tracing::debug!("DOSSIER_ENRICHMENT: greynoise live fetch for {ip} timed out");
            return None;
        }
    };

    // (3) Cache the result for 24h regardless — even "unknown" is worth
    // caching so the next dossier doesn't re-tap GreyNoise.
    let cache_payload = serde_json::json!({
        "ip": result.ip,
        "noise": result.noise,
        "riot": result.riot,
        "classification": result.classification,
        "name": result.name,
    });
    crate::agent::production_safeguards::cache_ioc(store, "greynoise", ip, &cache_payload).await;

    // (4) Only surface the reputation when GreyNoise has an actual signal.
    if result.classification != "unknown" || result.noise || result.riot {
        Some(IpReputation {
            ip: ip.into(),
            is_malicious: result.classification == "malicious",
            classification: result.classification,
            source: "greynoise".into(),
            details: format!(
                "noise={} riot={}{}",
                result.noise,
                result.riot,
                result
                    .name
                    .as_deref()
                    .map(|n| format!(" name={n}"))
                    .unwrap_or_default()
            ),
        })
    } else {
        None
    }
}

/// Spamhaus DROP/EDROP lookup — free, no key required, hard-coded
/// drop-list of hostile IPs (botnets, hijacked ranges).
async fn lookup_spamhaus(ip: &str) -> Option<IpReputation> {
    let spam = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::enrichment::spamhaus::check_ip(ip),
    )
    .await
    .ok()?
    .ok()?;
    if spam.listings.is_empty() {
        return None;
    }
    let lists: Vec<String> = spam.listings.iter().map(|l| l.list.clone()).collect();
    Some(IpReputation {
        ip: ip.into(),
        is_malicious: true,
        classification: "malicious".into(),
        source: "spamhaus".into(),
        details: format!("listed in {}", lists.join(", ")),
    })
}

/// ThreatFox abuse.ch IOC lookup — free, no key required, matches against
/// the public C2 / malware-bridge feeds.
async fn lookup_threatfox(ip: &str) -> Option<IpReputation> {
    let iocs = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::enrichment::threatfox::lookup_ioc(ip, None),
    )
    .await
    .ok()?
    .ok()?;
    if iocs.is_empty() {
        return None;
    }
    let first = &iocs[0];
    Some(IpReputation {
        ip: ip.into(),
        is_malicious: true,
        classification: "malicious".into(),
        source: "threatfox".into(),
        details: format!(
            "threat_type={} confidence={}",
            first.threat_type,
            first
                .confidence_level
                .map(|c| c.to_string())
                .unwrap_or_else(|| "n/a".into())
        ),
    })
}

/// Read an `api_key` value from `skill_configs` for the given skill. Returns
/// `None` when the skill isn't configured or the key is empty (the public
/// Community endpoint will then be used). Trimmed for safety against
/// trailing whitespace from copy-paste configuration.
async fn load_skill_api_key(store: &dyn Database, skill_id: &str) -> Option<String> {
    match store.get_setting(skill_id, "api_key").await.ok().flatten() {
        Some(v) => v
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        None => None,
    }
}

/// Pour les threat intel matches (URLs, hashes) — actuellement skip parce que
/// les findings du dossier n'exposent pas systématiquement ces champs. À étendre
/// dans une itération future quand le dossier portera les IOCs extraits.
async fn enrich_threat_intel(_store: &dyn Database, dossier: &mut IncidentDossier) {
    let matches: Vec<ThreatIntelMatch> = Vec::new();
    // Placeholder pour Phase ultérieure : URLhaus / MalwareBazaar lookups
    // sur les indicateurs URL/hash extraits des findings.
    dossier.enrichment.threat_intel = matches;
}

/// Phase 3 — cross-correlation via les firewalls connectés.
/// Pour chaque IP source du dossier, on demande au(x) firewall(s) connectés
/// les logs récents pour cette IP. Le résultat alimente `enrichment_lines`
/// avec des constatations factuelles ("Suricata sur skill-opnsense :
/// 14.102.231.203:80 → 10.77.0.174:55925, ET INFO Packed Executable Download,
/// allowed, 47054 bytes downloaded").
///
/// Aucun firewall connecté = section vide, pas d'erreur.
async fn enrich_firewall_logs(
    registry: &crate::agent::skills::registry::SkillRegistry,
    dossier: &mut IncidentDossier,
) {
    if !registry.has_firewall() {
        return;
    }

    let ips = collect_unique_routable_source_ips(dossier);
    if ips.is_empty() {
        return;
    }

    let since = chrono::Utc::now() - chrono::Duration::hours(4);
    let until = chrono::Utc::now();

    let mut new_lines: Vec<String> = Vec::new();

    for ip in ips.iter().take(MAX_IPS_PER_DOSSIER) {
        for fw in &registry.firewalls {
            // Timeout par lookup pour ne jamais bloquer le pipeline. Un firewall
            // injoignable ne casse pas la construction du dossier.
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                fw.lookup_logs_for_ip(ip, since, until),
            )
            .await;

            let entries = match result {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::debug!(
                        skill = fw.skill_id(),
                        ip = ip,
                        error = %e,
                        "DOSSIER_ENRICHMENT: firewall lookup failed"
                    );
                    continue;
                }
                Err(_) => {
                    tracing::debug!(
                        skill = fw.skill_id(),
                        ip = ip,
                        "DOSSIER_ENRICHMENT: firewall lookup timeout"
                    );
                    continue;
                }
            };

            // Cap 5 entrées par firewall+IP pour ne pas exploser le prompt L2
            for e in entries.iter().take(5) {
                new_lines.push(format_firewall_entry(e));
            }
        }
    }

    if !new_lines.is_empty() {
        dossier.enrichment.enrichment_lines.extend(new_lines);
    }
}

/// Formate une `FirewallLogEntry` en ligne factuelle prête à inclure dans le
/// prompt L2. Format français lisible mais préfixé par le skill source
/// pour traçabilité.
fn format_firewall_entry(e: &crate::agent::skills::firewall::FirewallLogEntry) -> String {
    let mut s = format!(
        "[{}] {} — {}:{} → {}:{}, action={}",
        e.source_skill,
        e.timestamp.format("%Y-%m-%d %H:%M:%S"),
        e.source_ip,
        e.source_port.map(|p| p.to_string()).unwrap_or_default(),
        e.dest_ip.as_deref().unwrap_or(""),
        e.dest_port.map(|p| p.to_string()).unwrap_or_default(),
        e.action
    );
    if let Some(p) = &e.proto {
        s.push_str(&format!(" proto={p}"));
    }
    if let Some(sig) = &e.signature {
        s.push_str(&format!(" sig=\"{}\"", sig));
    }
    if let Some(b) = e.bytes_to_client {
        s.push_str(&format!(" bytes_dl={b}"));
    }
    if let Some(b) = e.bytes_to_server {
        s.push_str(&format!(" bytes_ul={b}"));
    }
    s
}

// ── Helpers de collecte (pure, testable) ───────────────────────────

/// Liste les CVE uniques attestées par les findings du dossier.
///
/// Phase 9e — Quand au moins un `sigma_alert` est présent (= attaque
/// observée), on exclut les findings dont le `skill_id` est listé dans
/// `PREDICTIVE_SKILLS` (`software-vuln`, `wordpress-vuln`, ...). Ces
/// findings sont des **CVE statiques** liées à la posture de l'asset, pas
/// à l'attaque en cours. Les inclure dans `enrichment.cve_details`
/// pollue la chronologie d'attaque et fait croire au RSSI que l'attaque
/// exploite ces CVE, alors qu'un SSH brute force n'a rien à voir avec
/// une CVE tcl-expect par exemple. La posture vulnérabilité reste
/// disponible sur la page asset.
fn collect_unique_cves(dossier: &IncidentDossier) -> Vec<String> {
    use crate::agent::intelligence_engine::PREDICTIVE_SKILLS;

    let sigma_driven = !dossier.sigma_alerts.is_empty();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for f in &dossier.findings {
        if sigma_driven {
            let is_predictive = f
                .skill_id
                .as_deref()
                .map(|s| PREDICTIVE_SKILLS.contains(&s))
                .unwrap_or(false);
            if is_predictive {
                continue;
            }
        }
        if let Some(cve) = f.metadata.get("cve").and_then(|v| v.as_str()) {
            if seen.insert(cve.to_string()) {
                out.push(cve.to_string());
            }
        }
    }
    out
}

fn collect_unique_routable_source_ips(dossier: &IncidentDossier) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for a in &dossier.sigma_alerts {
        if let Some(ip) = &a.source_ip {
            let trimmed = ip.split('/').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            if crate::agent::ip_classifier::is_non_routable(trimmed) {
                continue;
            }
            if seen.insert(trimmed.to_string()) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::incident_dossier::*;
    use crate::agent::intelligence_engine::NotificationLevel;
    use chrono::Utc;
    use uuid::Uuid;

    fn mk_finding_with_cve(id: i64, cve: &str) -> DossierFinding {
        DossierFinding {
            id,
            title: format!("vuln {}", cve),
            description: None,
            severity: "CRITICAL".into(),
            asset: Some("a1".into()),
            source: None,
            skill_id: Some("software-vuln".into()),
            metadata: serde_json::json!({"cve": cve}),
            detected_at: Utc::now(),
        }
    }

    fn mk_finding_no_cve(id: i64) -> DossierFinding {
        DossierFinding {
            id,
            title: "f".into(),
            description: None,
            severity: "MEDIUM".into(),
            asset: Some("a1".into()),
            source: None,
            skill_id: Some("ml-clustering".into()),
            metadata: serde_json::json!({}),
            detected_at: Utc::now(),
        }
    }

    fn mk_alert_with_ip(id: i64, ip: Option<&str>) -> DossierAlert {
        DossierAlert {
            id,
            rule_id: "test-rule".into(),
            rule_name: "Test".into(),
            level: "high".into(),
            source_ip: ip.map(String::from),
            matched_fields: serde_json::json!({}),
            created_at: Utc::now(),
            username: None,
        }
    }

    fn mk_dossier(findings: Vec<DossierFinding>, alerts: Vec<DossierAlert>) -> IncidentDossier {
        IncidentDossier {
            id: Uuid::nil(),
            created_at: Utc::now(),
            primary_asset: "a1".into(),
            findings,
            sigma_alerts: alerts,
            enrichment: EnrichmentBundle {
                ip_reputations: vec![],
                cve_details: vec![],
                threat_intel: vec![],
                enrichment_lines: vec![],
            },
            correlations: CorrelationBundle {
                kill_chain_detected: false,
                kill_chain_steps: vec![],
                active_attack: false,
                known_exploits: vec![],
                related_assets: vec![],
                campaign_id: None,
            },
            graph_intel: None,
            ml_scores: MlBundle {
                anomaly_score: 0.0,
                dga_domains: vec![],
                behavioral_cluster: None,
            },
            asset_score: 0.0,
            global_score: 0.0,
            notification_level: NotificationLevel::Alert,
            connected_skills: vec![],
            graph_context: None,
            investigation_log: Default::default(),
        }
    }

    #[test]
    fn collect_unique_cves_extracts_from_metadata() {
        let d = mk_dossier(
            vec![
                mk_finding_with_cve(1, "CVE-2023-20867"),
                mk_finding_with_cve(2, "CVE-2016-7200"),
                mk_finding_no_cve(3),
            ],
            vec![],
        );
        let cves = collect_unique_cves(&d);
        assert_eq!(cves, vec!["CVE-2023-20867", "CVE-2016-7200"]);
    }

    #[test]
    fn collect_unique_cves_dedupes() {
        let d = mk_dossier(
            vec![
                mk_finding_with_cve(1, "CVE-2023-20867"),
                mk_finding_with_cve(2, "CVE-2023-20867"),
                mk_finding_with_cve(3, "CVE-2023-20867"),
            ],
            vec![],
        );
        let cves = collect_unique_cves(&d);
        assert_eq!(cves, vec!["CVE-2023-20867"]);
    }

    #[test]
    fn collect_unique_cves_empty_when_no_metadata() {
        let d = mk_dossier(vec![mk_finding_no_cve(1)], vec![]);
        let cves = collect_unique_cves(&d);
        assert!(cves.is_empty());
    }

    #[test]
    fn collect_unique_cves_drops_predictive_when_sigma_driven() {
        // Phase 9e — un incident sigma-driven (au moins 1 sigma_alert) ne doit
        // pas remonter les CVE des findings prédictifs (software-vuln). Sans
        // sigma_alert le filtrage ne s'applique pas (cas posture asset).
        let predictive = mk_finding_with_cve(1, "CVE-2021-42237"); // software-vuln
        let mut behavioural = mk_finding_with_cve(2, "CVE-2099-1234");
        behavioural.skill_id = Some("ml-clustering".into()); // non-prédictif

        // (1) Sans sigma_alert : tout est gardé (page asset).
        let d_static = mk_dossier(vec![predictive.clone(), behavioural.clone()], vec![]);
        let cves_static = collect_unique_cves(&d_static);
        assert_eq!(cves_static.len(), 2);
        assert!(cves_static.contains(&"CVE-2021-42237".to_string()));
        assert!(cves_static.contains(&"CVE-2099-1234".to_string()));

        // (2) Avec sigma_alert (incident d'attaque) : on drop le predictif.
        let alert = mk_alert_with_ip(99, Some("62.210.201.235"));
        let d_attack = mk_dossier(vec![predictive, behavioural], vec![alert]);
        let cves_attack = collect_unique_cves(&d_attack);
        assert_eq!(cves_attack, vec!["CVE-2099-1234"]);
    }

    #[test]
    fn collect_routable_ips_skips_non_routable() {
        let d = mk_dossier(
            vec![],
            vec![
                mk_alert_with_ip(1, Some("14.102.231.203")), // public, kept
                mk_alert_with_ip(2, Some("10.0.0.5")),       // RFC1918, skipped
                mk_alert_with_ip(3, Some("192.168.1.10")),   // RFC1918, skipped
                mk_alert_with_ip(4, Some("127.0.0.1")),      // loopback, skipped
                mk_alert_with_ip(5, Some("162.210.195.117")), // public, kept
            ],
        );
        let ips = collect_unique_routable_source_ips(&d);
        assert_eq!(ips, vec!["14.102.231.203", "162.210.195.117"]);
    }

    #[test]
    fn collect_routable_ips_dedupes() {
        let d = mk_dossier(
            vec![],
            vec![
                mk_alert_with_ip(1, Some("14.102.231.203")),
                mk_alert_with_ip(2, Some("14.102.231.203")),
                mk_alert_with_ip(3, Some("14.102.231.203")),
            ],
        );
        let ips = collect_unique_routable_source_ips(&d);
        assert_eq!(ips, vec!["14.102.231.203"]);
    }

    #[test]
    fn collect_routable_ips_handles_none_source_ip() {
        let d = mk_dossier(
            vec![],
            vec![
                mk_alert_with_ip(1, None),
                mk_alert_with_ip(2, Some("14.102.231.203")),
            ],
        );
        let ips = collect_unique_routable_source_ips(&d);
        assert_eq!(ips, vec!["14.102.231.203"]);
    }

    #[test]
    fn collect_routable_ips_handles_empty_string() {
        let d = mk_dossier(vec![], vec![mk_alert_with_ip(1, Some(""))]);
        let ips = collect_unique_routable_source_ips(&d);
        assert!(ips.is_empty());
    }

    #[test]
    fn collect_routable_ips_strips_cidr() {
        let d = mk_dossier(vec![], vec![mk_alert_with_ip(1, Some("14.102.231.203/32"))]);
        let ips = collect_unique_routable_source_ips(&d);
        assert_eq!(ips, vec!["14.102.231.203"]);
    }
}

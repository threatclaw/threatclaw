//! Forensic enricher — async deep analysis on confirmed incidents.
//!
//! Background task that polls every few minutes, picks the most recent confirmed
//! incident without `forensic_enriched_at`, runs the forensic LLM over it, and
//! updates the incident with a detailed narrative + MITRE mapping + evidence citations.
//!
//! One incident at a time (forensic model is resource-intensive). Idempotent:
//! `forensic_enriched_at` stays NULL on crash, so the next pass retries cleanly.
//!
//! See ADR-049 (two-speed LLM pipeline — triage sync + forensic async).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::agent::incident_action::{IncidentAction, ProposedActionsBundle};
use crate::agent::llm_router::LlmRouterConfig;
use crate::agent::llm_schemas::forensic_schema;
use crate::agent::react_runner::call_ollama_with_schema;
use crate::agent::skills::registry::SkillRegistry;
use crate::db::Database;

const POLL_INTERVAL: Duration = Duration::from_secs(180);

pub async fn run_forensic_enricher(db: Arc<dyn Database>, llm_config: LlmRouterConfig) {
    info!(
        "Forensic enricher started — polling every {}s",
        POLL_INTERVAL.as_secs()
    );
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        if let Err(e) = enrich_one(&db, &llm_config).await {
            warn!("Forensic enricher error: {e}");
        }
    }
}

async fn enrich_one(db: &Arc<dyn Database>, llm_config: &LlmRouterConfig) -> Result<(), String> {
    let incidents = db
        .list_confirmed_unenriched_incidents()
        .await
        .map_err(|e| format!("DB query failed: {e}"))?;

    let Some(inc) = incidents.into_iter().next() else {
        debug!("Forensic enricher: no confirmed incidents pending enrichment");
        return Ok(());
    };

    let id = inc["id"].as_i64().unwrap_or(0) as i32;
    let title = inc["title"].as_str().unwrap_or("").to_string();
    let asset = inc["asset"].as_str().unwrap_or("").to_string();
    let severity = inc["severity"].as_str().unwrap_or("MEDIUM").to_string();
    let alert_count_field = inc["alert_count"].as_i64().unwrap_or(0);
    let existing_summary = inc["summary"].as_str().unwrap_or("").to_string();
    let mitre_existing: Vec<String> = inc["mitre_techniques"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Phase 2a — re-fetch the full grounded context from the DB instead of
    // building the prompt from the bare incident fields. The L2 hallucinated
    // (88.88.88.88, EternalBlue, fail2ban, Wazuh references) when given only
    // title+summary because there was nothing concrete to ground its narrative.
    // Now we pass the actual findings, sigma_alerts (with source_ip), and the
    // pre-computed enrichment_cache hits (CVE details, IP reputations).
    let finding_ids: Vec<i64> = inc["finding_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default();
    let alert_ids: Vec<i64> = inc["alert_ids"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default();

    // Phase 7d — Anti-hallucination gate utilise la vraie quantité de preuves.
    //
    // Avant : `alert_count` (colonne DB peuplée par l'IE). Bug observé sur
    // cyb06 : alert_count reste à 0 alors que alert_ids contient 6 sigma
    // alerts. Conséquence : tous les incidents skipent le L2 → summary vide,
    // proposed_actions vide. Cas d'école : #1580 SSH brute force avec
    // alert_count=0 mais 6 sigma_alerts attestés.
    //
    // Maintenant : on compte les preuves RÉELLEMENT présentes en base
    // (alert_ids + finding_ids). Si le L1 a aussi laissé des
    // evidence_citations, c'est un signal fort qu'on a des preuves même
    // avec un seul ID listé.
    let evidence_count = (alert_ids.len() + finding_ids.len()) as i64;
    let has_evidence = inc["evidence_citations"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if evidence_count < 2 && !has_evidence {
        info!(
            "Forensic enricher: incident #{id} — insufficient evidence (alert_ids={}, finding_ids={}, alert_count_db={alert_count_field}, no citations) — skipping LLM",
            alert_ids.len(),
            finding_ids.len()
        );
        let msg = "Données insuffisantes pour produire une analyse forensique fiable. \
            Une seule alerte sans preuves corroborantes ne permet pas d'établir une narrative avec certitude.";
        db.mark_forensic_enriched(id, Some(msg), None, None)
            .await
            .map_err(|e| format!("DB stamp failed: {e}"))?;
        return Ok(());
    }

    info!(
        "Forensic enricher: processing incident #{id} — {title} (alert_ids={}, finding_ids={})",
        alert_ids.len(),
        finding_ids.len()
    );

    let findings = db
        .get_findings_by_ids(&finding_ids)
        .await
        .unwrap_or_default();
    let sigma_alerts = db
        .get_sigma_alerts_by_ids(&alert_ids)
        .await
        .unwrap_or_default();

    let context = ForensicContext {
        incident_id: id,
        asset: asset.clone(),
        severity: severity.clone(),
        alert_count: evidence_count,
        title: title.clone(),
        findings,
        sigma_alerts,
        mitre_existing: mitre_existing.clone(),
    };

    // Phase 9b — registry des skills connectés. Un seul probe DB par
    // incident, utilisé par `derive_response_actions` pour adapter le
    // panel d'actions au stack effectivement câblé chez le client.
    let registry = SkillRegistry::from_db(db.as_ref()).await;

    let prompt = build_forensic_prompt(&context);

    // Phase 7f — timeout 1200s → 300s. Au-delà de 5 min, le L2 a soit crashé
    // soit le hardware sature ; pas la peine d'attendre 20 min pour stamper.
    // Le derive_block_actions déterministe garantit une proposition HITL
    // même si le L2 timeout.
    let llm_start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(300),
        call_ollama_with_schema(
            &llm_config.forensic.base_url,
            &llm_config.forensic.model,
            &prompt,
            Some(forensic_schema()),
        ),
    )
    .await;

    match result {
        Err(_) => {
            warn!(
                "Forensic enricher: timeout on incident #{id} (300s) — stamping as enriched, deriving fallback actions"
            );
            // Phase 9o — log le timeout L2 dans la timeline d'investigation.
            crate::agent::investigation_log::StepBuilder::new(
                crate::db::threatclaw_store::StepKind::LlmCall,
                "L2 forensic Foundation-Sec — timeout 300s",
            )
            .duration_from(llm_start)
            .status(crate::db::threatclaw_store::StepStatus::Timeout)
            .payload(serde_json::json!({
                "model": llm_config.forensic.model,
                "prompt_len": prompt.len(),
            }))
            .record(db.as_ref(), id)
            .await;
            db.mark_forensic_enriched(id, None, None, None)
                .await
                .map_err(|e| format!("DB stamp failed: {e}"))?;

            // Phase 7f / 9b — fallback déterministe en cas de timeout L2.
            // Sans ça, l'incident reste sans action proposée. Phase 9b
            // élargit du single block_ip à un panel multi-skill (block_ip,
            // isolate_host, disable_user...) selon le type d'attaque
            // classifié et les skills connectés. Le RSSI valide via HITL
            // avant exécution.
            let derived = derive_response_actions(&context, &registry);
            // Diagnostic : confirme que le contexte sigma_alerts a bien été
            // hydraté avant le call L2 — si vide ici, c'est qu'on a perdu
            // l'enrichment dans le pipe (DB error sur get_sigma_alerts_by_ids).
            let sigma_with_ip = context
                .sigma_alerts
                .iter()
                .filter_map(|a| a["source_ip"].as_str())
                .collect::<Vec<_>>()
                .join(",");
            info!(
                "Forensic enricher: incident #{id} timeout context — sigma_alerts.len()={}, source_ips=[{}], derived={}",
                context.sigma_alerts.len(),
                sigma_with_ip,
                derived.len()
            );
            if !derived.is_empty() {
                let action_count = derived.len();
                let bundle = ProposedActionsBundle::new(derived.clone());
                if let Err(e) = db
                    .set_incident_proposed_actions(id, &bundle.to_value())
                    .await
                {
                    warn!("Forensic enricher: timeout fallback persist for #{id} failed: {e}");
                } else {
                    info!(
                        "Forensic enricher: incident #{id} timeout — derived {action_count} block_ip persisted (HITL)"
                    );
                }
                // Phase 9o — log le derive fallback dans la timeline.
                crate::agent::investigation_log::StepBuilder::new(
                    crate::db::threatclaw_store::StepKind::DeriveActions,
                    format!(
                        "Fallback déterministe (L2 timeout) — {action_count} action(s) HITL proposée(s)"
                    ),
                )
                .status(crate::db::threatclaw_store::StepStatus::Fallback)
                .payload(serde_json::json!({
                    "actions": derived
                        .iter()
                        .map(|a| serde_json::json!({
                            "kind": a.kind,
                            "cmd_id": a.cmd_id,
                            "skill_id": a.skill_id,
                        }))
                        .collect::<Vec<_>>(),
                }))
                .record(db.as_ref(), id)
                .await;
            }
        }
        Ok(Err(e)) => {
            warn!("Forensic enricher: LLM error on incident #{id}: {e}");
            // Phase 9o — log l'erreur LLM (transient) dans la timeline.
            crate::agent::investigation_log::StepBuilder::new(
                crate::db::threatclaw_store::StepKind::LlmCall,
                format!("L2 forensic — erreur LLM transient ({e})"),
            )
            .duration_from(llm_start)
            .status(crate::db::threatclaw_store::StepStatus::Error)
            .payload(serde_json::json!({"error": e}))
            .record(db.as_ref(), id)
            .await;
            // Do not stamp — will retry next pass (transient error)
        }
        Ok(Ok(raw)) => {
            match parse_forensic_response(&raw) {
                Ok(parsed) => {
                    let mitre: Vec<String> = parsed["mitre_techniques"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let summary = parsed["analysis"].as_str().unwrap_or("").to_string();
                    let evidence_citations = parsed["evidence_citations"].clone();

                    // Phase 2c — Reconciler narrative.
                    // Avant d'écrire la réponse L2 en base, on valide que :
                    //  - les evidence_citations.evidence_id référencent bien des
                    //    IDs réels du dossier (finding_id / alert_id)
                    //  - les MITRE techniques mentionnés sont dans la liste
                    //    pré-attestée
                    //  - le narrative ne cite pas d'entités (IPs, CVEs) absentes
                    //    du dossier
                    // Si une violation est détectée, on overwrite la réponse par un
                    // summary auto-généré déterministe — pas de hallucination en DB.
                    let validation = validate_l2_response(&parsed, &context);
                    let (final_summary, final_mitre, final_citations) = if validation.is_valid() {
                        // Phase 9o — log un succès LLM L2.
                        crate::agent::investigation_log::StepBuilder::new(
                            crate::db::threatclaw_store::StepKind::LlmCall,
                            format!(
                                "L2 forensic — narrative {} chars · {} MITRE technique(s) · validation OK",
                                summary.len(),
                                mitre.len()
                            ),
                        )
                        .duration_from(llm_start)
                        .payload(serde_json::json!({
                            "model": llm_config.forensic.model,
                            "prompt_len": prompt.len(),
                            "summary_len": summary.len(),
                            "mitre_techniques": mitre,
                        }))
                        .record(db.as_ref(), id)
                        .await;
                        (summary, mitre, evidence_citations)
                    } else {
                        warn!(
                            "Forensic enricher: incident #{id} — L2 response REJECTED ({}) — falling back to deterministic summary",
                            validation.violations.join("; ")
                        );
                        // Phase 9o — log la réponse rejetée par le reconciler.
                        crate::agent::investigation_log::StepBuilder::new(
                            crate::db::threatclaw_store::StepKind::LlmCall,
                            format!(
                                "L2 forensic — réponse rejetée par le reconciler ({} violation(s)) — fallback déterministe",
                                validation.violations.len()
                            ),
                        )
                        .duration_from(llm_start)
                        .status(crate::db::threatclaw_store::StepStatus::Fallback)
                        .payload(serde_json::json!({
                            "violations": validation.violations,
                            "rejected_summary_preview": summary.chars().take(200).collect::<String>(),
                        }))
                        .record(db.as_ref(), id)
                        .await;
                        (
                            build_fallback_summary(&context, &validation.violations),
                            ctx_mitre_only(&context),
                            serde_json::json!([]),
                        )
                    };

                    db.mark_forensic_enriched(
                        id,
                        Some(&final_summary),
                        Some(&final_mitre),
                        Some(&final_citations),
                    )
                    .await
                    .map_err(|e| format!("DB update failed: {e}"))?;

                    // Phase 6/7b — persist proposed_actions du L2 si valides,
                    // sinon dériver déterministiquement.
                    //
                    // Phase 6 originale : on prend ce que le L2 a renvoyé.
                    // Phase 7b (#1580 cas d'école) : le L2 a souvent renvoyé
                    // `proposed_actions: []` malgré l'instruction explicite.
                    // Quand validation OK + IPs externes attestées dans le
                    // dossier, on injecte côté Rust un opnsense_block_ip par
                    // IP unique. Le RSSI valide ou refuse via HITL — pas
                    // d'execution auto.
                    if validation.is_valid() {
                        // Phase 9c — normaliser ce que le L2 a renvoyé vers le
                        // schéma canonique via le parser rétrocompat. Le L2 peut
                        // sortir un array plat `[{cmd_id, ...}]` ou un wrapper
                        // `{actions: [...], iocs: [...]}` ; les deux atterrissent
                        // ici sur `ProposedActionsBundle`.
                        let l2_bundle =
                            crate::agent::incident_action::parse_proposed_actions_legacy(
                                &parsed["proposed_actions"],
                            );

                        info!(
                            "Forensic enricher: incident #{id} — Phase 7b gate: L2 returned {} action(s), context has {} sigma_alerts",
                            l2_bundle.actions.len(),
                            context.sigma_alerts.len()
                        );

                        let final_bundle = if l2_bundle.actions.is_empty() {
                            // Le L2 n'a rien proposé : on dérive déterministe via
                            // les builders canoniques + Phase 9b multi-skill.
                            let derived = derive_response_actions(&context, &registry);
                            info!(
                                "Forensic enricher: incident #{id} — derive_response_actions returned {} action(s)",
                                derived.len()
                            );
                            ProposedActionsBundle::new(derived)
                        } else {
                            // L2 OK + non-vide : on garde son output (déjà
                            // normalisé canonique par `parse_legacy`).
                            l2_bundle
                        };

                        if !final_bundle.actions.is_empty() {
                            let n = final_bundle.actions.len();
                            if let Err(e) = db
                                .set_incident_proposed_actions(id, &final_bundle.to_value())
                                .await
                            {
                                warn!(
                                    "Forensic enricher: persist proposed_actions for #{id} failed: {e}"
                                );
                            } else {
                                info!(
                                    "Forensic enricher: incident #{id} — {n} proposed_actions persisted"
                                );
                            }
                            // Phase 9o — log le panel d'actions HITL produit.
                            crate::agent::investigation_log::StepBuilder::new(
                                crate::db::threatclaw_store::StepKind::DeriveActions,
                                format!("Panel HITL — {n} action(s) proposée(s)"),
                            )
                            .payload(serde_json::json!({
                                "actions": final_bundle
                                    .actions
                                    .iter()
                                    .map(|a| serde_json::json!({
                                        "kind": a.kind,
                                        "cmd_id": a.cmd_id,
                                        "skill_id": a.skill_id,
                                        "description": a.description,
                                    }))
                                    .collect::<Vec<_>>(),
                            }))
                            .record(db.as_ref(), id)
                            .await;
                        } else {
                            info!(
                                "Forensic enricher: incident #{id} — no actions to persist (L2 empty AND no external IP)"
                            );
                        }
                    } else {
                        info!(
                            "Forensic enricher: incident #{id} — Phase 7b skipped (validation REJECTED)"
                        );
                    }

                    info!(
                        "Forensic enricher: incident #{id} enriched — {} MITRE techniques, {}-char narrative (validation: {})",
                        final_mitre.len(),
                        final_summary.len(),
                        if validation.is_valid() {
                            "OK"
                        } else {
                            "REJECTED→FALLBACK"
                        }
                    );
                }
                Err(e) => {
                    warn!("Forensic enricher: failed to parse response for incident #{id}: {e}");
                    // Stamp without content — response was malformed, avoid infinite retry
                    db.mark_forensic_enriched(id, None, None, None)
                        .await
                        .map_err(|e2| format!("DB stamp failed: {e2}"))?;
                }
            }
        }
    }

    Ok(())
}

/// Données factuelles passées au prompt L2 forensic. Toutes proviennent de la
/// DB (re-fetched via finding_ids / alert_ids du incident) — aucun champ
/// halluciné par un L1 antérieur n'est remonté ici. Voir `roadmap-mai.md`
/// Phase 2a pour le design.
pub(crate) struct ForensicContext {
    pub incident_id: i32,
    pub asset: String,
    pub severity: String,
    pub alert_count: i64,
    pub title: String,
    /// Findings re-fetched via `get_findings_by_ids` à partir de
    /// `incidents.finding_ids` (peuplé par l'IE). Format JSON brut DB.
    pub findings: Vec<Value>,
    /// Sigma alerts re-fetched via `get_sigma_alerts_by_ids` à partir de
    /// `incidents.alert_ids` (peuplé par Phase 1a). Format JSON brut DB.
    pub sigma_alerts: Vec<Value>,
    /// MITRE techniques déjà identifiés par l'IE (depuis le metadata.mitre
    /// des findings, pas inventés par un LLM).
    pub mitre_existing: Vec<String>,
}

fn build_forensic_prompt(ctx: &ForensicContext) -> String {
    let mut p = String::with_capacity(8000);

    p.push_str("Tu es un analyste forensique expert. Produis un rapport pour le RSSI.\n\n");

    // ── Règle absolue (en HAUT pour qu'elle pèse plus) ──
    p.push_str("## RÈGLE ABSOLUE — anti-hallucination\n\n");
    p.push_str("Tu n'as accès QU'AUX données du dossier ci-dessous (sections DOSSIER FACTUEL, ");
    p.push_str("FINDINGS et SIGMA ALERTS). Tu ne dois mentionner :\n");
    p.push_str("- AUCUNE IP, CVE, signature, ou hash absent du dossier\n");
    p.push_str("- AUCUN service externe (Wazuh, GreyNoise, fail2ban, GoAccess, ELK, Splunk...) ");
    p.push_str("absent du dossier\n");
    p.push_str("- AUCUNE technique MITRE ATT&CK qui ne soit pas dans la liste fournie\n");
    p.push_str("- AUCUN exécutable, malware, ou outil qui ne soit pas explicitement cité dans les findings\n\n");
    p.push_str(
        "Chaque claim de ton `analysis` DOIT être traçable à un `finding_id` ou `alert_id` ",
    );
    p.push_str("listé ci-dessous. Si les données sont insuffisantes, dis-le clairement plutôt que d'inférer.\n\n");

    // ── Dossier factuel ──
    p.push_str("## DOSSIER FACTUEL\n\n");
    p.push_str(&format!("Incident ID: {}\n", ctx.incident_id));
    p.push_str(&format!("Asset: {}\n", ctx.asset));
    p.push_str(&format!("Sévérité: {}\n", ctx.severity));
    p.push_str(&format!(
        "Nombre d'alertes corrélées: {}\n\n",
        ctx.alert_count
    ));
    p.push_str(&format!("Titre généré par l'IE: {}\n\n", ctx.title));

    // ── Findings (source de vérité) ──
    //
    // Phase 7a — Si l'incident a AU MOINS 1 sigma_alert, c'est une attaque
    // observée temps-réel. Les findings de type software-vuln sont alors du
    // contexte d'environnement (état du patch), PAS l'attaque. On les masque
    // du prompt pour empêcher le L2 d'inverser sa narrative (#1577 / #1580 :
    // SSH brute force a sorti une analyse "exploitation tcl-expect" parce que
    // le dossier mélangeait sigma SSH + findings vuln tcl-expect).
    let predictive_skills = [
        "software-vuln",
        "wordpress-vuln",
        "ssl-tls",
        "wp-security",
        "dns-misconfig",
    ];
    let findings_filtered: Vec<&Value> = if !ctx.sigma_alerts.is_empty() {
        ctx.findings
            .iter()
            .filter(|f| {
                let skill = f["skill_id"].as_str().unwrap_or("");
                !predictive_skills.iter().any(|p| skill.starts_with(p))
            })
            .collect()
    } else {
        ctx.findings.iter().collect()
    };
    let masked = ctx.findings.len().saturating_sub(findings_filtered.len());
    p.push_str(&format!(
        "## FINDINGS ({} entrées{})\n\n",
        findings_filtered.len(),
        if masked > 0 {
            format!(" — {masked} finding(s) software-vuln masqués (incident sigma-driven)")
        } else {
            String::new()
        }
    ));
    if findings_filtered.is_empty() {
        p.push_str(
            "(aucun finding pertinent — l'incident est piloté par les SIGMA ALERTS ci-dessous)\n\n",
        );
    } else {
        for f in findings_filtered.iter().take(10) {
            let fid = f["id"].as_i64().unwrap_or(0);
            let title = f["title"].as_str().unwrap_or("");
            let sev = f["severity"].as_str().unwrap_or("");
            let skill = f["skill_id"].as_str().unwrap_or("");
            let asset = f["asset"].as_str().unwrap_or("");
            let cve = f["metadata"]["cve"].as_str().unwrap_or("");
            p.push_str(&format!(
                "- finding_id={fid} skill={skill} severity={sev} asset={asset}\n"
            ));
            p.push_str(&format!("  title: {title}\n"));
            if !cve.is_empty() {
                p.push_str(&format!("  cve: {cve}\n"));
            }
        }
        p.push('\n');
    }

    // ── Sigma alerts (source de vérité) ──
    p.push_str(&format!(
        "## SIGMA ALERTS ({} entrées)\n\n",
        ctx.sigma_alerts.len()
    ));
    if ctx.sigma_alerts.is_empty() {
        p.push_str("(aucun sigma alert lié — l'incident est probablement basé sur des findings statiques)\n\n");
    } else {
        for a in ctx.sigma_alerts.iter().take(10) {
            let aid = a["id"].as_i64().unwrap_or(0);
            let rule_id = a["rule_id"].as_str().unwrap_or("");
            let title = a["title"]
                .as_str()
                .or_else(|| a["rule_name"].as_str())
                .unwrap_or("");
            let level = a["level"].as_str().unwrap_or("");
            let src_ip = a["source_ip"].as_str().unwrap_or("");
            let dst_ip = a["dest_ip"].as_str().unwrap_or("");
            let host = a["hostname"].as_str().unwrap_or("");
            p.push_str(&format!(
                "- alert_id={aid} rule_id={rule_id} level={level}\n"
            ));
            p.push_str(&format!("  title: {title}\n"));
            if !src_ip.is_empty() {
                p.push_str(&format!("  source_ip: {src_ip}\n"));
            }
            if !dst_ip.is_empty() {
                p.push_str(&format!("  dest_ip: {dst_ip}\n"));
            }
            if !host.is_empty() {
                p.push_str(&format!("  hostname: {host}\n"));
            }
        }
        p.push('\n');
    }

    // ── MITRE existant (déjà extrait par l'IE depuis metadata.mitre des findings) ──
    if !ctx.mitre_existing.is_empty() {
        p.push_str("## MITRE ATT&CK techniques attestées par les findings\n\n");
        p.push_str("(Tu ne peux mentionner QUE ces techniques. Aucune autre.)\n\n");
        for t in &ctx.mitre_existing {
            p.push_str(&format!("- {t}\n"));
        }
        p.push('\n');
    } else {
        p.push_str("## MITRE ATT&CK techniques attestées\n\n");
        p.push_str("Aucune technique MITRE n'a été extraite des findings. ");
        p.push_str("Ne mentionne AUCUNE technique MITRE dans ton rapport.\n\n");
    }

    // ── Phase 6 — Source IPs externes détectées (cibles potentielles de blocage) ──
    let external_source_ips: Vec<String> = ctx
        .sigma_alerts
        .iter()
        .filter_map(|a| {
            a["source_ip"]
                .as_str()
                .filter(|ip| !ip.is_empty())
                .filter(|ip| !is_private_ipv4(ip))
                .map(String::from)
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    if !external_source_ips.is_empty() {
        p.push_str("## IPS SOURCE EXTERNES (candidates au blocage)\n\n");
        for ip in &external_source_ips {
            p.push_str(&format!("- {ip}\n"));
        }
        p.push_str("\n→ Si une de ces IPs est l'origine d'un sigma alert (auth failed, IDS, brute force) sur un asset interne, ");
        p.push_str("propose une action `opnsense_block_ip` (ou équivalent fortinet/pfsense/mikrotik) avec cette IP comme paramètre.\n\n");
    }

    // ── Instructions de sortie ──
    p.push_str("## INSTRUCTIONS\n\n");
    p.push_str("1. Rédige `analysis` : narrative forensique 200-400 mots lisible par un RSSI ");
    p.push_str("non-technique, basée UNIQUEMENT sur les findings et sigma alerts ci-dessus.\n");
    p.push_str("   - NE NOMME PAS de groupe APT (Lazarus, APT28, Carbanak...) sauf si attesté ");
    p.push_str("dans une finding/alert ci-dessus.\n");
    p.push_str("   - NE PARLE PAS d'exfiltration, ransomware, C2, malware, backdoor sauf si ");
    p.push_str("explicitement présent dans les sigma alerts ci-dessus.\n");
    p.push_str("   - Si l'attaque visible est un SSH brute force, dis-le simplement : ");
    p.push_str("\"Tentatives d'authentification SSH répétées depuis <IP> sur <asset>\". ");
    p.push_str("Pas de spéculation sur des objectifs d'attaque non documentés.\n");
    p.push_str("   - Si DOSSIER FACTUEL contient un titre IE clair, suis-le pour la nature de l'incident.\n");
    p.push_str(
        "2. `mitre_techniques` : liste UNIQUEMENT les codes ATT&CK déjà attestés ci-dessus.\n",
    );
    p.push_str("3. `evidence_citations` : pour chaque claim majeur de l'analysis, cite le ");
    p.push_str("`finding_id` ou `alert_id` correspondant (champ `evidence_id`).\n");
    p.push_str("4. `proposed_actions` : si une IP source externe est listée ci-dessus, propose ");
    p.push_str("UNE action `opnsense_block_ip` avec params `{ip: \"<ip>\"}` et un rationale ");
    p.push_str("court qui réfère le sigma alert.\n");
    p.push_str("5. Si les données sont insuffisantes pour produire une narrative claire, ");
    p.push_str("réponds avec `analysis: \"Données insuffisantes — N findings et M alerts ");
    p.push_str("disponibles, mais aucune corrélation observable.\"`\n\n");

    p.push_str("Réponds en JSON strict avec les champs: ");
    p.push_str("verdict (confirmed/inconclusive), severity, confidence (0.0-1.0), ");
    p.push_str("analysis (string), mitre_techniques (array of strings), ");
    p.push_str("evidence_citations (array of {claim, evidence_type, evidence_id, excerpt}), ");
    p.push_str("proposed_actions (array of {cmd_id, params, rationale}).\n");

    p
}

fn is_private_ipv4(s: &str) -> bool {
    let octets: Vec<u8> = match s
        .split('/')
        .next()
        .unwrap_or("")
        .parse::<std::net::Ipv4Addr>()
    {
        Ok(v) => v.octets().to_vec(),
        Err(_) => return false,
    };
    let o = octets.as_slice();
    matches!(
        (o[0], o[1]),
        (10, _) | (192, 168) | (127, _) | (169, 254) | (172, 16..=31)
    )
}

/// Type d'attaque détecté à partir des sigma_alerts du dossier. Drive le
/// panel d'actions HITL proposé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttackKind {
    /// Brute force d'authentification (SSH, RDP, web login, fortinet auth
    /// failed). L'attaquant teste des mots de passe — block IP + isolate
    /// + disable user pertinents.
    AuthBruteForce,
    /// Alerte IDS/IPS générique sur trafic externe → asset interne (scan,
    /// exploit attempt). Suppose que Phase 8b a déjà filtré les FP update.
    IdsAlert,
    /// Crypto-mining détecté (process pkr, outbound vers pool). Killer le
    /// process est l'action prioritaire.
    Cryptomining,
    /// Mouvement latéral / abus AD (golden ticket, dcsync, escalade
    /// privilèges). Reset krbtgt + isolation prioritaires.
    LateralMovement,
    /// Trafic outbound suspect (Phase 7c — Windows Update etc.) — analyse
    /// manuelle recommandée plutôt que blocage automatique pour éviter de
    /// casser des updates légitimes.
    SuspiciousOutbound,
    /// Pattern non classifié — au mieux on propose un block_ip si IP
    /// externe attestée.
    Generic,
}

/// Classifie un dossier d'incident selon ses sigma_alerts. Le premier
/// pattern reconnu gagne — l'ordre des matches est conçu pour être
/// déterministe : les attaques actives (cryptomining, golden ticket)
/// dominent sur les patterns plus génériques (auth, IDS).
fn classify_attack(sigma_alerts: &[Value]) -> AttackKind {
    let rule_ids: Vec<&str> = sigma_alerts
        .iter()
        .filter_map(|a| a["rule_id"].as_str())
        .collect();
    let titles_lower: Vec<String> = sigma_alerts
        .iter()
        .filter_map(|a| a["title"].as_str())
        .map(|s| s.to_lowercase())
        .collect();

    let any_rule = |needles: &[&str]| -> bool {
        rule_ids
            .iter()
            .any(|r| needles.iter().any(|n| r.contains(n)))
    };
    let any_title = |needles: &[&str]| -> bool {
        titles_lower
            .iter()
            .any(|t| needles.iter().any(|n| t.contains(n)))
    };

    // Patterns spécifiques d'abord (haute confiance)
    if any_rule(&["cryptomining"]) || any_title(&["cryptomining", "miner", "monero"]) {
        return AttackKind::Cryptomining;
    }
    if any_rule(&["golden-ticket", "dcsync"]) || any_title(&["golden ticket", "dcsync"]) {
        return AttackKind::LateralMovement;
    }
    if any_title(&[
        "trafic sortant suspect",
        "suspicious outbound",
        "outbound suspect",
    ]) {
        return AttackKind::SuspiciousOutbound;
    }
    if any_rule(&[
        "ssh-brute",
        "rdp-brute",
        "tc-ssh-brute",
        "opnsense-001",
        "fortinet-auth-failed",
    ]) || any_title(&["brute force", "auth failed", "failed login"])
    {
        return AttackKind::AuthBruteForce;
    }
    if any_rule(&["opnsense-004", "ids-alert"])
        || any_title(&["ids alert", "ips alert", "suricata", "snort"])
    {
        return AttackKind::IdsAlert;
    }
    AttackKind::Generic
}

/// Phase 9b — Dérive déterministe du panel d'actions HITL à partir du
/// dossier + des skills connectés. Remplace `derive_block_actions`
/// (Phase 7b, single-action `opnsense_block_ip`) par un panel adapté au
/// type d'attaque détecté ET aux capacités effectivement câblées chez le
/// client.
///
/// Doctrine :
///   * Toujours `block_ip` quand IP externe attestée + firewall connecté.
///   * `isolate_host` quand EDR connecté ET attaque suggère compromission
///     (brute force OU exploit OU lateral OU mining).
///   * `disable_user` quand IAM connecté ET un username est attesté dans
///     les sigma_alerts.
///   * `kill_process` pour mining (PID requis dans le sigma).
///   * `reset_krbtgt` pour golden ticket attesté.
///   * `collect_artifacts` pour incidents forensiques (lateral, exploit,
///     mining) quand EDR connecté.
///
/// Quand un skill **n'est pas connecté**, on génère une `IncidentAction`
/// `Manual` avec une description recommandant l'opération hors-bande
/// plutôt que rien — l'opérateur garde la guidance.
///
/// Les call sites wrap le `Vec<IncidentAction>` dans
/// `ProposedActionsBundle` avant persist. Aucune action n'est exécutée
/// automatiquement : tout passe par HITL.
fn derive_response_actions(ctx: &ForensicContext, registry: &SkillRegistry) -> Vec<IncidentAction> {
    let mut external_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut usernames: std::collections::HashSet<String> = std::collections::HashSet::new();
    for a in &ctx.sigma_alerts {
        if let Some(ip) = a["source_ip"].as_str() {
            let stripped = ip.split('/').next().unwrap_or(ip);
            if !stripped.is_empty() && !is_private_ipv4(stripped) {
                external_ips.insert(stripped.to_string());
            }
        }
        if let Some(user) = a["username"].as_str() {
            let trimmed = user.trim();
            if !trimmed.is_empty() {
                usernames.insert(trimmed.to_string());
            }
        }
    }

    let kind = classify_attack(&ctx.sigma_alerts);
    let mut actions: Vec<IncidentAction> = Vec::new();

    // Helper : pick le firewall skill préféré (1er enregistré, OPNsense
    // en fallback pour le stack bundlé même si le registry est vide —
    // l'exécution râlera mais le RSSI aura la guidance).
    let firewall_skill: &str = registry
        .firewall_skill_ids()
        .first()
        .copied()
        .unwrap_or("skill-opnsense");
    let edr_skill: Option<&str> = registry.edr_skill_ids().first().copied();
    let iam_skill: Option<String> = registry.iam_skill_ids.first().cloned();

    // ── (1) Block IP — toujours pertinent pour AuthBruteForce / IdsAlert
    //        / Cryptomining / Generic avec IP externe.
    let propose_block_ip = matches!(
        kind,
        AttackKind::AuthBruteForce
            | AttackKind::IdsAlert
            | AttackKind::Cryptomining
            | AttackKind::Generic
    );
    if propose_block_ip {
        for ip in &external_ips {
            let alert_ids: Vec<i64> = ctx
                .sigma_alerts
                .iter()
                .filter(|a| {
                    a["source_ip"]
                        .as_str()
                        .and_then(|s| s.split('/').next())
                        .map(|s| s == ip.as_str())
                        .unwrap_or(false)
                })
                .filter_map(|a| a["id"].as_i64())
                .collect();
            let rationale = format!(
                "IP externe attestée par {} sigma alert(s) (ids={:?}) sur l'asset {} — proposition de blocage HITL",
                alert_ids.len(),
                alert_ids,
                ctx.asset
            );
            if registry.has_firewall() {
                actions.push(IncidentAction::block_ip(ip, firewall_skill, rationale));
            } else {
                actions.push(IncidentAction::manual(
                    format!("Bloquer manuellement l'IP {ip} au pare-feu (aucun firewall ThreatClaw connecté)"),
                    rationale,
                ));
            }
        }
    }

    // ── (2) Isolate host — compromission suspectée pour AuthBruteForce
    //        confirmé, IdsAlert critique, Cryptomining, LateralMovement.
    let propose_isolate = matches!(
        kind,
        AttackKind::AuthBruteForce
            | AttackKind::IdsAlert
            | AttackKind::Cryptomining
            | AttackKind::LateralMovement
    );
    if propose_isolate {
        let alert_ids: Vec<i64> = ctx
            .sigma_alerts
            .iter()
            .filter_map(|a| a["id"].as_i64())
            .collect();
        let rationale = format!(
            "Compromission suspectée — {} alert(s) ({:?}) — isolation EDR du host {}",
            alert_ids.len(),
            alert_ids,
            ctx.asset
        );
        match edr_skill {
            Some(skill) => actions.push(IncidentAction::isolate_host(&ctx.asset, skill, rationale)),
            None => actions.push(IncidentAction::manual(
                format!(
                    "Isoler manuellement {} au niveau EDR (aucun EDR ThreatClaw connecté)",
                    ctx.asset
                ),
                rationale,
            )),
        }
    }

    // ── (3) Disable user — quand un username est attesté ET attaque
    //        d'authentification ou lateral movement.
    let propose_disable_user = matches!(
        kind,
        AttackKind::AuthBruteForce | AttackKind::LateralMovement
    );
    if propose_disable_user {
        for user in &usernames {
            let rationale = format!(
                "Compte ciblé par tentatives d'authentification — désactivation HITL recommandée pour {user}"
            );
            match iam_skill.as_deref() {
                Some(skill) => actions.push(IncidentAction::disable_user(user, skill, rationale)),
                None => actions.push(IncidentAction::manual(
                    format!("Désactiver manuellement le compte {user} dans l'annuaire (aucun IAM ThreatClaw connecté)"),
                    rationale,
                )),
            }
        }
    }

    // ── (4) Kill process — Cryptomining quand PID attesté.
    if matches!(kind, AttackKind::Cryptomining) {
        let pids: Vec<u32> = ctx
            .sigma_alerts
            .iter()
            .filter_map(|a| a["matched_fields"]["pid"].as_u64().map(|p| p as u32))
            .collect();
        for pid in pids {
            let rationale = format!("PID {pid} attesté par les sigma alerts cryptomining");
            match edr_skill {
                Some(skill) => actions.push(IncidentAction::kill_process(
                    &ctx.asset, pid, skill, rationale,
                )),
                None => actions.push(IncidentAction::manual(
                    format!(
                        "Tuer manuellement le PID {pid} sur {} (aucun EDR connecté)",
                        ctx.asset
                    ),
                    rationale,
                )),
            }
        }
    }

    // ── (5) Reset krbtgt — golden ticket confirmé.
    if matches!(kind, AttackKind::LateralMovement)
        && ctx.sigma_alerts.iter().any(|a| {
            a["rule_id"]
                .as_str()
                .map(|r| r.contains("golden-ticket"))
                .unwrap_or(false)
        })
    {
        let rationale = "Golden ticket attesté — rotation immédiate du krbtgt (impact: tous les TGT existants invalidés)".to_string();
        match iam_skill.as_deref() {
            Some(skill) if skill == "skill-active-directory" => {
                actions.push(IncidentAction::reset_krbtgt(skill, rationale))
            }
            _ => actions.push(IncidentAction::manual(
                "Faire tourner manuellement le krbtgt AD deux fois (aucun connecteur AD)"
                    .to_string(),
                rationale,
            )),
        }
    }

    // ── (6) Collect artifacts — Lateral / Cryptomining / IdsAlert critique.
    if matches!(
        kind,
        AttackKind::LateralMovement | AttackKind::Cryptomining | AttackKind::IdsAlert
    ) && edr_skill.is_some()
    {
        let rationale = format!(
            "Collecte forensique sur {} pour reconstituer la chaîne d'attaque",
            ctx.asset
        );
        actions.push(IncidentAction::collect_artifacts(
            &ctx.asset,
            "Generic.Forensic.Timeline",
            edr_skill.unwrap(),
            rationale,
        ));
    }

    // ── (7) SuspiciousOutbound — pas de blocage automatique (risque de
    //        casser un Windows Update légitime). Action manual de
    //        vérification.
    if matches!(kind, AttackKind::SuspiciousOutbound) {
        let dest_ips: std::collections::HashSet<String> = ctx
            .sigma_alerts
            .iter()
            .filter_map(|a| a["dest_ip"].as_str().map(str::to_string))
            .filter(|ip| !is_private_ipv4(ip))
            .collect();
        let dest_list = if dest_ips.is_empty() {
            "(IP externe non attestée)".into()
        } else {
            dest_ips.into_iter().collect::<Vec<_>>().join(", ")
        };
        actions.push(IncidentAction::manual(
            format!("Vérifier le trafic sortant de {} vers {dest_list}", ctx.asset),
            "Trafic outbound suspect — possible Windows Update / auto-updater légitime, OU exfiltration. Analyse manuelle requise avant blocage.".to_string(),
        ));
    }

    actions
}

fn parse_forensic_response(raw: &str) -> Result<Value, String> {
    let trimmed = raw.trim();
    let json_str = if let Some(start) = trimmed.find('{') {
        &trimmed[start..]
    } else {
        trimmed
    };

    let v: Value = serde_json::from_str(json_str).map_err(|e| {
        format!(
            "JSON parse error: {e} — raw: {}",
            &raw[..raw.len().min(200)]
        )
    })?;

    if v["analysis"].as_str().map(|s| s.len()).unwrap_or(0) < 10 {
        return Err("analysis field too short or missing".to_string());
    }

    Ok(v)
}

// ── Phase 2c — Reconciler narrative ────────────────────────────────

/// Sentinelles de noms de services / outils que le L2 hallucine fréquemment
/// quand il ne reçoit pas un dossier riche. Si l'un de ces tokens apparaît
/// dans le `analysis` produit ET qu'il n'est pas dans le contexte fourni,
/// la réponse est rejetée. Liste maintenue empiriquement à partir des
/// hallucinations observées (88.88.88.88, fail2ban, Wazuh sans connecteur,
/// EternalBlue inventé, etc.).
const HALLUCINATION_SENTINELS: &[&str] = &[
    "fail2ban",
    "GreyNoise", // si pas en context.enrichment_lines / ip_reputations source
    "VirusTotal",
    "AbuseIPDB",
    "EternalBlue",
    "SMBv1",
    "Wazuh",
    "ELK",
    "Splunk",
    "GoAccess",
    "MS17-010",
    "88.88.88.88",
    "1.2.3.4",
    "192.0.2.",
    "203.0.113.",
    // Hallucinations narratives observées sur cyb06 (#1577, #1580):
    // le L2 invente des groupes APT et des scénarios d'exfiltration sur
    // un simple SSH brute force. Ces tokens ne doivent JAMAIS apparaître
    // dans une narrative sauf s'ils sont attestés dans le dossier.
    "groupe X",
    "groupe Y",
    "groupe Z",
    "groupe inconnu",
    "exfiltration",
    "ransomware",
    "APT28",
    "APT29",
    "APT41",
    "Fancy Bear",
    "Cozy Bear",
    "Lazarus",
    "Sandworm",
    "Carbanak",
    "FIN7",
    "Conti",
    "LockBit",
    "Black Basta",
];

#[derive(Default, Debug)]
pub(crate) struct ValidationResult {
    pub violations: Vec<String>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Valide la réponse L2 contre le contexte du dossier.
/// Une violation = soit un evidence_id qui ne référence aucun finding/alert
/// du contexte, soit une mention dans l'analysis d'un sentinel hallucination
/// qui n'apparaît pas dans le contexte.
pub(crate) fn validate_l2_response(parsed: &Value, ctx: &ForensicContext) -> ValidationResult {
    let mut result = ValidationResult::default();

    // (a) Collecte des IDs valides
    let mut valid_finding_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for f in &ctx.findings {
        if let Some(id) = f["id"].as_i64() {
            valid_finding_ids.insert(id);
        }
    }
    let mut valid_alert_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for a in &ctx.sigma_alerts {
        if let Some(id) = a["id"].as_i64() {
            valid_alert_ids.insert(id);
        }
    }

    // (b) Vérifier les evidence_citations
    if let Some(citations) = parsed["evidence_citations"].as_array() {
        for (idx, c) in citations.iter().enumerate() {
            let ev_type = c["evidence_type"].as_str().unwrap_or("");
            let ev_id_raw = &c["evidence_id"];
            let ev_id = ev_id_raw
                .as_i64()
                .or_else(|| ev_id_raw.as_str().and_then(|s| s.parse().ok()));

            match (ev_type, ev_id) {
                ("finding", Some(id)) if !valid_finding_ids.contains(&id) => {
                    result.violations.push(format!(
                        "evidence_citation[{}] references unknown finding_id={}",
                        idx, id
                    ));
                }
                ("alert", Some(id)) if !valid_alert_ids.contains(&id) => {
                    result.violations.push(format!(
                        "evidence_citation[{}] references unknown alert_id={}",
                        idx, id
                    ));
                }
                ("finding", None) | ("alert", None) => {
                    result.violations.push(format!(
                        "evidence_citation[{}] missing/invalid evidence_id",
                        idx
                    ));
                }
                _ => {}
            }
        }
    }

    // (c) Construire le "haystack" du contexte (toutes les valeurs textuelles
    // du dossier que le LLM a vues). Une mention dans l'analysis qui n'est
    // PAS dans ce haystack est une hallucination potentielle.
    let mut haystack = String::with_capacity(2000);
    haystack.push_str(&ctx.title);
    haystack.push(' ');
    haystack.push_str(&ctx.asset);
    haystack.push(' ');
    for f in &ctx.findings {
        if let Some(s) = f["title"].as_str() {
            haystack.push_str(s);
            haystack.push(' ');
        }
        if let Some(s) = f["description"].as_str() {
            haystack.push_str(s);
            haystack.push(' ');
        }
        if let Some(s) = f["skill_id"].as_str() {
            haystack.push_str(s);
            haystack.push(' ');
        }
        if let Some(s) = f["metadata"]["cve"].as_str() {
            haystack.push_str(s);
            haystack.push(' ');
        }
    }
    for a in &ctx.sigma_alerts {
        for k in &[
            "title",
            "rule_id",
            "rule_name",
            "source_ip",
            "dest_ip",
            "hostname",
        ] {
            if let Some(s) = a[k].as_str() {
                haystack.push_str(s);
                haystack.push(' ');
            }
        }
    }

    let analysis = parsed["analysis"].as_str().unwrap_or("");
    let analysis_lower = analysis.to_lowercase();
    let haystack_lower = haystack.to_lowercase();

    // (d) Vérifier les sentinelles d'hallucination
    for sentinel in HALLUCINATION_SENTINELS {
        let s_lower = sentinel.to_lowercase();
        if analysis_lower.contains(&s_lower) && !haystack_lower.contains(&s_lower) {
            result.violations.push(format!(
                "analysis mentions '{}' but this entity is absent from the dossier",
                sentinel
            ));
        }
    }

    // (e) MITRE techniques : ne doivent être que celles attestées
    if let Some(mitre_arr) = parsed["mitre_techniques"].as_array() {
        let attested: std::collections::HashSet<&str> =
            ctx.mitre_existing.iter().map(|s| s.as_str()).collect();
        for t in mitre_arr {
            if let Some(s) = t.as_str() {
                if !attested.is_empty() && !attested.contains(s) {
                    result.violations.push(format!(
                        "mitre_techniques contains '{}' which is not attested by findings (allowed: {:?})",
                        s, ctx.mitre_existing
                    ));
                }
            }
        }
    }

    result
}

/// Récupère la liste MITRE pré-attestée du contexte (déjà extraite par l'IE
/// depuis `metadata.mitre` des findings — ne peut pas être hallucinée).
fn ctx_mitre_only(ctx: &ForensicContext) -> Vec<String> {
    ctx.mitre_existing.clone()
}

/// Génère un summary forensique déterministe minimal quand la réponse L2
/// est rejetée. Pas de narration "rich" mais factuellement correct, à partir
/// des findings et sigma_alerts du contexte uniquement.
fn build_fallback_summary(ctx: &ForensicContext, violations: &[String]) -> String {
    let mut s = String::with_capacity(1000);
    s.push_str(&format!(
        "Analyse automatique (réponse LLM rejetée — {} violation{} détectée{}).\n\n",
        violations.len(),
        if violations.len() > 1 { "s" } else { "" },
        if violations.len() > 1 { "s" } else { "" }
    ));
    s.push_str(&format!(
        "Asset concerné: {}. Sévérité: {}. {} alerte{} corrélée{}.\n\n",
        ctx.asset,
        ctx.severity,
        ctx.alert_count,
        if ctx.alert_count > 1 { "s" } else { "" },
        if ctx.alert_count > 1 { "s" } else { "" }
    ));

    if !ctx.findings.is_empty() {
        s.push_str(&format!("Findings ({} entrées):\n", ctx.findings.len()));
        for f in ctx.findings.iter().take(5) {
            let title = f["title"].as_str().unwrap_or("");
            let sev = f["severity"].as_str().unwrap_or("");
            s.push_str(&format!("- [{}] {}\n", sev, title));
        }
        s.push('\n');
    }

    if !ctx.sigma_alerts.is_empty() {
        s.push_str(&format!(
            "Sigma alerts ({} entrées):\n",
            ctx.sigma_alerts.len()
        ));
        for a in ctx.sigma_alerts.iter().take(5) {
            let title = a["title"]
                .as_str()
                .or_else(|| a["rule_name"].as_str())
                .unwrap_or("");
            let level = a["level"].as_str().unwrap_or("");
            let src_ip = a["source_ip"].as_str().unwrap_or("");
            if src_ip.is_empty() {
                s.push_str(&format!("- [{}] {}\n", level, title));
            } else {
                s.push_str(&format!(
                    "- [{}] {} (source_ip: {})\n",
                    level, title, src_ip
                ));
            }
        }
        s.push('\n');
    }

    s.push_str("Une analyse approfondie par un analyste humain est recommandée pour ce dossier.");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_ctx() -> ForensicContext {
        ForensicContext {
            incident_id: 1,
            asset: "srv-01".into(),
            severity: "HIGH".into(),
            alert_count: 2,
            title: "Test incident on srv-01".into(),
            findings: vec![json!({
                "id": 100,
                "title": "CVE-2023-20867 in virtio-win-guest-tools",
                "description": "VMware vulnerability",
                "severity": "CRITICAL",
                "skill_id": "software-vuln",
                "metadata": {"cve": "CVE-2023-20867", "mitre": ["T1190"]}
            })],
            sigma_alerts: vec![json!({
                "id": 200,
                "rule_id": "opnsense-004",
                "rule_name": "OPNsense IDS alert",
                "title": "OPNsense IDS alert",
                "level": "high",
                "source_ip": "14.102.231.203",
                "hostname": "srv-01",
            })],
            mitre_existing: vec!["T1190".into()],
        }
    }

    #[test]
    fn validate_clean_response_passes() {
        let ctx = mk_ctx();
        let resp = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.85,
            "analysis": "L'asset srv-01 est affecté par CVE-2023-20867 sur virtio-win-guest-tools. Une alerte OPNsense IDS a été déclenchée depuis 14.102.231.203.",
            "mitre_techniques": ["T1190"],
            "evidence_citations": [
                {"claim": "CVE present", "evidence_type": "finding", "evidence_id": 100},
                {"claim": "IDS alert", "evidence_type": "alert", "evidence_id": 200},
            ]
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(result.is_valid(), "violations: {:?}", result.violations);
    }

    #[test]
    fn validate_rejects_unknown_finding_id() {
        let ctx = mk_ctx();
        let resp = json!({
            "analysis": "Asset srv-01 affecté.",
            "mitre_techniques": [],
            "evidence_citations": [
                {"claim": "x", "evidence_type": "finding", "evidence_id": 999}
            ]
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(!result.is_valid());
        assert!(result.violations[0].contains("unknown finding_id=999"));
    }

    #[test]
    fn validate_rejects_unknown_alert_id() {
        let ctx = mk_ctx();
        let resp = json!({
            "analysis": "x",
            "mitre_techniques": [],
            "evidence_citations": [
                {"claim": "x", "evidence_type": "alert", "evidence_id": 9999}
            ]
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(!result.is_valid());
    }

    #[test]
    fn validate_rejects_hallucinated_88_88_88_88() {
        let ctx = mk_ctx();
        let resp = json!({
            "analysis": "L'attaquant 88.88.88.88 a tenté une connexion SSH brute force.",
            "mitre_techniques": [],
            "evidence_citations": []
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(!result.is_valid());
        assert!(result.violations.iter().any(|v| v.contains("88.88.88.88")));
    }

    #[test]
    fn validate_rejects_hallucinated_eternalblue() {
        let ctx = mk_ctx();
        let resp = json!({
            "analysis": "EternalBlue exploit detected on the server via SMBv1.",
            "mitre_techniques": [],
            "evidence_citations": []
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(!result.is_valid());
        assert!(result.violations.iter().any(|v| v.contains("EternalBlue")));
    }

    #[test]
    fn validate_rejects_hallucinated_wazuh() {
        let ctx = mk_ctx();
        let resp = json!({
            "analysis": "Wazuh detected the activity on the asset.",
            "mitre_techniques": [],
            "evidence_citations": []
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(!result.is_valid());
        assert!(result.violations.iter().any(|v| v.contains("Wazuh")));
    }

    #[test]
    fn validate_accepts_sentinel_when_present_in_context() {
        // If the dossier mentions Wazuh (e.g., the skill produced the finding),
        // the L2 can mention it.
        let mut ctx = mk_ctx();
        ctx.findings.push(json!({
            "id": 101,
            "title": "Wazuh finding on the asset",
            "skill_id": "wazuh-vuln",
            "metadata": {}
        }));
        let resp = json!({
            "analysis": "Wazuh a remonté un finding.",
            "mitre_techniques": [],
            "evidence_citations": []
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(result.is_valid(), "violations: {:?}", result.violations);
    }

    #[test]
    fn validate_rejects_unattested_mitre_technique() {
        let ctx = mk_ctx();
        let resp = json!({
            "analysis": "OK",
            "mitre_techniques": ["T1190", "T1059"],  // T1059 not in mitre_existing
            "evidence_citations": []
        });
        let result = validate_l2_response(&resp, &ctx);
        assert!(!result.is_valid());
        assert!(result.violations.iter().any(|v| v.contains("T1059")));
    }

    #[test]
    fn fallback_summary_mentions_real_findings_only() {
        let ctx = mk_ctx();
        let s = build_fallback_summary(&ctx, &["test violation".to_string()]);
        assert!(s.contains("srv-01"));
        assert!(s.contains("CVE-2023-20867"));
        assert!(s.contains("14.102.231.203"));
        assert!(!s.contains("88.88.88.88"));
        assert!(!s.contains("fail2ban"));
    }
}

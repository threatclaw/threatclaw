//! Dispatcher : pousser un `IncidentDossier` en queue d'Investigation Graph
//! quand un graph match son sigma_rule.
//!
//! Mode parallel-run (G1b → G1e) : on enqueue le graph en plus du ReAct,
//! pas à la place. Les deux verdicts coexistent — graph dans
//! `graph_executions`, ReAct dans `incidents.verdict`. On compare
//! offline pour calibrer les graphs avant de couper le ReAct (G1e).
//!
//! L'API exposée :
//! - `set_library(lib)` — appelé par `boot()` au démarrage
//! - `library()` — accès lecture, retourne une library vide si pas encore set
//! - `try_enqueue_graph_for_dossier(store, dossier)` — best-effort,
//!   retourne `Some(exec_id)` si un graph a été enqueued, sinon `None`.

use std::sync::Arc;
use std::sync::OnceLock;

use chrono::Timelike;
use serde_json::{Value, json};
use tracing::{info, warn};

use super::store::{NewGraphExecution, NewTask, TaskKind};
use crate::agent::incident_dossier::IncidentDossier;
use crate::agent::investigation_graph::GraphLibrary;
use crate::db::Database;

static GRAPH_LIBRARY: OnceLock<Arc<GraphLibrary>> = OnceLock::new();

/// Stocke la library dans le static global. À appeler une seule fois par
/// `boot()`. Les appels ultérieurs sont ignorés (OnceLock).
pub fn set_library(lib: Arc<GraphLibrary>) {
    let _ = GRAPH_LIBRARY.set(lib);
}

/// Retourne la library globale. Si pas encore initialisée (boot pas
/// encore tourné, ou environnement de test sans library), retourne une
/// library vide — `find_for_sigma_rule` y renvoie `None`, ce qui fait
/// fallback ReAct silencieusement.
pub fn library() -> Arc<GraphLibrary> {
    GRAPH_LIBRARY
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(GraphLibrary::empty()))
}

/// Best-effort : si on trouve un graph qui match le sigma_rule du dossier,
/// on crée une row `graph_executions` + on enqueue un task `graph_step`,
/// puis on renvoie `Some(exec_id)`. Sinon `None` (le caller fait son
/// fallback ReAct sans rien savoir).
///
/// Toute erreur DB / payload est loggée et silencieusement convertie en
/// `None` — on ne casse jamais le pipeline existant pour un graph qui
/// échoue à enqueue.
/// Sprint 5 #1 — return value extended to expose whether the matched graph
/// can emit a `PendingAsync(investigate-llm)`. The IE callsite uses this to
/// decide whether to short-circuit ReAct (`TC_GRAPH_ONLY=1`): if the graph
/// might delegate to the LLM, we must let ReAct run even in graph-only mode
/// — otherwise the verdict never lands and the incident dies in `running`.
#[derive(Debug, Clone, Copy)]
pub struct GraphDispatch {
    pub exec_id: i64,
    pub requires_llm: bool,
}

pub async fn try_enqueue_graph_for_dossier(
    store: &Arc<dyn Database>,
    dossier: &IncidentDossier,
) -> Option<GraphDispatch> {
    let lib = library();
    if lib.is_empty() {
        return None;
    }

    let sigma_rule = pick_dominant_sigma_rule(dossier)?;
    let compiled = lib.find_for_sigma_rule(&sigma_rule)?;
    let graph_name = compiled.name.clone();
    let requires_llm = compiled.requires_llm;

    let new_exec = NewGraphExecution {
        graph_name: graph_name.clone(),
        sigma_alert_id: dossier.sigma_alerts.first().map(|a| a.id),
        asset_id: Some(dossier.primary_asset.clone()),
    };

    let exec_id = match store.create_graph_execution(&new_exec).await {
        Ok(id) => id,
        Err(e) => {
            warn!(
                "GRAPH DISPATCH: create_graph_execution échoué pour '{}': {}",
                graph_name, e
            );
            return None;
        }
    };

    let payload = json!({
        "graph_name": graph_name,
        "ctx": build_ctx_from_dossier(store, dossier).await,
    });
    let new_task = NewTask {
        kind: TaskKind::GraphStep,
        graph_run_id: Some(exec_id),
        payload,
        priority: 5,
        max_attempts: 3,
    };

    match store.enqueue_task(&new_task).await {
        Ok(task_id) => {
            info!(
                "GRAPH DISPATCH: graph='{}' enqueued task={} exec_id={} sigma_rule='{}' asset='{}' requires_llm={}",
                graph_name, task_id, exec_id, sigma_rule, dossier.primary_asset, requires_llm
            );
            Some(GraphDispatch {
                exec_id,
                requires_llm,
            })
        }
        Err(e) => {
            warn!(
                "GRAPH DISPATCH: enqueue_task échoué pour '{}': {}",
                graph_name, e
            );
            None
        }
    }
}

/// Trouve un sigma_rule représentatif du dossier. Stratégie :
/// 1. Premier sigma_alert du dossier — utilise `rule_id` (identifiant machine,
///    ex: "tc-ssh-brute") qui correspond au `trigger.sigma_rule` des graphs CACAO.
///    NE PAS utiliser `rule_name` (= titre humain, ex: "SSH Brute Force") qui ne
///    matche jamais les triggers.
/// 2. Sinon, premier finding qui a `metadata.sigma_rule` ou `metadata.rule_id`.
/// 3. Sinon `None` (pas de graph applicable, fallback ReAct).
fn pick_dominant_sigma_rule(dossier: &IncidentDossier) -> Option<String> {
    if let Some(alert) = dossier.sigma_alerts.first() {
        if !alert.rule_id.is_empty() {
            return Some(alert.rule_id.clone());
        }
    }
    dossier
        .findings
        .iter()
        .find_map(|f| {
            f.metadata
                .get("sigma_rule")
                .or_else(|| f.metadata.get("rule_id"))
                .and_then(Value::as_str)
        })
        .map(String::from)
}

/// Construit le payload `ctx` que le `graph_step_worker` injectera dans
/// l'`EvalContext` pour évaluer les prédicats CEL.
///
/// **Phase G1c** : on enrichit avec les vrais helpers existants au lieu
/// d'approximations :
/// - `signals.recent_count_5m` / `signals.recent_count_1h` : compteurs
///   réels via `count_recent_signals_on_asset` (Phase A — agrège
///   sigma_alerts + findings + firewall_events sur l'asset dans la
///   fenêtre temporelle).
/// - `graph.*` : tirés du `GraphAssetContext` (Phase C2 — Cypher AGE qui
///   pré-resolve criticality, lateral_paths, CVE liées, recent users).
///
/// Conventions de nommage alignées avec les YAMLs existants :
/// - `alert.firewall_action`, `alert.src_ip`, `alert.severity`
/// - `asset.id`, `asset.criticality` (string : low/medium/high/critical),
///   `asset.criticality_score` (int 0..9 dérivé)
/// - `signals.recent_count_5m`, `signals.recent_count_1h`,
///   `signals.corroborated`
/// - `graph.asset_in_graph`, `graph.lateral_paths`,
///   `graph.linked_cves_count`, `graph.recent_users_count`
async fn build_ctx_from_dossier(store: &Arc<dyn Database>, dossier: &IncidentDossier) -> Value {
    // Premier finding ou alert pour les fields "alert.*"
    let first_alert_meta = dossier
        .sigma_alerts
        .first()
        .map(|a| a.matched_fields.clone())
        .unwrap_or(Value::Null);
    let first_finding_meta = dossier
        .findings
        .first()
        .map(|f| f.metadata.clone())
        .unwrap_or(Value::Null);

    let firewall_action = pick(&[&first_alert_meta, &first_finding_meta], "firewall_action")
        .or_else(|| pick(&[&first_alert_meta, &first_finding_meta], "action"));
    let src_ip = pick(&[&first_alert_meta, &first_finding_meta], "src_ip");
    let severity = dossier
        .findings
        .first()
        .map(|f| Value::String(f.severity.clone()))
        .unwrap_or_else(|| {
            dossier
                .sigma_alerts
                .first()
                .map(|a| Value::String(a.level.clone()))
                .unwrap_or(Value::Null)
        });

    // Compteurs temporels réels (Phase A helper). Couvrent sigma_alerts +
    // findings + firewall_events sur l'asset, dans la fenêtre demandée.
    // Si l'asset est vide (dossier sans asset_id) ou si la requête
    // échoue, on retombe sur 0 — le YAML doit accepter ça.
    let recent_count_5m = store
        .count_recent_signals_on_asset(&dossier.primary_asset, 5)
        .await
        .unwrap_or(0);
    let recent_count_1h = store
        .count_recent_signals_on_asset(&dossier.primary_asset, 60)
        .await
        .unwrap_or(0);

    // Graph context — Phase C2. Quand `graph_context` est `Some`, l'asset
    // a été résolu dans le graph AGE — on a criticality, lateral_paths,
    // CVE liées, users récents.
    let (asset_in_graph, lateral_paths, linked_cves_count, recent_users_count, criticality_str) =
        match &dossier.graph_context {
            Some(g) => (
                true,
                g.lateral_paths as i64,
                g.linked_cves.len() as i64,
                g.recent_users.len() as i64,
                g.criticality.clone(),
            ),
            None => (false, 0i64, 0i64, 0i64, "unknown".to_string()),
        };
    let criticality_score = criticality_to_score(&criticality_str);

    json!({
        "alert": {
            "firewall_action": firewall_action.unwrap_or(Value::Null),
            "src_ip": src_ip.unwrap_or(Value::Null),
            "severity": severity,
        },
        "asset": {
            "id": dossier.primary_asset,
            "criticality": criticality_str,
            "criticality_score": criticality_score,
            "score": dossier.asset_score.round() as i64,
        },
        "dossier": {
            "id": dossier.id.to_string(),
            "findings_count": dossier.findings.len(),
            "alerts_count": dossier.sigma_alerts.len(),
            "global_score": dossier.global_score,
        },
        "signals": {
            "recent_count_5m": recent_count_5m,
            "recent_count_1h": recent_count_1h,
            "corroborated": recent_count_1h >= 2,
            "is_service_acct": compute_is_service_acct(dossier),
            "is_admin": compute_is_admin(dossier),
            "hour_of_day": chrono::Utc::now().hour() as i64,
        },
        "graph": {
            "asset_in_graph": asset_in_graph,
            "lateral_paths": lateral_paths,
            "linked_cves_count": linked_cves_count,
            "recent_users_count": recent_users_count,
        },
    })
}

/// Détermine si l'alerte concerne un compte de service.
/// Critères : suffixe `$` (Windows machine accounts), comptes système Linux connus,
/// ou champ `matched_fields.service_account` explicitement vrai.
fn compute_is_service_acct(dossier: &IncidentDossier) -> bool {
    let username = dossier
        .sigma_alerts
        .first()
        .and_then(|a| {
            a.username
                .as_deref()
                .map(str::to_owned)
                .or_else(|| a.matched_fields.get("username").and_then(Value::as_str).map(str::to_owned))
        })
        .unwrap_or_default();
    if username.is_empty() {
        return false;
    }
    // Windows machine account (DOMAIN$) or explicit service_account field
    if username.ends_with('$') {
        return true;
    }
    // Known Linux/Windows system accounts
    matches!(
        username.to_lowercase().as_str(),
        "system"
            | "localservice"
            | "networkservice"
            | "daemon"
            | "www-data"
            | "nobody"
            | "sshd"
            | "nginx"
            | "apache"
            | "mysql"
            | "postgres"
            | "redis"
    )
}

/// Détermine si l'alerte concerne un compte administrateur.
fn compute_is_admin(dossier: &IncidentDossier) -> bool {
    let username = dossier
        .sigma_alerts
        .first()
        .and_then(|a| {
            a.username
                .as_deref()
                .map(str::to_owned)
                .or_else(|| a.matched_fields.get("username").and_then(Value::as_str).map(str::to_owned))
        })
        .unwrap_or_default();
    if username.is_empty() {
        return false;
    }
    let lc = username.to_lowercase();
    lc == "root"
        || lc == "admin"
        || lc == "administrator"
        || lc.contains("_admin")
        || lc.contains("admin_")
}

/// Convertit `criticality` string ("low" / "medium" / "high" / "critical" /
/// "unknown") en score numérique pour comparaisons CEL (`asset.criticality_score >= 7`).
fn criticality_to_score(s: &str) -> i64 {
    match s.to_lowercase().as_str() {
        "critical" => 9,
        "high" => 7,
        "medium" => 5,
        "low" => 3,
        _ => 0,
    }
}

/// Cherche un champ dans la première source qui le contient.
fn pick(sources: &[&Value], field: &str) -> Option<Value> {
    for s in sources {
        if let Some(v) = s.get(field) {
            if !v.is_null() {
                return Some(v.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn criticality_score_maps_known_levels() {
        assert_eq!(criticality_to_score("critical"), 9);
        assert_eq!(criticality_to_score("HIGH"), 7);
        assert_eq!(criticality_to_score("Medium"), 5);
        assert_eq!(criticality_to_score("low"), 3);
    }

    #[test]
    fn criticality_score_unknown_or_empty_is_zero() {
        assert_eq!(criticality_to_score("unknown"), 0);
        assert_eq!(criticality_to_score(""), 0);
        assert_eq!(criticality_to_score("garbage"), 0);
    }

    #[test]
    fn pick_returns_first_non_null() {
        let a = json!({"x": null, "y": "from_a"});
        let b = json!({"x": "from_b"});
        assert_eq!(pick(&[&a, &b], "x"), Some(json!("from_b")));
        assert_eq!(pick(&[&a, &b], "y"), Some(json!("from_a")));
        assert_eq!(pick(&[&a, &b], "z"), None);
    }

    #[test]
    fn pick_dominant_sigma_rule_uses_rule_id_not_rule_name() {
        use crate::agent::incident_dossier::*;
        use crate::agent::intelligence_engine::NotificationLevel;
        use chrono::Utc;
        use uuid::Uuid;

        let dossier = IncidentDossier {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            primary_asset: "srv-01".into(),
            findings: vec![],
            sigma_alerts: vec![DossierAlert {
                id: 1,
                rule_id: "tc-ssh-brute".into(),
                rule_name: "SSH Brute Force".into(),
                level: "high".into(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
                username: None,
            }],
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
            notification_level: NotificationLevel::Silence,
            connected_skills: vec![],
            graph_context: None,
        };

        let rule = pick_dominant_sigma_rule(&dossier);
        assert_eq!(rule, Some("tc-ssh-brute".to_string()));
        assert_ne!(rule, Some("SSH Brute Force".to_string()));
    }

    #[test]
    fn compute_is_service_acct_detects_dollar_suffix() {
        use crate::agent::incident_dossier::*;
        use crate::agent::intelligence_engine::NotificationLevel;
        use chrono::Utc;
        use uuid::Uuid;

        let make = |username: &str| IncidentDossier {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            primary_asset: "host".into(),
            findings: vec![],
            sigma_alerts: vec![DossierAlert {
                id: 1,
                rule_id: "r".into(),
                rule_name: "r".into(),
                level: "low".into(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
                username: Some(username.into()),
            }],
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
            notification_level: NotificationLevel::Silence,
            connected_skills: vec![],
            graph_context: None,
        };

        assert!(compute_is_service_acct(&make("DOMAIN$")));
        assert!(compute_is_service_acct(&make("www-data")));
        assert!(compute_is_service_acct(&make("postgres")));
        assert!(!compute_is_service_acct(&make("alice")));
        assert!(compute_is_admin(&make("root")));
        assert!(compute_is_admin(&make("Administrator")));
        assert!(!compute_is_admin(&make("alice")));
    }
}

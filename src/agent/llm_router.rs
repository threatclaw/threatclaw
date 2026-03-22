//! LLM Router — orchestration multi-niveaux local + cloud.
//!
//! Niveau 1 : IA locale rapide (triage, corrélation simple)
//! Niveau 2 : IA locale enrichie (plus de contexte, 2ème chance)
//! Niveau 3 : IA cloud anonymisée (corrélation profonde, fallback)
//!
//! Le client configure son IA principale (obligatoire) et son IA cloud (optionnel)
//! via le wizard d'onboarding. Le router décide automatiquement quand escalader.

use serde::{Deserialize, Serialize};

/// Type de tâche LLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmTask {
    Chat,
    Correlation,
    Report,
    Triage,
}

/// Politique d'escalade vers le cloud.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudEscalation {
    /// Jamais de cloud — 100% local.
    Never,
    /// Cloud avec anonymisation des données (défaut recommandé).
    Anonymized,
    /// Cloud sans anonymisation (déconseillé, données sensibles exposées).
    Direct,
}

impl Default for CloudEscalation {
    fn default() -> Self {
        Self::Anonymized
    }
}

/// Configuration de l'IA principale (obligatoire).
/// Par défaut : threatclaw-redsage (modèle cyber spécialisé RedSage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimaryLlmConfig {
    /// Backend : ollama, mistral, anthropic, openai_compatible.
    pub backend: String,
    /// Modèle principal (L1/L2 — triage, corrélation, actions).
    pub model: String,
    /// URL de base (Ollama ou compatible).
    pub base_url: String,
    /// Clé API (pour Mistral/Anthropic/OpenAI).
    pub api_key: Option<String>,
}

impl Default for PrimaryLlmConfig {
    fn default() -> Self {
        Self {
            backend: "ollama".to_string(),
            model: std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "threatclaw-redsage".to_string()),
            base_url: std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".to_string()),
            api_key: None,
        }
    }
}

/// Configuration du LLM forensique (L2+ — chargé à la demande).
/// Utilisé pour les analyses approfondies sur les incidents Critical/High.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicLlmConfig {
    /// Modèle forensique (Foundation-sec ou équivalent).
    pub model: String,
    /// URL Ollama (même instance que primary par défaut).
    pub base_url: String,
    /// Timeout d'inactivité avant déchargement (secondes).
    pub idle_timeout_secs: u64,
}

impl Default for ForensicLlmConfig {
    fn default() -> Self {
        Self {
            model: std::env::var("FORENSIC_MODEL").unwrap_or_else(|_| "threatclaw-forensic".to_string()),
            base_url: std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".to_string()),
            idle_timeout_secs: 600, // 10 minutes
        }
    }
}

/// Configuration de l'IA cloud de secours (optionnel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudLlmConfig {
    /// Backend cloud : mistral, anthropic, openai_compatible.
    pub backend: String,
    /// Modèle cloud.
    pub model: String,
    /// URL de base (si openai_compatible).
    pub base_url: Option<String>,
    /// Clé API (obligatoire pour le cloud).
    pub api_key: String,
}

/// Configuration complète du routeur LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmRouterConfig {
    /// IA principale L1/L2 — triage et corrélation (obligatoire).
    pub primary: PrimaryLlmConfig,
    /// IA forensique L2+ — analyse approfondie (optionnel, chargé à la demande).
    #[serde(default)]
    pub forensic: ForensicLlmConfig,
    /// IA cloud L3 — rapports et incidents critiques (optionnel).
    pub cloud: Option<CloudLlmConfig>,
    /// Politique d'escalade.
    pub cloud_escalation: CloudEscalation,
    /// Anonymiser les données envoyées à l'IA principale.
    /// True si les données quittent l'infrastructure (cloud provider, API externe).
    /// False si l'IA tourne en local (Ollama, vLLM sur le réseau local).
    #[serde(default)]
    pub anonymize_primary: bool,
    /// Seuil de confiance pour accepter l'analyse locale (0.0-1.0).
    pub confidence_accept: f64,
    /// Seuil de confiance pour l'escalade au niveau 2 (0.0-1.0).
    pub confidence_retry: f64,
}

impl Default for LlmRouterConfig {
    fn default() -> Self {
        Self {
            primary: PrimaryLlmConfig::default(),
            forensic: ForensicLlmConfig::default(),
            cloud: None,
            cloud_escalation: CloudEscalation::Anonymized,
            anonymize_primary: false, // Ollama local par défaut
            confidence_accept: 0.70,
            confidence_retry: 0.50,
        }
    }
}

/// Décision d'escalade après une analyse.
#[derive(Debug, Clone, PartialEq)]
pub enum EscalationDecision {
    /// Analyse acceptée, pas d'escalade.
    Accept,
    /// Réessayer en local avec plus de contexte (Niveau 2).
    RetryLocal,
    /// Escalader vers le cloud (Niveau 3).
    EscalateCloud,
    /// Cloud non configuré, garder l'analyse locale en mode dégradé.
    AcceptDegraded,
}

impl LlmRouterConfig {
    /// Charge la config LLM depuis la base de données (settings du dashboard).
    /// Priorité : env vars > DB settings > défauts.
    pub async fn from_db_settings(store: &dyn crate::db::Database) -> Self {
        let mut config = Self::default();

        // ── Primary LLM (tc_config_llm) ──
        if let Ok(Some(llm_val)) = store.get_setting("_system", "tc_config_llm").await {
            if let Some(backend) = llm_val["backend"].as_str() {
                if !backend.is_empty() && std::env::var("LLM_BACKEND").is_err() {
                    config.primary.backend = backend.to_string();
                }
            }
            if let Some(url) = llm_val["url"].as_str() {
                if !url.is_empty() && std::env::var("OLLAMA_BASE_URL").is_err() {
                    config.primary.base_url = url.to_string();
                }
            }
            if let Some(model) = llm_val["model"].as_str() {
                if !model.is_empty() && std::env::var("OLLAMA_MODEL").is_err() {
                    config.primary.model = model.to_string();
                }
            }
            if let Some(key) = llm_val["apiKey"].as_str() {
                if !key.is_empty() {
                    config.primary.api_key = Some(key.to_string());
                }
            }
        }

        // ── Cloud LLM (tc_config_cloud) ──
        if let Ok(Some(cloud_val)) = store.get_setting("_system", "tc_config_cloud").await {
            let backend = cloud_val["backend"].as_str().unwrap_or("").to_string();
            let model = cloud_val["model"].as_str().unwrap_or("").to_string();
            let api_key = cloud_val["apiKey"].as_str().unwrap_or("").to_string();
            let base_url = cloud_val["url"].as_str().map(|s| s.to_string());

            if !backend.is_empty() && !api_key.is_empty() {
                config.cloud = Some(CloudLlmConfig {
                    backend,
                    model: if model.is_empty() { "claude-sonnet-4-20250514".to_string() } else { model },
                    base_url,
                    api_key,
                });
            }
        }

        // ── Forensic LLM L2 (tc_config_forensic) ──
        if let Ok(Some(forensic_val)) = store.get_setting("_system", "tc_config_forensic").await {
            if let Some(model) = forensic_val["model"].as_str() {
                if !model.is_empty() && std::env::var("FORENSIC_MODEL").is_err() {
                    config.forensic.model = model.to_string();
                }
            }
            if let Some(url) = forensic_val["url"].as_str() {
                if !url.is_empty() {
                    config.forensic.base_url = url.to_string();
                }
            }
        }

        // ── Anonymize primary (tc_config_anonymize_primary) ──
        if let Ok(Some(anon_val)) = store.get_setting("_system", "tc_config_anonymize_primary").await {
            if let Some(anon) = anon_val.as_bool() {
                config.anonymize_primary = anon;
            }
        }

        tracing::debug!(
            "LLM config loaded: primary={}/{} cloud={}",
            config.primary.backend, config.primary.model,
            config.cloud.as_ref().map(|c| format!("{}/{}", c.backend, c.model)).unwrap_or("none".into())
        );

        config
    }

    /// Détermine s'il faut escalader après une analyse.
    pub fn decide_escalation(
        &self,
        confidence: f64,
        severity: &str,
        injection_detected: bool,
        is_retry: bool,
    ) -> EscalationDecision {
        // Injection détectée → toujours escalader pour deuxième avis
        if injection_detected && self.cloud_available() {
            return EscalationDecision::EscalateCloud;
        }

        // Confiance suffisante → accepter
        if confidence >= self.confidence_accept && severity != "CRITICAL" {
            return EscalationDecision::Accept;
        }

        // CRITICAL avec actions proposées → escalader pour validation
        if severity == "CRITICAL" && !is_retry && self.cloud_available() {
            return EscalationDecision::EscalateCloud;
        }

        // Confiance entre retry et accept → réessayer en local (si pas déjà fait)
        if confidence >= self.confidence_retry && !is_retry {
            return EscalationDecision::RetryLocal;
        }

        // Confiance trop basse après retry → escalader au cloud
        if confidence < self.confidence_retry && self.cloud_available() {
            return EscalationDecision::EscalateCloud;
        }

        // Pas de cloud configuré → garder l'analyse locale
        if confidence >= self.confidence_accept {
            EscalationDecision::Accept
        } else {
            EscalationDecision::AcceptDegraded
        }
    }

    /// Vérifie si le cloud est disponible et autorisé.
    pub fn cloud_available(&self) -> bool {
        self.cloud.is_some() && self.cloud_escalation != CloudEscalation::Never
    }

    /// Vérifie si l'anonymisation est requise pour le cloud.
    pub fn requires_anonymization(&self) -> bool {
        self.cloud_escalation == CloudEscalation::Anonymized
    }

    /// Vérifie si l'anonymisation est requise pour l'IA principale.
    /// Basé sur le flag `anonymize_primary` défini par l'utilisateur dans le wizard.
    /// True = les données quittent l'infrastructure → anonymiser avant envoi.
    pub fn primary_requires_anonymization(&self) -> bool {
        self.anonymize_primary
    }

    /// Vérifie si l'IA principale utilise une API cloud (pas Ollama local).
    /// Utilisé pour router les appels vers cloud_caller au lieu d'Ollama.
    pub fn primary_uses_cloud_api(&self) -> bool {
        self.primary.backend != "ollama"
    }

    /// Retourne le modèle principal pour une tâche.
    pub fn model_for_task(&self, _task: LlmTask) -> &str {
        &self.primary.model
    }

    /// Détecte automatiquement le modèle recommandé selon la RAM disponible.
    pub fn recommend_model(available_ram_gb: u64) -> &'static str {
        match available_ram_gb {
            0..=7 => "qwen3:4b",
            8..=15 => "qwen3:8b",
            16..=31 => "qwen3:14b",
            32..=63 => "qwen3:32b",
            _ => "qwen3:72b",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LlmRouterConfig::default();
        // Default model depends on OLLAMA_MODEL env var; without it, "threatclaw-redsage"
        let expected_model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "threatclaw-redsage".to_string());
        assert_eq!(config.primary.model, expected_model);
        assert_eq!(config.primary.backend, "ollama");
        assert!(config.cloud.is_none());
        assert_eq!(config.cloud_escalation, CloudEscalation::Anonymized);
    }

    #[test]
    fn test_high_confidence_accepted() {
        let config = LlmRouterConfig::default();
        let decision = config.decide_escalation(0.85, "LOW", false, false);
        assert_eq!(decision, EscalationDecision::Accept);
    }

    #[test]
    fn test_medium_confidence_retry() {
        let config = LlmRouterConfig::default();
        let decision = config.decide_escalation(0.55, "MEDIUM", false, false);
        assert_eq!(decision, EscalationDecision::RetryLocal);
    }

    #[test]
    fn test_medium_confidence_after_retry_no_cloud() {
        let config = LlmRouterConfig::default(); // no cloud
        let decision = config.decide_escalation(0.55, "MEDIUM", false, true);
        assert_eq!(decision, EscalationDecision::AcceptDegraded);
    }

    #[test]
    fn test_low_confidence_escalate_cloud() {
        let config = LlmRouterConfig {
            cloud: Some(CloudLlmConfig {
                backend: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                base_url: None,
                api_key: "sk-test".to_string(),
            }),
            ..Default::default()
        };
        let decision = config.decide_escalation(0.30, "HIGH", false, true);
        assert_eq!(decision, EscalationDecision::EscalateCloud);
    }

    #[test]
    fn test_critical_escalates_to_cloud() {
        let config = LlmRouterConfig {
            cloud: Some(CloudLlmConfig {
                backend: "mistral".to_string(),
                model: "mistral-large".to_string(),
                base_url: None,
                api_key: "key".to_string(),
            }),
            ..Default::default()
        };
        let decision = config.decide_escalation(0.90, "CRITICAL", false, false);
        assert_eq!(decision, EscalationDecision::EscalateCloud);
    }

    #[test]
    fn test_critical_no_cloud_accepts() {
        let config = LlmRouterConfig::default(); // no cloud
        // CRITICAL with high confidence and no cloud → Accept (can't escalate)
        let decision = config.decide_escalation(0.90, "CRITICAL", false, true);
        assert_eq!(decision, EscalationDecision::Accept);
    }

    #[test]
    fn test_injection_escalates() {
        let config = LlmRouterConfig {
            cloud: Some(CloudLlmConfig {
                backend: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                base_url: None,
                api_key: "key".to_string(),
            }),
            ..Default::default()
        };
        let decision = config.decide_escalation(0.95, "LOW", true, false);
        assert_eq!(decision, EscalationDecision::EscalateCloud);
    }

    #[test]
    fn test_injection_no_cloud_accepts() {
        let config = LlmRouterConfig::default();
        let decision = config.decide_escalation(0.95, "LOW", true, false);
        assert_eq!(decision, EscalationDecision::Accept);
    }

    #[test]
    fn test_cloud_never_blocks() {
        let config = LlmRouterConfig {
            cloud: Some(CloudLlmConfig {
                backend: "anthropic".to_string(),
                model: "claude".to_string(),
                base_url: None,
                api_key: "key".to_string(),
            }),
            cloud_escalation: CloudEscalation::Never,
            ..Default::default()
        };
        assert!(!config.cloud_available());
        let decision = config.decide_escalation(0.30, "CRITICAL", true, true);
        assert_eq!(decision, EscalationDecision::AcceptDegraded);
    }

    #[test]
    fn test_requires_anonymization() {
        let anon = LlmRouterConfig { cloud_escalation: CloudEscalation::Anonymized, ..Default::default() };
        assert!(anon.requires_anonymization());

        let direct = LlmRouterConfig { cloud_escalation: CloudEscalation::Direct, ..Default::default() };
        assert!(!direct.requires_anonymization());
    }

    #[test]
    fn test_recommend_model() {
        assert_eq!(LlmRouterConfig::recommend_model(4), "qwen3:4b");
        assert_eq!(LlmRouterConfig::recommend_model(8), "qwen3:8b");
        assert_eq!(LlmRouterConfig::recommend_model(16), "qwen3:14b");
        assert_eq!(LlmRouterConfig::recommend_model(29), "qwen3:14b");
        assert_eq!(LlmRouterConfig::recommend_model(48), "qwen3:32b");
        assert_eq!(LlmRouterConfig::recommend_model(128), "qwen3:72b");
    }

    #[test]
    fn test_primary_uses_cloud_api() {
        let local = LlmRouterConfig::default(); // ollama
        assert!(!local.primary_uses_cloud_api());

        let cloud = LlmRouterConfig {
            primary: PrimaryLlmConfig {
                backend: "anthropic".to_string(),
                model: "claude-sonnet-4-20250514".to_string(),
                base_url: "https://api.anthropic.com".to_string(),
                api_key: Some("sk-test".to_string()),
            },
            ..Default::default()
        };
        assert!(cloud.primary_uses_cloud_api());

        let compatible = LlmRouterConfig {
            primary: PrimaryLlmConfig {
                backend: "openai_compatible".to_string(),
                model: "my-model".to_string(),
                base_url: "http://localhost:8000".to_string(),
                api_key: None,
            },
            ..Default::default()
        };
        assert!(compatible.primary_uses_cloud_api()); // routed via cloud_caller even if local
    }

    #[test]
    fn test_primary_requires_anonymization_flag() {
        // Flag true → anonymise
        let anon = LlmRouterConfig {
            anonymize_primary: true,
            ..Default::default()
        };
        assert!(anon.primary_requires_anonymization());

        // Flag false → no anonymization (default)
        let local = LlmRouterConfig::default();
        assert!(!local.primary_requires_anonymization());

        // Flag works regardless of backend
        let ollama_anon = LlmRouterConfig {
            anonymize_primary: true,
            primary: PrimaryLlmConfig {
                backend: "ollama".to_string(),
                base_url: "http://remote-server:11434".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(ollama_anon.primary_requires_anonymization());
    }

    #[test]
    fn test_model_for_task() {
        let config = LlmRouterConfig::default();
        let expected_model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "threatclaw-redsage".to_string());
        assert_eq!(config.model_for_task(LlmTask::Correlation), expected_model);
        assert_eq!(config.model_for_task(LlmTask::Chat), expected_model);
    }
}

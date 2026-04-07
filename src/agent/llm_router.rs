//! LLM Router — multi-level orchestration. See ADR-011.

use serde::{Deserialize, Serialize};

/// Type de tâche LLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmTask {
    Chat,
    Conversation,
    Correlation,
    Report,
    Triage,
}

/// Mode de tool calling supporté par le modèle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallMode {
    /// Ollama native tools API (Mistral, Llama 3.1+).
    Native,
    /// Outils décrits dans le system prompt, réponse JSON parsée (Qwen3, autres).
    PromptBased,
    /// Pas de tool calling — mode conversation simple.
    None,
}

impl Default for ToolCallMode {
    fn default() -> Self {
        Self::PromptBased
    }
}

/// Source du modèle L0 conversationnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L0Source {
    /// Modèle local via Ollama.
    Local,
    /// Modèle cloud (Anthropic, Mistral, OpenAI compatible).
    Cloud,
    /// L0 désactivé — L1 gère tout (mode économique).
    Disabled,
}

impl Default for L0Source {
    fn default() -> Self {
        Self::Local
    }
}

/// Informations d'un modèle dans le catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Identifiant Ollama ou cloud du modèle.
    pub model_id: String,
    /// Nom affiché dans le dashboard.
    pub display_name: String,
    /// RAM estimée en GB (pour la barre mémoire dashboard).
    pub ram_gb: f64,
    /// Mode de tool calling supporté.
    pub tool_call_mode: ToolCallMode,
    /// Description courte.
    pub detail: String,
    /// RAM minimale recommandée pour le serveur.
    pub recommended_ram: String,
}

/// Catalogue des modèles recommandés par niveau.
pub fn model_catalog() -> std::collections::HashMap<&'static str, Vec<ModelInfo>> {
    let mut catalog = std::collections::HashMap::new();
    catalog.insert("l0", vec![
        ModelInfo {
            model_id: "mistral-small:24b".into(),
            display_name: "Mistral Small 24B".into(),
            ram_gb: 14.0,
            tool_call_mode: ToolCallMode::Native,
            detail: "Excellent FR · Tool calling natif".into(),
            recommended_ram: "64GB+".into(),
        },
        ModelInfo {
            model_id: "qwen3:14b".into(),
            display_name: "Qwen3 14B".into(),
            ram_gb: 9.3,
            tool_call_mode: ToolCallMode::PromptBased,
            detail: "Bon FR · Rapide sur CPU".into(),
            recommended_ram: "32GB+".into(),
        },
        ModelInfo {
            model_id: "qwen3:8b".into(),
            display_name: "Qwen3 8B".into(),
            ram_gb: 5.2,
            tool_call_mode: ToolCallMode::PromptBased,
            detail: "Basique · Très léger".into(),
            recommended_ram: "16GB+".into(),
        },
    ]);
    catalog.insert("l1", vec![
        ModelInfo {
            model_id: "threatclaw-l1".into(),
            display_name: "ThreatClaw AI Triage".into(),
            ram_gb: 5.8,
            tool_call_mode: ToolCallMode::None,
            detail: "qwen3:8b + SOC prompt · Recommandé".into(),
            recommended_ram: "16GB+".into(),
        },
        ModelInfo {
            model_id: "qwen3:14b".into(),
            display_name: "Qwen3 14B Triage".into(),
            ram_gb: 9.3,
            tool_call_mode: ToolCallMode::None,
            detail: "Meilleur parsing · Plus lourd".into(),
            recommended_ram: "32GB+".into(),
        },
    ]);
    catalog.insert("l2", vec![
        ModelInfo {
            model_id: "threatclaw-l2".into(),
            display_name: "ThreatClaw AI Reasoning".into(),
            ram_gb: 8.5,
            tool_call_mode: ToolCallMode::None,
            detail: "Foundation-Sec Q8_0 · Recommandé".into(),
            recommended_ram: "32GB+".into(),
        },
        ModelInfo {
            model_id: "redsage:8b".into(),
            display_name: "RedSage 8B (SOC Workflows)".into(),
            ram_gb: 5.5,
            tool_call_mode: ToolCallMode::None,
            detail: "RISYS Lab · Workflows SOC réels · Q4_K_M".into(),
            recommended_ram: "16GB+".into(),
        },
    ]);
    catalog.insert("l25", vec![
        ModelInfo {
            model_id: "threatclaw-l3".into(),
            display_name: "ThreatClaw AI Instruct".into(),
            ram_gb: 5.0,
            tool_call_mode: ToolCallMode::None,
            detail: "Foundation-Sec Q4_K_M · Recommandé".into(),
            recommended_ram: "32GB+".into(),
        },
    ]);
    catalog
}

/// Configuration du LLM conversationnel L0 (dialogue RSSI).
/// C'est le "visage" de ThreatClaw — celui qui parle au RSSI.
/// Peut être local (Ollama) ou cloud (Anthropic/Mistral/OpenAI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationalLlmConfig {
    /// Source : local, cloud ou désactivé.
    pub source: L0Source,
    /// Modèle local Ollama (si source=local).
    pub local_model: String,
    /// Backend cloud (si source=cloud) : anthropic, mistral, openai_compatible.
    pub cloud_backend: String,
    /// Modèle cloud (si source=cloud).
    pub cloud_model: String,
    /// URL de base cloud (si openai_compatible).
    pub cloud_base_url: Option<String>,
    /// Clé API cloud (si source=cloud).
    pub cloud_api_key: String,
    /// Anonymiser les données avant envoi au cloud L0.
    pub anonymize: bool,
    /// Mode de tool calling (auto-détecté selon le modèle).
    pub tool_call_mode: ToolCallMode,
    /// URL Ollama pour les modèles locaux.
    pub ollama_url: String,
    /// RAM estimée du modèle actif (pour le dashboard).
    pub ram_estimate_gb: f64,
}

impl Default for ConversationalLlmConfig {
    fn default() -> Self {
        Self {
            source: L0Source::Disabled,
            local_model: "qwen3:14b".to_string(),
            cloud_backend: String::new(),
            cloud_model: String::new(),
            cloud_base_url: None,
            cloud_api_key: String::new(),
            anonymize: true,
            tool_call_mode: ToolCallMode::PromptBased,
            ollama_url: std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".to_string()),
            ram_estimate_gb: 0.0,
        }
    }
}

impl ConversationalLlmConfig {
    /// Détecte le mode de tool calling basé sur le modèle sélectionné.
    pub fn detect_tool_call_mode(&self) -> ToolCallMode {
        if self.source == L0Source::Cloud {
            return ToolCallMode::Native; // All cloud APIs support native tool calling
        }
        let model = self.local_model.to_lowercase();
        if model.contains("mistral") || model.contains("llama3") || model.contains("command-r") {
            ToolCallMode::Native
        } else {
            ToolCallMode::PromptBased
        }
    }

    /// RAM estimée du modèle L0 actif.
    pub fn estimated_ram_gb(&self) -> f64 {
        if self.source != L0Source::Local {
            return 0.0;
        }
        let catalog = model_catalog();
        if let Some(models) = catalog.get("l0") {
            for m in models {
                if m.model_id == self.local_model {
                    return m.ram_gb;
                }
            }
        }
        // Unknown model — estimate from name
        if self.local_model.contains("24b") || self.local_model.contains("22b") {
            14.0
        } else if self.local_model.contains("14b") {
            9.3
        } else if self.local_model.contains("8b") || self.local_model.contains("7b") {
            5.2
        } else {
            8.0 // conservative default
        }
    }

    /// Est-ce que L0 est actif (local ou cloud configuré) ?
    pub fn is_enabled(&self) -> bool {
        match &self.source {
            L0Source::Local => !self.local_model.is_empty(),
            L0Source::Cloud => !self.cloud_api_key.is_empty(),
            L0Source::Disabled => false,
        }
    }
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

/// Configuration de l'IA Instruct (playbooks SOAR, rapports, Sigma rules).
/// Foundation-sec-8B-Instruct — chargé à la demande uniquement, jamais en même temps que Forensic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructLlmConfig {
    /// Modèle Instruct (Foundation-sec Instruct ou équivalent).
    pub model: String,
    /// URL Ollama (même instance que primary par défaut).
    pub base_url: String,
    /// Timeout d'inactivité avant déchargement (secondes).
    /// Court (5min) car on ne l'utilise qu'à la demande.
    pub idle_timeout_secs: u64,
}

impl Default for InstructLlmConfig {
    fn default() -> Self {
        Self {
            model: std::env::var("INSTRUCT_MODEL").unwrap_or_else(|_| "threatclaw-l3".to_string()),
            base_url: std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".to_string()),
            idle_timeout_secs: 300, // 5 minutes — déchargement rapide
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
    /// IA conversationnelle L0 — dialogue RSSI, tool calling (optionnel).
    #[serde(default)]
    pub conversational: ConversationalLlmConfig,
    /// IA principale L1/L2 — triage et corrélation (obligatoire).
    pub primary: PrimaryLlmConfig,
    /// IA forensique L2 — analyse approfondie (chargé à la demande).
    #[serde(default)]
    pub forensic: ForensicLlmConfig,
    /// IA instruct L3 — playbooks SOAR, rapports, Sigma rules (à la demande RSSI).
    /// Mutual exclusion avec forensic (jamais chargés simultanément).
    #[serde(default)]
    pub instruct: InstructLlmConfig,
    /// IA cloud L4 — rapports NIS2 finaux et incidents critiques (optionnel).
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
            conversational: ConversationalLlmConfig::default(),
            primary: PrimaryLlmConfig::default(),
            forensic: ForensicLlmConfig::default(),
            instruct: InstructLlmConfig::default(),
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

        // ── Instruct LLM (tc_config_instruct) ──
        if let Ok(Some(instruct_val)) = store.get_setting("_system", "tc_config_instruct").await {
            if let Some(model) = instruct_val["model"].as_str() {
                if !model.is_empty() && std::env::var("INSTRUCT_MODEL").is_err() {
                    config.instruct.model = model.to_string();
                }
            }
            if let Some(url) = instruct_val["url"].as_str() {
                if !url.is_empty() {
                    config.instruct.base_url = url.to_string();
                }
            }
        }

        // ── Anonymize primary (tc_config_anonymize_primary) ──
        if let Ok(Some(anon_val)) = store.get_setting("_system", "tc_config_anonymize_primary").await {
            if let Some(anon) = anon_val.as_bool() {
                config.anonymize_primary = anon;
            }
        }

        // ── Conversational L0 (tc_config_conversational) ──
        if let Ok(Some(conv_val)) = store.get_setting("_system", "tc_config_conversational").await {
            let source = match conv_val["source"].as_str().unwrap_or("disabled") {
                "local" => L0Source::Local,
                "cloud" => L0Source::Cloud,
                _ => L0Source::Disabled,
            };
            config.conversational.source = source;

            if let Some(model) = conv_val["localModel"].as_str() {
                if !model.is_empty() {
                    config.conversational.local_model = model.to_string();
                }
            }
            if let Some(backend) = conv_val["cloudBackend"].as_str() {
                config.conversational.cloud_backend = backend.to_string();
            }
            if let Some(model) = conv_val["cloudModel"].as_str() {
                config.conversational.cloud_model = model.to_string();
            }
            if let Some(url) = conv_val["cloudBaseUrl"].as_str() {
                if !url.is_empty() {
                    config.conversational.cloud_base_url = Some(url.to_string());
                }
            }
            if let Some(key) = conv_val["cloudApiKey"].as_str() {
                config.conversational.cloud_api_key = key.to_string();
            }
            if let Some(anon) = conv_val["anonymize"].as_bool() {
                config.conversational.anonymize = anon;
            }

            // Auto-detect tool call mode
            config.conversational.tool_call_mode = config.conversational.detect_tool_call_mode();
            config.conversational.ram_estimate_gb = config.conversational.estimated_ram_gb();
            config.conversational.ollama_url = config.primary.base_url.clone();
        }

        tracing::debug!(
            "LLM config loaded: L0={:?}/{} primary={}/{} cloud={}",
            config.conversational.source,
            if config.conversational.source == L0Source::Local { &config.conversational.local_model } else { &config.conversational.cloud_model },
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

        // CRITICAL → TOUJOURS passer par L2 Forensique d'abord (chain-of-thought obligatoire)
        // Un incident critique mérite une analyse approfondie, pas juste un triage L1.
        if severity == "CRITICAL" && !is_retry {
            return EscalationDecision::RetryLocal; // → L2 Forensique
        }

        // CRITICAL après L2 → escalader vers Cloud si disponible
        if severity == "CRITICAL" && is_retry && self.cloud_available() {
            return EscalationDecision::EscalateCloud;
        }

        // Confiance suffisante (non-CRITICAL) → accepter
        if confidence >= self.confidence_accept && severity != "CRITICAL" {
            return EscalationDecision::Accept;
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
        if confidence >= self.confidence_accept || severity == "CRITICAL" {
            EscalationDecision::Accept // CRITICAL after L2 without cloud = accept L2 analysis
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

    /// Estime la RAM totale utilisée par tous les modèles permanents (L0 + L1).
    /// L2 et L2.5 sont à la demande et swappent avec les permanents.
    pub fn total_permanent_ram_gb(&self) -> f64 {
        let l0 = self.conversational.estimated_ram_gb();
        let l1 = {
            let catalog = model_catalog();
            catalog.get("l1").and_then(|models| {
                models.iter().find(|m| m.model_id == self.primary.model).map(|m| m.ram_gb)
            }).unwrap_or(5.8) // conservative default for unknown model
        };
        l0 + l1
    }

    /// Estime la RAM maximale (L0 + L1 + max(L2, L2.5) en on-demand).
    pub fn total_peak_ram_gb(&self) -> f64 {
        let permanent = self.total_permanent_ram_gb();
        let l2 = {
            let catalog = model_catalog();
            catalog.get("l2").and_then(|models| {
                models.iter().find(|m| m.model_id == self.forensic.model).map(|m| m.ram_gb)
            }).unwrap_or(8.5)
        };
        let l25 = {
            let catalog = model_catalog();
            catalog.get("l25").and_then(|models| {
                models.iter().find(|m| m.model_id == self.instruct.model).map(|m| m.ram_gb)
            }).unwrap_or(5.0)
        };
        permanent + l2.max(l25) // mutual exclusion: max of L2 and L2.5
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
    fn test_critical_retries_local_first() {
        let config = LlmRouterConfig {
            cloud: Some(CloudLlmConfig {
                backend: "mistral".to_string(),
                model: "mistral-large".to_string(),
                base_url: None,
                api_key: "key".to_string(),
            }),
            ..Default::default()
        };
        // CRITICAL first attempt → always retry local L2 first
        let decision = config.decide_escalation(0.90, "CRITICAL", false, false);
        assert_eq!(decision, EscalationDecision::RetryLocal);
        // CRITICAL after L2 retry → escalate to cloud
        let decision2 = config.decide_escalation(0.90, "CRITICAL", false, true);
        assert_eq!(decision2, EscalationDecision::EscalateCloud);
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
        // CRITICAL after retry without cloud → Accept (L2 analysis is sufficient for CRITICAL)
        let decision = config.decide_escalation(0.30, "CRITICAL", true, true);
        assert_eq!(decision, EscalationDecision::Accept);
        // LOW with low confidence, no cloud → AcceptDegraded
        let decision2 = config.decide_escalation(0.30, "LOW", false, true);
        assert_eq!(decision2, EscalationDecision::AcceptDegraded);
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

    #[test]
    fn test_l0_default_disabled() {
        let config = LlmRouterConfig::default();
        assert_eq!(config.conversational.source, L0Source::Disabled);
        assert!(!config.conversational.is_enabled());
        assert_eq!(config.conversational.estimated_ram_gb(), 0.0);
    }

    #[test]
    fn test_l0_local_enabled() {
        let config = LlmRouterConfig {
            conversational: ConversationalLlmConfig {
                source: L0Source::Local,
                local_model: "mistral-small:24b".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.conversational.is_enabled());
        assert_eq!(config.conversational.estimated_ram_gb(), 14.0);
        assert_eq!(config.conversational.detect_tool_call_mode(), ToolCallMode::Native);
    }

    #[test]
    fn test_l0_cloud_enabled() {
        let config = LlmRouterConfig {
            conversational: ConversationalLlmConfig {
                source: L0Source::Cloud,
                cloud_backend: "anthropic".into(),
                cloud_model: "claude-sonnet-4-20250514".into(),
                cloud_api_key: "sk-test".into(),
                anonymize: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.conversational.is_enabled());
        assert_eq!(config.conversational.estimated_ram_gb(), 0.0);
        assert_eq!(config.conversational.detect_tool_call_mode(), ToolCallMode::Native);
        assert!(config.conversational.anonymize);
    }

    #[test]
    fn test_l0_qwen_prompt_based_tool_calling() {
        let config = ConversationalLlmConfig {
            source: L0Source::Local,
            local_model: "qwen3:14b".into(),
            ..Default::default()
        };
        assert_eq!(config.detect_tool_call_mode(), ToolCallMode::PromptBased);
        assert_eq!(config.estimated_ram_gb(), 9.3);
    }

    #[test]
    fn test_ram_estimates() {
        let config = LlmRouterConfig {
            conversational: ConversationalLlmConfig {
                source: L0Source::Local,
                local_model: "qwen3:14b".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        // L0 (9.3) + L1 (5.8 default)
        assert!(config.total_permanent_ram_gb() > 14.0);
        // + max(L2, L2.5) on-demand
        assert!(config.total_peak_ram_gb() > config.total_permanent_ram_gb());
    }

    #[test]
    fn test_model_catalog_completeness() {
        let catalog = model_catalog();
        assert!(catalog.contains_key("l0"));
        assert!(catalog.contains_key("l1"));
        assert!(catalog.contains_key("l2"));
        assert!(catalog.contains_key("l25"));
        assert!(!catalog["l0"].is_empty());
        // Mistral Small should be native tool calling
        let mistral = catalog["l0"].iter().find(|m| m.model_id.contains("mistral")).unwrap();
        assert_eq!(mistral.tool_call_mode, ToolCallMode::Native);
    }
}

//! Registry des skills connectés chez le client.
//!
//! Lit `skill_configs` (enabled + credentials), instancie les implémentations
//! des traits (FirewallSkill, à venir : SiemSkill, EdrSkill) selon ce qui est
//! disponible. Le registry est consulté par `dossier_enrichment` et le
//! `remediation_engine` pour adapter le pipeline à l'infra du client.

use std::sync::Arc;

use crate::agent::skills::edr::EdrSkill;
use crate::agent::skills::firewall::FirewallSkill;
use crate::agent::skills::siem::SiemSkill;
use crate::db::Database;

/// Snapshot des skills disponibles à un instant T. Reconstruit à chaque cycle
/// IE (cheap : ~5-10 reads en DB).
pub struct SkillRegistry {
    pub firewalls: Vec<Arc<dyn FirewallSkill>>,
    pub siems: Vec<Arc<dyn SiemSkill>>,
    pub edrs: Vec<Arc<dyn EdrSkill>>,
}

impl SkillRegistry {
    /// Probe les skills configurés en DB et instancie les implémentations
    /// disponibles. Tolérant : un skill avec config incomplète est ignoré
    /// (debug log), pas d'erreur.
    pub async fn from_db(store: &dyn Database) -> Self {
        let mut firewalls: Vec<Arc<dyn FirewallSkill>> = Vec::new();
        let mut siems: Vec<Arc<dyn SiemSkill>> = Vec::new();
        let mut edrs: Vec<Arc<dyn EdrSkill>> = Vec::new();

        // ── Firewalls ─────────────────────────────────────────────
        if let Some(fw) = try_build_opnsense(store).await {
            firewalls.push(fw);
        }
        if let Some(fw) = try_build_fortinet(store).await {
            firewalls.push(fw);
        }
        if let Some(fw) = try_build_pfsense(store).await {
            firewalls.push(fw);
        }
        if let Some(fw) = try_build_mikrotik(store).await {
            firewalls.push(fw);
        }

        // ── SIEM ──────────────────────────────────────────────────
        if let Some(siem) = try_build_elastic_siem(store).await {
            siems.push(siem);
        }
        if let Some(siem) = try_build_graylog(store).await {
            siems.push(siem);
        }
        if let Some(siem) = try_build_wazuh(store).await {
            siems.push(siem);
        }

        // ── EDR ───────────────────────────────────────────────────
        if let Some(edr) = try_build_velociraptor(store).await {
            edrs.push(edr);
        }

        Self {
            firewalls,
            siems,
            edrs,
        }
    }

    pub fn has_firewall(&self) -> bool {
        !self.firewalls.is_empty()
    }
    pub fn has_siem(&self) -> bool {
        !self.siems.is_empty()
    }
    pub fn has_edr(&self) -> bool {
        !self.edrs.is_empty()
    }
}

async fn read_skill_config_map(
    store: &dyn Database,
    skill_id: &str,
) -> Option<std::collections::HashMap<String, String>> {
    use crate::db::threatclaw_store::ThreatClawStore;
    let records = store.get_skill_config(skill_id).await.ok()?;
    let mut cfg: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(records.len());
    for r in records {
        cfg.insert(r.key, r.value);
    }
    if cfg.get("enabled").map(|s| s.as_str()) != Some("true") {
        return None;
    }
    Some(cfg)
}

async fn try_build_fortinet(store: &dyn Database) -> Option<Arc<dyn FirewallSkill>> {
    let cfg = read_skill_config_map(store, "skill-fortinet").await?;
    let url = cfg.get("url").cloned()?;
    let api_key = cfg.get("api_key").cloned()?;
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);
    Some(Arc::new(crate::agent::skills::fortinet::FortinetFirewall {
        url,
        api_key,
        no_tls_verify,
    }))
}

async fn try_build_elastic_siem(store: &dyn Database) -> Option<Arc<dyn SiemSkill>> {
    let cfg = read_skill_config_map(store, "skill-elastic-siem").await?;
    let url = cfg.get("url").cloned()?;
    let index_pattern = cfg
        .get("index_pattern")
        .cloned()
        .unwrap_or_else(|| "logs-*".to_string());
    let api_key = cfg.get("api_key").cloned();
    let username = cfg.get("username").cloned();
    let password = cfg.get("password").cloned();
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);
    if api_key.is_none() && (username.is_none() || password.is_none()) {
        return None;
    }
    Some(Arc::new(
        crate::agent::skills::elastic_siem::ElasticSiemSkill {
            url,
            index_pattern,
            api_key,
            username,
            password,
            no_tls_verify,
        },
    ))
}

async fn try_build_velociraptor(store: &dyn Database) -> Option<Arc<dyn EdrSkill>> {
    let cfg = read_skill_config_map(store, "skill-velociraptor").await?;
    let url = cfg.get("url").cloned()?;
    let api_cert_pem = cfg.get("api_cert").cloned();
    let api_key_pem = cfg.get("api_key").cloned();
    let ca_pem = cfg.get("ca").cloned();
    let username = cfg.get("api_client").cloned();
    Some(Arc::new(
        crate::agent::skills::velociraptor::VelociraptorEdrSkill {
            url,
            api_cert_pem,
            api_key_pem,
            ca_pem,
            username,
        },
    ))
}

async fn try_build_pfsense(store: &dyn Database) -> Option<Arc<dyn FirewallSkill>> {
    let cfg = read_skill_config_map(store, "skill-pfsense").await?;
    let url = cfg.get("url").cloned()?;
    let api_key = cfg.get("api_key").cloned()?;
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);
    Some(Arc::new(crate::agent::skills::pfsense::PfsenseFirewall {
        url,
        api_key,
        no_tls_verify,
    }))
}

async fn try_build_mikrotik(store: &dyn Database) -> Option<Arc<dyn FirewallSkill>> {
    let cfg = read_skill_config_map(store, "skill-mikrotik").await?;
    let url = cfg.get("url").cloned()?;
    let username = cfg.get("username").cloned()?;
    let password = cfg.get("password").cloned()?;
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);
    Some(Arc::new(crate::agent::skills::mikrotik::MikrotikFirewall {
        url,
        username,
        password,
        no_tls_verify,
    }))
}

async fn try_build_graylog(store: &dyn Database) -> Option<Arc<dyn SiemSkill>> {
    let cfg = read_skill_config_map(store, "skill-graylog").await?;
    let url = cfg.get("url").cloned()?;
    let api_token = cfg.get("api_token").cloned()?;
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);
    Some(Arc::new(crate::agent::skills::graylog::GraylogSkill {
        url,
        api_token,
        no_tls_verify,
    }))
}

async fn try_build_wazuh(store: &dyn Database) -> Option<Arc<dyn SiemSkill>> {
    let cfg = read_skill_config_map(store, "skill-wazuh-connector").await?;
    let indexer_url = cfg.get("indexer_url").or_else(|| cfg.get("url")).cloned()?;
    let username = cfg
        .get("indexer_username")
        .or_else(|| cfg.get("username"))
        .cloned()?;
    let password = cfg
        .get("indexer_password")
        .or_else(|| cfg.get("password"))
        .cloned()?;
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);
    Some(Arc::new(crate::agent::skills::wazuh::WazuhSkill {
        indexer_url,
        username,
        password,
        no_tls_verify,
    }))
}

/// Essaie de construire un OpnsenseFirewall depuis les skill_configs.
/// Retourne None si pas configuré ou credentials manquants.
async fn try_build_opnsense(store: &dyn Database) -> Option<Arc<dyn FirewallSkill>> {
    use crate::db::threatclaw_store::ThreatClawStore;

    let records = store.get_skill_config("skill-opnsense").await.ok()?;
    let mut cfg: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(records.len());
    for r in records {
        cfg.insert(r.key, r.value);
    }

    if cfg.get("enabled").map(|s| s.as_str()) != Some("true") {
        return None;
    }

    let url = cfg.get("url").cloned()?;
    let auth_user = cfg.get("auth_user").cloned()?;
    let auth_secret = cfg.get("auth_secret").cloned()?;
    let no_tls_verify = cfg
        .get("no_tls_verify")
        .map(|s| s == "true")
        .unwrap_or(false);

    Some(Arc::new(crate::agent::skills::opnsense::OpnsenseFirewall {
        url,
        auth_user,
        auth_secret,
        no_tls_verify,
    }))
}

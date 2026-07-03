//! Identité d'agent par-poste — enrôlement + vérification.
//!
//! Remplace le modèle « un token statique partagé par toute la flotte + hostname
//! auto-asserté » (findings ING-C1 / H6 de l'audit écosystème 2026-07-02) par :
//!
//!  - un **secret d'enrôlement** unique (bootstrap au premier démarrage), utilisé
//!    UNIQUEMENT à l'installation pour enrôler un poste (rotable ensuite) ;
//!  - un **token par-agent** émis à l'enrôlement, stocké **haché** (SHA-256) et lié
//!    à un `agent_id` (UUID généré côté serveur, non devinable) et à un `hostname` ;
//!  - une **vérification stricte** côté worker : le couple (`agent_id`, `hostname`)
//!    doit correspondre à un enregistrement enrôlé — plus de TOFU, plus de
//!    `agent_id` vide accepté. La fuite du token d'un poste ne compromet que ce
//!    poste, et un poste ne peut usurper l'identité d'un autre (il ne connaît pas
//!    l'`agent_id` UUID de sa cible).
//!
//! Le registre réutilise le namespace de settings `_osquery_agents` (clé
//! `agent_<id>`) : pas de migration de schéma. Les champs ajoutés
//! (`token_sha256`, `platform`, `enrolled_at`, `revoked`) sont ignorés par les
//! lecteurs existants (dashboard) qui ne lisent que `hostname` / `last_seen`.

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::db::Database;

/// Namespace de settings pour le registre d'agents.
const AGENTS_NS: &str = "_osquery_agents";
/// Namespace/clé du secret d'enrôlement.
const SYSTEM_NS: &str = "_system";
const ENROLL_SECRET_KEY: &str = "tc_agent_enroll_secret";

/// SHA-256 hex d'une chaîne (token / secret). Non secret une fois haché.
fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// 32 octets aléatoires CSPRNG encodés en hex (64 caractères).
fn random_hex_32() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Comparaison en temps constant de deux chaînes (anti-timing).
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Lit le secret d'enrôlement, le générant au premier appel s'il est absent.
/// Le secret est retourné en clair (l'appelant — endpoint admin — le protège
/// derrière le bearer du dashboard).
pub async fn get_or_create_enroll_secret(store: &dyn Database) -> Result<String, String> {
    if let Ok(Some(v)) = store.get_setting(SYSTEM_NS, ENROLL_SECRET_KEY).await {
        if let Some(s) = v.as_str() {
            if !s.is_empty() {
                return Ok(s.to_string());
            }
        }
    }
    let secret = random_hex_32();
    store
        .set_setting(SYSTEM_NS, ENROLL_SECRET_KEY, &json!(secret))
        .await
        .map_err(|e| format!("persist enroll secret: {e}"))?;
    Ok(secret)
}

/// Régénère le secret d'enrôlement (rotation opérateur). N'affecte AUCUN agent
/// déjà enrôlé (chacun a son propre token) — invalide seulement les anciennes
/// commandes d'install. Retourne le nouveau secret.
pub async fn rotate_enroll_secret(store: &dyn Database) -> Result<String, String> {
    let secret = random_hex_32();
    store
        .set_setting(SYSTEM_NS, ENROLL_SECRET_KEY, &json!(secret))
        .await
        .map_err(|e| format!("rotate enroll secret: {e}"))?;
    tracing::info!("ENROLL: secret d'enrôlement régénéré (rotation opérateur)");
    Ok(secret)
}

/// Vérifie le secret d'enrôlement présenté (temps constant). Ne crée rien.
pub async fn verify_enroll_secret(store: &dyn Database, presented: &str) -> bool {
    if presented.is_empty() {
        return false;
    }
    match store.get_setting(SYSTEM_NS, ENROLL_SECRET_KEY).await {
        Ok(Some(v)) => v.as_str().map(|s| ct_eq(s, presented)).unwrap_or(false),
        _ => false,
    }
}

/// Résultat d'un enrôlement : identité + token en clair (retourné une seule fois).
#[derive(Debug, Clone)]
pub struct EnrolledAgent {
    pub agent_id: String,
    pub token: String,
}

/// Enrôle un agent : génère un `agent_id` (si absent) + un token par-agent,
/// persiste le record (token haché, lié au hostname). Idempotent sur `agent_id`
/// fourni : ré-enrôler un même `agent_id` fait tourner son token.
pub async fn enroll_agent(
    store: &dyn Database,
    hostname: &str,
    platform: Option<&str>,
    agent_id: Option<&str>,
) -> Result<EnrolledAgent, String> {
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err("hostname requis".into());
    }
    let agent_id = match agent_id {
        Some(a) if !a.trim().is_empty() => a.trim().to_string(),
        _ => uuid::Uuid::new_v4().to_string(),
    };
    let token = random_hex_32();
    let now = chrono::Utc::now().to_rfc3339();
    let key = format!("agent_{agent_id}");
    let record = json!({
        "hostname": hostname,
        "platform": platform.unwrap_or(""),
        "token_sha256": sha256_hex(&token),
        "enrolled_at": now,
        "last_seen": now,
        "revoked": false,
    });
    store
        .set_setting(AGENTS_NS, &key, &record)
        .await
        .map_err(|e| format!("persist agent record: {e}"))?;
    tracing::info!("ENROLL: agent {agent_id} enrôlé pour {hostname}");
    Ok(EnrolledAgent { agent_id, token })
}

/// Authentifie un token par-agent (hot path). Retourne true si `agent_id` existe,
/// n'est pas révoqué, et que `sha256(token)` correspond (temps constant).
pub async fn verify_agent_token(store: &dyn Database, agent_id: &str, token: &str) -> bool {
    if agent_id.is_empty() || token.is_empty() {
        return false;
    }
    let key = format!("agent_{agent_id}");
    match store.get_setting(AGENTS_NS, &key).await {
        Ok(Some(rec)) => {
            if rec["revoked"].as_bool().unwrap_or(false) {
                return false;
            }
            let stored = rec["token_sha256"].as_str().unwrap_or("");
            !stored.is_empty() && ct_eq(stored, &sha256_hex(token))
        }
        _ => false,
    }
}

/// Vérification stricte côté worker : le couple (`agent_id`, `hostname`) doit
/// correspondre à un agent enrôlé, non révoqué. Rejette `agent_id` vide, agent
/// inconnu, ou hostname divergent (anti-spoofing ING-C1). Met à jour `last_seen`
/// EN PRÉSERVANT les autres champs (le token notamment).
pub async fn verify_agent_binding(store: &dyn Database, agent_id: &str, hostname: &str) -> bool {
    if agent_id.is_empty() {
        tracing::warn!("OSQUERY: rejet — agent_id vide (enrôlement par-agent requis)");
        return false;
    }
    let key = format!("agent_{agent_id}");
    let mut rec = match store.get_setting(AGENTS_NS, &key).await {
        Ok(Some(r)) => r,
        _ => {
            tracing::warn!("OSQUERY: rejet — agent {agent_id} inconnu (non enrôlé)");
            return false;
        }
    };
    if rec["revoked"].as_bool().unwrap_or(false) {
        tracing::warn!("OSQUERY: rejet — agent {agent_id} révoqué");
        return false;
    }
    let enrolled_host = rec["hostname"].as_str().unwrap_or("");
    if !enrolled_host.eq_ignore_ascii_case(hostname) {
        tracing::warn!(
            "OSQUERY: rejet — agent {agent_id} hostname mismatch: enrôlé={enrolled_host}, reçu={hostname}"
        );
        return false;
    }
    // Update last_seen sans détruire token_sha256/revoked/enrolled_at.
    rec["last_seen"] = json!(chrono::Utc::now().to_rfc3339());
    crate::connectors::log_db_write(
        "agent_identity:touch_last_seen",
        store.set_setting(AGENTS_NS, &key, &rec),
    )
    .await;
    true
}

#[cfg(all(test, feature = "libsql"))]
mod tests {
    use super::*;
    use crate::db::libsql::LibSqlBackend;

    async fn mem() -> LibSqlBackend {
        let b = LibSqlBackend::new_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[tokio::test]
    async fn test_enroll_then_verify_token() {
        let db = mem().await;
        let e = enroll_agent(&db, "DC01", Some("windows"), None)
            .await
            .unwrap();
        assert!(!e.agent_id.is_empty());
        assert_eq!(e.token.len(), 64);
        // Bon token → OK ; mauvais token → rejet.
        assert!(verify_agent_token(&db, &e.agent_id, &e.token).await);
        assert!(!verify_agent_token(&db, &e.agent_id, "deadbeef").await);
        assert!(!verify_agent_token(&db, "inconnu", &e.token).await);
    }

    #[tokio::test]
    async fn test_binding_rejects_spoof_and_empty() {
        let db = mem().await;
        let e = enroll_agent(&db, "DC01", Some("windows"), None)
            .await
            .unwrap();
        // Bon couple (casse insensible) → OK.
        assert!(verify_agent_binding(&db, &e.agent_id, "dc01").await);
        // agent_id vide → rejet (H6).
        assert!(!verify_agent_binding(&db, "", "DC01").await);
        // agent_id connu mais hostname usurpé → rejet (ING-C1).
        assert!(!verify_agent_binding(&db, &e.agent_id, "WORKSTATION-7").await);
        // agent_id inconnu → rejet.
        assert!(!verify_agent_binding(&db, "nope", "DC01").await);
    }

    #[tokio::test]
    async fn test_last_seen_preserves_token() {
        let db = mem().await;
        let e = enroll_agent(&db, "DC01", None, None).await.unwrap();
        // Une vérif de binding met à jour last_seen ; le token doit rester valide.
        assert!(verify_agent_binding(&db, &e.agent_id, "DC01").await);
        assert!(verify_agent_token(&db, &e.agent_id, &e.token).await);
    }

    #[tokio::test]
    async fn test_enroll_secret_bootstrap_and_verify() {
        let db = mem().await;
        let s1 = get_or_create_enroll_secret(&db).await.unwrap();
        let s2 = get_or_create_enroll_secret(&db).await.unwrap();
        assert_eq!(s1, s2); // idempotent
        assert!(verify_enroll_secret(&db, &s1).await);
        assert!(!verify_enroll_secret(&db, "wrong").await);
        assert!(!verify_enroll_secret(&db, "").await);
    }
}

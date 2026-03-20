//! HITL Nonce — Anti-replay protection for Human-in-the-Loop approvals.
//!
//! Each approval request gets a unique nonce. The nonce can only be used once.
//! Prevents replay attacks where an attacker resends a valid approval.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// Erreur de nonce.
#[derive(Debug, Clone, PartialEq)]
pub enum NonceError {
    /// Le nonce n'existe pas (jamais émis ou expiré).
    NotFound,
    /// Le nonce a déjà été utilisé (replay détecté).
    AlreadyUsed,
    /// Le nonce a expiré.
    Expired,
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Nonce not found — never issued or expired"),
            Self::AlreadyUsed => write!(f, "SECURITY: Nonce already used — possible replay attack"),
            Self::Expired => write!(f, "Nonce expired"),
        }
    }
}

impl std::error::Error for NonceError {}

#[derive(Debug, Clone)]
struct NonceEntry {
    created_at: Instant,
    used: bool,
    cmd_id: String,
    ttl: Duration,
}

/// Gestionnaire de nonces anti-replay.
pub struct NonceManager {
    nonces: Arc<RwLock<HashMap<String, NonceEntry>>>,
    default_ttl: Duration,
}

impl NonceManager {
    /// Crée un nouveau gestionnaire avec un TTL par défaut.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Génère un nonce unique pour une action.
    pub async fn generate(&self, cmd_id: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let random: u64 = rand_u64();

        let mut hasher = Sha256::new();
        hasher.update(cmd_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(random.to_le_bytes());
        let nonce = format!("{:x}", hasher.finalize());

        // Tronquer à 32 chars pour Slack
        let nonce = nonce[..32].to_string();

        let entry = NonceEntry {
            created_at: Instant::now(),
            used: false,
            cmd_id: cmd_id.to_string(),
            ttl: self.default_ttl,
        };

        self.nonces.write().await.insert(nonce.clone(), entry);

        tracing::debug!("HITL nonce generated for {}: {}", cmd_id, &nonce[..8]);
        nonce
    }

    /// Vérifie et consomme un nonce. Ne peut être appelé qu'une seule fois.
    pub async fn verify_and_consume(&self, nonce: &str) -> Result<String, NonceError> {
        let mut nonces = self.nonces.write().await;

        let entry = nonces.get_mut(nonce).ok_or(NonceError::NotFound)?;

        if entry.used {
            tracing::error!(
                "SECURITY: Nonce replay attempt detected for cmd_id={}, nonce={}",
                entry.cmd_id,
                &nonce[..8]
            );
            return Err(NonceError::AlreadyUsed);
        }

        if entry.created_at.elapsed() > entry.ttl {
            return Err(NonceError::Expired);
        }

        entry.used = true;
        let cmd_id = entry.cmd_id.clone();

        tracing::info!("HITL nonce consumed for {}: {}", cmd_id, &nonce[..8]);
        Ok(cmd_id)
    }

    /// Nettoie les nonces expirés.
    pub async fn cleanup_expired(&self) {
        let mut nonces = self.nonces.write().await;
        let before = nonces.len();
        nonces.retain(|_, entry| entry.created_at.elapsed() < entry.ttl);
        let removed = before - nonces.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} expired nonces", removed);
        }
    }

    /// Nombre de nonces actifs (pour monitoring).
    pub async fn active_count(&self) -> usize {
        self.nonces.read().await.len()
    }
}

/// Pseudo-random u64 sans dépendance externe (utilise l'adresse stack + timestamp).
fn rand_u64() -> u64 {
    let stack_addr = &0u8 as *const u8 as u64;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    stack_addr.wrapping_mul(6364136223846793005).wrapping_add(time)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> NonceManager {
        NonceManager::new(Duration::from_secs(3600))
    }

    #[tokio::test]
    async fn test_generate_unique() {
        let mgr = make_manager();
        let n1 = mgr.generate("net-001").await;
        let n2 = mgr.generate("net-001").await;
        assert_ne!(n1, n2);
        assert_eq!(n1.len(), 32);
        assert_eq!(n2.len(), 32);
    }

    #[tokio::test]
    async fn test_verify_valid() {
        let mgr = make_manager();
        let nonce = mgr.generate("net-001").await;
        let result = mgr.verify_and_consume(&nonce).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "net-001");
    }

    #[tokio::test]
    async fn test_replay_blocked() {
        let mgr = make_manager();
        let nonce = mgr.generate("net-001").await;

        // First use: OK
        assert!(mgr.verify_and_consume(&nonce).await.is_ok());

        // Second use: REPLAY
        let result = mgr.verify_and_consume(&nonce).await;
        assert_eq!(result, Err(NonceError::AlreadyUsed));
    }

    #[tokio::test]
    async fn test_unknown_nonce() {
        let mgr = make_manager();
        let result = mgr.verify_and_consume("fake_nonce_1234567890123456").await;
        assert_eq!(result, Err(NonceError::NotFound));
    }

    #[tokio::test]
    async fn test_expired_nonce() {
        let mgr = NonceManager::new(Duration::from_millis(1));
        let nonce = mgr.generate("net-001").await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = mgr.verify_and_consume(&nonce).await;
        assert_eq!(result, Err(NonceError::Expired));
    }

    #[tokio::test]
    async fn test_cleanup() {
        let mgr = NonceManager::new(Duration::from_millis(1));
        mgr.generate("cmd-1").await;
        mgr.generate("cmd-2").await;
        assert_eq!(mgr.active_count().await, 2);

        tokio::time::sleep(Duration::from_secs(2)).await;
        mgr.cleanup_expired().await;
        assert_eq!(mgr.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_active_count() {
        let mgr = make_manager();
        assert_eq!(mgr.active_count().await, 0);
        mgr.generate("cmd-1").await;
        mgr.generate("cmd-2").await;
        assert_eq!(mgr.active_count().await, 2);
    }

    #[test]
    fn test_nonce_error_display() {
        assert!(NonceError::NotFound.to_string().contains("not found"));
        assert!(NonceError::AlreadyUsed.to_string().contains("replay"));
        assert!(NonceError::Expired.to_string().contains("expired"));
    }
}

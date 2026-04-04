//! Emergency kill switch. See ADR-010.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Raison du déclenchement du kill switch.
#[derive(Debug, Clone)]
pub enum KillReason {
    /// Tentative d'écriture mémoire non autorisée.
    UnauthorizedMemoryWrite,
    /// Tentative d'appel de commande hors whitelist.
    WhitelistViolation { attempts: u32 },
    /// Tentative de modification du system prompt (soul).
    SoulTamperingAttempt,
    /// L'agent tourne depuis trop longtemps sans checkpoint RSSI.
    AutonomyTimeout { hours: u32 },
    /// Score d'anomalie comportementale dépasse le seuil.
    BehaviorAnomaly { score: f32 },
    /// L'agent a tenté de cibler ses propres containers/processus.
    SelfTargetingAttempt,
    /// Trop d'erreurs consécutives (possible boucle infinie).
    ConsecutiveErrors { count: u32 },
    /// Le RSSI a déclenché l'arrêt d'urgence manuellement.
    ManualTrigger { triggered_by: String },
}

impl std::fmt::Display for KillReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnauthorizedMemoryWrite => write!(f, "Tentative d'écriture mémoire non autorisée"),
            Self::WhitelistViolation { attempts } => write!(f, "Violation whitelist ({attempts} tentatives)"),
            Self::SoulTamperingAttempt => write!(f, "Tentative de modification du system prompt"),
            Self::AutonomyTimeout { hours } => write!(f, "Timeout autonomie ({hours}h sans checkpoint)"),
            Self::BehaviorAnomaly { score } => write!(f, "Anomalie comportementale (score: {score:.2})"),
            Self::SelfTargetingAttempt => write!(f, "Tentative de ciblage des propres services"),
            Self::ConsecutiveErrors { count } => write!(f, "Erreurs consécutives ({count})"),
            Self::ManualTrigger { triggered_by } => write!(f, "Arrêt manuel par {triggered_by}"),
        }
    }
}

/// Configuration du kill switch.
#[derive(Debug, Clone)]
pub struct KillSwitchConfig {
    /// Nombre max de violations whitelist avant kill.
    pub max_whitelist_violations: u32,
    /// Nombre max d'erreurs consécutives avant kill.
    pub max_consecutive_errors: u32,
    /// Durée max sans checkpoint RSSI (heures).
    pub max_autonomy_hours: u32,
    /// Seuil d'anomalie comportementale (0.0 - 1.0).
    pub anomaly_threshold: f32,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        Self {
            max_whitelist_violations: 3,
            max_consecutive_errors: 10,
            max_autonomy_hours: 8,
            anomaly_threshold: 0.8,
        }
    }
}

/// Kill switch de l'agent — vérifié à chaque action.
pub struct KillSwitch {
    config: KillSwitchConfig,
    /// L'agent est-il toujours actif ?
    active: Arc<AtomicBool>,
    /// Compteur de violations whitelist.
    whitelist_violations: AtomicU32,
    /// Compteur d'erreurs consécutives.
    consecutive_errors: AtomicU32,
    /// Instant du dernier checkpoint RSSI.
    last_rssi_checkpoint: Arc<RwLock<Instant>>,
    /// Raison du kill si déclenché.
    kill_reason: Arc<RwLock<Option<KillReason>>>,
}

impl KillSwitch {
    pub fn new(config: KillSwitchConfig) -> Self {
        Self {
            config,
            active: Arc::new(AtomicBool::new(true)),
            whitelist_violations: AtomicU32::new(0),
            consecutive_errors: AtomicU32::new(0),
            last_rssi_checkpoint: Arc::new(RwLock::new(Instant::now())),
            kill_reason: Arc::new(RwLock::new(None)),
        }
    }

    /// Vérifie si l'agent est toujours actif.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Retourne la raison du kill si déclenché.
    pub async fn kill_reason(&self) -> Option<KillReason> {
        self.kill_reason.read().await.clone()
    }

    /// Enregistre un checkpoint RSSI (le RSSI a vérifié l'agent).
    pub async fn rssi_checkpoint(&self) {
        *self.last_rssi_checkpoint.write().await = Instant::now();
        tracing::info!("RSSI checkpoint registered — autonomy timer reset");
    }

    /// Réinitialise le compteur d'erreurs consécutives (après une action réussie).
    pub fn reset_errors(&self) {
        self.consecutive_errors.store(0, Ordering::SeqCst);
    }

    /// Signale une violation de whitelist.
    pub async fn report_whitelist_violation(&self) -> Option<KillReason> {
        let count = self.whitelist_violations.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::warn!("SECURITY: Whitelist violation #{count}");

        if count >= self.config.max_whitelist_violations {
            let reason = KillReason::WhitelistViolation { attempts: count };
            self.engage(reason.clone()).await;
            return Some(reason);
        }
        None
    }

    /// Signale une erreur consécutive.
    pub async fn report_error(&self) -> Option<KillReason> {
        let count = self.consecutive_errors.fetch_add(1, Ordering::SeqCst) + 1;

        if count >= self.config.max_consecutive_errors {
            let reason = KillReason::ConsecutiveErrors { count };
            self.engage(reason.clone()).await;
            return Some(reason);
        }
        None
    }

    /// Signale une tentative de modification du soul.
    pub async fn report_soul_tampering(&self) -> KillReason {
        let reason = KillReason::SoulTamperingAttempt;
        self.engage(reason.clone()).await;
        reason
    }

    /// Signale une tentative d'écriture mémoire non autorisée.
    pub async fn report_unauthorized_memory_write(&self) -> KillReason {
        let reason = KillReason::UnauthorizedMemoryWrite;
        self.engage(reason.clone()).await;
        reason
    }

    /// Signale une tentative de ciblage propre (containers ThreatClaw).
    pub async fn report_self_targeting(&self) -> KillReason {
        let reason = KillReason::SelfTargetingAttempt;
        self.engage(reason.clone()).await;
        reason
    }

    /// Déclenchement manuel par le RSSI (bouton d'urgence).
    pub async fn manual_trigger(&self, triggered_by: &str) -> KillReason {
        let reason = KillReason::ManualTrigger {
            triggered_by: triggered_by.to_string(),
        };
        self.engage(reason.clone()).await;
        reason
    }

    /// Vérifie les conditions temporelles (timeout autonomie).
    pub async fn check_autonomy_timeout(&self) -> Option<KillReason> {
        let checkpoint = *self.last_rssi_checkpoint.read().await;
        let elapsed = checkpoint.elapsed();
        let max_duration = Duration::from_secs(self.config.max_autonomy_hours as u64 * 3600);

        if elapsed > max_duration {
            let hours = (elapsed.as_secs() / 3600) as u32;
            let reason = KillReason::AutonomyTimeout { hours };
            self.engage(reason.clone()).await;
            return Some(reason);
        }
        None
    }

    /// Vérifie un score d'anomalie comportementale.
    pub async fn check_behavior_anomaly(&self, score: f32) -> Option<KillReason> {
        if score >= self.config.anomaly_threshold {
            let reason = KillReason::BehaviorAnomaly { score };
            self.engage(reason.clone()).await;
            return Some(reason);
        }
        None
    }

    /// Engage le kill switch — arrêt immédiat de l'agent.
    async fn engage(&self, reason: KillReason) {
        tracing::error!("KILL SWITCH ENGAGED: {}", reason);

        // 1. Marquer l'agent comme inactif (atomique, immédiat)
        self.active.store(false, Ordering::SeqCst);

        // 2. Stocker la raison
        *self.kill_reason.write().await = Some(reason);

        // 3. Note: Le caller (boucle agentique) doit vérifier is_active()
        //    et arrêter la boucle. On ne fait PAS process::exit ici
        //    car on veut que le core Rust continue à servir le dashboard
        //    et les logs forensics.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ks() -> KillSwitch {
        KillSwitch::new(KillSwitchConfig {
            max_whitelist_violations: 3,
            max_consecutive_errors: 5,
            max_autonomy_hours: 1,
            anomaly_threshold: 0.8,
        })
    }

    #[test]
    fn test_initially_active() {
        let ks = make_ks();
        assert!(ks.is_active());
    }

    #[tokio::test]
    async fn test_manual_trigger() {
        let ks = make_ks();
        ks.manual_trigger("admin@example.com").await;
        assert!(!ks.is_active());
        let reason = ks.kill_reason().await.unwrap();
        assert!(matches!(reason, KillReason::ManualTrigger { .. }));
    }

    #[tokio::test]
    async fn test_soul_tampering_kills() {
        let ks = make_ks();
        ks.report_soul_tampering().await;
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_unauthorized_memory_write_kills() {
        let ks = make_ks();
        ks.report_unauthorized_memory_write().await;
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_self_targeting_kills() {
        let ks = make_ks();
        ks.report_self_targeting().await;
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_whitelist_violations_threshold() {
        let ks = make_ks();

        // 1st and 2nd violation: still active
        assert!(ks.report_whitelist_violation().await.is_none());
        assert!(ks.is_active());
        assert!(ks.report_whitelist_violation().await.is_none());
        assert!(ks.is_active());

        // 3rd violation: kill
        let reason = ks.report_whitelist_violation().await;
        assert!(reason.is_some());
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_consecutive_errors_threshold() {
        let ks = make_ks();

        for _ in 0..4 {
            assert!(ks.report_error().await.is_none());
            assert!(ks.is_active());
        }

        // 5th error: kill
        let reason = ks.report_error().await;
        assert!(reason.is_some());
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_reset_errors() {
        let ks = make_ks();

        // 4 errors, then reset
        for _ in 0..4 {
            ks.report_error().await;
        }
        ks.reset_errors();

        // 4 more errors: still active (counter was reset)
        for _ in 0..4 {
            assert!(ks.report_error().await.is_none());
        }
        assert!(ks.is_active());
    }

    #[tokio::test]
    async fn test_rssi_checkpoint_resets_timer() {
        let ks = make_ks();
        ks.rssi_checkpoint().await;
        assert!(ks.check_autonomy_timeout().await.is_none());
    }

    #[tokio::test]
    async fn test_behavior_anomaly_below_threshold() {
        let ks = make_ks();
        assert!(ks.check_behavior_anomaly(0.5).await.is_none());
        assert!(ks.is_active());
    }

    #[tokio::test]
    async fn test_behavior_anomaly_above_threshold() {
        let ks = make_ks();
        let reason = ks.check_behavior_anomaly(0.9).await;
        assert!(reason.is_some());
        assert!(!ks.is_active());
    }

    #[tokio::test]
    async fn test_kill_reason_stored() {
        let ks = make_ks();
        assert!(ks.kill_reason().await.is_none());

        ks.manual_trigger("test").await;
        let reason = ks.kill_reason().await;
        assert!(matches!(reason, Some(KillReason::ManualTrigger { .. })));
    }

    #[test]
    fn test_kill_reason_display() {
        let reasons = vec![
            KillReason::UnauthorizedMemoryWrite,
            KillReason::WhitelistViolation { attempts: 3 },
            KillReason::SoulTamperingAttempt,
            KillReason::AutonomyTimeout { hours: 8 },
            KillReason::BehaviorAnomaly { score: 0.95 },
            KillReason::SelfTargetingAttempt,
            KillReason::ConsecutiveErrors { count: 10 },
            KillReason::ManualTrigger { triggered_by: "admin".to_string() },
        ];

        for reason in reasons {
            let display = format!("{reason}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_default_config() {
        let config = KillSwitchConfig::default();
        assert_eq!(config.max_whitelist_violations, 3);
        assert_eq!(config.max_consecutive_errors, 10);
        assert_eq!(config.max_autonomy_hours, 8);
        assert!((config.anomaly_threshold - 0.8).abs() < f32::EPSILON);
    }
}

//! Backpressure : si la queue dépasse un seuil critique, on refuse les
//! nouveaux graphs gracieusement plutôt que de saturer Ollama / les
//! workers. Permet au système de dégrader proprement sous charge (100
//! sigma_alerts/min en attaque massive) au lieu d'empiler indéfiniment.

use serde::{Deserialize, Serialize};

/// Comptage par status, lu via `count_tasks_by_status` côté store.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct QueueDepths {
    pub queued: i64,
    pub running: i64,
}

impl QueueDepths {
    pub fn total(&self) -> i64 {
        self.queued + self.running
    }
}

/// Décision de backpressure. `Accept` = on peut pousser. `Reject` = on
/// renvoie au caller un message "system overloaded — retry in N min".
/// `Degrade` = on accepte mais en down-priority (priorité 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverloadDecision {
    Accept,
    Degrade,
    Reject,
}

/// Politique de backpressure configurable. Les seuils sont en nombre de
/// rows `queued + running` dans `task_queue` (tous kinds confondus).
#[derive(Debug, Clone, Copy)]
pub struct BackpressureCheck {
    /// En dessous de ce seuil : on accepte sans réserve.
    pub accept_below: i64,
    /// Entre `accept_below` et `degrade_below` : accepté mais down-priority.
    pub degrade_below: i64,
    /// Au-dessus de `degrade_below` : on refuse.
    pub reject_at: i64,
}

impl Default for BackpressureCheck {
    fn default() -> Self {
        // Valeurs calibrées pour l'archi Phase G :
        // - 200 tasks queued : encore confortable (~ 4 min si LLM = 1 task/min)
        // - 500 tasks queued : on dégrade les nouveaux graphs en priorité 9
        // - 1000 tasks queued : on refuse, le système est saturé
        Self {
            accept_below: 200,
            degrade_below: 500,
            reject_at: 1_000,
        }
    }
}

impl BackpressureCheck {
    pub fn decide(&self, depths: &QueueDepths) -> OverloadDecision {
        let total = depths.total();
        if total < self.accept_below {
            OverloadDecision::Accept
        } else if total < self.degrade_below {
            OverloadDecision::Degrade
        } else if total < self.reject_at {
            OverloadDecision::Degrade
        } else {
            OverloadDecision::Reject
        }
    }

    /// Estimation grossière du temps d'attente avant que la queue
    /// redescende sous `accept_below`, basée sur un débit de `throughput`
    /// tasks par minute. Utilisé pour le message "retry in N min".
    pub fn est_retry_after_minutes(&self, depths: &QueueDepths, throughput_per_min: f64) -> u64 {
        if throughput_per_min <= 0.0 {
            return 60;
        }
        let excess = (depths.total() - self.accept_below).max(0) as f64;
        ((excess / throughput_per_min).ceil() as u64).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue_accepts() {
        let check = BackpressureCheck::default();
        assert_eq!(
            check.decide(&QueueDepths::default()),
            OverloadDecision::Accept
        );
    }

    #[test]
    fn at_accept_threshold_degrades() {
        let check = BackpressureCheck::default();
        let d = QueueDepths {
            queued: 200,
            running: 0,
        };
        assert_eq!(check.decide(&d), OverloadDecision::Degrade);
    }

    #[test]
    fn above_reject_threshold_rejects() {
        let check = BackpressureCheck::default();
        let d = QueueDepths {
            queued: 800,
            running: 300,
        };
        assert_eq!(check.decide(&d), OverloadDecision::Reject);
    }

    #[test]
    fn retry_estimate_scales_with_excess() {
        let check = BackpressureCheck::default();
        let d = QueueDepths {
            queued: 800,
            running: 0,
        };
        // excess = 600, throughput = 60/min → 10 min
        assert_eq!(check.est_retry_after_minutes(&d, 60.0), 10);
    }

    #[test]
    fn retry_estimate_clamps_at_one_minute_minimum() {
        let check = BackpressureCheck::default();
        let d = QueueDepths {
            queued: 199,
            running: 0,
        };
        assert_eq!(check.est_retry_after_minutes(&d, 60.0), 1);
    }
}

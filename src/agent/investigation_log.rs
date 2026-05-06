//! Investigation timeline helpers (Phase 9o).
//!
//! Wraps `Database::append_investigation_step` so call sites have a
//! fluent, readable builder rather than a half-empty struct literal.
//!
//! # Two flushing strategies
//!
//! Some steps happen *before* the incident exists (skill calls fired
//! during `pre_enrich_dossier`). The dossier holds the incident id only
//! after `create_incident`. To handle both worlds:
//!
//! 1. **Pre-incident**: enqueue steps in [`InvestigationLogBuffer`]
//!    (lives on `IncidentDossier.investigation_log`). After
//!    `create_incident`, the IE drains the buffer with
//!    [`flush_buffer`].
//! 2. **Post-incident**: any code with an `incident_id` on hand calls
//!    [`record_step`] directly — fire and forget, errors logged but
//!    never propagated, since persistence failure must not abort the
//!    pipeline.
//!
//! Both paths build [`StepBuilder`] the same way, so call sites read
//! the same regardless of timing.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::Database;
use crate::db::threatclaw_store::{NewInvestigationStep, StepKind, StepStatus};

/// Pending step queued before the incident has an id. The fields mirror
/// `NewInvestigationStep` minus `incident_id`, which is filled in at
/// flush time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvestigationStep {
    pub kind: StepKind,
    pub skill_id: Option<String>,
    pub summary: String,
    pub payload: Value,
    pub duration_ms: Option<i32>,
    pub status: StepStatus,
}

/// Buffer of pre-incident steps. Default-empty so `IncidentDossier` can
/// derive `Default`. Cheap to clone — the dossier itself is cloned around
/// the IE pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvestigationLogBuffer {
    pub pending: Vec<PendingInvestigationStep>,
}

impl InvestigationLogBuffer {
    pub fn push(&mut self, step: PendingInvestigationStep) {
        self.pending.push(step);
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn drain(&mut self) -> Vec<PendingInvestigationStep> {
        std::mem::take(&mut self.pending)
    }
}

/// Fluent builder for an investigation step. All fields default to safe
/// values; only `kind` and `summary` are required (passed to `new`).
///
/// ```ignore
/// StepBuilder::new(StepKind::SkillCall, "skill-greynoise classify 1.2.3.4")
///     .skill("skill-greynoise")
///     .payload(json!({"classification": "malicious"}))
///     .duration_from(start)
///     .status(StepStatus::Ok)
///     .record(store, incident_id).await;
/// ```
#[derive(Debug, Clone)]
pub struct StepBuilder {
    kind: StepKind,
    skill_id: Option<String>,
    summary: String,
    payload: Value,
    duration_ms: Option<i32>,
    status: StepStatus,
}

impl StepBuilder {
    pub fn new(kind: StepKind, summary: impl Into<String>) -> Self {
        Self {
            kind,
            skill_id: None,
            summary: summary.into(),
            payload: serde_json::json!({}),
            duration_ms: None,
            status: StepStatus::Ok,
        }
    }

    pub fn skill(mut self, skill_id: impl Into<String>) -> Self {
        self.skill_id = Some(skill_id.into());
        self
    }

    pub fn payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }

    /// Set the duration explicitly. Prefer [`duration_from`] when you
    /// have an `Instant` from the start of the operation.
    pub fn duration_ms(mut self, ms: i32) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Compute duration from a captured `Instant::now()` taken at the
    /// start of the operation. Saturating cast so a duration overflowing
    /// `i32::MAX` (~24 days) doesn't panic.
    pub fn duration_from(mut self, start: Instant) -> Self {
        let elapsed = start.elapsed().as_millis();
        self.duration_ms = Some(elapsed.min(i32::MAX as u128) as i32);
        self
    }

    pub fn status(mut self, status: StepStatus) -> Self {
        self.status = status;
        self
    }

    /// Persist the step against an existing incident. Errors are logged
    /// at warn level but never bubble up — recording the trace must
    /// never abort the pipeline.
    pub async fn record(self, store: &dyn Database, incident_id: i32) {
        let new = NewInvestigationStep {
            incident_id,
            kind: self.kind,
            skill_id: self.skill_id,
            summary: self.summary,
            payload: self.payload,
            duration_ms: self.duration_ms,
            status: self.status,
        };
        if let Err(e) = store.append_investigation_step(&new).await {
            tracing::warn!("INVESTIGATION_LOG: persist failed for incident #{incident_id}: {e}");
        }
    }

    /// Buffer the step on a pre-incident dossier — flushed by
    /// [`flush_buffer`] right after the incident is created.
    pub fn enqueue(self, buffer: &mut InvestigationLogBuffer) {
        buffer.push(PendingInvestigationStep {
            kind: self.kind,
            skill_id: self.skill_id,
            summary: self.summary,
            payload: self.payload,
            duration_ms: self.duration_ms,
            status: self.status,
        });
    }
}

/// Drain a pre-incident buffer and persist every queued step against a
/// freshly-created incident. Errors are logged but not propagated — the
/// trace is best-effort, the incident itself stays valid.
pub async fn flush_buffer(
    store: &dyn Database,
    incident_id: i32,
    buffer: &mut InvestigationLogBuffer,
) {
    let pending = buffer.drain();
    if pending.is_empty() {
        return;
    }
    let count = pending.len();
    for step in pending {
        let new = NewInvestigationStep {
            incident_id,
            kind: step.kind,
            skill_id: step.skill_id,
            summary: step.summary,
            payload: step.payload,
            duration_ms: step.duration_ms,
            status: step.status,
        };
        if let Err(e) = store.append_investigation_step(&new).await {
            tracing::warn!("INVESTIGATION_LOG: flush failed for incident #{incident_id}: {e}");
        }
    }
    tracing::debug!(
        "INVESTIGATION_LOG: flushed {count} pending step(s) for incident #{incident_id}"
    );
}

/// Convenience for callers that only need a one-shot recording without a
/// builder — `record_step(store, id, StepKind::Note, "operator added context", json!({}))`.
pub async fn record_step(
    store: &dyn Database,
    incident_id: i32,
    kind: StepKind,
    summary: impl Into<String>,
    payload: Value,
) {
    StepBuilder::new(kind, summary)
        .payload(payload)
        .record(store, incident_id)
        .await;
}

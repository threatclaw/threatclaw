//! Canonical schema for HITL response actions surfaced on incidents.
//!
//! Phase 9a — single source of truth for `incidents.proposed_actions` JSONB.
//!
//! # Why this module exists
//!
//! Before Phase 9, three writers produced three incompatible JSON shapes for
//! `incidents.proposed_actions`:
//!
//! 1. `forensic_enricher::derive_block_actions` — wrote
//!    `{actions: [{cmd_id, params, rationale, derived_by}], iocs: []}`.
//! 2. `task_queue::workers::create_incident_from_graph` — wrote a flat
//!    `[{cmd_id, rationale, requires_hitl}]` array (CACAO graph YAML format).
//! 3. The dashboard expected `{actions: [{kind, description}], iocs: []}`.
//!
//! Result: even when a real `opnsense_block_ip` was persisted, the operator
//! UI could not render it (missing `kind`/`description`). The remediation
//! pipeline downstream worked, but the human in the loop saw nothing.
//!
//! This module fixes that:
//!
//! * [`ActionKind`] is the typed taxonomy ("block_ip", "isolate_host", ...)
//!   used by the UI for badges, filtering, and grouping.
//! * [`IncidentAction`] carries everything the operator needs to make a
//!   decision (description, parameters, rationale, originating skill).
//! * [`ProposedActionsBundle`] is the wrapper persisted in the JSONB column
//!   so the operator can also see related IOCs.
//! * Builders (`block_ip`, `isolate_host`, ...) generate canonical actions —
//!   every producer in the codebase should call them rather than hand-rolling
//!   a JSON object.
//! * [`parse_proposed_actions_legacy`] reads the old shapes back as the
//!   canonical type. Old incidents stay viewable while the database catches
//!   up via the Phase 9d cleanup script.
//!
//! See `internal/roadmap-mai.md` Phase 9a + 9c.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Short taxonomy of HITL actions, exposed verbatim to the dashboard as the
/// stable API surface.
///
/// Multiple `cmd_id`s may map to the same `ActionKind` (`opnsense_block_ip`
/// and `fortinet_block_ip` both produce `BlockIp`). The kind is what the
/// operator filters on; the cmd_id is what the remediation engine routes on.
///
/// `Unknown` is used by the legacy parser when it encounters a `cmd_id` it
/// does not recognise (forward compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Drop traffic from / to an IP at the firewall layer.
    BlockIp,
    /// Reverse a previous `BlockIp`.
    UnblockIp,
    /// Quarantine an asset at the EDR layer (block all network egress except
    /// EDR control channel).
    IsolateHost,
    /// Reverse a previous `IsolateHost`.
    ReleaseHost,
    /// Terminate a specific process by PID.
    KillProcess,
    /// Trigger a forensic artifact collection (memory, timeline, browser
    /// history, ...).
    CollectArtifacts,
    /// Disable an identity / user account.
    DisableUser,
    /// Reverse a previous `DisableUser`.
    EnableUser,
    /// Force a password reset on next login.
    ResetPassword,
    /// Rotate the AD `krbtgt` account — golden ticket response.
    ResetKrbtgt,
    /// Force MFA enrolment on the next login.
    ForceMfa,
    /// Documentary recommendation for the operator — no automation.
    /// Used when the relevant skill isn't connected.
    Manual,
    /// Unknown / unmapped — the `cmd_id` was not recognised. Forward-compat
    /// only; should never be produced by the builders below.
    #[serde(other)]
    Unknown,
}

impl ActionKind {
    /// Human-readable label for badges. Kept short — the description carries
    /// the detail.
    pub fn label(&self) -> &'static str {
        match self {
            ActionKind::BlockIp => "BLOCK_IP",
            ActionKind::UnblockIp => "UNBLOCK_IP",
            ActionKind::IsolateHost => "ISOLATE_HOST",
            ActionKind::ReleaseHost => "RELEASE_HOST",
            ActionKind::KillProcess => "KILL_PROCESS",
            ActionKind::CollectArtifacts => "COLLECT_ARTIFACTS",
            ActionKind::DisableUser => "DISABLE_USER",
            ActionKind::EnableUser => "ENABLE_USER",
            ActionKind::ResetPassword => "RESET_PASSWORD",
            ActionKind::ResetKrbtgt => "RESET_KRBTGT",
            ActionKind::ForceMfa => "FORCE_MFA",
            ActionKind::Manual => "MANUAL",
            ActionKind::Unknown => "UNKNOWN",
        }
    }

    /// Map a known `cmd_id` to its taxonomy. Falls back to [`ActionKind::Unknown`]
    /// for anything we have not catalogued.
    ///
    /// Centralising this here means a vendor adding a new firewall only has
    /// to register their `cmd_id` in the match, and the UI / filter / metrics
    /// pick it up automatically.
    pub fn from_cmd_id(cmd_id: &str) -> Self {
        match cmd_id {
            "opnsense_block_ip" | "fortinet_block_ip" | "pfsense_block_ip"
            | "mikrotik_block_ip" | "proxmox_block_ip" => ActionKind::BlockIp,
            "opnsense_unblock_ip"
            | "fortinet_unblock_ip"
            | "pfsense_unblock_ip"
            | "mikrotik_unblock_ip" => ActionKind::UnblockIp,
            "velociraptor_isolate_host" | "edr_isolate_host" => ActionKind::IsolateHost,
            "velociraptor_release_host" | "edr_release_host" => ActionKind::ReleaseHost,
            "velociraptor_kill_process" | "edr_kill_process" => ActionKind::KillProcess,
            "velociraptor_collect_artifacts" | "edr_collect_artifacts" => {
                ActionKind::CollectArtifacts
            }
            "ad_disable_user"
            | "azuread_disable_user"
            | "keycloak_disable_user"
            | "authentik_disable_user" => ActionKind::DisableUser,
            "ad_enable_user" | "azuread_enable_user" => ActionKind::EnableUser,
            "ad_reset_password" | "azuread_reset_password" | "keycloak_reset_password" => {
                ActionKind::ResetPassword
            }
            "ad_reset_krbtgt" => ActionKind::ResetKrbtgt,
            "ad_force_mfa" | "azuread_force_mfa" => ActionKind::ForceMfa,
            "manual" => ActionKind::Manual,
            _ => ActionKind::Unknown,
        }
    }
}

/// Default skill identifier responsible for executing a given `cmd_id`. Used
/// by the legacy parser to backfill `skill_id` for incidents written before
/// Phase 9c. New writers should set `skill_id` explicitly via the builder.
pub fn skill_id_from_cmd_id(cmd_id: &str) -> &'static str {
    if cmd_id.starts_with("opnsense_") {
        "skill-opnsense"
    } else if cmd_id.starts_with("fortinet_") {
        "skill-fortinet"
    } else if cmd_id.starts_with("pfsense_") {
        "skill-pfsense"
    } else if cmd_id.starts_with("mikrotik_") {
        "skill-mikrotik"
    } else if cmd_id.starts_with("proxmox_") {
        "skill-proxmox"
    } else if cmd_id.starts_with("velociraptor_") || cmd_id.starts_with("edr_") {
        "skill-velociraptor"
    } else if cmd_id.starts_with("ad_") {
        "skill-active-directory"
    } else if cmd_id.starts_with("azuread_") {
        "skill-microsoft-graph"
    } else if cmd_id.starts_with("keycloak_") {
        "skill-keycloak"
    } else if cmd_id.starts_with("authentik_") {
        "skill-authentik"
    } else {
        "skill-unknown"
    }
}

/// One canonical HITL action exposed on an incident.
///
/// The `serde` representation is what gets persisted in
/// `incidents.proposed_actions.actions[]` and is therefore part of the
/// public API contract with the dashboard. Field changes are breaking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAction {
    /// Short typed taxonomy. Drives UI badge + filtering + metrics.
    pub kind: ActionKind,
    /// Executable identifier consumed by `remediation_engine` and the
    /// vendor connectors. Stable string — never rename without a migration.
    pub cmd_id: String,
    /// Human-readable description for the operator. The builders generate
    /// it so the UI never has to translate (e.g. "Block 62.210.201.235 at
    /// the OPNsense firewall").
    pub description: String,
    /// Stringified parameters. Stays string-only for stable serde and
    /// trivial JSONB indexing on `params->>'ip'`.
    pub params: HashMap<String, String>,
    /// Why this action is proposed. Should reference at least one
    /// `sigma_alert.id` or `finding.id` so the operator can audit the
    /// decision.
    pub rationale: String,
    /// `true` for everything Phase 9 produces — no auto-execution. Reserved
    /// for a future low-risk allowlist (e.g. auto-block confirmed Tor exit
    /// nodes), explicitly out of scope today.
    pub requires_hitl: bool,
    /// Skill that executes the action. Drives UI vendor badge and the
    /// `remediation_engine` routing.
    pub skill_id: String,
    /// Provenance for the audit trail. Conventional values:
    ///   * `forensic_enricher_phase7b` — derived deterministically from
    ///     attested external IPs after L2 forensic.
    ///   * `cacao_graph:<graph_name>` — produced by an investigation graph.
    ///   * `react_l1` — proposed by the L1 ReAct cycle LLM.
    ///   * `legacy_cacao_graph` — backfilled by the legacy parser.
    pub origin: String,
}

impl IncidentAction {
    // ── Builders ──
    //
    // Use these instead of constructing the struct field-by-field. They
    // guarantee `kind` and `cmd_id` stay in sync, generate consistent
    // descriptions, and make adding a new action everywhere a one-liner.

    /// Block an IP at the firewall. `skill_id` decides the vendor; the
    /// `cmd_id` is derived to match. Pass an [`Ipv4Addr`]-shaped string —
    /// CIDR masks are stripped to keep the param consistent across vendors.
    ///
    /// [`Ipv4Addr`]: std::net::Ipv4Addr
    pub fn block_ip(ip: &str, skill_id: &str, rationale: impl Into<String>) -> Self {
        let ip = ip.split('/').next().unwrap_or(ip).to_string();
        let cmd_id = match skill_id {
            "skill-fortinet" => "fortinet_block_ip",
            "skill-pfsense" => "pfsense_block_ip",
            "skill-mikrotik" => "mikrotik_block_ip",
            "skill-proxmox" => "proxmox_block_ip",
            _ => "opnsense_block_ip", // OPNsense default — covers the bundled stack
        };
        let mut params = HashMap::with_capacity(1);
        params.insert("ip".into(), ip.clone());
        Self {
            kind: ActionKind::BlockIp,
            cmd_id: cmd_id.into(),
            description: format!("Bloquer {ip} au pare-feu ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Isolate an asset at the EDR layer. Reversible via [`release_host`].
    ///
    /// [`release_host`]: IncidentAction::release_host
    pub fn isolate_host(asset: &str, skill_id: &str, rationale: impl Into<String>) -> Self {
        let mut params = HashMap::with_capacity(1);
        params.insert("asset".into(), asset.to_string());
        Self {
            kind: ActionKind::IsolateHost,
            cmd_id: "velociraptor_isolate_host".into(),
            description: format!("Isoler {asset} via l'EDR ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Release a previously isolated asset.
    pub fn release_host(asset: &str, skill_id: &str, rationale: impl Into<String>) -> Self {
        let mut params = HashMap::with_capacity(1);
        params.insert("asset".into(), asset.to_string());
        Self {
            kind: ActionKind::ReleaseHost,
            cmd_id: "velociraptor_release_host".into(),
            description: format!("Lever l'isolation de {asset} ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Terminate a process on the asset.
    pub fn kill_process(
        asset: &str,
        pid: u32,
        skill_id: &str,
        rationale: impl Into<String>,
    ) -> Self {
        let mut params = HashMap::with_capacity(2);
        params.insert("asset".into(), asset.to_string());
        params.insert("pid".into(), pid.to_string());
        Self {
            kind: ActionKind::KillProcess,
            cmd_id: "velociraptor_kill_process".into(),
            description: format!("Tuer le processus PID {pid} sur {asset} ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Trigger a forensic artifact collection (memory dump, timeline, browser
    /// history, ...). `artifact_set` is the named bundle understood by the
    /// EDR (e.g. `Generic.Forensic.Timeline` for Velociraptor).
    pub fn collect_artifacts(
        asset: &str,
        artifact_set: &str,
        skill_id: &str,
        rationale: impl Into<String>,
    ) -> Self {
        let mut params = HashMap::with_capacity(2);
        params.insert("asset".into(), asset.to_string());
        params.insert("artifact_set".into(), artifact_set.to_string());
        Self {
            kind: ActionKind::CollectArtifacts,
            cmd_id: "velociraptor_collect_artifacts".into(),
            description: format!("Collecter {artifact_set} sur {asset} ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Disable a user account in the IAM / IdP. `skill_id` selects the
    /// directory (`skill-active-directory`, `skill-microsoft-graph`,
    /// `skill-keycloak`, `skill-authentik`).
    pub fn disable_user(user_id: &str, skill_id: &str, rationale: impl Into<String>) -> Self {
        let cmd_id = match skill_id {
            "skill-microsoft-graph" => "azuread_disable_user",
            "skill-keycloak" => "keycloak_disable_user",
            "skill-authentik" => "authentik_disable_user",
            _ => "ad_disable_user", // Active Directory default
        };
        let mut params = HashMap::with_capacity(1);
        params.insert("user_id".into(), user_id.to_string());
        Self {
            kind: ActionKind::DisableUser,
            cmd_id: cmd_id.into(),
            description: format!("Désactiver le compte {user_id} ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Force a password reset at next login.
    pub fn reset_password(user_id: &str, skill_id: &str, rationale: impl Into<String>) -> Self {
        let cmd_id = match skill_id {
            "skill-microsoft-graph" => "azuread_reset_password",
            "skill-keycloak" => "keycloak_reset_password",
            _ => "ad_reset_password",
        };
        let mut params = HashMap::with_capacity(1);
        params.insert("user_id".into(), user_id.to_string());
        Self {
            kind: ActionKind::ResetPassword,
            cmd_id: cmd_id.into(),
            description: format!("Forcer le reset password de {user_id} ({skill_id})"),
            params,
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Rotate the AD `krbtgt` account. Mandatory after a confirmed
    /// golden-ticket attack.
    pub fn reset_krbtgt(skill_id: &str, rationale: impl Into<String>) -> Self {
        Self {
            kind: ActionKind::ResetKrbtgt,
            cmd_id: "ad_reset_krbtgt".into(),
            description: format!("Rotation du krbtgt AD ({skill_id})"),
            params: HashMap::new(),
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: skill_id.into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    /// Documentary recommendation only — no automation. Used when the
    /// relevant skill isn't connected but the operator still benefits from
    /// the suggestion.
    pub fn manual(description: impl Into<String>, rationale: impl Into<String>) -> Self {
        Self {
            kind: ActionKind::Manual,
            cmd_id: "manual".into(),
            description: description.into(),
            params: HashMap::new(),
            rationale: rationale.into(),
            requires_hitl: true,
            skill_id: "skill-manual".into(),
            origin: "forensic_enricher_phase7b".into(),
        }
    }

    // ── Mutators ──

    /// Override the audit-trail origin of the action. Builders default to
    /// `forensic_enricher_phase7b` — graph workers and the L1 cycle should
    /// chain `.with_origin("cacao_graph:<name>")` or
    /// `.with_origin("react_l1")`.
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = origin.into();
        self
    }
}

/// Wrapper persisted in `incidents.proposed_actions` JSONB.
///
/// Keeping `actions` and `iocs` together gives the operator a single payload
/// to look at: the actions to validate plus the indicators worth pivoting on
/// in their SIEM / TIP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProposedActionsBundle {
    pub actions: Vec<IncidentAction>,
    pub iocs: Vec<String>,
}

impl ProposedActionsBundle {
    pub fn new(actions: Vec<IncidentAction>) -> Self {
        Self {
            actions,
            iocs: Vec::new(),
        }
    }

    pub fn with_iocs(mut self, iocs: Vec<String>) -> Self {
        self.iocs = iocs;
        self
    }

    /// Convenience for callers that persist via `set_incident_proposed_actions`
    /// and just need a `serde_json::Value`.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self)
            .unwrap_or_else(|_| serde_json::json!({"actions": [], "iocs": []}))
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.iocs.is_empty()
    }
}

/// Read any of the three legacy shapes of `incidents.proposed_actions` and
/// return the canonical bundle.
///
/// Recognised inputs:
///
/// 1. **Canonical** — `{"actions": [...], "iocs": [...]}`. Returned as-is
///    after validating each action's `kind` is recognised. If an action has
///    `kind: Unknown` (legacy persisted before Phase 9a) we re-derive it
///    from `cmd_id` so the UI renders a useful badge.
/// 2. **Phase 7b legacy** — `{"actions": [{cmd_id, params, rationale, derived_by}], "iocs": []}`.
///    Same wrapper as canonical, but missing `kind` / `description` /
///    `skill_id`. Backfilled from `cmd_id`.
/// 3. **CACAO graph legacy** — flat array
///    `[{"cmd_id": "...", "rationale": "...", "requires_hitl": true}]`.
///    Wrapped and backfilled.
/// 4. **Empty** — `[]`, `null`, or the empty object. Returns the default
///    bundle.
///
/// Anything else returns the default bundle and is silently ignored — we
/// never panic on legacy data.
pub fn parse_proposed_actions_legacy(value: &serde_json::Value) -> ProposedActionsBundle {
    if value.is_null() {
        return ProposedActionsBundle::default();
    }

    // (1) Canonical wrapper — try first.
    if value.is_object() && value.get("actions").is_some() {
        if let Ok(mut bundle) = serde_json::from_value::<ProposedActionsBundle>(value.clone()) {
            backfill_actions(&mut bundle.actions);
            return bundle;
        }
        // (2) Phase 7b legacy wrapper — same shape but actions are loose
        // objects without `kind`. Re-parse the inner array manually.
        if let Some(arr) = value["actions"].as_array() {
            let actions = parse_action_array(arr);
            let iocs: Vec<String> = value["iocs"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            return ProposedActionsBundle { actions, iocs };
        }
    }

    // (3) CACAO graph legacy — flat array.
    if let Some(arr) = value.as_array() {
        let actions = parse_action_array(arr);
        return ProposedActionsBundle::new(actions);
    }

    ProposedActionsBundle::default()
}

/// Build canonical `IncidentAction`s from a `&[Value]` of legacy / partial
/// objects. Skips entries without a `cmd_id` (nothing to map).
fn parse_action_array(arr: &[serde_json::Value]) -> Vec<IncidentAction> {
    arr.iter()
        .filter_map(|item| {
            let cmd_id = item.get("cmd_id")?.as_str()?.to_string();
            let kind = ActionKind::from_cmd_id(&cmd_id);
            let skill_id = item
                .get("skill_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| skill_id_from_cmd_id(&cmd_id).to_string());
            let description = item
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("[legacy] {cmd_id}"));
            let rationale = item
                .get("rationale")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let requires_hitl = item
                .get("requires_hitl")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let params = item
                .get("params")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let origin = item
                .get("origin")
                .or_else(|| item.get("derived_by"))
                .and_then(|v| v.as_str())
                .unwrap_or("legacy")
                .to_string();
            Some(IncidentAction {
                kind,
                cmd_id,
                description,
                params,
                rationale,
                requires_hitl,
                skill_id,
                origin,
            })
        })
        .collect()
}

/// Re-derive `kind` from `cmd_id` for any action whose stored `kind` is
/// `Unknown` (older row written before the kind field was reliable).
fn backfill_actions(actions: &mut [IncidentAction]) {
    for a in actions.iter_mut() {
        if matches!(a.kind, ActionKind::Unknown) {
            a.kind = ActionKind::from_cmd_id(&a.cmd_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_kind_round_trips_through_serde() {
        let kinds = [
            ActionKind::BlockIp,
            ActionKind::IsolateHost,
            ActionKind::KillProcess,
            ActionKind::DisableUser,
            ActionKind::ResetKrbtgt,
            ActionKind::Manual,
        ];
        for k in kinds {
            let s = serde_json::to_string(&k).unwrap();
            let back: ActionKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back, "round-trip failed for {k:?}");
        }
    }

    #[test]
    fn unknown_serialised_label_does_not_panic() {
        // Forward-compat: the dashboard could surface a kind we don't know
        // yet — `Unknown` must accept anything thanks to `#[serde(other)]`.
        let v = serde_json::json!("some_future_kind");
        let parsed: ActionKind = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, ActionKind::Unknown);
    }

    #[test]
    fn block_ip_strips_cidr_and_picks_correct_cmd_id() {
        let a = IncidentAction::block_ip("62.210.201.235/32", "skill-opnsense", "test");
        assert_eq!(a.kind, ActionKind::BlockIp);
        assert_eq!(a.cmd_id, "opnsense_block_ip");
        assert_eq!(a.params.get("ip").unwrap(), "62.210.201.235");
        assert!(a.requires_hitl);
        assert_eq!(a.skill_id, "skill-opnsense");
    }

    #[test]
    fn block_ip_routes_to_vendor_cmd_id() {
        for (skill, cmd) in [
            ("skill-fortinet", "fortinet_block_ip"),
            ("skill-pfsense", "pfsense_block_ip"),
            ("skill-mikrotik", "mikrotik_block_ip"),
            ("skill-opnsense", "opnsense_block_ip"),
        ] {
            let a = IncidentAction::block_ip("1.2.3.4", skill, "test");
            assert_eq!(a.cmd_id, cmd, "wrong cmd_id for {skill}");
        }
    }

    #[test]
    fn isolate_host_carries_asset_param() {
        let a = IncidentAction::isolate_host(
            "asset-bc2411e4af27",
            "skill-velociraptor",
            "compromission suspectée",
        );
        assert_eq!(a.kind, ActionKind::IsolateHost);
        assert_eq!(a.cmd_id, "velociraptor_isolate_host");
        assert_eq!(a.params.get("asset").unwrap(), "asset-bc2411e4af27");
    }

    #[test]
    fn disable_user_routes_to_directory_cmd_id() {
        for (skill, cmd) in [
            ("skill-active-directory", "ad_disable_user"),
            ("skill-microsoft-graph", "azuread_disable_user"),
            ("skill-keycloak", "keycloak_disable_user"),
            ("skill-authentik", "authentik_disable_user"),
        ] {
            let a = IncidentAction::disable_user("alice", skill, "test");
            assert_eq!(a.cmd_id, cmd);
        }
    }

    #[test]
    fn skill_id_from_cmd_id_recognises_known_prefixes() {
        for (cmd, skill) in [
            ("opnsense_block_ip", "skill-opnsense"),
            ("velociraptor_isolate_host", "skill-velociraptor"),
            ("ad_reset_krbtgt", "skill-active-directory"),
            ("azuread_disable_user", "skill-microsoft-graph"),
            ("manual", "skill-unknown"), // Manual has no skill — `Unknown` is correct
        ] {
            assert_eq!(skill_id_from_cmd_id(cmd), skill, "mismatch for {cmd}");
        }
    }

    #[test]
    fn action_kind_from_cmd_id_falls_back_to_unknown() {
        assert_eq!(
            ActionKind::from_cmd_id("future_vendor_block_ip"),
            ActionKind::Unknown
        );
    }

    #[test]
    fn with_origin_overrides_default() {
        let a = IncidentAction::block_ip("1.2.3.4", "skill-opnsense", "test")
            .with_origin("cacao_graph:ssh-bruteforce");
        assert_eq!(a.origin, "cacao_graph:ssh-bruteforce");
    }

    #[test]
    fn bundle_to_value_yields_canonical_shape() {
        let bundle = ProposedActionsBundle::new(vec![IncidentAction::block_ip(
            "1.2.3.4",
            "skill-opnsense",
            "test",
        )])
        .with_iocs(vec!["1.2.3.4".into(), "evil.example".into()]);
        let v = bundle.to_value();
        assert!(v.is_object());
        assert_eq!(v["actions"].as_array().unwrap().len(), 1);
        assert_eq!(v["iocs"].as_array().unwrap().len(), 2);
        assert_eq!(v["actions"][0]["kind"], "block_ip");
    }

    #[test]
    fn bundle_round_trips_through_serde() {
        let bundle = ProposedActionsBundle::new(vec![
            IncidentAction::block_ip("1.2.3.4", "skill-opnsense", "r1"),
            IncidentAction::isolate_host("asset-x", "skill-velociraptor", "r2"),
        ])
        .with_iocs(vec!["1.2.3.4".into()]);
        let v = bundle.to_value();
        let back: ProposedActionsBundle = serde_json::from_value(v).unwrap();
        assert_eq!(back.actions.len(), 2);
        assert_eq!(back.actions[0].kind, ActionKind::BlockIp);
        assert_eq!(back.actions[1].kind, ActionKind::IsolateHost);
        assert_eq!(back.iocs, vec!["1.2.3.4".to_string()]);
    }

    // ── Legacy parser ──

    #[test]
    fn parse_legacy_canonical_passes_through() {
        let v = serde_json::json!({
            "actions": [{
                "kind": "block_ip",
                "cmd_id": "opnsense_block_ip",
                "description": "Bloquer 1.2.3.4",
                "params": {"ip": "1.2.3.4"},
                "rationale": "test",
                "requires_hitl": true,
                "skill_id": "skill-opnsense",
                "origin": "test"
            }],
            "iocs": ["1.2.3.4"]
        });
        let bundle = parse_proposed_actions_legacy(&v);
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.actions[0].kind, ActionKind::BlockIp);
        assert_eq!(bundle.iocs, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn parse_legacy_phase7b_wrapper_backfills_kind_and_description() {
        // What forensic_enricher Phase 7b actually wrote to the DB.
        let v = serde_json::json!({
            "actions": [{
                "cmd_id": "opnsense_block_ip",
                "params": {"ip": "62.210.201.235"},
                "rationale": "IP externe attestée",
                "derived_by": "forensic_enricher_phase7b"
            }],
            "iocs": []
        });
        let bundle = parse_proposed_actions_legacy(&v);
        assert_eq!(bundle.actions.len(), 1);
        let a = &bundle.actions[0];
        assert_eq!(a.kind, ActionKind::BlockIp);
        assert_eq!(a.cmd_id, "opnsense_block_ip");
        assert_eq!(a.skill_id, "skill-opnsense");
        assert_eq!(a.params.get("ip").unwrap(), "62.210.201.235");
        assert_eq!(a.origin, "forensic_enricher_phase7b");
        // `description` is a backfill placeholder — UI can render it.
        assert!(!a.description.is_empty());
    }

    #[test]
    fn parse_legacy_cacao_flat_array_is_wrapped() {
        // What graph workers historically wrote on incident #1577.
        let v = serde_json::json!([{
            "cmd_id": "opnsense_block_ip",
            "rationale": "Burst IDS sur asset critique — bloquer la source",
            "requires_hitl": true
        }]);
        let bundle = parse_proposed_actions_legacy(&v);
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.actions[0].kind, ActionKind::BlockIp);
        assert!(bundle.actions[0].requires_hitl);
        assert_eq!(bundle.actions[0].origin, "legacy");
    }

    #[test]
    fn parse_legacy_empty_inputs_yield_default_bundle() {
        for v in [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!({"actions": [], "iocs": []}),
        ] {
            let bundle = parse_proposed_actions_legacy(&v);
            assert!(bundle.is_empty(), "expected empty for {v:?}");
        }
    }

    #[test]
    fn parse_legacy_drops_actions_without_cmd_id() {
        let v = serde_json::json!([
            {"cmd_id": "opnsense_block_ip"},
            {"rationale": "no cmd_id here, dropped"},
        ]);
        let bundle = parse_proposed_actions_legacy(&v);
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.actions[0].cmd_id, "opnsense_block_ip");
    }

    #[test]
    fn parse_legacy_unknown_cmd_id_lands_on_unknown_kind() {
        // Forward-compat: a future cmd_id we don't know parses to Unknown
        // and is still surfaced (rather than dropped).
        let v = serde_json::json!([{
            "cmd_id": "future_vendor_block_ip",
            "rationale": "test"
        }]);
        let bundle = parse_proposed_actions_legacy(&v);
        assert_eq!(bundle.actions.len(), 1);
        assert_eq!(bundle.actions[0].kind, ActionKind::Unknown);
    }
}

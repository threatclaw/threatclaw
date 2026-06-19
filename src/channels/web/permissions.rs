//! Permission catalogue and role → permission mapping for the dashboard RBAC.
//!
//! The authorization layer always tests an atomic permission
//! (`incidents:remediate`), never a role name. The role → permission mapping
//! lives here as versioned code (three fixed roles); per-user `granted` /
//! `denied` overrides ride on top. Moving the mapping into the DB later (custom
//! roles) is an internal change to `effective_permissions` — no call site moves.

use std::collections::HashSet;

/// Every permission the product recognises. The anti-orphan route test asserts
/// each `/api/tc/*` route maps to one of these (or to a machine-token route).
pub const ALL_PERMISSIONS: &[&str] = &[
    "incidents:read",
    "incidents:triage",
    "incidents:remediate",
    "assets:read",
    "assets:edit",
    "assets:delete",
    "assets:purge",
    "skills:read",
    "skills:configure",
    "rules:read",
    "rules:edit",
    "exclusions:read",
    "exclusions:edit",
    "hunt:run",
    "graph:read",
    "endpoint_agents:read",
    "endpoint_agents:manage",
    "exports:run",
    "users:manage",
    "audit:read",
    "settings:read",
    "settings:edit",
];

/// Read-only baseline shared by every role.
const VIEWER: &[&str] = &[
    "incidents:read",
    "assets:read",
    "skills:read",
    "rules:read",
    "exclusions:read",
    "graph:read",
    "hunt:run",
    "endpoint_agents:read",
    "settings:read",
];

/// What an analyst gets on top of the viewer baseline.
const ANALYST_EXTRA: &[&str] = &[
    "incidents:triage",
    "incidents:remediate",
    "assets:edit",
    "exclusions:edit",
    "exports:run",
];

/// Base permissions granted by a role name, before per-user overrides.
/// An unknown role yields nothing (fail closed).
pub fn role_permissions(role: &str) -> Vec<&'static str> {
    match role {
        "admin" => ALL_PERMISSIONS.to_vec(),
        "analyst" => VIEWER.iter().chain(ANALYST_EXTRA).copied().collect(),
        "viewer" => VIEWER.to_vec(),
        _ => Vec::new(),
    }
}

/// Effective permission set = role base, plus per-user `granted`, minus
/// per-user `denied`. `denied` wins over both role and `granted`.
pub fn effective_permissions(role: &str, granted: &[String], denied: &[String]) -> HashSet<String> {
    let mut set: HashSet<String> = role_permissions(role).iter().map(|s| s.to_string()).collect();
    for g in granted {
        set.insert(g.clone());
    }
    for d in denied {
        set.remove(d);
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_reads_only() {
        let p = effective_permissions("viewer", &[], &[]);
        assert!(p.contains("incidents:read"));
        assert!(!p.contains("incidents:remediate"));
        assert!(!p.contains("assets:purge"));
        assert!(!p.contains("users:manage"));
    }

    #[test]
    fn analyst_triages_and_remediates_by_default() {
        let p = effective_permissions("analyst", &[], &[]);
        assert!(p.contains("incidents:triage"));
        assert!(p.contains("incidents:remediate"));
        assert!(p.contains("assets:edit"));
        // but not admin-only powers
        assert!(!p.contains("assets:purge"));
        assert!(!p.contains("skills:configure"));
        assert!(!p.contains("users:manage"));
    }

    #[test]
    fn analyst_remediate_can_be_denied() {
        let p = effective_permissions("analyst", &[], &["incidents:remediate".into()]);
        assert!(p.contains("incidents:triage"));
        assert!(!p.contains("incidents:remediate"));
    }

    #[test]
    fn granted_override_adds_a_permission() {
        let p = effective_permissions("viewer", &["exports:run".into()], &[]);
        assert!(p.contains("exports:run"));
    }

    #[test]
    fn denied_wins_over_granted() {
        let p = effective_permissions(
            "viewer",
            &["assets:purge".into()],
            &["assets:purge".into()],
        );
        assert!(!p.contains("assets:purge"));
    }

    #[test]
    fn admin_has_everything() {
        let p = effective_permissions("admin", &[], &[]);
        for perm in ALL_PERMISSIONS {
            assert!(p.contains(*perm), "admin missing {perm}");
        }
    }

    #[test]
    fn unknown_role_has_nothing() {
        let p = effective_permissions("intruder", &[], &[]);
        assert!(p.is_empty());
    }
}

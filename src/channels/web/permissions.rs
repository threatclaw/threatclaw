//! Permission catalogue and role → permission mapping for the dashboard RBAC.
//!
//! The authorization layer always tests an atomic permission
//! (`incidents:remediate`), never a role name. The role → permission mapping
//! lives here as versioned code (three fixed roles); per-user `granted` /
//! `denied` overrides ride on top. Moving the mapping into the DB later (custom
//! roles) is an internal change to `effective_permissions` — no call site moves.

use axum::http::Method;
use std::collections::HashSet;

/// Authorization decision for an `/api/tc/*` route.
#[derive(Debug, Clone, PartialEq)]
pub enum RoutePolicy {
    /// Caller must hold this permission (resolved from their session).
    Require(&'static str),
    /// Machine ingress (agent/webhook) — authenticated by a per-source token
    /// inside the handler, not by a dashboard session.
    MachineToken,
    /// Not an `/api/tc` route (e.g. `/api/auth/*`); the middleware lets it pass
    /// and the handler enforces its own access control.
    Public,
}

/// First path segment after `/api/tc/` (the "domain").
fn domain_of(path: &str) -> &str {
    path.strip_prefix("/api/tc/")
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
}

/// Machine ingress paths — mirrors the proxy's `isAgentIngressPath`. These
/// carry their own `webhook_token`, validated by the core handler.
fn is_machine(path: &str) -> bool {
    path.starts_with("/api/tc/webhook/ingest/")
        || path == "/api/tc/agent/enroll"
        || path == "/api/tc/agent/manifest"
        || path == "/api/tc/agent/install.sh"
        || path == "/api/tc/agent/install.ps1"
        || path == "/api/tc/agent/uninstall.sh"
        || path == "/api/tc/agent/uninstall.ps1"
}

/// Read permission for a domain. Every value here is held by `viewer`, so any
/// authenticated user can read across the product (viewer = read-only).
fn read_perm(domain: &str) -> &'static str {
    match domain {
        "assets" | "targets" | "networks" | "network" | "company" => "assets:read",
        "skills" | "catalog" | "connectors" | "channel" | "channels" | "telegram" | "olvid"
        | "bot" | "notifications" => "skills:read",
        "rules"
        | "sigma"
        | "suppression-rules"
        | "suppression-rules-preview"
        | "threat-profiles" => "rules:read",
        "exclusions" => "exclusions:read",
        "graph" | "graphs" | "graph-executions" | "intelligence" => "graph:read",
        "endpoint-agents" | "agent" => "endpoint_agents:read",
        // sensitive/admin config domains: still viewer-readable (settings:read
        // is in the viewer baseline) — reading config is not dangerous.
        "settings" | "config" | "admin" | "licensing" | "license" | "governance" | "security"
        | "anonymizer" | "scheduler" | "pause" | "backups" | "backup" | "db" | "system-logs"
        | "sources" | "firewall" | "ssh" | "command" | "test" | "version" | "metrics" | "logs"
        | "health" | "openapi" => "settings:read",
        // incidents, alerts, findings, hitl, remediation, enrichment, scans,
        // hunt, exports, reports, conversations, chat, instruct, etc.
        _ => "incidents:read",
    }
}

/// Write permission for a domain. Unknown / sensitive-admin domains default to
/// `settings:edit` (admin-only) — an unclassified mutation is locked to admin,
/// never silently opened.
fn write_perm(domain: &str) -> &'static str {
    match domain {
        "assets" | "targets" | "networks" | "network" | "company" => "assets:edit",
        "exclusions" => "exclusions:edit",
        "skills" | "catalog" | "connectors" | "channel" | "channels" | "telegram" | "olvid"
        | "bot" | "notifications" => "skills:configure",
        "rules" | "sigma" | "suppression-rules" | "threat-profiles" => "rules:edit",
        "hunt" | "scans" => "hunt:run",
        "exports" | "reports" => "exports:run",
        "incidents" | "alerts" | "findings" | "hitl" | "enrichment" | "conversations"
        | "conversation" | "chat" | "instruct" | "soul" => "incidents:triage",
        "remediation" | "command" | "firewall" | "ssh" => "incidents:remediate",
        "endpoint-agents" | "agent" => "endpoint_agents:manage",
        "users" => "users:manage",
        // graph/intelligence mutations are rare and structural → admin.
        // Everything else (settings, config, admin, licensing, backups,
        // governance, scheduler, db, anonymizer, test, …) → admin-only.
        _ => "settings:edit",
    }
}

/// Map a request `(method, path)` to its authorization policy.
///
/// Families + deny-by-default: reads resolve to a viewer-held permission;
/// mutations resolve to a family permission, with named overrides for the
/// dangerous ones (purge / delete / remediate); unclassified mutating domains
/// fall back to admin-only. Anything not under `/api/tc/` is `Public` (the
/// handler enforces its own checks — e.g. `/api/auth/*`).
pub fn route_permission(method: &Method, path: &str) -> RoutePolicy {
    if !path.starts_with("/api/tc/") {
        return RoutePolicy::Public;
    }
    if is_machine(path) {
        return RoutePolicy::MachineToken;
    }

    let is_write = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if is_write {
        // Named sensitive mutations override the family rule.
        if path.ends_with("/purge") {
            return RoutePolicy::Require("assets:purge");
        }
        if path.ends_with("/remediate") {
            return RoutePolicy::Require("incidents:remediate");
        }
        if (domain_of(path) == "assets")
            && (*method == Method::DELETE || path.ends_with("/decommission"))
        {
            return RoutePolicy::Require("assets:delete");
        }
        return RoutePolicy::Require(write_perm(domain_of(path)));
    }
    RoutePolicy::Require(read_perm(domain_of(path)))
}

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
    let mut set: HashSet<String> = role_permissions(role)
        .iter()
        .map(|s| s.to_string())
        .collect();
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
        let p = effective_permissions("viewer", &["assets:purge".into()], &["assets:purge".into()]);
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

    // ── Route mapping (anti-orphan) ──

    #[test]
    fn machine_routes_bypass_session() {
        use axum::http::Method;
        assert_eq!(
            route_permission(&Method::POST, "/api/tc/webhook/ingest/osquery"),
            RoutePolicy::MachineToken
        );
        assert_eq!(
            route_permission(&Method::GET, "/api/tc/agent/install.sh"),
            RoutePolicy::MachineToken
        );
    }

    #[test]
    fn sensitive_mutations_are_gated() {
        use axum::http::Method;
        assert_eq!(
            route_permission(&Method::POST, "/api/tc/assets/{id}/purge"),
            RoutePolicy::Require("assets:purge")
        );
        assert_eq!(
            route_permission(&Method::POST, "/api/tc/incidents/{id}/remediate"),
            RoutePolicy::Require("incidents:remediate")
        );
        assert_eq!(
            route_permission(&Method::DELETE, "/api/tc/assets/{id}"),
            RoutePolicy::Require("assets:delete")
        );
        // an unclassified mutating domain falls back to admin-only
        assert_eq!(
            route_permission(&Method::POST, "/api/tc/licensing/activate"),
            RoutePolicy::Require("settings:edit")
        );
    }

    #[test]
    fn reads_are_viewer_accessible() {
        use axum::http::Method;
        let viewer = effective_permissions("viewer", &[], &[]);
        for path in crate::channels::web::tc_routes_snapshot::TC_ROUTES {
            if let RoutePolicy::Require(p) = route_permission(&Method::GET, path) {
                assert!(
                    viewer.contains(p),
                    "GET {path} requires {p} which viewer lacks"
                );
            }
        }
    }

    /// The anti-orphan guarantee: every real /api/tc route resolves to a known
    /// permission (or a machine route), never to an unknown permission or
    /// Public, under read and mutating methods. Fails if a route escapes the
    /// mapping or references a typo'd permission.
    #[test]
    fn every_tc_route_maps_to_a_valid_policy() {
        use axum::http::Method;
        let valid: HashSet<&str> = ALL_PERMISSIONS.iter().copied().collect();
        for path in crate::channels::web::tc_routes_snapshot::TC_ROUTES {
            for m in [Method::GET, Method::POST, Method::DELETE] {
                match route_permission(&m, path) {
                    RoutePolicy::Require(p) => {
                        assert!(valid.contains(p), "{m} {path} -> unknown perm {p}")
                    }
                    RoutePolicy::MachineToken => {}
                    RoutePolicy::Public => panic!("/api/tc route {path} resolved to Public"),
                }
            }
        }
    }
}

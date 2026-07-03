// See ADR-044: Remediation security guard — validates all remediation actions
// before execution. 5 layers of protection.

use std::collections::HashSet;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ── Layer 1: Boot-locked protected infrastructure ──
// Read once at boot, immutable for the lifetime of the process.
// Modifying the DB after boot has no effect.

static PROTECTED_IPS: OnceLock<HashSet<String>> = OnceLock::new();
/// Plages CIDR protégées (config RSSI + défauts) — ING-C2. IPv4 uniquement
/// (les block_ip firewall ciblent quasi toujours de l'IPv4).
static PROTECTED_CIDRS: OnceLock<Vec<(std::net::Ipv4Addr, u8)>> = OnceLock::new();
static SELF_IP: OnceLock<String> = OnceLock::new();
static SELF_HOSTNAME: OnceLock<String> = OnceLock::new();

/// IPs jamais bloquables/isolables par défaut : résolveurs DNS publics, metadata
/// cloud. Bloquer/isoler ceux-ci via une règle firewall WAN = auto-DoS de la
/// victime par sa propre défense (finding ING-C2 — un attaquant injecte une
/// fausse alerte avec `source_ip=1.1.1.1` pour faire blacklister le résolveur).
const DEFAULT_PROTECTED_IPS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1", // Cloudflare
    "8.8.8.8",
    "8.8.4.4", // Google
    "9.9.9.9",
    "149.112.112.112", // Quad9
    "208.67.222.222",
    "208.67.220.220",  // OpenDNS
    "169.254.169.254", // metadata cloud (IMDS)
];

/// IPs qui ne sont JAMAIS une cible de blocage/isolation valide (bloquer/isoler
/// n'a aucun sens et/ou est dangereux). N'inclut PAS le RFC1918 privé : isoler
/// un poste interne compromis est légitime — seul le RSSI protège ses plages via
/// `tc_protected_assets` (CIDR).
fn ip_is_never_blockable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
        }
    }
}

/// `ip` tombe-t-il dans le CIDR `net/prefix` (IPv4) ?
fn ipv4_in_cidr(net: std::net::Ipv4Addr, prefix: u8, ip: std::net::Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask: u32 = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Call once at boot to lock the protected infrastructure list.
pub async fn init_protected_infrastructure(store: &dyn crate::db::Database) {
    // Self-detection
    let self_ip = detect_self_ip();
    let self_hostname = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "threatclaw".into());

    SELF_IP.set(self_ip.clone()).ok();
    SELF_HOSTNAME.set(self_hostname.clone()).ok();

    // Build protected set
    let mut protected = HashSet::new();
    protected.insert("127.0.0.1".into());
    protected.insert("::1".into());
    protected.insert("localhost".into());
    protected.insert(self_ip.clone());
    protected.insert(self_hostname.clone());
    // ING-C2 : résolveurs/CDN/metadata jamais bloquables (anti auto-DoS).
    for ip in DEFAULT_PROTECTED_IPS {
        protected.insert((*ip).to_string());
    }
    let mut cidrs: Vec<(std::net::Ipv4Addr, u8)> = Vec::new();

    // Read RSSI-configured protected assets from DB (locked at boot). Une entrée
    // `a.b.c.d/N` est traitée comme une plage CIDR protégée (ING-C2).
    if let Ok(Some(val)) = store.get_setting("_system", "tc_protected_assets").await {
        if let Some(arr) = val.as_array() {
            for v in arr {
                if let Some(s) = v.as_str() {
                    if let Some((net, pfx)) = s.split_once('/') {
                        if let (Ok(net), Ok(pfx)) =
                            (net.parse::<std::net::Ipv4Addr>(), pfx.parse::<u8>())
                        {
                            if pfx <= 32 {
                                cidrs.push((net, pfx));
                                continue;
                            }
                        }
                    }
                    protected.insert(s.to_string());
                }
            }
        }
    }

    // Auto-detect gateway
    if let Some(gw) = detect_gateway() {
        protected.insert(gw);
    }

    let count = protected.len();
    let cidr_count = cidrs.len();
    PROTECTED_IPS.set(protected).ok();
    PROTECTED_CIDRS.set(cidrs).ok();

    // Boot-lock rate limits from DB (RSSI-configured via dashboard)
    if let Ok(Some(val)) = store.get_setting("_system", "tc_hitl_limits").await {
        let iso = val["max_isolations_per_hour"].as_u64().unwrap_or(3) as u32;
        let appr = val["max_approvals_per_hour"].as_u64().unwrap_or(10) as u32;
        MAX_ISOLATIONS.set(iso.max(1).min(10)).ok(); // clamp 1-10
        MAX_APPROVALS.set(appr.max(1).min(50)).ok(); // clamp 1-50
        tracing::info!(
            "REMEDIATION_GUARD: Limits boot-locked — isolations={}/h, approvals={}/h",
            iso,
            appr
        );
    }

    tracing::info!(
        "REMEDIATION_GUARD: {} protected IPs/hosts + {} CIDR ranges locked at boot (self={})",
        count,
        cidr_count,
        self_ip
    );
}

/// Check if a target is protected (cannot be isolated/blocked).
pub fn is_protected_target(target: &str) -> bool {
    let Some(protected) = PROTECTED_IPS.get() else {
        // If not initialized, block everything (fail-safe).
        return true;
    };
    if protected.contains(target) {
        return true;
    }
    // Case-insensitive hostname match.
    let target_lower = target.to_lowercase();
    if protected.iter().any(|p| p.to_lowercase() == target_lower) {
        return true;
    }
    // ING-C2 : checks IP — jamais bloquables (loopback / link-local / metadata /
    // broadcast) + plages CIDR protégées configurées par le RSSI.
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        if ip_is_never_blockable(ip) {
            return true;
        }
        if let (std::net::IpAddr::V4(v4), Some(cidrs)) = (ip, PROTECTED_CIDRS.get()) {
            if cidrs.iter().any(|(net, pfx)| ipv4_in_cidr(*net, *pfx, v4)) {
                return true;
            }
        }
    }
    false
}

// ── Layer 3: Rate limits (boot-locked from DB, fallback to hardcoded) ──

static ISOLATION_COUNT_1H: AtomicU32 = AtomicU32::new(0);
static ISOLATION_LAST_RESET: AtomicU64 = AtomicU64::new(0);
static HITL_APPROVALS_1H: AtomicU32 = AtomicU32::new(0);
static HITL_LAST_RESET: AtomicU64 = AtomicU64::new(0);

static MAX_ISOLATIONS: OnceLock<u32> = OnceLock::new();
static MAX_APPROVALS: OnceLock<u32> = OnceLock::new();

fn max_isolations_per_hour() -> u32 {
    *MAX_ISOLATIONS.get().unwrap_or(&3)
}
fn max_approvals_per_hour() -> u32 {
    *MAX_APPROVALS.get().unwrap_or(&10)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn check_rate_limit(counter: &AtomicU32, reset_ts: &AtomicU64, max: u32, name: &str) -> bool {
    let now = now_secs();
    let last = reset_ts.load(Ordering::Relaxed);
    if now - last > 3600 {
        counter.store(0, Ordering::Relaxed);
        reset_ts.store(now, Ordering::Relaxed);
    }
    let current = counter.fetch_add(1, Ordering::Relaxed);
    if current >= max {
        tracing::error!(
            "SECURITY: Rate limit exceeded — {} ({}/{})",
            name,
            current,
            max
        );
        counter.fetch_sub(1, Ordering::Relaxed);
        false
    } else {
        true
    }
}

/// Check if an isolation action is allowed (rate limit).
pub fn can_isolate() -> bool {
    check_rate_limit(
        &ISOLATION_COUNT_1H,
        &ISOLATION_LAST_RESET,
        max_isolations_per_hour(),
        "isolation",
    )
}

/// Check if a HITL approval is allowed (rate limit against alert fatigue).
pub fn can_approve_hitl() -> bool {
    check_rate_limit(
        &HITL_APPROVALS_1H,
        &HITL_LAST_RESET,
        max_approvals_per_hour(),
        "HITL approval",
    )
}

// ── Layer 3: LDAP escaping (RFC 4515) ──

/// Escape special characters in LDAP filter values per RFC 4515.
pub fn ldap_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '\\' => escaped.push_str("\\5c"),
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Validate a remediation action before execution.
pub fn validate_remediation(action: &str, target: &str) -> Result<(), String> {
    // Check protected targets
    if is_protected_target(target) {
        return Err(format!(
            "SECURITY: Target '{}' is in the protected infrastructure list",
            target
        ));
    }

    // Check rate limits for isolation actions
    if action == "isolate_host" || action == "block_ip_internal" {
        if !can_isolate() {
            return Err("SECURITY: Isolation rate limit exceeded (max 3/hour)".into());
        }
    }

    Ok(())
}

// ── Helpers ──

fn detect_self_ip() -> String {
    // Try to get the primary interface IP
    if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
        if let Ok(ips) = String::from_utf8(output.stdout) {
            if let Some(ip) = ips.split_whitespace().next() {
                return ip.to_string();
            }
        }
    }
    "127.0.0.1".into()
}

fn detect_gateway() -> Option<String> {
    if let Ok(output) = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if let Ok(route) = String::from_utf8(output.stdout) {
            // "default via 192.168.1.1 dev eth0"
            let parts: Vec<&str> = route.split_whitespace().collect();
            if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_escape() {
        assert_eq!(ldap_escape("user"), "user");
        assert_eq!(ldap_escape("user*"), "user\\2a");
        assert_eq!(ldap_escape("user)(cn=*)"), "user\\29\\28cn=\\2a\\29");
        assert_eq!(ldap_escape("admin\\test"), "admin\\5ctest");
    }

    #[test]
    fn test_ip_never_blockable() {
        use std::net::IpAddr;
        // ING-C2 : loopback / link-local / metadata / broadcast jamais bloquables.
        assert!(ip_is_never_blockable("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ip_is_never_blockable("169.254.169.254".parse::<IpAddr>().unwrap()));
        assert!(ip_is_never_blockable("169.254.1.1".parse::<IpAddr>().unwrap()));
        assert!(ip_is_never_blockable("255.255.255.255".parse::<IpAddr>().unwrap()));
        assert!(ip_is_never_blockable("::1".parse::<IpAddr>().unwrap()));
        // Un poste interne RFC1918 RESTE bloquable/isolable (isolation légitime).
        assert!(!ip_is_never_blockable("10.0.0.5".parse::<IpAddr>().unwrap()));
        // Une IP publique normale reste bloquable (vraie remédiation).
        assert!(!ip_is_never_blockable("203.0.113.7".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_ipv4_in_cidr() {
        use std::net::Ipv4Addr;
        let net: Ipv4Addr = "10.0.0.0".parse().unwrap();
        assert!(ipv4_in_cidr(net, 8, "10.5.6.7".parse().unwrap()));
        assert!(!ipv4_in_cidr(net, 8, "11.0.0.1".parse().unwrap()));
        let net2: Ipv4Addr = "192.168.1.0".parse().unwrap();
        assert!(ipv4_in_cidr(net2, 24, "192.168.1.42".parse().unwrap()));
        assert!(!ipv4_in_cidr(net2, 24, "192.168.2.1".parse().unwrap()));
        assert!(ipv4_in_cidr("0.0.0.0".parse().unwrap(), 0, "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_rate_limit() {
        // Reset state
        ISOLATION_COUNT_1H.store(0, Ordering::Relaxed);
        ISOLATION_LAST_RESET.store(now_secs(), Ordering::Relaxed);

        assert!(can_isolate()); // 1
        assert!(can_isolate()); // 2
        assert!(can_isolate()); // 3
        assert!(!can_isolate()); // 4 = blocked
    }
}

//! Stormshield SNS IDS/IPS alert normalizer (Phase 8b).
//!
//! SNS ships its logs over syslog (RFC3164/"Legacy") as space-separated
//! `key=value` pairs, e.g.
//! `id=firewall time="..." fw="..." ... logtype="alarm" class="..." src=... dst=... msg="..."`.
//! fluent-bit strips the syslog header; the sigma matcher hands us the message
//! body under `matched_fields[*] == ("line", "<raw sns line>")`.
//!
//! The `key=value` parser ([`parse_sns_fields`]) is validated against real
//! SNS 5.0.6 output. The alarm-specific field MAPPING (which field carries the
//! severity/category) follows Stormshield's documented log format — it should
//! be confirmed against a captured `logtype="alarm"` line, so the normalizer is
//! deliberately conservative (defaults to Medium, returns `None` for non-alarm
//! log types so non-IDS lines are never mis-filtered).

use super::{Direction, IdsAlertNormalizer, NormalizedAlert, RawFields, SeverityLevel};

/// Parse a Stormshield SNS log line into `(key, value)` pairs. Values are
/// either unquoted (up to the next space) or double-quoted (may contain
/// spaces). A leading syslog priority marker like `<13>` is tolerated.
pub fn parse_sns_fields(line: &str) -> Vec<(String, String)> {
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        while i < n && bytes[i] == b' ' {
            i += 1;
        }
        if i >= n {
            break;
        }
        let key_start = i;
        while i < n && bytes[i] != b'=' && bytes[i] != b' ' {
            i += 1;
        }
        if i >= n || bytes[i] != b'=' {
            // token with no '=' (e.g. a stray `<13>id` head) — skip it.
            while i < n && bytes[i] != b' ' {
                i += 1;
            }
            continue;
        }
        let key = line[key_start..i].to_string();
        i += 1; // skip '='
        let value = if i < n && bytes[i] == b'"' {
            i += 1;
            let vs = i;
            while i < n && bytes[i] != b'"' {
                i += 1;
            }
            let v = line[vs..i].to_string();
            if i < n {
                i += 1; // closing quote
            }
            v
        } else {
            let vs = i;
            while i < n && bytes[i] != b' ' {
                i += 1;
            }
            line[vs..i].to_string()
        };
        out.push((key, value));
    }
    out
}

#[derive(Default)]
pub struct StormshieldNormalizer;

impl IdsAlertNormalizer for StormshieldNormalizer {
    fn vendor_id(&self) -> &'static str {
        "stormshield"
    }

    fn matches_rule(&self, rule_id: &str) -> bool {
        matches!(rule_id, "stormshield-001" | "stormshield-ids-001")
    }

    fn normalize(&self, raw: RawFields<'_>) -> Option<NormalizedAlert> {
        // SNS logs ship over syslog: fluent-bit's RFC3164 parser drops the
        // `id=firewall time=…` prefix and leaves the key=value tail under
        // `message` (the legacy webhook path used `line`). Accept either.
        let line = raw
            .iter()
            .find(|(k, _)| k == "message" || k == "line")
            .map(|(_, v)| v.as_str())?;
        let fields = parse_sns_fields(line);
        let get = |k: &str| {
            fields
                .iter()
                .find(|(kk, _)| kk == k)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
        };

        // Only IPS/IDS alarms are IDS alerts; filter/connection/server/auth log
        // types are not — return None so they flow through unfiltered.
        if get("logtype").as_deref() != Some("alarm") {
            return None;
        }

        // SNS alarm priority: 0/1 ~ major, 2 ~ medium, 3 ~ minor. Documented
        // mapping (confirm against a real alarm); default Medium so we never
        // under-rate an alert we couldn't classify.
        let severity = match get("pri").as_deref() {
            Some("0") | Some("1") => SeverityLevel::High,
            Some("2") => SeverityLevel::Medium,
            Some("3") => SeverityLevel::Low,
            Some("4") => SeverityLevel::Info,
            _ => SeverityLevel::Medium,
        };

        let category = get("class").or_else(|| get("classification")).unwrap_or_default();
        let signature = get("msg").unwrap_or_default();
        let source_ip = get("src");
        let dest_ip = get("dst");
        let direction = classify_direction(source_ip.as_deref(), dest_ip.as_deref());

        Some(NormalizedAlert {
            vendor: "stormshield".into(),
            severity,
            category,
            signature,
            flowbits: Vec::new(),
            direction,
            source_ip,
            dest_ip,
        })
    }
}

fn is_private_v4(ip: &str) -> bool {
    let p: std::net::Ipv4Addr = match ip.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let o = p.octets();
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || o[0] == 127
}

fn classify_direction(src: Option<&str>, dst: Option<&str>) -> Direction {
    match (src.map(is_private_v4), dst.map(is_private_v4)) {
        (Some(true), Some(false)) => Direction::Outbound,
        (Some(false), Some(true)) => Direction::Inbound,
        (Some(true), Some(true)) => Direction::Internal,
        (Some(false), Some(false)) => Direction::External,
        _ => Direction::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_sns_server_line() {
        // Captured live from SNS 5.0.6 (syslog, Legacy/RFC3164).
        let line = r#"id=firewall time="2026-06-21 17:12:04" fw="VMSNSX00Z0000A0" tz=+0000 user="admin" address=10.77.0.254 sessionid=29 msg="CONFIG COMMUNICATION" logtype="server""#;
        let f = parse_sns_fields(line);
        let get = |k: &str| f.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("id"), Some("firewall"));
        assert_eq!(get("time"), Some("2026-06-21 17:12:04")); // quoted, has a space
        assert_eq!(get("fw"), Some("VMSNSX00Z0000A0"));
        assert_eq!(get("logtype"), Some("server"));
        assert_eq!(get("sessionid"), Some("29"));
    }

    #[test]
    fn leading_priority_marker_tolerated() {
        let f = parse_sns_fields(r#"<13>id=firewall logtype="alarm" src=1.2.3.4"#);
        let get = |k: &str| f.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(get("logtype"), Some("alarm"));
        assert_eq!(get("src"), Some("1.2.3.4"));
    }

    #[test]
    fn non_alarm_logtype_returns_none() {
        let raw = vec![(
            "line".to_string(),
            r#"id=firewall logtype="filter" src=10.0.0.1 dst=8.8.8.8 action=block"#.to_string(),
        )];
        assert!(StormshieldNormalizer::default().normalize(&raw).is_none());
    }

    #[test]
    fn alarm_inbound_normalizes() {
        let raw = vec![(
            "line".to_string(),
            r#"id=firewall logtype="alarm" pri=1 class="application:web" msg="HTTP forbidden method" src=203.0.113.9 dst=10.77.0.50 action=block"#.to_string(),
        )];
        let n = StormshieldNormalizer::default().normalize(&raw).unwrap();
        assert_eq!(n.vendor, "stormshield");
        assert_eq!(n.severity, SeverityLevel::High);
        assert_eq!(n.category, "application:web");
        assert_eq!(n.signature, "HTTP forbidden method");
        assert_eq!(n.direction, Direction::Inbound);
    }

    #[test]
    fn rule_id_binding() {
        let n = StormshieldNormalizer::default();
        assert!(n.matches_rule("stormshield-001"));
        assert!(!n.matches_rule("opnsense-004"));
    }
}

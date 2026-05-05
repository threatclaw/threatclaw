//! Suricata `eve.json` IDS alert normalizer (Phase 8b).
//!
//! Suricata writes one JSON line per event, syslog-shipped via OPNsense
//! to fluent-bit. The sigma matcher receives the whole line under
//! `matched_fields[*] == ("line", "<raw eve.json>")`. This adapter
//! parses that payload and exposes its native severity (1=High … 3=Info),
//! category, signature, flowbits, and IPs in the canonical
//! [`NormalizedAlert`] shape.
//!
//! Rule_id binding: every sigma rule named `opnsense-004` (the generic
//! "OPNsense IDS alert" rule) is currently a Suricata alert under the
//! hood. If we later add a separate `pfsense-suricata-001` rule for a
//! pfSense+Suricata customer, this normalizer also claims it.

use serde_json::Value;

use super::{Direction, IdsAlertNormalizer, NormalizedAlert, RawFields, SeverityLevel};

#[derive(Default)]
pub struct SuricataNormalizer;

impl IdsAlertNormalizer for SuricataNormalizer {
    fn vendor_id(&self) -> &'static str {
        "suricata"
    }

    fn matches_rule(&self, rule_id: &str) -> bool {
        // OPNsense + pfSense both ship their IDS alerts via Suricata in
        // the default ThreatClaw deployments. Add new rule_ids here as
        // we onboard new customers.
        matches!(rule_id, "opnsense-004" | "pfsense-suricata-001")
    }

    fn normalize(&self, raw: RawFields<'_>) -> Option<NormalizedAlert> {
        let line = raw
            .iter()
            .find(|(k, _)| k == "line")
            .map(|(_, v)| v.as_str())?;
        let payload: Value = serde_json::from_str(line.trim()).ok()?;

        let alert = &payload["alert"];

        // Suricata severity scale: 1 (High), 2 (Medium), 3 (Informational).
        // Some signatures have severity=4 (Low) — rare but exists.
        let severity = match alert["severity"].as_i64().unwrap_or(0) {
            1 => SeverityLevel::High,
            2 => SeverityLevel::Medium,
            3 => SeverityLevel::Info,
            4 => SeverityLevel::Low,
            _ => SeverityLevel::Medium,
        };

        let category = alert["category"].as_str().unwrap_or("").to_string();
        let signature = alert["signature"].as_str().unwrap_or("").to_string();

        let flowbits: Vec<String> = payload["metadata"]["flowbits"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let source_ip = payload["src_ip"].as_str().map(|s| s.to_string());
        let dest_ip = payload["dest_ip"].as_str().map(|s| s.to_string());

        let direction = classify_direction(source_ip.as_deref(), dest_ip.as_deref());

        Some(NormalizedAlert {
            vendor: "suricata".into(),
            severity,
            category,
            signature,
            flowbits,
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

    fn line_field(line: &str) -> Vec<(String, String)> {
        vec![("line".into(), line.into())]
    }

    #[test]
    fn rule_id_recognized() {
        let n = SuricataNormalizer::default();
        assert!(n.matches_rule("opnsense-004"));
        assert!(n.matches_rule("pfsense-suricata-001"));
        assert!(!n.matches_rule("tc-ssh-brute"));
        assert!(!n.matches_rule("fortinet-ips-001"));
    }

    #[test]
    fn windows_update_outbound_normalizes_to_info() {
        let line = r#"{
          "src_ip":"10.77.0.174","dest_ip":"14.102.231.203",
          "alert":{"signature":"ET INFO Packed Executable Download",
                   "category":"Misc activity","severity":3},
          "metadata":{"flowbits":["exe.no.referer","http.dottedquadhost","ET.INFO.WindowsUpdate"]}
        }"#;
        let n = SuricataNormalizer::default()
            .normalize(&line_field(line))
            .unwrap();
        assert_eq!(n.severity, SeverityLevel::Info);
        assert_eq!(n.category, "Misc activity");
        assert_eq!(n.direction, Direction::Outbound);
        assert!(
            n.flowbits
                .iter()
                .any(|f| f.contains("ET.INFO.WindowsUpdate"))
        );
    }

    #[test]
    fn ssh_invalid_banner_inbound_normalizes_to_info() {
        let line = r#"{
          "src_ip":"62.210.201.235","dest_ip":"10.77.0.136",
          "alert":{"signature":"SURICATA SSH invalid banner",
                   "category":"Generic Protocol Command Decode","severity":3}
        }"#;
        let n = SuricataNormalizer::default()
            .normalize(&line_field(line))
            .unwrap();
        assert_eq!(n.severity, SeverityLevel::Info);
        assert_eq!(n.direction, Direction::Inbound);
    }

    #[test]
    fn high_severity_trojan_normalizes_correctly() {
        let line = r#"{"alert":{"signature":"ET TROJAN Win32/Emotet CnC",
                               "category":"A Network Trojan was Detected",
                               "severity":1}}"#;
        let n = SuricataNormalizer::default()
            .normalize(&line_field(line))
            .unwrap();
        assert_eq!(n.severity, SeverityLevel::High);
        assert_eq!(n.direction, Direction::Unknown); // no IPs in payload
    }

    #[test]
    fn unparseable_line_returns_none() {
        let n = SuricataNormalizer::default().normalize(&line_field("not json"));
        assert!(n.is_none());
    }

    #[test]
    fn missing_line_field_returns_none() {
        let n = SuricataNormalizer::default().normalize(&[]);
        assert!(n.is_none());
    }
}

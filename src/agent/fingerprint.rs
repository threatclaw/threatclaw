//! Fingerprint — basic asset classification from ports, MAC, and hostname patterns.
//!
//! Tier 1 fingerprinting: uses only data we already have (no external tools).
//! Returns a probable category + subcategory + confidence.

/// Classification result from fingerprinting.
#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub category: String,
    pub subcategory: Option<String>,
    pub confidence: f32, // 0.0-1.0
    pub reason: String,
}

/// Classify a device from its open ports.
pub fn classify_from_ports(ports: &[u16]) -> Option<FingerprintResult> {
    if ports.is_empty() { return None; }

    let has = |p: u16| ports.contains(&p);

    // Active Directory / Domain Controller
    if has(389) && has(636) && has(88) && has(445) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("ad".into()),
            confidence: 0.90, reason: "LDAP(389) + LDAPS(636) + Kerberos(88) + SMB(445)".into(),
        });
    }

    // DNS server
    if has(53) && (has(953) || has(8053)) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("dns".into()),
            confidence: 0.85, reason: "DNS(53) + RNDC(953) or management port".into(),
        });
    }

    // Mail server
    if has(25) || (has(587) && has(993)) || (has(110) && has(143)) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("mail".into()),
            confidence: 0.85, reason: "SMTP/IMAP/POP3 ports".into(),
        });
    }

    // Web server + database = web stack
    if (has(80) || has(443)) && (has(3306) || has(5432) || has(27017)) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("web".into()),
            confidence: 0.80, reason: "HTTP(S) + database port".into(),
        });
    }

    // IP camera / RTSP (before generic web check — cameras often have port 80 too)
    if has(554) || has(8554) {
        return Some(FingerprintResult {
            category: "iot".into(), subcategory: Some("camera".into()),
            confidence: 0.85, reason: "RTSP(554) streaming port".into(),
        });
    }

    // Printer (before generic web check — printers often have port 80 too)
    if has(9100) || has(515) || (has(631) && !has(443)) {
        return Some(FingerprintResult {
            category: "printer".into(), subcategory: Some("imprimante".into()),
            confidence: 0.85, reason: "Printer port (JetDirect/LPD/IPP)".into(),
        });
    }

    // Industrial / OT (before generic web check)
    if has(502) || has(102) || has(44818) || has(20000) {
        return Some(FingerprintResult {
            category: "ot".into(), subcategory: Some("plc".into()),
            confidence: 0.80, reason: "Industrial protocol (Modbus/S7/EtherNet-IP)".into(),
        });
    }

    // Pure web server
    if has(80) || has(443) || has(8080) || has(8443) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("web".into()),
            confidence: 0.60, reason: "HTTP/HTTPS port".into(),
        });
    }

    // Database server
    if has(3306) || has(5432) || has(1433) || has(1521) || has(27017) || has(6379) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("db".into()),
            confidence: 0.80, reason: "Database port (MySQL/PG/MSSQL/Oracle/Mongo/Redis)".into(),
        });
    }

    // File server (SMB/NFS)
    if has(445) && has(139) && !has(88) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("file".into()),
            confidence: 0.70, reason: "SMB(445) + NetBIOS(139) without Kerberos".into(),
        });
    }

    // Windows desktop (RDP + SMB but not server-like ports)
    if has(3389) && has(445) && !has(80) && !has(443) {
        return Some(FingerprintResult {
            category: "workstation".into(), subcategory: Some("desktop".into()),
            confidence: 0.65, reason: "RDP(3389) + SMB(445) without web ports".into(),
        });
    }

    // SSH only = likely Linux server or workstation
    if has(22) && ports.len() <= 3 {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: None,
            confidence: 0.50, reason: "SSH(22) only".into(),
        });
    }

    // VoIP
    if has(5060) || has(5061) {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: Some("voip".into()),
            confidence: 0.80, reason: "SIP(5060/5061)".into(),
        });
    }

    // Network device (SNMP + web management)
    if has(161) && (has(80) || has(443)) {
        return Some(FingerprintResult {
            category: "network".into(), subcategory: None,
            confidence: 0.60, reason: "SNMP(161) + web management".into(),
        });
    }

    None
}

/// Classify from DHCP hostname pattern.
pub fn classify_from_hostname(hostname: &str) -> Option<FingerprintResult> {
    let h = hostname.to_lowercase();

    // iPhone / iPad
    if h.contains("iphone") || h.contains("ipad") {
        return Some(FingerprintResult {
            category: "mobile".into(), subcategory: Some("smartphone".into()),
            confidence: 0.95, reason: format!("Hostname contains Apple device name: {}", hostname),
        });
    }

    // Android
    if h.contains("android") || h.contains("galaxy") || h.contains("pixel") {
        return Some(FingerprintResult {
            category: "mobile".into(), subcategory: Some("smartphone".into()),
            confidence: 0.90, reason: format!("Hostname suggests Android device: {}", hostname),
        });
    }

    // Windows workstation patterns
    if h.starts_with("desktop-") || h.starts_with("laptop-") || h.starts_with("pc-") || h.starts_with("win-") {
        return Some(FingerprintResult {
            category: "workstation".into(), subcategory: Some("desktop".into()),
            confidence: 0.70, reason: format!("Windows workstation hostname pattern: {}", hostname),
        });
    }

    // Server patterns
    if h.starts_with("srv-") || h.starts_with("server-") || h.starts_with("dc-") || h.starts_with("ns-") {
        return Some(FingerprintResult {
            category: "server".into(), subcategory: None,
            confidence: 0.65, reason: format!("Server hostname pattern: {}", hostname),
        });
    }

    // Printer
    if h.contains("printer") || h.contains("mfp") || h.contains("hp-") || h.contains("epson") || h.contains("canon") {
        return Some(FingerprintResult {
            category: "printer".into(), subcategory: Some("imprimante".into()),
            confidence: 0.80, reason: format!("Printer hostname pattern: {}", hostname),
        });
    }

    None
}

/// Classify from MAC vendor (OUI).
pub fn classify_from_mac_vendor(vendor: &str) -> Option<FingerprintResult> {
    let v = vendor.to_lowercase();

    if v.contains("apple") {
        return Some(FingerprintResult {
            category: "workstation".into(), subcategory: Some("laptop".into()),
            confidence: 0.50, reason: "Apple device (Mac/iPhone/iPad)".into(),
        });
    }

    if v.contains("hikvision") || v.contains("dahua") || v.contains("axis") {
        return Some(FingerprintResult {
            category: "iot".into(), subcategory: Some("camera".into()),
            confidence: 0.90, reason: format!("IP camera manufacturer: {}", vendor),
        });
    }

    if v.contains("cisco") || v.contains("juniper") || v.contains("aruba") || v.contains("ubiquiti") {
        return Some(FingerprintResult {
            category: "network".into(), subcategory: None,
            confidence: 0.70, reason: format!("Network equipment manufacturer: {}", vendor),
        });
    }

    if v.contains("siemens") || v.contains("schneider") || v.contains("allen-bradley") || v.contains("rockwell") {
        return Some(FingerprintResult {
            category: "ot".into(), subcategory: Some("plc".into()),
            confidence: 0.85, reason: format!("Industrial manufacturer: {}", vendor),
        });
    }

    if v.contains("hp ") || v.contains("hewlett") || v.contains("brother") || v.contains("xerox") || v.contains("ricoh") {
        // Could be printer or workstation — low confidence
        return Some(FingerprintResult {
            category: "printer".into(), subcategory: None,
            confidence: 0.40, reason: format!("Possible printer manufacturer: {}", vendor),
        });
    }

    None
}

/// Combine all fingerprint sources and return the best classification.
pub fn classify_best(
    ports: &[u16],
    hostname: Option<&str>,
    mac_vendor: Option<&str>,
) -> Option<FingerprintResult> {
    let mut candidates: Vec<FingerprintResult> = vec![];

    if let Some(r) = classify_from_ports(ports) { candidates.push(r); }
    if let Some(h) = hostname { if let Some(r) = classify_from_hostname(h) { candidates.push(r); } }
    if let Some(v) = mac_vendor { if let Some(r) = classify_from_mac_vendor(v) { candidates.push(r); } }

    // Return the one with highest confidence
    candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    candidates.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ad_controller() {
        let r = classify_from_ports(&[389, 636, 88, 445, 53]).unwrap();
        assert_eq!(r.category, "server");
        assert_eq!(r.subcategory, Some("ad".into()));
        assert!(r.confidence >= 0.90);
    }

    #[test]
    fn test_web_server() {
        let r = classify_from_ports(&[80, 443, 22]).unwrap();
        assert_eq!(r.category, "server");
        assert_eq!(r.subcategory, Some("web".into()));
    }

    #[test]
    fn test_database() {
        let r = classify_from_ports(&[5432, 22]).unwrap();
        assert_eq!(r.category, "server");
        assert_eq!(r.subcategory, Some("db".into()));
    }

    #[test]
    fn test_printer_port() {
        let r = classify_from_ports(&[9100, 80]).unwrap();
        assert_eq!(r.category, "printer");
    }

    #[test]
    fn test_camera() {
        let r = classify_from_ports(&[554, 80]).unwrap();
        assert_eq!(r.category, "iot");
        assert_eq!(r.subcategory, Some("camera".into()));
    }

    #[test]
    fn test_iphone_hostname() {
        let r = classify_from_hostname("iPhone-de-Marie").unwrap();
        assert_eq!(r.category, "mobile");
        assert!(r.confidence >= 0.90);
    }

    #[test]
    fn test_windows_hostname() {
        let r = classify_from_hostname("DESKTOP-ABC123").unwrap();
        assert_eq!(r.category, "workstation");
    }

    #[test]
    fn test_hikvision_mac() {
        let r = classify_from_mac_vendor("Hikvision Digital Technology").unwrap();
        assert_eq!(r.category, "iot");
        assert_eq!(r.subcategory, Some("camera".into()));
    }

    #[test]
    fn test_best_combines() {
        let r = classify_best(&[80, 443, 3306], Some("srv-web-01"), None).unwrap();
        // Port-based (0.80) should win over hostname (0.65)
        assert_eq!(r.category, "server");
        assert_eq!(r.subcategory, Some("web".into()));
    }
}

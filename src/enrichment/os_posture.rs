//! OS posture — flags end-of-life / soon-EOL operating systems using endoflife.date.
//! Best-effort: any failure logs and yields nothing; never panics, never blocks.

/// First run of digits in `s` (e.g. "debian 12" → "12", "rhel 9.2" → "9").
fn first_int(s: &str) -> Option<String> {
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            break;
        }
    }
    (!cur.is_empty()).then_some(cur)
}

/// First `NN.NN`-style token (e.g. "ubuntu 22.04.3" → "22.04", "alpine v3.18" → "3.18").
fn first_dotted2(s: &str) -> Option<String> {
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() || (ch == '.' && !cur.is_empty()) {
            cur.push(ch);
        } else if !cur.is_empty() {
            break;
        }
    }
    let parts: Vec<&str> = cur.split('.').filter(|p| !p.is_empty()).collect();
    (parts.len() >= 2).then(|| format!("{}.{}", parts[0], parts[1]))
}

/// Map an osquery-derived `asset.os` to an endoflife.date `(product, cycle)`.
/// `None` when not confidently mappable, so no EOL finding is produced.
pub fn parse_os(os: &str) -> Option<(&'static str, String)> {
    let s = os.to_lowercase();
    if s.contains("windows server") {
        if s.contains("2012 r2") {
            return Some(("windows-server", "2012-r2".into()));
        }
        for year in ["2025", "2022", "2019", "2016", "2012"] {
            if s.contains(year) {
                return Some(("windows-server", year.to_string()));
            }
        }
        return None;
    }
    if s.contains("windows") {
        return None; // client Windows EOL deferred to a later pass
    }
    if s.contains("debian") {
        return first_int(&s).map(|v| ("debian", v));
    }
    if s.contains("ubuntu") {
        return first_dotted2(&s).map(|v| ("ubuntu", v));
    }
    if s.contains("alpine") {
        return first_dotted2(&s).map(|v| ("alpine", v));
    }
    if s.contains("red hat") || s.contains("rhel") {
        return first_int(&s).map(|v| ("rhel", v));
    }
    if s.contains("almalinux") || s.contains("alma") {
        return first_int(&s).map(|v| ("almalinux", v));
    }
    if s.contains("rocky") {
        return first_int(&s).map(|v| ("rocky", v));
    }
    if s.contains("centos") {
        return first_int(&s).map(|v| ("centos", v));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_server_and_linux() {
        assert_eq!(
            parse_os("Microsoft Windows Server 2019 10.0.17763"),
            Some(("windows-server", "2019".into()))
        );
        assert_eq!(
            parse_os("Microsoft Windows Server 2012 R2"),
            Some(("windows-server", "2012-r2".into()))
        );
        assert_eq!(
            parse_os("Debian GNU/Linux 12 (bookworm)"),
            Some(("debian", "12".into()))
        );
        assert_eq!(
            parse_os("Ubuntu 22.04.3 LTS"),
            Some(("ubuntu", "22.04".into()))
        );
        assert_eq!(
            parse_os("Red Hat Enterprise Linux 9.2"),
            Some(("rhel", "9".into()))
        );
        assert_eq!(
            parse_os("Alpine Linux v3.18"),
            Some(("alpine", "3.18".into()))
        );
    }

    #[test]
    fn unknown_os_is_none() {
        assert_eq!(parse_os("Microsoft Windows 11 Pro"), None); // client OS deferred
        assert_eq!(parse_os("Stormshield NS-BSD"), None);
        assert_eq!(parse_os(""), None);
    }
}

//! Web server access-log ingestion (nginx / Apache / any Combined-format log).
//!
//! Prerequisite for the `webserver` Sigma logsource. The rules there match
//! `cs-method`, `cs-uri-query`, `sc-status`, `cs-user-agent` — the W3C-style
//! field names — plus keyword searches over the request. Nothing in the product
//! produced those fields, so every webserver rule had no data to evaluate: they
//! looked healthy to the field oracle only because the telemetry fixture
//! declared the tag. This connector makes the tag real.
//!
//! Handles the two formats that cover nginx and Apache defaults:
//!
//! ```text
//! Common:   1.2.3.4 - frank [10/Oct/2026:13:55:36 +0000] "GET /a?b=1 HTTP/1.1" 200 2326
//! Combined: … same … 200 2326 "http://ref/" "Mozilla/5.0"
//! ```
//!
//! A leading virtual host (`example.com:443 1.2.3.4 - - [...]`, common in Apache
//! multi-vhost setups) is recognised and becomes `cs-host`.

use serde_json::{json, Value};

/// One parsed access-log line in the Sigma `webserver` field taxonomy.
/// Absent optional pieces are simply not emitted — a rule needing them will
/// not match, which is the honest outcome.
pub fn parse_access_log_line(line: &str) -> Option<Value> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // The request is the first quoted segment; everything before it holds the
    // client (and possibly the vhost), everything after holds status/bytes and
    // the optional referer / user-agent quotes.
    let q1 = line.find('"')?;
    let rest = &line[q1 + 1..];
    let q2 = rest.find('"')?;
    let request = &rest[..q2];
    let after = rest[q2 + 1..].trim();

    let head = &line[..q1];
    let bracket = head.find('[');
    let pre = head[..bracket.unwrap_or(head.len())].trim();
    let mut pre_tokens = pre.split_whitespace();
    let first = pre_tokens.next()?;
    // `example.com:443 1.2.3.4 - -` → vhost first; otherwise the client is first.
    let (host, client_ip) = if first.contains('.') && !looks_like_ip(first) {
        (Some(first.trim_end_matches(":443").trim_end_matches(":80")), pre_tokens.next())
    } else {
        (None, Some(first))
    };

    // "GET /path?query HTTP/1.1" — a request line with no method (malformed or
    // a raw TLS byte dump) is not an access record we can use.
    let mut rparts = request.split_whitespace();
    let method = rparts.next()?;
    let uri = rparts.next().unwrap_or("");
    if method.is_empty() || !method.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    let (stem, query) = match uri.split_once('?') {
        Some((s, q)) => (s, Some(q)),
        None => (uri, None),
    };

    let mut tail = after.split_whitespace();
    let status = tail.next().filter(|s| s.chars().all(|c| c.is_ascii_digit()));
    let bytes = tail.next();

    // Trailing quoted fields, in Combined order: referer then user-agent.
    let quoted: Vec<&str> = split_quoted(after);
    let referer = quoted.first().copied();
    let agent = quoted.get(1).copied();

    let mut obj = serde_json::Map::new();
    let mut put = |k: &str, v: Option<&str>| {
        if let Some(v) = v {
            if !v.is_empty() && v != "-" {
                obj.insert(k.to_string(), json!(v));
            }
        }
    };
    put("c-ip", client_ip);
    put("cs-host", host);
    put("cs-method", Some(method));
    put("c-uri", Some(uri));
    put("cs-uri-stem", Some(stem));
    put("cs-uri-query", query);
    put("sc-status", status);
    put("cs-bytes", bytes);
    put("cs-referer", referer);
    // Both spellings appear across the SigmaHQ webserver rules; emit each so
    // neither half of the corpus dies on a naming detail.
    put("c-useragent", agent);
    put("cs-user-agent", agent);
    if obj.is_empty() {
        return None;
    }
    Some(Value::Object(obj))
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Collect the contents of each `"…"` segment, in order.
fn split_quoted(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(a) = rest.find('"') {
        rest = &rest[a + 1..];
        match rest.find('"') {
            Some(b) => {
                out.push(&rest[..b]);
                rest = &rest[b + 1..];
            }
            None => break,
        }
    }
    out
}

/// Parse the access-log lines carried in an agent payload into `webserver` logs.
/// Returns how many were ingested.
pub fn ingest_access_logs(
    batch: &mut super::webhook_ingest::LogBatch,
    hostname: &str,
    lines: &[Value],
) -> u32 {
    let now = chrono::Utc::now().to_rfc3339();
    let mut n = 0;
    for line in lines.iter().filter_map(|v| v.as_str()) {
        if let Some(data) = parse_access_log_line(line) {
            batch.emit("webserver", hostname, &data, &now);
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_format_maps_to_w3c_field_names() {
        let line = r#"203.0.113.7 - frank [10/Oct/2026:13:55:36 +0000] "GET /admin.php?id=1%27 HTTP/1.1" 200 2326 "http://ref.example/" "Mozilla/5.0 (X11)""#;
        let v = parse_access_log_line(line).expect("parsed");
        assert_eq!(v["c-ip"], "203.0.113.7");
        assert_eq!(v["cs-method"], "GET");
        assert_eq!(v["cs-uri-stem"], "/admin.php");
        assert_eq!(v["cs-uri-query"], "id=1%27");
        assert_eq!(v["c-uri"], "/admin.php?id=1%27");
        assert_eq!(v["sc-status"], "200");
        assert_eq!(v["cs-bytes"], "2326");
        assert_eq!(v["cs-referer"], "http://ref.example/");
        // Both user-agent spellings are used across the SigmaHQ webserver rules.
        assert_eq!(v["c-useragent"], "Mozilla/5.0 (X11)");
        assert_eq!(v["cs-user-agent"], "Mozilla/5.0 (X11)");
    }

    #[test]
    fn common_format_without_referer_or_agent() {
        let line = r#"198.51.100.9 - - [10/Oct/2026:13:55:36 +0000] "POST /login HTTP/1.1" 401 12"#;
        let v = parse_access_log_line(line).expect("parsed");
        assert_eq!(v["cs-method"], "POST");
        assert_eq!(v["sc-status"], "401");
        assert!(v.get("cs-user-agent").is_none());
        // No query string in the URI: the field must be absent, not empty.
        assert!(v.get("cs-uri-query").is_none());
    }

    #[test]
    fn vhost_prefixed_line_yields_cs_host() {
        let line = r#"shop.example.com:443 203.0.113.7 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 5"#;
        let v = parse_access_log_line(line).expect("parsed");
        assert_eq!(v["cs-host"], "shop.example.com");
        assert_eq!(v["c-ip"], "203.0.113.7");
    }

    #[test]
    fn dash_placeholders_are_not_emitted() {
        // Apache writes "-" for an absent referer; a rule matching on the
        // literal "-" would be nonsense, so the field is left out entirely.
        let line = r#"203.0.113.7 - - [10/Oct/2026:13:55:36 +0000] "GET /x HTTP/1.1" 200 - "-" "-""#;
        let v = parse_access_log_line(line).expect("parsed");
        assert!(v.get("cs-referer").is_none());
        assert!(v.get("cs-user-agent").is_none());
        assert!(v.get("cs-bytes").is_none());
    }

    #[test]
    fn non_access_lines_are_rejected() {
        assert!(parse_access_log_line("").is_none());
        assert!(parse_access_log_line("2026/08/23 [error] 12#12: connect() failed").is_none());
        // A TLS handshake dumped into the HTTP log: quoted, but no method.
        assert!(parse_access_log_line(r#"1.2.3.4 - - [x] "\x16\x03\x01" 400 0"#).is_none());
    }
}

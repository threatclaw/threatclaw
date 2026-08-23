//! Linux auditd record ingestion.
//!
//! auditd writes `/var/log/audit/audit.log` in a flat `key=value` format that
//! the SigmaHQ `linux/auditd` rules match field by field (`type`, `a0`…`a4`,
//! `name`, `exe`, `key`, `syscall`). Shipping those lines as an opaque syslog
//! `message` leaves every one of those rules silently dead — the field-map has
//! nothing to resolve. So we parse the record here and emit it under its own
//! tag (`linux.auditd`) with one JSON key per audit field.
//!
//! Record shape (one line, space-separated):
//!
//! ```text
//! type=SYSCALL msg=audit(1755939600.123:4567): arch=c000003e syscall=59 \
//!   success=yes exit=0 a0=7ffd1c a1=7ffd20 items=2 ppid=1234 pid=1235 \
//!   auid=1000 uid=0 comm="bash" exe="/usr/bin/bash" key="execve"
//! type=EXECVE msg=audit(1755939600.123:4567): argc=3 a0="curl" a1="-s" a2=2D6F
//! type=PATH   msg=audit(1755939600.123:4567): item=0 name="/etc/passwd"
//! ```
//!
//! Two traps this parser is written around:
//!
//! * `aN` means different things per record type. In `SYSCALL` they are raw
//!   syscall arguments — hex memory addresses that must stay verbatim. In
//!   `EXECVE` they are the argv, and auditd hex-encodes any argument holding a
//!   space or quote. Decoding hex unconditionally would turn `a0=7ffd1c` into
//!   mojibake and silently break the syscall rules, so hex decoding is scoped
//!   to `EXECVE`/`PROCTITLE` — where it is the documented encoding.
//! * A quoted value can hold spaces (`exe="/usr/local/my tool"`), so the record
//!   cannot be split on whitespace before quotes are honoured.

use serde_json::{Map, Value};

/// Decode auditd's hex encoding (`2D6C61` → `-la`). Returns `None` unless the
/// whole token is even-length hex that decodes to valid UTF-8, so a value that
/// merely looks hex-ish is left alone.
fn decode_hex(token: &str) -> Option<String> {
    if token.len() < 2 || token.len() % 2 != 0 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..token.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&token[i..i + 2], 16).unwrap_or(0))
        .collect();
    String::from_utf8(bytes).ok()
}

/// Split an auditd record body into `(key, value)` pairs, honouring quotes.
fn split_pairs(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = body.char_indices().peekable();
    let bytes = body.as_bytes();

    while let Some((i, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        // key = everything up to '='
        let key_start = i;
        let mut key_end = None;
        for (j, cj) in body[key_start..].char_indices() {
            let abs = key_start + j;
            if cj == '=' {
                key_end = Some(abs);
                break;
            }
            if cj.is_whitespace() {
                break;
            }
        }
        let Some(eq) = key_end else {
            // token without '=' (e.g. the trailing ':' of msg=audit(...)) — skip it
            while let Some(&(_, cn)) = chars.peek() {
                if cn.is_whitespace() {
                    break;
                }
                chars.next();
            }
            continue;
        };
        let key = body[key_start..eq].trim().to_string();

        // value: quoted (may contain spaces) or bare (up to next whitespace)
        let vstart = eq + 1;
        let (value, vend) = if bytes.get(vstart) == Some(&b'"') {
            let rel = body[vstart + 1..].find('"');
            match rel {
                Some(r) => (
                    body[vstart + 1..vstart + 1 + r].to_string(),
                    vstart + 1 + r + 1,
                ),
                None => (body[vstart + 1..].to_string(), body.len()),
            }
        } else {
            let rel = body[vstart..]
                .find(char::is_whitespace)
                .unwrap_or(body.len() - vstart);
            (body[vstart..vstart + rel].to_string(), vstart + rel)
        };

        if !key.is_empty() {
            out.push((key, value));
        }
        // fast-forward the iterator past the value we just consumed
        while let Some(&(k, _)) = chars.peek() {
            if k >= vend {
                break;
            }
            chars.next();
        }
    }
    out
}

/// Parse one auditd record into the field shape the Sigma `linux/auditd`
/// rules match. Returns `None` for a line that is not an audit record.
pub fn parse_auditd_line(line: &str) -> Option<Value> {
    // Tolerate a syslog prefix ("Aug 23 09:00:00 host audited: type=…"):
    // anchor on the record itself rather than the start of the line.
    let start = line.find("type=")?;
    let rest = &line[start..];
    if !rest.contains("msg=audit(") {
        return None;
    }

    let mut obj = Map::new();

    // type=<TOKEN>
    let type_val = rest[5..]
        .split(|c: char| c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim_end_matches(',')
        .to_string();
    if type_val.is_empty() {
        return None;
    }
    let hex_decodable = type_val == "EXECVE" || type_val == "PROCTITLE";
    obj.insert("type".into(), Value::String(type_val));

    // msg=audit(<epoch>.<ms>:<serial>): — keep both parts, they correlate the
    // records of one event (SYSCALL + EXECVE + PATH share a serial).
    let after_msg = rest.find("msg=audit(").map(|p| p + "msg=audit(".len())?;
    if let Some(close) = rest[after_msg..].find(')') {
        let inner = &rest[after_msg..after_msg + close];
        if let Some((ts, serial)) = inner.split_once(':') {
            obj.insert("audit_epoch".into(), Value::String(ts.to_string()));
            obj.insert("audit_serial".into(), Value::String(serial.to_string()));
        }
        // Everything after "):" is the field body.
        let body_start = after_msg + close + 1;
        let body = rest[body_start..].trim_start_matches(':').trim();
        for (k, v) in split_pairs(body) {
            let decoded = if hex_decodable && !v.is_empty() {
                decode_hex(&v).unwrap_or(v)
            } else {
                v
            };
            obj.insert(k, Value::String(decoded));
        }
    }

    Some(Value::Object(obj))
}

/// Parse an auditd push payload. Accepts a single record, an array of records,
/// or a fluent-bit style envelope: each entry may be a raw string or an object
/// carrying the line under `log` / `message` / `line`.
pub async fn parse_auditd(
    batch: &mut super::webhook_ingest::LogBatch,
    json: &Value,
) -> u32 {
    let entries: Vec<&Value> = match json {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    let default_host = json
        .get("hostname")
        .and_then(|v| v.as_str())
        .or_else(|| json.get("host").and_then(|v| v.as_str()))
        .unwrap_or("");
    let now = chrono::Utc::now().to_rfc3339();

    let mut count = 0u32;
    for entry in entries {
        let (line, host) = match entry {
            Value::String(s) => (s.as_str(), default_host),
            Value::Object(_) => {
                let line = entry
                    .get("log")
                    .or_else(|| entry.get("message"))
                    .or_else(|| entry.get("line"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let host = entry
                    .get("hostname")
                    .or_else(|| entry.get("host"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(default_host);
                (line, host)
            }
            _ => continue,
        };
        if let Some(data) = parse_auditd_line(line) {
            batch.emit("linux.auditd", host, &data, &now);
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_record_keeps_hex_addresses_verbatim() {
        let line = "type=SYSCALL msg=audit(1755939600.123:4567): arch=c000003e syscall=59 \
                    success=yes exit=0 a0=7ffd1c a1=7ffd20 a2=0 ppid=1234 pid=1235 \
                    comm=\"bash\" exe=\"/usr/bin/bash\" key=\"execve\"";
        let v = parse_auditd_line(line).expect("parsed");
        assert_eq!(v["type"], "SYSCALL");
        assert_eq!(v["syscall"], "59");
        // a0 here is a memory address — decoding it as hex text would corrupt it
        // and silently break every auditd syscall rule.
        assert_eq!(v["a0"], "7ffd1c");
        assert_eq!(v["exe"], "/usr/bin/bash");
        assert_eq!(v["key"], "execve");
        assert_eq!(v["audit_serial"], "4567");
    }

    #[test]
    fn execve_record_decodes_hex_argv() {
        // auditd hex-encodes an argument containing a space: 2D6C61 == "-la"
        let line = "type=EXECVE msg=audit(1755939600.123:4567): argc=3 a0=\"ls\" a1=2D6C61 \
                    a2=\"/root\"";
        let v = parse_auditd_line(line).expect("parsed");
        assert_eq!(v["type"], "EXECVE");
        assert_eq!(v["a0"], "ls");
        assert_eq!(v["a1"], "-la");
        assert_eq!(v["a2"], "/root");
    }

    #[test]
    fn quoted_value_may_contain_spaces() {
        let line = "type=PATH msg=audit(1755939600.123:1): item=0 name=\"/opt/my tool/x\" \
                    inode=42";
        let v = parse_auditd_line(line).expect("parsed");
        assert_eq!(v["name"], "/opt/my tool/x");
        assert_eq!(v["inode"], "42");
    }

    #[test]
    fn syslog_prefixed_line_still_parses() {
        let line = "Aug 23 09:00:00 srv01 audispd: type=PATH msg=audit(1755939600.1:9): \
                    name=\"/etc/audit/auditd.conf\"";
        let v = parse_auditd_line(line).expect("parsed");
        assert_eq!(v["type"], "PATH");
        assert_eq!(v["name"], "/etc/audit/auditd.conf");
    }

    #[test]
    fn non_audit_line_is_rejected() {
        assert!(parse_auditd_line("Aug 23 sshd[1]: Accepted password for root").is_none());
        assert!(parse_auditd_line("type=SYSCALL but no msg envelope").is_none());
    }

    /// END-TO-END contract: a Sigma `linux/auditd` rule, compiled through the
    /// PRODUCTION engine, must fire on a record produced by this parser under
    /// tag `linux.auditd`. Guards the field-name contract (auditd spelling ↔
    /// rule spelling) against the silent-death class this ingestion exists to fix.
    #[test]
    fn auditd_rule_fires_end_to_end_through_the_engine() {
        use crate::agent::sigma_engine::{
            compile_detection_for_tests, match_rule_for_tests, CompiledRule,
        };

        let detection = serde_json::json!({
            "selection": { "type": "PATH", "name": "/etc/audit/auditd.conf" },
            "condition": "selection"
        });
        let (matchers, condition) =
            compile_detection_for_tests(&detection).expect("rule compiles");
        let rule = CompiledRule {
            id: "tc-auditd-audit-config-touched".into(),
            title: "auditd configuration touched".into(),
            level: "high".into(),
            logsource_category: Some("linux".into()),
            logsource_product: Some("auditd".into()),
            logsource_service: None,
            tags: vec![],
            matchers,
            condition,
            disposition: "detect".into(),
            tier: "queue".into(),
            risk_score: None,
        };

        let hit = parse_auditd_line(
            "type=PATH msg=audit(1755939600.1:9): item=0 name=\"/etc/audit/auditd.conf\"",
        )
        .expect("parsed");
        let log = serde_json::json!({ "data": hit });
        assert!(
            match_rule_for_tests(&rule, &log, Some("linux.auditd")).is_some(),
            "an auditd PATH record must fire the rule end-to-end"
        );

        let miss = parse_auditd_line(
            "type=PATH msg=audit(1755939600.1:10): item=0 name=\"/tmp/harmless\"",
        )
        .expect("parsed");
        let log2 = serde_json::json!({ "data": miss });
        assert!(
            match_rule_for_tests(&rule, &log2, Some("linux.auditd")).is_none(),
            "an unrelated path must not fire"
        );
    }

    #[test]
    fn hex_decode_only_accepts_clean_even_hex() {
        assert_eq!(decode_hex("2D6C61").as_deref(), Some("-la"));
        assert_eq!(decode_hex("2D6C6"), None); // odd length
        assert_eq!(decode_hex("zz"), None); // not hex
    }
}

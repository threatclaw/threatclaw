//! Minimal client for the Stormshield SNS `serverd` (NSRPC) API over HTTPS.
//!
//! Unlike OPNsense / pfSense (plain REST), an SNS firewall is driven through a
//! stateful command protocol that mirrors the official Python SDK
//! (`stormshield.sns.sslclient`). The handshake is:
//!   1. `POST /auth/admin.html` with `uid=base64(user)`, `pswd=base64(pass)`,
//!      `app=sslclient` → sets a session cookie (or a brute-force error).
//!   2. `POST /api/auth/login` with `app=sslclient&id=0` → returns a `sessionid`.
//!   3. `GET /api/command?sessionid=<id>&cmd=<urlencoded NSRPC command>` →
//!      an XML envelope whose `<serverd ret="..">` is `100` on success.
//!   4. `GET /api/auth/logout?sessionid=<id>`.
//!
//! Config-modifying commands (`CONFIG …`) additionally require acquiring the
//! write right with `MODIFY ON` inside the session; callers do that explicitly.
//!
//! Responses are small XML documents; we extract the handful of fields we need
//! (`msg`, `sessionid`, serverd `ret`) by hand rather than pulling an XML crate.

use std::time::Duration;

use base64::Engine as _;

use crate::connectors::remediation::RemediationResult;

/// Connection parameters for an SNS appliance. Mirrors the `skill_configs`
/// keys (`url`, `auth_user`, `auth_secret`, `no_tls_verify`).
#[derive(Debug, Clone)]
pub struct SnsConfig {
    /// Base URL, e.g. `https://10.0.0.1` (port defaults to 443).
    pub url: String,
    pub user: String,
    pub password: String,
    /// Accept the appliance's self-signed certificate (true by default on SNS).
    pub no_tls_verify: bool,
}

/// One serverd command result. `ret == 100` means OK; `200` is an argument
/// error; other codes are surfaced verbatim.
#[derive(Debug, Clone)]
pub struct SnsResponse {
    pub ret: i32,
    pub msg: String,
    /// Raw XML body, for callers that need to parse data sections (e.g. logs).
    pub raw: String,
}

impl SnsResponse {
    pub fn is_ok(&self) -> bool {
        self.ret == 100
    }
}

#[derive(Debug)]
pub enum SnsError {
    /// Wrong credentials (serverd refused the login).
    Auth,
    /// Anti-brute-force lockout; retry after the given number of seconds.
    BruteForce(u64),
    /// Transport / TLS / connectivity failure.
    Network(String),
    /// Could not decode the serverd envelope.
    Parse(String),
    /// serverd returned a non-OK code for a command we expected to succeed.
    Server { ret: i32, msg: String },
}

impl std::fmt::Display for SnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "SNS authentication failed"),
            Self::BruteForce(s) => {
                write!(f, "SNS brute-force lockout active, retry in {s}s")
            }
            Self::Network(s) => write!(f, "SNS network error: {s}"),
            Self::Parse(s) => write!(f, "SNS parse error: {s}"),
            Self::Server { ret, msg } => write!(f, "SNS command error {ret}: {msg}"),
        }
    }
}

impl std::error::Error for SnsError {}

const APP: &str = "sslclient";

/// An authenticated serverd session. Hold it to run multiple commands, then
/// `logout`. The session cookie lives in the inner client's cookie jar; the
/// `sessionid` is threaded into every command URL.
pub struct SnsSession {
    http: reqwest::Client,
    base: String,
    sessionid: String,
}

impl SnsSession {
    /// Perform the two-step handshake and return a live session.
    pub async fn connect(cfg: &SnsConfig) -> Result<Self, SnsError> {
        let base = cfg.url.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_certs(cfg.no_tls_verify)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| SnsError::Network(e.to_string()))?;

        // 1. Password authentication → session cookie.
        let b64 = base64::engine::general_purpose::STANDARD;
        let uid = b64.encode(cfg.user.as_bytes());
        let pswd = b64.encode(cfg.password.as_bytes());
        let auth_body = [("uid", uid.as_str()), ("pswd", pswd.as_str()), ("app", APP)];
        let auth_resp = http
            .post(format!("{base}/auth/admin.html"))
            .form(&auth_body)
            .send()
            .await
            .map_err(|e| SnsError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| SnsError::Network(e.to_string()))?;

        match parse_auth_msg(&auth_resp) {
            AuthOutcome::Success => {}
            AuthOutcome::BruteForce(delay) => return Err(SnsError::BruteForce(delay)),
            AuthOutcome::Failed => return Err(SnsError::Auth),
            AuthOutcome::Undecodable => {
                return Err(SnsError::Parse("auth response had no msg".into()));
            }
        }

        // 2. Open the serverd session → sessionid.
        let login_resp = http
            .post(format!("{base}/api/auth/login"))
            .form(&[("app", APP), ("id", "0")])
            .send()
            .await
            .map_err(|e| SnsError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| SnsError::Network(e.to_string()))?;

        let sessionid = parse_sessionid(&login_resp)
            .ok_or_else(|| SnsError::Parse("no sessionid in login response".into()))?;

        Ok(Self {
            http,
            base,
            sessionid,
        })
    }

    /// Run one NSRPC command. Returns the parsed serverd result regardless of
    /// `ret` (use [`SnsResponse::is_ok`] or [`Self::command_ok`] to gate).
    pub async fn command(&self, cmd: &str) -> Result<SnsResponse, SnsError> {
        let encoded = urlencoding::encode(cmd);
        let url = format!(
            "{}/api/command?sessionid={}&cmd={}",
            self.base, self.sessionid, encoded
        );
        let raw = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| SnsError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| SnsError::Network(e.to_string()))?;

        let (ret, msg) = parse_serverd_result(&raw)
            .ok_or_else(|| SnsError::Parse(format!("undecodable serverd response: {raw:.200}")))?;
        Ok(SnsResponse { ret, msg, raw })
    }

    /// Like [`Self::command`] but maps a non-OK serverd `ret` to an error.
    pub async fn command_ok(&self, cmd: &str) -> Result<SnsResponse, SnsError> {
        let resp = self.command(cmd).await?;
        if resp.is_ok() {
            Ok(resp)
        } else {
            Err(SnsError::Server {
                ret: resp.ret,
                msg: resp.msg,
            })
        }
    }

    /// Acquire the write right; required before any `CONFIG …` mutation.
    /// `ret == 110` ("Session already have this level") is success too.
    pub async fn modify_on(&self) -> Result<(), SnsError> {
        let resp = self.command("MODIFY ON FORCE").await?;
        if resp.ret == 100 || resp.ret == 110 {
            Ok(())
        } else {
            Err(SnsError::Server {
                ret: resp.ret,
                msg: resp.msg,
            })
        }
    }

    /// Best-effort logout; errors are ignored (the session expires on its own).
    pub async fn logout(&self) {
        let url = format!("{}/api/auth/logout?sessionid={}", self.base, self.sessionid);
        let _ = self.http.get(url).send().await;
    }
}

// ── Response parsing (small, regex-free string extraction) ──────────────────

#[derive(Debug, PartialEq)]
enum AuthOutcome {
    Success,
    BruteForce(u64),
    Failed,
    Undecodable,
}

/// Extract the value of an XML attribute `name="value"` from a fragment.
fn attr<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let start = xml.find(&needle)? + needle.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn parse_auth_msg(xml: &str) -> AuthOutcome {
    match attr(xml, "msg") {
        Some("AUTH_SUCCESS") => AuthOutcome::Success,
        Some("ERR_BRUTEFORCE") => {
            let delay = attr(xml, "delay").and_then(|d| d.parse().ok()).unwrap_or(600);
            AuthOutcome::BruteForce(delay)
        }
        Some(_) => AuthOutcome::Failed,
        None => AuthOutcome::Undecodable,
    }
}

fn parse_sessionid(xml: &str) -> Option<String> {
    let start = xml.find("<sessionid>")? + "<sessionid>".len();
    let rest = &xml[start..];
    let end = rest.find("</sessionid>")?;
    let id = rest[..end].trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// Pull the `<serverd ret=".." msg="..">` result from a command envelope.
/// For multi-section answers the trailing serverd node carries the final code,
/// so we take the LAST `ret="…"` occurrence.
fn parse_serverd_result(xml: &str) -> Option<(i32, String)> {
    let idx = xml.rfind("ret=\"")?;
    let tail = &xml[idx..];
    let ret = attr(tail, "ret")?.parse().ok()?;
    let msg = attr(tail, "msg").unwrap_or("").to_string();
    Some((ret, msg))
}

// ── HITL remediation actions (validated live against SNS 5.0.6) ─────────────
//
// Block is a two-object operation: a host object for the IP, then a `block`
// filter rule (srctarget=object) inserted at the top of the active policy
// (slot 1, position 2 — before the pass rules). Undo reverses both, rule first
// (the object can't be deleted while a rule still references it).

/// SNS object names cannot contain `.`/`:`; map an IP to a stable name, e.g.
/// `tc-block-203-0-113-66`. The same IP always yields the same object so block
/// then unblock line up.
fn block_object_name(ip: &str) -> String {
    format!("tc-block-{}", ip.replace(['.', ':'], "-"))
}

/// Pull `<line>…</line>` bodies out of a serverd `format="list"` response.
fn extract_lines(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find("<line>") {
        let after = &rest[s + "<line>".len()..];
        match after.find("</line>") {
            Some(e) => {
                out.push(after[..e].to_string());
                rest = &after[e + "</line>".len()..];
            }
            None => break,
        }
    }
    out
}

/// Find the active-slot `position=N` of the rule whose source is `obj`.
/// Lines look like `position=2; ruleid=1: block from <obj> to any # comment`.
fn find_rule_position(explicit_raw: &str, obj: &str) -> Option<u32> {
    let needle = format!("from {obj} to");
    for line in extract_lines(explicit_raw) {
        if line.contains(&needle) {
            let after = line.split_once("position=")?.1;
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            return digits.parse().ok();
        }
    }
    None
}

fn fail(action: &str, ip: &str, message: String) -> RemediationResult {
    RemediationResult {
        action: action.to_string(),
        target: ip.to_string(),
        success: false,
        message,
        reversible: false,
        undo_info: None,
    }
}

/// Shared core for block / isolate: both insert a `block from <obj> to any`
/// rule; only the audit comment differs.
async fn insert_block_rule(cfg: &SnsConfig, ip: &str, comment: &str) -> Result<String, SnsError> {
    let obj = block_object_name(ip);
    let session = SnsSession::connect(cfg).await?;
    let outcome = async {
        session.modify_on().await?;
        // Create the host object; tolerate "already exists" on re-block.
        let new = session
            .command(&format!("CONFIG OBJECT HOST NEW name={obj} ip={ip}"))
            .await?;
        if !new.is_ok() && !new.msg.to_lowercase().contains("already") {
            return Err(SnsError::Server {
                ret: new.ret,
                msg: new.msg,
            });
        }
        session.command_ok("CONFIG OBJECT ACTIVATE").await?;
        session
            .command_ok(&format!(
                "CONFIG FILTER RULE INSERT index=1 type=filter state=on action=block \
                 srctarget={obj} dsttarget=any position=2 comment=\"{comment}\""
            ))
            .await?;
        session.command_ok("CONFIG FILTER ACTIVATE").await?;
        Ok::<String, SnsError>(obj.clone())
    }
    .await;
    session.logout().await;
    outcome
}

/// Block all traffic from a source IP (filter rule at the top of the policy).
pub async fn block_ip(cfg: &SnsConfig, ip: &str) -> RemediationResult {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return fail("stormshield_block_ip", ip, format!("invalid IP: {ip}"));
    }
    match insert_block_rule(cfg, ip, &format!("ThreatClaw auto-block {ip}")).await {
        Ok(obj) => RemediationResult {
            action: "stormshield_block_ip".into(),
            target: ip.into(),
            success: true,
            message: format!("Blocked {ip} via filter rule (object {obj}) on the active policy"),
            reversible: true,
            undo_info: Some(format!("stormshield_unblock_ip {ip}")),
        },
        Err(e) => fail("stormshield_block_ip", ip, e.to_string()),
    }
}

/// Isolate an internal host: cut all traffic sourced from it. Same mechanism
/// as [`block_ip`]; the audit comment marks it as an isolation.
pub async fn isolate_host(cfg: &SnsConfig, ip: &str) -> RemediationResult {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return fail("stormshield_isolate_host", ip, format!("invalid IP: {ip}"));
    }
    match insert_block_rule(cfg, ip, &format!("ThreatClaw isolate {ip}")).await {
        Ok(obj) => RemediationResult {
            action: "stormshield_isolate_host".into(),
            target: ip.into(),
            success: true,
            message: format!("Isolated {ip} via filter rule (object {obj})"),
            reversible: true,
            undo_info: Some(format!("stormshield_unblock_ip {ip}")),
        },
        Err(e) => fail("stormshield_isolate_host", ip, e.to_string()),
    }
}

/// Remove a ThreatClaw block/isolation for an IP: drop the filter rule then the
/// host object (order matters — the object is "in use" until the rule is gone).
pub async fn unblock_ip(cfg: &SnsConfig, ip: &str) -> RemediationResult {
    let obj = block_object_name(ip);
    let session = match SnsSession::connect(cfg).await {
        Ok(s) => s,
        Err(e) => return fail("stormshield_unblock_ip", ip, e.to_string()),
    };
    let outcome = async {
        session.modify_on().await?;
        let explicit = session
            .command_ok("CONFIG FILTER EXPLICIT type=filter index=1")
            .await?;
        if let Some(pos) = find_rule_position(&explicit.raw, &obj) {
            session
                .command_ok(&format!(
                    "CONFIG FILTER RULE REMOVE index=1 type=filter position={pos}"
                ))
                .await?;
            session.command_ok("CONFIG FILTER ACTIVATE").await?;
        }
        // Delete the now-unreferenced object (best effort — may already be gone).
        let _ = session
            .command(&format!("CONFIG OBJECT HOST DELETE name={obj}"))
            .await?;
        session.command_ok("CONFIG OBJECT ACTIVATE").await?;
        Ok::<(), SnsError>(())
    }
    .await;
    session.logout().await;
    match outcome {
        Ok(()) => RemediationResult {
            action: "stormshield_unblock_ip".into(),
            target: ip.into(),
            success: true,
            message: format!("Removed ThreatClaw block for {ip}"),
            reversible: false,
            undo_info: None,
        },
        Err(e) => fail("stormshield_unblock_ip", ip, e.to_string()),
    }
}

// ── Periodic sync: firmware version → asset (CVE / CERT-FR matching) ────────

/// Pull `SYSTEM PROPERTY` (model / firmware / serial) and record the firmware
/// as the enrolled firewall asset's software inventory, so the precise SNS
/// version flows into CVE + CERT-FR matching. Called by the connector sync
/// scheduler. The asset (`skill-stormshield-host`) is created by skill
/// auto-enrolment when the connector is configured.
pub async fn sync_stormshield(
    store: &dyn crate::db::Database,
    cfg: &SnsConfig,
) -> Result<String, String> {
    use crate::db::threatclaw_store::ThreatClawStore;
    let session = SnsSession::connect(cfg).await.map_err(|e| e.to_string())?;
    let info = session.command_ok("SYSTEM PROPERTY").await;
    session.logout().await;
    let info = info.map_err(|e| e.to_string())?;

    let model = property_value(&info.raw, "Model");
    let version = property_value(&info.raw, "Version");
    let serial = property_value(&info.raw, "SerialNumber");

    if let Some(ver) = &version {
        let software = serde_json::json!([{
            "vendor": "Stormshield",
            "product": "Stormshield Network Security",
            "version": ver,
        }]);
        if let Err(e) = store
            .update_asset_software("skill-stormshield-host", &software)
            .await
        {
            tracing::warn!("stormshield sync: update_asset_software failed: {e}");
        }
    }

    Ok(format!(
        "SNS model={} firmware={} serial={}",
        model.as_deref().unwrap_or("?"),
        version.as_deref().unwrap_or("?"),
        serial.as_deref().unwrap_or("?"),
    ))
}

/// Read a property from a `SYSTEM PROPERTY` response. Handles both the
/// `section` shape (`<key name="Model" value="EVA1"/>`) and the `raw` shape
/// (`Model=EVA1` line text).
fn property_value(xml: &str, name: &str) -> Option<String> {
    let anchor = format!("name=\"{name}\"");
    if let Some(pos) = xml.find(&anchor) {
        let after = &xml[pos + anchor.len()..];
        if let Some(vpos) = after.find("value=\"") {
            let rest = &after[vpos + "value=\"".len()..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
    }
    let kv = format!("{name}=");
    let pos = xml.find(&kv)? + kv.len();
    let rest = &xml[pos..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '<' || c == '"')
        .unwrap_or(rest.len());
    let val = rest[..end].trim();
    (!val.is_empty()).then(|| val.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_value_section_and_raw() {
        let section = r#"<section title="Result"><key name="Model" value="EVA1"/><key name="Version" value="5.0.6"/></section>"#;
        assert_eq!(property_value(section, "Model").as_deref(), Some("EVA1"));
        assert_eq!(property_value(section, "Version").as_deref(), Some("5.0.6"));
        let raw = "<line>Model=EVA1</line><line>Version=5.0.6</line>";
        assert_eq!(property_value(raw, "Version").as_deref(), Some("5.0.6"));
        // `Model=` must not be confused by `ModelSize=`
        let raw2 = "<line>ModelSize=XL-VM</line><line>Model=EVA1</line>";
        assert_eq!(property_value(raw2, "Model").as_deref(), Some("EVA1"));
    }

    #[test]
    fn object_name_sanitizes_ip() {
        assert_eq!(block_object_name("203.0.113.66"), "tc-block-203-0-113-66");
        assert_eq!(block_object_name("2001:db8::1"), "tc-block-2001-db8--1");
    }

    #[test]
    fn lines_extracted_from_list_xml() {
        let xml = "<data format=\"list\"><line>position=1; sep</line><line>position=2; ruleid=1: block from tc-block-203-0-113-66 to any # x</line></data>";
        let lines = extract_lines(xml);
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("tc-block-203-0-113-66"));
    }

    #[test]
    fn rule_position_found_by_object() {
        let xml = "<data format=\"list\"><line>position=2; ruleid=1: block from tc-block-203-0-113-66 to any # ThreatClaw</line></data>";
        assert_eq!(
            find_rule_position(xml, "tc-block-203-0-113-66"),
            Some(2)
        );
        assert_eq!(find_rule_position(xml, "tc-block-10-0-0-9"), None);
    }

    #[test]
    fn auth_success_detected() {
        let xml = r#"<nws code="100" msg="AUTH_SUCCESS"></nws>"#;
        assert_eq!(parse_auth_msg(xml), AuthOutcome::Success);
    }

    #[test]
    fn auth_bruteforce_carries_delay() {
        let xml = r#"<nws msg="ERR_BRUTEFORCE" delay="600"></nws>"#;
        assert_eq!(parse_auth_msg(xml), AuthOutcome::BruteForce(600));
    }

    #[test]
    fn auth_failure_detected() {
        let xml = r#"<nws msg="AUTH_ERROR"></nws>"#;
        assert_eq!(parse_auth_msg(xml), AuthOutcome::Failed);
    }

    #[test]
    fn sessionid_extracted() {
        let xml = r#"<nws code="100"><sessionid>ABC123</sessionid><protocol>1</protocol></nws>"#;
        assert_eq!(parse_sessionid(xml).as_deref(), Some("ABC123"));
    }

    #[test]
    fn serverd_ok_result() {
        let xml = r#"<nws code="100"><serverd ret="100" code="00a00100" msg="Ok"></serverd></nws>"#;
        let (ret, msg) = parse_serverd_result(xml).unwrap();
        assert_eq!(ret, 100);
        assert_eq!(msg, "Ok");
    }

    #[test]
    fn serverd_takes_final_ret_on_multisection() {
        let xml = r#"<nws><serverd ret="101" msg="Begin"></serverd><serverd ret="100" msg="Ok"></serverd></nws>"#;
        let (ret, msg) = parse_serverd_result(xml).unwrap();
        assert_eq!(ret, 100);
        assert_eq!(msg, "Ok");
    }
}

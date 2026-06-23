//! Email rendering — clean, ThreatClaw-branded HTML (+ plain-text fallback),
//! **bilingual (FR/EN)**.
//!
//! The chat channels (Telegram/Slack) reuse an emoji-heavy plain-text message.
//! Email deserves better: a dynamic subject (severity + host) and a branded HTML
//! body using the dashboard palette — no emoji spam. Every HTML mail ships with a
//! plain-text alternative (multipart), so text-only clients still render cleanly.
//!
//! Language follows the single backend output-language setting
//! (`report_lang::report_language`), the same one that governs reports — so mails
//! and reports stay consistent. Callers pass the resolved `lang` string.
//!
//! Anonymisation: callers pass already-anonymised content; this module only adds
//! presentation (it never re-fetches raw data).

/// Dashboard palette (src/app/globals.css, dark theme).
const BG: &str = "#0a0a0f";
const CARD: &str = "#14141c";
const BORDER: &str = "#2a2a35";
const TEXT: &str = "#e8e4e0";
const TEXT_SEC: &str = "#b0a8a0";
const TEXT_MUTED: &str = "#7a726c";

/// True when the configured output language is French (`report.language`).
/// Anything starting with `fr` (fr, fr-FR, français, french) → FR; else EN.
pub fn is_fr(lang: &str) -> bool {
    lang.trim().to_lowercase().starts_with("fr")
}

/// Accent colour for a severity (matches the dashboard severity colours).
pub fn severity_color(severity: &str) -> &'static str {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "#d03020", // red
        "HIGH" => "#d09020",     // amber
        "MEDIUM" => "#3080d0",   // blue
        _ => "#30a050",          // green (low/info)
    }
}

/// HTML-escape a content string before interpolating into the template.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Dynamic subject for an incident mail: `[CRITICAL] SRV-01 — <short summary>`.
/// Scannable in a mailbox (vs the old static "ThreatClaw Security Alert").
pub fn incident_subject(_lang: &str, severity: &str, asset: &str, summary: &str) -> String {
    // Severity + host are language-neutral; the short summary is already localised
    // upstream. No FR/EN divergence needed for the subject shell.
    let sev = severity.to_ascii_uppercase();
    let short: String = summary
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .take(70)
        .collect();
    if short.is_empty() {
        format!("[{sev}] {asset} — ThreatClaw")
    } else {
        format!("[{sev}] {asset} — {short}")
    }
}

/// The branded HTML shell: dark page, accent header bar with the ThreatClaw
/// wordmark + optional severity badge, a content card, and an optional dashboard
/// button. Table-based + inline styles for broad email-client compatibility.
pub fn brand_html(
    lang: &str,
    accent: &str,
    badge: Option<&str>,
    inner_html: &str,
    dashboard_url: Option<&str>,
) -> String {
    let fr = is_fr(lang);
    let tagline = if fr {
        "Agent de cybersécurité autonome"
    } else {
        "Autonomous cybersecurity agent"
    };
    let button_label = if fr {
        "Ouvrir dans le dashboard"
    } else {
        "Open in the dashboard"
    };
    let footer = if fr {
        "ThreatClaw — notification automatique. Ne pas répondre à cet email."
    } else {
        "ThreatClaw — automated notification. Please do not reply to this email."
    };

    let badge_html = badge
        .map(|b| {
            format!(
                "<span style=\"display:inline-block;margin-left:12px;padding:2px 10px;border-radius:4px;\
                 background:{accent};color:#ffffff;font-size:12px;font-weight:700;letter-spacing:.5px;\
                 vertical-align:middle;\">{}</span>",
                esc(b)
            )
        })
        .unwrap_or_default();

    let button_html = dashboard_url
        .map(|u| {
            format!(
                "<tr><td style=\"padding:24px 28px 4px;\">\
                 <a href=\"{u}\" style=\"display:inline-block;padding:11px 22px;border-radius:6px;\
                 background:{accent};color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;\">\
                 {button_label}</a></td></tr>",
                u = esc(u)
            )
        })
        .unwrap_or_default();

    format!(
        "<!DOCTYPE html><html><body style=\"margin:0;padding:0;background:{BG};\">\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
           style=\"background:{BG};padding:24px 0;\"><tr><td align=\"center\">\
         <table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" \
           style=\"width:600px;max-width:92%;background:{CARD};border:1px solid {BORDER};border-radius:10px;overflow:hidden;\
           font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;\">\
         <tr><td style=\"height:4px;background:{accent};font-size:0;line-height:0;\">&nbsp;</td></tr>\
         <tr><td style=\"padding:20px 28px 8px;\">\
           <span style=\"font-size:18px;font-weight:800;color:{TEXT};letter-spacing:.5px;\">Threat<span style=\"color:{accent};\">Claw</span></span>{badge_html}\
           <div style=\"font-size:11px;color:{TEXT_MUTED};margin-top:2px;\">{tagline}</div>\
         </td></tr>\
         <tr><td style=\"padding:8px 28px 4px;color:{TEXT};font-size:14px;line-height:1.55;\">{inner_html}</td></tr>\
         {button_html}\
         <tr><td style=\"padding:20px 28px;border-top:1px solid {BORDER};color:{TEXT_MUTED};font-size:11px;\">{footer}</td></tr>\
         </table></td></tr></table></body></html>"
    )
}

/// Render an incident notification as `(plain_text, html)` — clean, no emoji, FR/EN.
pub fn incident_email(
    lang: &str,
    severity: &str,
    asset: &str,
    summary: &str,
    alert_count: i32,
    dashboard_url: Option<&str>,
) -> (String, String) {
    let fr = is_fr(lang);
    let sev = severity.to_ascii_uppercase();
    let accent = severity_color(&sev);

    let (l_incident, l_host, l_corr, l_sev, l_detected, l_link) = if fr {
        (
            "INCIDENT",
            "Hôte",
            "Alertes corrélées",
            "Sévérité",
            "Incident détecté",
            "Dashboard",
        )
    } else {
        (
            "INCIDENT",
            "Host",
            "Correlated alerts",
            "Severity",
            "Incident detected",
            "Dashboard",
        )
    };

    let text = format!(
        "{l_incident} {sev}\n{l_host} : {asset}\n{l_corr} : {alert_count}\n\n{summary}\n{link}\n\n— ThreatClaw",
        link = dashboard_url
            .map(|u| format!("\n{l_link} : {u}"))
            .unwrap_or_default(),
    );

    let body_html = esc(summary).replace('\n', "<br>");
    let inner = format!(
        "<div style=\"font-size:15px;font-weight:700;color:{TEXT};margin-bottom:10px;\">{l_detected}</div>\
         <table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin-bottom:14px;\">\
         <tr><td style=\"color:{TEXT_MUTED};font-size:12px;padding:2px 16px 2px 0;\">{l_sev}</td>\
             <td style=\"color:{accent};font-size:13px;font-weight:700;\">{sev}</td></tr>\
         <tr><td style=\"color:{TEXT_MUTED};font-size:12px;padding:2px 16px 2px 0;\">{l_host}</td>\
             <td style=\"color:{TEXT};font-size:13px;font-family:monospace;\">{asset}</td></tr>\
         <tr><td style=\"color:{TEXT_MUTED};font-size:12px;padding:2px 16px 2px 0;\">{l_corr}</td>\
             <td style=\"color:{TEXT};font-size:13px;\">{alert_count}</td></tr>\
         </table>\
         <div style=\"color:{TEXT_SEC};font-size:13px;line-height:1.55;\">{body_html}</div>",
        asset = esc(asset),
    );
    (
        text,
        brand_html(lang, accent, Some(&sev), &inner, dashboard_url),
    )
}

/// Wrap an existing plain-text message (digest / verdict) into the branded shell.
/// `title` is already localised by the caller; the template adds no emoji.
pub fn wrap_email(
    lang: &str,
    title: &str,
    body_text: &str,
    dashboard_url: Option<&str>,
) -> (String, String) {
    let accent = "#30a050";
    let inner = format!(
        "<div style=\"font-size:15px;font-weight:700;color:{TEXT};margin-bottom:10px;\">{}</div>\
         <div style=\"color:{TEXT_SEC};font-size:13px;line-height:1.55;white-space:pre-wrap;\">{}</div>",
        esc(title),
        esc(body_text)
    );
    (
        body_text.to_string(),
        brand_html(lang, accent, None, &inner, dashboard_url),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_fr_detection() {
        assert!(is_fr("fr"));
        assert!(is_fr("français"));
        assert!(is_fr("FR-fr"));
        assert!(!is_fr("English"));
        assert!(!is_fr("en"));
        assert!(!is_fr("afrikaans")); // must NOT match on the inner "fr"
    }

    #[test]
    fn subject_is_dynamic_and_scannable() {
        let s = incident_subject("fr", "critical", "SRV-01", "Brute-force SSH\nautre ligne");
        assert!(s.starts_with("[CRITICAL] SRV-01 — Brute-force"));
        assert_eq!(
            incident_subject("en", "high", "WIN-02", "  "),
            "[HIGH] WIN-02 — ThreatClaw"
        );
    }

    #[test]
    fn incident_email_localised_and_escaped() {
        let (text_fr, html_fr) = incident_email(
            "fr",
            "CRITICAL",
            "SRV<1>",
            "a <script>b",
            3,
            Some("https://x/y"),
        );
        assert!(text_fr.contains("Hôte : SRV<1>"));
        assert!(html_fr.contains("SRV&lt;1&gt;")); // escaped
        assert!(html_fr.contains("Ouvrir dans le dashboard"));
        assert!(html_fr.contains("Agent de cybersécurité"));

        let (text_en, html_en) =
            incident_email("English", "CRITICAL", "SRV-1", "x", 1, Some("https://x/y"));
        assert!(text_en.contains("Host : SRV-1"));
        assert!(html_en.contains("Open in the dashboard"));
        assert!(html_en.contains("Autonomous cybersecurity"));
    }
}

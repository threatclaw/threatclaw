//! Output language resolver for any text the LLM produces for the
//! customer (forensic narratives, incident analyses, executive summaries).
//!
//! Server prompt structure is intentionally English — Foundation-Sec is
//! more reliably grounded in English and the structural rules are not
//! customer-visible. Only the *output* language of the narrative is
//! configurable, via this resolver. The dashboard UI language is
//! separate (see `dashboard/src/lib/i18n.ts`).
//!
//! Resolution order:
//!   1. DB setting `system` / `report.language` (set by the operator from
//!      Config > General > Report language in the dashboard)
//!   2. `TC_REPORT_LANG` environment variable
//!   3. `"English"` default
//!
//! The string flows verbatim into a single instruction appended at the
//! end of every LLM prompt: `Respond in {lang}.` Foundation-Sec
//! interprets natural language well, so values like "French",
//! "English", "Chinese", "German", "Spanish" all work without code
//! changes here.

use crate::db::Database;

const REPORT_LANG_USER: &str = "system";
const REPORT_LANG_KEY: &str = "report.language";
const DEFAULT_LANG: &str = "English";

/// Resolve the report output language for LLM-generated content.
/// Always returns a usable string; never errors.
pub async fn report_language(db: &dyn Database) -> String {
    if let Ok(Some(value)) = db.get_setting(REPORT_LANG_USER, REPORT_LANG_KEY).await {
        if let Some(s) = value.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Ok(v) = std::env::var("TC_REPORT_LANG") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_LANG.to_string()
}

/// Render the trailing prompt directive. Call this once at the very end
/// of an LLM prompt so the model sees it last and gives it weight.
pub fn output_language_directive(lang: &str) -> String {
    format!(
        "\n## OUTPUT LANGUAGE\n\nRespond in {}. Field names and enum values (verdict, severity, ...) stay in English; only natural-language content (analysis, rationales, summaries) follows this language.\n",
        lang
    )
}

//! Builds the `metadata.i18n` object that lets the dashboard localize a finding.
//! The stored French title/description remain the fallback — this is additive.

/// Build `{"key": ..., "params": ...}` for a finding's `metadata.i18n`.
pub fn i18n(key: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "key": key, "params": params })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i18n_builds_key_and_params() {
        let v = i18n("finding.os_posture.eol", serde_json::json!({"os": "Debian 12"}));
        assert_eq!(v["key"], "finding.os_posture.eol");
        assert_eq!(v["params"]["os"], "Debian 12");
    }
}

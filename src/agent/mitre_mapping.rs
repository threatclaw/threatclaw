//! Deterministic MITRE ATT&CK and proposed-action baseline per sigma rule.
//!
//! ## Why this module exists
//!
//! When the L2 enrichment LLM cannot run to completion (CPU-only Ollama on
//! constrained hardware times out before producing structured output), the
//! previous design left `mitre_techniques` empty and `proposed_actions`
//! empty. The RSSI saw an incident with a title and a fallback summary but
//! no usable actionables — defeating the purpose of the tier.
//!
//! Every alert that our own connectors emit is by definition tied to a
//! known offensive pattern (brute force, user creation, log tampering, etc.).
//! We can map the rule_id directly to the canonical ATT&CK technique(s) and
//! to a small set of standard remediation actions. The LLM remains free to
//! refine or add on top, but the baseline is guaranteed.
//!
//! ## Contract
//!
//! - `baseline_for_rule(rule_id, dominant_alert)` returns `(mitre, actions)`.
//! - `mitre` is a list of `"T1110.001 Password Brute Force"`-style strings,
//!   ready to drop into `incidents.mitre_techniques`.
//! - `actions` is a list of JSON objects matching the dashboard's expected
//!   shape: `{cmd_id, params, rationale, requires_hitl}`. The params are
//!   templated from the alert (target_user, source_ip).
//! - When the rule_id has no entry in the table (skill we don't recognise,
//!   community rules), both vectors are returned empty — the caller stays in
//!   charge of falling back to LLM output.

use crate::agent::incident_dossier::DossierAlert;

pub struct Baseline {
    pub mitre: Vec<String>,
    pub actions: Vec<serde_json::Value>,
}

impl Baseline {
    pub fn empty() -> Self {
        Self {
            mitre: vec![],
            actions: vec![],
        }
    }
    pub fn is_empty(&self) -> bool {
        self.mitre.is_empty() && self.actions.is_empty()
    }
}

/// Build the deterministic baseline for an alert. `dominant_alert` lets us
/// template params (target user, source IP). Returns empty baseline when the
/// rule_id is unknown so the caller can keep its LLM-driven path.
pub fn baseline_for_rule(rule_id: &str, dominant_alert: Option<&DossierAlert>) -> Baseline {
    let user = dominant_alert
        .and_then(|a| a.username.as_deref())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let ip = dominant_alert
        .and_then(|a| a.source_ip.as_deref())
        .filter(|s| !s.is_empty())
        // Strip CIDR suffix and net mask if any — cmd_id net-001 expects an IP, not 1.2.3.4/32.
        .map(|s| s.split('/').next().unwrap_or(s).to_string());

    match rule_id {
        // ── Windows agent (osquery / sysmon) ──────────────────────────────
        "osquery-win-failed-logon-burst" => Baseline {
            mitre: vec!["T1110.001 Password Brute Force".into()],
            actions: vec![
                action_block_ip(&ip, "Bloquer l'IP source du brute force au périmètre"),
                action_lock_account(&user, "Verrouiller le compte cible pendant l'investigation"),
            ]
            .into_iter()
            .flatten()
            .collect(),
        },
        "osquery-win-user-created" => Baseline {
            mitre: vec!["T1136.001 Create Account: Local Account".into()],
            actions: vec![action_lock_account(
                &user,
                "Verrouiller le compte nouvellement créé jusqu'à validation RSSI",
            )]
            .into_iter()
            .flatten()
            .collect(),
        },
        "osquery-win-user-deleted" => Baseline {
            mitre: vec!["T1531 Account Access Removal".into()],
            actions: vec![ticket(
                "Compte utilisateur supprimé — revue manuelle requise (impact opérationnel possible)",
            )],
        },
        "osquery-win-group-membership-add" => Baseline {
            mitre: vec![
                "T1098 Account Manipulation".into(),
                "T1078 Valid Accounts".into(),
            ],
            actions: vec![ticket(
                "Ajout à un groupe — vérifier la légitimité et la chaîne d'approbation",
            )],
        },
        "osquery-win-audit-log-cleared" => Baseline {
            mitre: vec!["T1070.001 Indicator Removal: Clear Windows Event Logs".into()],
            actions: vec![
                forensic_snapshot("Snapshot forensique avant toute compromission supplémentaire"),
                ticket(
                    "Effacement de journal d'audit : escalade RSSI immédiate, contexte anti-forensique",
                ),
            ],
        },
        "osquery-win-powershell-suspicious" => Baseline {
            mitre: vec!["T1059.001 Command and Scripting Interpreter: PowerShell".into()],
            actions: vec![
                forensic_snapshot("Snapshot forensique du host (process tree, registry, fichiers)"),
                ticket("PowerShell offensif détecté — revue immédiate du contexte"),
            ],
        },
        "sysmon-offensive-tool" => Baseline {
            mitre: vec![
                "T1003 OS Credential Dumping".into(),
                "T1059 Command and Scripting Interpreter".into(),
            ],
            actions: vec![
                forensic_snapshot("Snapshot forensique du host avant retrait de l'outil"),
                ticket("Outil offensif détecté — isolement réseau recommandé"),
            ],
        },
        "sysmon-lsass-access" => Baseline {
            mitre: vec!["T1003.001 OS Credential Dumping: LSASS Memory".into()],
            actions: vec![
                forensic_snapshot("Snapshot forensique LSASS avant tout reset"),
                ticket("Accès LSASS — rotation des credentials du host requise"),
            ],
        },

        // ── Linux baseline (skills existants, signal connu) ───────────────
        "lnx-auth-001" => {
            let mut actions = vec![];
            if let Some(a) = action_block_ip(&ip, "Bloquer l'IP source du brute force SSH") {
                actions.push(a);
            }
            actions.push(ticket("Brute force SSH — revue de la configuration sshd"));
            Baseline {
                mitre: vec!["T1110.001 Password Brute Force".into()],
                actions,
            }
        }
        "lnx-fim-001" => Baseline {
            mitre: vec!["T1565.001 Stored Data Manipulation".into()],
            actions: vec![ticket(
                "Modification d'un fichier d'authentification — revue immédiate",
            )],
        },
        "lnx-acct-002" => Baseline {
            mitre: vec![
                "T1078.003 Valid Accounts: Local Accounts".into(),
                "T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching".into(),
            ],
            actions: vec![ticket(
                "Compte promu UID 0 — escalade post-compromis suspectée",
            )],
        },

        // Rule unknown to this catalog — caller keeps its own behavior.
        _ => Baseline::empty(),
    }
}

// ── Helpers d'action ────────────────────────────────────────────────────────

fn action_block_ip(ip: &Option<String>, rationale: &str) -> Option<serde_json::Value> {
    let ip = ip.as_deref()?;
    Some(serde_json::json!({
        "cmd_id": "net-001",
        "params": { "IP": ip },
        "rationale": rationale,
        "requires_hitl": true,
        "origin": "deterministic_baseline",
    }))
}

fn action_lock_account(user: &Option<String>, rationale: &str) -> Option<serde_json::Value> {
    let user = user.as_deref()?;
    Some(serde_json::json!({
        "cmd_id": "usr-001",
        "params": { "USER": user },
        "rationale": rationale,
        "requires_hitl": true,
        "origin": "deterministic_baseline",
    }))
}

fn forensic_snapshot(rationale: &str) -> serde_json::Value {
    serde_json::json!({
        "cmd_id": "forensic-004",
        "params": {},
        "rationale": rationale,
        "requires_hitl": true,
        "origin": "deterministic_baseline",
    })
}

fn ticket(rationale: &str) -> serde_json::Value {
    serde_json::json!({
        "cmd_id": "ticket-001",
        "params": {},
        "rationale": rationale,
        "requires_hitl": true,
        "origin": "deterministic_baseline",
    })
}

/// Merge LLM-produced output with the deterministic baseline. The LLM is the
/// preferred source; we only top up missing fields. Same-cmd_id collisions
/// preserve the LLM version (it presumably tailored the params).
pub fn merge_with_baseline(
    parsed_mitre: Vec<String>,
    parsed_actions: Vec<serde_json::Value>,
    baseline: Baseline,
) -> (Vec<String>, Vec<serde_json::Value>) {
    let mut mitre = parsed_mitre;
    for t in baseline.mitre {
        if !mitre
            .iter()
            .any(|existing| existing.starts_with(t.split(' ').next().unwrap_or(&t)))
        {
            mitre.push(t);
        }
    }

    let mut actions = parsed_actions;
    for b in baseline.actions {
        let bid = b.get("cmd_id").and_then(|v| v.as_str()).unwrap_or("");
        let already = actions.iter().any(|a| {
            a.get("cmd_id")
                .and_then(|v| v.as_str())
                .map(|s| s == bid)
                .unwrap_or(false)
        });
        if !already {
            actions.push(b);
        }
    }

    (mitre, actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(rule_id: &str, user: Option<&str>, ip: Option<&str>) -> DossierAlert {
        DossierAlert {
            id: 1,
            rule_id: rule_id.into(),
            rule_name: "test".into(),
            level: "high".into(),
            source_ip: ip.map(|s| s.into()),
            username: user.map(|s| s.into()),
            created_at: chrono::Utc::now(),
            matched_fields: serde_json::json!({}),
        }
    }

    #[test]
    fn windows_bruteforce_has_mitre_and_two_actions() {
        let a = alert(
            "osquery-win-failed-logon-burst",
            Some("alice"),
            Some("10.0.0.5"),
        );
        let b = baseline_for_rule("osquery-win-failed-logon-burst", Some(&a));
        assert_eq!(b.mitre, vec!["T1110.001 Password Brute Force"]);
        assert_eq!(b.actions.len(), 2);
        assert_eq!(b.actions[0]["cmd_id"], "net-001");
        assert_eq!(b.actions[0]["params"]["IP"], "10.0.0.5");
        assert_eq!(b.actions[1]["cmd_id"], "usr-001");
        assert_eq!(b.actions[1]["params"]["USER"], "alice");
    }

    #[test]
    fn windows_bruteforce_skips_actions_with_missing_params() {
        // No source IP and no username → both actions should be skipped, mitre kept.
        let a = alert("osquery-win-failed-logon-burst", None, None);
        let b = baseline_for_rule("osquery-win-failed-logon-burst", Some(&a));
        assert_eq!(b.mitre.len(), 1);
        assert_eq!(b.actions.len(), 0);
    }

    #[test]
    fn lsass_access_is_critical_mitre() {
        let a = alert("sysmon-lsass-access", None, None);
        let b = baseline_for_rule("sysmon-lsass-access", Some(&a));
        assert_eq!(
            b.mitre,
            vec!["T1003.001 OS Credential Dumping: LSASS Memory"]
        );
        assert!(!b.actions.is_empty());
    }

    #[test]
    fn unknown_rule_returns_empty() {
        let b = baseline_for_rule("some-third-party-rule", None);
        assert!(b.is_empty());
    }

    #[test]
    fn merge_keeps_llm_actions_then_appends_missing_baseline() {
        let llm_actions = vec![serde_json::json!({
            "cmd_id": "net-001",
            "params": { "IP": "1.2.3.4" },
            "rationale": "LLM choice"
        })];
        let baseline = Baseline {
            mitre: vec!["T1110.001 Password Brute Force".into()],
            actions: vec![
                serde_json::json!({"cmd_id": "net-001", "params": {"IP": "5.5.5.5"}, "rationale": "baseline net"}),
                serde_json::json!({"cmd_id": "usr-001", "params": {"USER": "bob"}, "rationale": "baseline user"}),
            ],
        };
        let (mitre, actions) = merge_with_baseline(vec![], llm_actions, baseline);
        assert_eq!(mitre.len(), 1);
        assert_eq!(actions.len(), 2);
        // LLM's net-001 wins on params:
        assert_eq!(actions[0]["params"]["IP"], "1.2.3.4");
        // Baseline usr-001 appended:
        assert_eq!(actions[1]["cmd_id"], "usr-001");
    }
}

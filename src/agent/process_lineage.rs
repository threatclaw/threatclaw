//! Process ancestry reconstruction for the incident dossier.
//!
//! A single Sigma alert tells you *what* ran (`powershell.exe -enc ...`); the
//! kill chain is in *who spawned it*. `explorer.exe -> powershell` is usually a
//! human; `winword.exe -> powershell -enc` is a macro payload; `w3wp.exe -> cmd
//! -> powershell` is a webshell. The parent is often THE discriminator between a
//! true positive and a false positive, and the lineage is the attack story.
//!
//! Sysmon EID 1 events already carry `ProcessGuid` / `ParentProcessGuid` plus
//! `ParentImage` / `ParentCommandLine`, so we can walk the ancestry by chaining
//! `ParentProcessGuid -> ProcessGuid`. This is computed on demand into the
//! dossier — NOT stored as graph nodes — so it adds no high-cardinality bloat to
//! the graph at fleet scale. See detection-chain audit 2026-06-20.

use serde_json::Value;

/// One process in the ancestry chain.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProcessStep {
    pub image: String,
    pub command_line: String,
    pub user: String,
}

/// Case-insensitive field lookup on a Sysmon EventData object (keys are normally
/// PascalCase, but we don't want to silently miss a differently-cased producer).
fn field<'a>(ev: &'a Value, key: &str) -> Option<&'a str> {
    if let Some(s) = ev.get(key).and_then(|v| v.as_str()) {
        return Some(s);
    }
    let lk = key.to_lowercase();
    ev.as_object()?
        .iter()
        .find(|(k, _)| k.to_lowercase() == lk)
        .and_then(|(_, v)| v.as_str())
}

fn to_step(ev: &Value) -> ProcessStep {
    ProcessStep {
        image: field(ev, "Image").unwrap_or("").to_string(),
        command_line: field(ev, "CommandLine").unwrap_or("").to_string(),
        user: field(ev, "User").unwrap_or("").to_string(),
    }
}

/// Build the process ancestry chain (leaf first -> root last) for the process
/// whose command line matches `leaf_commandline`, by walking ParentProcessGuid up
/// the supplied Sysmon EID 1 events. Bounded by `max_depth`; cycle-safe via a
/// visited set. When the parent event is outside the window, the immediate parent
/// is still recorded from the child's `ParentImage` / `ParentCommandLine`.
///
/// `events` are the Sysmon `EventData` objects (the inner `data` of each log).
pub fn build_process_lineage(
    events: &[&Value],
    leaf_commandline: &str,
    max_depth: usize,
) -> Vec<ProcessStep> {
    if leaf_commandline.is_empty() || events.is_empty() || max_depth == 0 {
        return Vec::new();
    }

    // Index by ProcessGuid for parent lookups (first occurrence wins; the caller
    // passes most-recent-first so we resolve to the latest instance of a guid).
    let mut by_guid: std::collections::HashMap<&str, &Value> = std::collections::HashMap::new();
    for ev in events {
        if let Some(g) = field(ev, "ProcessGuid") {
            by_guid.entry(g).or_insert(ev);
        }
    }

    // Find the leaf: exact command-line match first, then a contains() fallback
    // (the Sigma matched_fields value may be a normalized/truncated form).
    let needle = leaf_commandline.to_lowercase();
    let leaf = events
        .iter()
        .find(|ev| field(ev, "CommandLine").map(|c| c.to_lowercase() == needle) == Some(true))
        .or_else(|| {
            events.iter().find(|ev| {
                field(ev, "CommandLine").map(|c| c.to_lowercase().contains(&needle)) == Some(true)
            })
        });
    let Some(&leaf) = leaf else {
        return Vec::new();
    };

    let mut chain: Vec<ProcessStep> = Vec::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current = leaf;
    if let Some(g) = field(current, "ProcessGuid") {
        visited.insert(g.to_string());
    }
    for _ in 0..max_depth {
        chain.push(to_step(current));
        let Some(pguid) = field(current, "ParentProcessGuid") else {
            break;
        };
        if pguid.is_empty() || !visited.insert(pguid.to_string()) {
            break; // no parent guid, or a cycle
        }
        match by_guid.get(pguid) {
            Some(&parent) => current = parent,
            None => {
                // Parent event not in the window — record the immediate parent
                // from the child's own ParentImage/ParentCommandLine and stop.
                let p = ProcessStep {
                    image: field(current, "ParentImage").unwrap_or("").to_string(),
                    command_line: field(current, "ParentCommandLine")
                        .unwrap_or("")
                        .to_string(),
                    user: String::new(),
                };
                if !p.image.is_empty() || !p.command_line.is_empty() {
                    chain.push(p);
                }
                break;
            }
        }
    }
    chain
}

/// Render a lineage chain root -> leaf as an indented tree for the L2 prompt.
pub fn format_lineage(chain: &[ProcessStep]) -> String {
    if chain.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    // chain is leaf-first; render root-first (chronological spawn order).
    for (depth, step) in chain.iter().rev().enumerate() {
        let indent = "  ".repeat(depth);
        let arrow = if depth == 0 { "" } else { "└─ " };
        let user = if step.user.is_empty() {
            String::new()
        } else {
            format!("  [user: {}]", step.user)
        };
        let cmd = if step.command_line.is_empty() {
            step.image.clone()
        } else {
            step.command_line.clone()
        };
        s.push_str(&format!("{indent}{arrow}{cmd}{user}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reconstructs_macro_to_powershell_chain() {
        // explorer (G0, out of window) -> winword (G1) -> powershell (G2, leaf)
        let winword = json!({
            "ProcessGuid": "G1", "Image": "C:\\Office\\WINWORD.EXE",
            "CommandLine": "winword.exe /n evil.docm", "User": "CORP\\alice",
            "ParentProcessGuid": "G0", "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "explorer.exe"
        });
        let powershell = json!({
            "ProcessGuid": "G2", "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA", "User": "CORP\\alice",
            "ParentProcessGuid": "G1", "ParentImage": "C:\\Office\\WINWORD.EXE",
            "ParentCommandLine": "winword.exe /n evil.docm"
        });
        let events: Vec<&Value> = vec![&powershell, &winword];
        let chain = build_process_lineage(&events, "powershell.exe -enc SQBFAFgA", 8);

        // leaf -> parent -> grandparent (grandparent from ParentImage fallback)
        assert_eq!(chain.len(), 3);
        assert!(chain[0].command_line.contains("powershell"));
        assert!(chain[1].command_line.contains("winword"));
        assert!(chain[2].image.contains("explorer"));
        assert_eq!(chain[0].user, "CORP\\alice");
    }

    #[test]
    fn empty_when_leaf_not_found() {
        let ev = json!({"ProcessGuid": "G1", "CommandLine": "cmd.exe", "Image": "cmd.exe"});
        let events: Vec<&Value> = vec![&ev];
        assert!(build_process_lineage(&events, "no-such-command", 8).is_empty());
        assert!(build_process_lineage(&[], "anything", 8).is_empty());
    }

    #[test]
    fn cycle_safe_and_depth_bounded() {
        // Self-referential guid must not loop forever.
        let a = json!({"ProcessGuid": "G1", "CommandLine": "a.exe", "Image": "a.exe", "ParentProcessGuid": "G1"});
        let events: Vec<&Value> = vec![&a];
        let chain = build_process_lineage(&events, "a.exe", 8);
        assert_eq!(chain.len(), 1); // visited set stops the self-loop
    }

    #[test]
    fn format_renders_root_first() {
        let chain = vec![
            ProcessStep {
                image: "powershell.exe".into(),
                command_line: "powershell -enc x".into(),
                user: "alice".into(),
            },
            ProcessStep {
                image: "winword.exe".into(),
                command_line: "winword /n evil.docm".into(),
                user: "alice".into(),
            },
        ];
        let out = format_lineage(&chain);
        let winword_pos = out.find("winword").unwrap();
        let ps_pos = out.find("powershell").unwrap();
        assert!(
            winword_pos < ps_pos,
            "root (winword) must render before leaf (powershell)"
        );
    }
}

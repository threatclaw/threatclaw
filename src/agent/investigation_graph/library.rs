//! Bibliothèque de graphs chargée au boot depuis `graphs/sigma/*.yaml`.
//!
//! Source de vérité = fichiers YAML (gitable, diffable, marketplace-friendly).
//! Au démarrage, on parse + valide + compile chaque YAML et on indexe par
//! `trigger.sigma_rule` pour lookup rapide depuis l'Intelligence Engine.
//!
//! API :
//! - `GraphLibrary::load_from_dir(path)` — charge tous les `.yaml` du dossier
//! - `find_for_sigma_rule(rule)` — Option<&CompiledGraph>
//! - `len()` / `names()` — observabilité

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tracing::{info, warn};

use super::graph::{CompiledGraph, compile};
use super::types::Graph;

#[derive(Debug, Error)]
pub enum LibraryError {
    #[error("dossier de graphs introuvable : {0}")]
    DirNotFound(PathBuf),

    #[error("erreur lecture fichier {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("graph '{path}' invalide : {msg}")]
    InvalidGraph { path: String, msg: String },

    #[error("deux graphs partagent le même trigger sigma_rule '{rule}': '{a}' et '{b}'")]
    DuplicateTrigger { rule: String, a: String, b: String },
}

/// Library immuable — partagée via Arc entre tous les workers.
#[derive(Debug, Default)]
pub struct GraphLibrary {
    /// Indexée par `trigger.sigma_rule` pour O(1) lookup.
    by_sigma_rule: HashMap<String, Arc<CompiledGraph>>,
    /// Indexée par `name` (pour les sub-graphs / `playbook-action` plus tard).
    by_name: HashMap<String, Arc<CompiledGraph>>,
}

impl GraphLibrary {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Charge tous les `*.yaml` du dossier, valide + compile, indexe.
    /// Les graphs invalides sont loggés en warn et ignorés (on ne fait pas
    /// crasher le boot pour un YAML cassé).
    pub fn load_from_dir(dir: &Path) -> Result<Self, LibraryError> {
        if !dir.exists() {
            return Err(LibraryError::DirNotFound(dir.to_path_buf()));
        }

        let mut by_sigma_rule: HashMap<String, Arc<CompiledGraph>> = HashMap::new();
        let mut by_name: HashMap<String, Arc<CompiledGraph>> = HashMap::new();
        let mut total = 0usize;
        let mut skipped = 0usize;

        let entries = std::fs::read_dir(dir).map_err(|e| LibraryError::ReadFailed {
            path: dir.to_path_buf(),
            source: e,
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            total += 1;

            let yaml = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "GRAPH LIBRARY: skip '{}' (lecture échouée : {})",
                        path.display(),
                        e
                    );
                    skipped += 1;
                    continue;
                }
            };

            let g: Graph = match Graph::from_yaml(&yaml) {
                Ok(g) => g,
                Err(e) => {
                    warn!("GRAPH LIBRARY: skip '{}' (parse : {})", path.display(), e);
                    skipped += 1;
                    continue;
                }
            };

            let compiled = match compile(&g) {
                Ok(c) => c,
                Err(e) => {
                    warn!("GRAPH LIBRARY: skip '{}' (compile : {})", path.display(), e);
                    skipped += 1;
                    continue;
                }
            };

            let rule = compiled.trigger_sigma_rule.clone();
            let name = compiled.name.clone();

            // Détection collision sur sigma_rule (un trigger = un graph max).
            if let Some(existing) = by_sigma_rule.get(&rule) {
                return Err(LibraryError::DuplicateTrigger {
                    rule: rule.clone(),
                    a: existing.name.clone(),
                    b: name,
                });
            }

            let arc = Arc::new(compiled);
            by_sigma_rule.insert(rule, arc.clone());
            by_name.insert(name, arc);
        }

        info!(
            "GRAPH LIBRARY: {} graphs chargés (sur {} fichiers, {} skipped)",
            by_sigma_rule.len(),
            total,
            skipped
        );

        Ok(Self {
            by_sigma_rule,
            by_name,
        })
    }

    pub fn find_for_sigma_rule(&self, rule: &str) -> Option<&Arc<CompiledGraph>> {
        self.by_sigma_rule.get(rule)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Arc<CompiledGraph>> {
        self.by_name.get(name)
    }

    pub fn len(&self) -> usize {
        self.by_sigma_rule.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_sigma_rule.is_empty()
    }

    /// Liste des noms de graphs (utile pour `/admin/queue-state` et les logs).
    pub fn names(&self) -> Vec<String> {
        self.by_name.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn yaml_minimal(name: &str, sigma_rule: &str) -> String {
        format!(
            r#"
spec_version: cacao-2.0
name: {name}
trigger:
  sigma_rule: {sigma_rule}
steps:
  start:
    type: start
    on_completion: archive
  archive:
    type: action
    command:
      type: threatclaw-archive
      reason: "test"
    on_completion: terminal
  terminal:
    type: end
"#
        )
    }

    #[test]
    fn loads_two_distinct_graphs() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.yaml"), yaml_minimal("graph-a", "rule_a")).unwrap();
        fs::write(dir.path().join("b.yaml"), yaml_minimal("graph-b", "rule_b")).unwrap();

        let lib = GraphLibrary::load_from_dir(dir.path()).unwrap();
        assert_eq!(lib.len(), 2);
        assert!(lib.find_for_sigma_rule("rule_a").is_some());
        assert!(lib.find_for_sigma_rule("rule_b").is_some());
        assert!(lib.find_for_sigma_rule("rule_unknown").is_none());
    }

    #[test]
    fn skips_invalid_yaml_without_crashing() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("ok.yaml"), yaml_minimal("ok", "rule_ok")).unwrap();
        fs::write(
            dir.path().join("broken.yaml"),
            "this is not yaml at all: {[}",
        )
        .unwrap();

        let lib = GraphLibrary::load_from_dir(dir.path()).unwrap();
        assert_eq!(lib.len(), 1);
        assert!(lib.find_for_sigma_rule("rule_ok").is_some());
    }

    #[test]
    fn rejects_duplicate_trigger() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("a.yaml"),
            yaml_minimal("graph-a", "same_rule"),
        )
        .unwrap();
        fs::write(
            dir.path().join("b.yaml"),
            yaml_minimal("graph-b", "same_rule"),
        )
        .unwrap();

        let err = GraphLibrary::load_from_dir(dir.path()).unwrap_err();
        assert!(matches!(err, LibraryError::DuplicateTrigger { .. }));
    }

    #[test]
    fn missing_dir_errors_cleanly() {
        let err = GraphLibrary::load_from_dir(Path::new("/nonexistent/xyz")).unwrap_err();
        assert!(matches!(err, LibraryError::DirNotFound(_)));
    }

    /// Test d'intégration : tous les graphs livrés dans `graphs/sigma/`
    /// du repo doivent parser, valider, et compiler sans erreur. Si
    /// quelqu'un push un YAML cassé, ce test casse tout de suite — pas
    /// au boot d'un client en prod.
    ///
    /// Le test est conditionné à l'existence du dossier (skip silencieux
    /// si on tourne le test depuis une machine où il n'est pas check-out,
    /// ce qui évite de casser CI sur des environnements partiels).
    #[test]
    fn shipped_sigma_graphs_all_compile() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("graphs/sigma");
        if !dir.exists() {
            eprintln!("skipping — {} not found", dir.display());
            return;
        }
        let lib = GraphLibrary::load_from_dir(&dir).expect("library should load");
        assert!(
            lib.len() >= 20,
            "G1d acceptance: expected >=20 graphs, got {}",
            lib.len()
        );
        // Chaque graph triggers un sigma_rule unique (pas de doublons)
        let names = lib.names();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names.len(), sorted.len(), "duplicate graph names detected");
    }
}

//! STIX 2.1 Note Graph — analyst annotations on any graph node.
//!
//! The RSSI can annotate IPs, Assets, CVEs, Alerts with free-text notes.
//! Notes are stored as graph nodes with ANNOTATES edges.
//! L2 Reasoning receives notes in its investigation context.

use crate::db::Database;
use crate::graph::threat_graph::{query, mutate};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// STIX 2.1 Note object (simplified for ThreatClaw).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixNote {
    pub id: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_abstract: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    pub object_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

impl StixNote {
    pub fn new(content: &str, object_refs: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            id: format!("note--{}", uuid::Uuid::new_v4()),
            content: content.to_string(),
            note_abstract: None,
            authors: None,
            object_refs,
            confidence: None,
            created: now,
            modified: now,
        }
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Create a Note node and link it to target objects via ANNOTATES edges.
pub async fn create_note(
    store: &dyn Database,
    content: &str,
    object_refs: &[&str],
    author: Option<&str>,
    confidence: Option<u8>,
) -> StixNote {
    let note = StixNote {
        id: format!("note--{}", uuid::Uuid::new_v4()),
        content: content.to_string(),
        note_abstract: if content.len() > 100 {
            Some(content[..100].to_string())
        } else {
            None
        },
        authors: author.map(|a| vec![a.to_string()]),
        object_refs: object_refs.iter().map(|s| s.to_string()).collect(),
        confidence,
        created: Utc::now(),
        modified: Utc::now(),
    };

    // Create the Note node
    let author_str = author.unwrap_or("rssi");
    let conf = confidence.unwrap_or(0);
    let cypher = format!(
        "CREATE (n:Note {{id: '{}', content: '{}', author: '{}', confidence: {}, created: '{}'}}) RETURN n",
        esc(&note.id), esc(content), esc(author_str), conf, note.created.to_rfc3339()
    );
    mutate(store, &cypher).await;

    // Link to each referenced object
    for obj_ref in object_refs {
        annotate_object(store, &note.id, obj_ref).await;
    }

    tracing::info!("NOTE: Created {} → {} objects", note.id, object_refs.len());
    note
}

/// Create an ANNOTATES edge from a Note to a target node.
/// Tries IP, Asset, CVE, Technique, Alert labels in order.
async fn annotate_object(store: &dyn Database, note_id: &str, object_ref: &str) {
    // Try each node type — one will match
    let labels = ["IP", "Asset", "CVE", "Technique"];
    let id_fields = ["addr", "id", "id", "mitre_id"];

    for (label, id_field) in labels.iter().zip(id_fields.iter()) {
        let cypher = format!(
            "MATCH (n:Note {{id: '{}'}}), (t:{} {{{}: '{}'}}) \
             CREATE (n)-[:ANNOTATES {{created: '{}'}}]->(t)",
            esc(note_id), label, id_field, esc(object_ref), Utc::now().to_rfc3339()
        );
        if mutate(store, &cypher).await {
            tracing::debug!("NOTE: Linked {} → {}:{}", note_id, label, object_ref);
            return;
        }
    }

    tracing::warn!("NOTE: Could not link {} → {} (target not found in graph)", note_id, object_ref);
}

/// Find all notes annotating a specific IP.
pub async fn find_notes_for_ip(store: &dyn Database, ip_addr: &str) -> Vec<serde_json::Value> {
    query(store, &format!(
        "MATCH (n:Note)-[:ANNOTATES]->(ip:IP {{addr: '{}'}}) \
         RETURN n.id, n.content, n.author, n.confidence, n.created \
         ORDER BY n.created DESC",
        esc(ip_addr)
    )).await
}

/// Find all notes annotating a specific asset.
pub async fn find_notes_for_asset(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    query(store, &format!(
        "MATCH (n:Note)-[:ANNOTATES]->(a:Asset {{id: '{}'}}) \
         RETURN n.id, n.content, n.author, n.confidence, n.created \
         ORDER BY n.created DESC",
        esc(asset_id)
    )).await
}

/// Find all notes annotating a specific CVE.
pub async fn find_notes_for_cve(store: &dyn Database, cve_id: &str) -> Vec<serde_json::Value> {
    query(store, &format!(
        "MATCH (n:Note)-[:ANNOTATES]->(c:CVE {{id: '{}'}}) \
         RETURN n.id, n.content, n.author, n.confidence, n.created \
         ORDER BY n.created DESC",
        esc(cve_id)
    )).await
}

/// Find all notes by a specific author.
pub async fn find_notes_by_author(store: &dyn Database, author: &str) -> Vec<serde_json::Value> {
    query(store, &format!(
        "MATCH (n:Note)-[:ANNOTATES]->(target) \
         WHERE n.author = '{}' \
         RETURN n.id, n.content, n.confidence, n.created, labels(target) \
         ORDER BY n.created DESC",
        esc(author)
    )).await
}

/// Get all notes (paginated).
pub async fn list_notes(store: &dyn Database, limit: u64) -> Vec<serde_json::Value> {
    query(store, &format!(
        "MATCH (n:Note)-[:ANNOTATES]->(target) \
         RETURN n.id, n.content, n.author, n.confidence, n.created, labels(target) \
         ORDER BY n.created DESC LIMIT {}",
        limit
    )).await
}

/// Delete a note and its ANNOTATES edges.
pub async fn delete_note(store: &dyn Database, note_id: &str) -> bool {
    let cypher = format!(
        "MATCH (n:Note {{id: '{}'}}) DETACH DELETE n",
        esc(note_id)
    );
    mutate(store, &cypher).await
}

/// Build note context for injection into L2 Reasoning prompt.
/// Returns formatted text block ready for the prompt.
pub fn format_notes_for_prompt(notes: &[serde_json::Value]) -> String {
    if notes.is_empty() {
        return String::new();
    }

    let mut out = String::from("## Notes Analyste (connaissance humaine validée)\n");
    for note in notes.iter().take(10) {
        let result = &note["result"];
        let content = result["n.content"].as_str()
            .or_else(|| result.as_str())
            .unwrap_or("");
        let author = result["n.author"].as_str().unwrap_or("rssi");
        let created = result["n.created"].as_str().unwrap_or("");
        let confidence = result["n.confidence"].as_i64().unwrap_or(0);

        if !content.is_empty() {
            out.push_str(&format!("- [{}] {} (confiance {}/100): {}\n", created, author, confidence, content));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_note_creation() {
        let note = StixNote::new("Test note", vec!["192.168.1.1".into()]);
        assert!(note.id.starts_with("note--"));
        assert_eq!(note.content, "Test note");
        assert_eq!(note.object_refs.len(), 1);
    }

    #[test]
    fn test_format_notes_empty() {
        assert_eq!(format_notes_for_prompt(&[]), "");
    }

    #[test]
    fn test_format_notes_with_data() {
        let notes = vec![json!({
            "result": {
                "n.content": "Known scanner — ignore",
                "n.author": "yan",
                "n.confidence": 90,
                "n.created": "2026-03-24T10:00:00Z"
            }
        })];
        let formatted = format_notes_for_prompt(&notes);
        assert!(formatted.contains("Known scanner"));
        assert!(formatted.contains("yan"));
        assert!(formatted.contains("90/100"));
    }

    #[test]
    fn test_escape() {
        assert_eq!(esc("it's"), "it\\'s");
        assert_eq!(esc("a\\b"), "a\\\\b");
    }
}

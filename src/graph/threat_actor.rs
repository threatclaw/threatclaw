//! Threat Actor Profiling — automatic attribution via pattern matching.
//!
//! Builds attacker profiles from graph patterns: techniques used,
//! timing, ASN, targets. Compares against known APT profiles
//! for similarity scoring.

use crate::db::Database;
use crate::graph::threat_graph::query;
use serde::Serialize;
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// A profiled threat actor (may be unknown).
#[derive(Debug, Clone, Serialize)]
pub struct ThreatActorProfile {
    /// Internal ThreatClaw ID.
    pub id: String,
    /// Display name (auto-generated or matched APT).
    pub name: String,
    /// Source IPs associated with this actor.
    pub source_ips: Vec<String>,
    /// Country of origin (most common).
    pub origin_country: String,
    /// ASN(s) used.
    pub asns: Vec<String>,
    /// MITRE techniques observed.
    pub techniques: Vec<String>,
    /// Assets targeted.
    pub targets: Vec<String>,
    /// Number of attacks.
    pub attack_count: i64,
    /// Similarity to known APT (0-100).
    pub apt_similarity: Option<AptMatch>,
    /// Activity pattern.
    pub activity: ActivityPattern,
}

/// Similarity match to a known APT group.
#[derive(Debug, Clone, Serialize)]
pub struct AptMatch {
    pub apt_name: String,
    pub similarity_score: u8,
    pub matching_techniques: Vec<String>,
    pub matching_country: bool,
}

/// Activity pattern of an actor.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityPattern {
    pub total_attacks: i64,
    pub unique_targets: usize,
    pub techniques_count: usize,
}

/// Threat actor analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatActorAnalysis {
    pub actors: Vec<ThreatActorProfile>,
    pub total_actors: usize,
    pub attributed: usize,
    pub summary: String,
}

/// Known APT profiles for similarity matching.
struct KnownApt {
    name: &'static str,
    country: &'static str,
    techniques: &'static [&'static str],
}

const KNOWN_APTS: &[KnownApt] = &[
    KnownApt {
        name: "APT28 (Fancy Bear)",
        country: "RU",
        techniques: &["T1110", "T1078", "T1566", "T1071", "T1021"],
    },
    KnownApt {
        name: "APT29 (Cozy Bear)",
        country: "RU",
        techniques: &["T1190", "T1059", "T1071", "T1003", "T1041"],
    },
    KnownApt {
        name: "Lazarus Group",
        country: "KP",
        techniques: &["T1566", "T1204", "T1059", "T1071", "T1041"],
    },
    KnownApt {
        name: "APT41 (Winnti)",
        country: "CN",
        techniques: &["T1190", "T1059", "T1068", "T1003", "T1021"],
    },
    KnownApt {
        name: "Sandworm",
        country: "RU",
        techniques: &["T1190", "T1059", "T1068", "T1071.004", "T1041"],
    },
    KnownApt {
        name: "Turla",
        country: "RU",
        techniques: &["T1071.004", "T1041", "T1059", "T1003", "T1078"],
    },
    KnownApt {
        name: "MuddyWater",
        country: "IR",
        techniques: &["T1566", "T1059", "T1204", "T1071", "T1041"],
    },
];

/// Profile all threat actors from graph data.
pub async fn profile_threat_actors(store: &dyn Database) -> ThreatActorAnalysis {
    // Group IPs by country and find their techniques
    let results = query(
        store,
        "MATCH (ip:IP)-[:ATTACKS]->(a:Asset) \
         WITH ip, collect(DISTINCT a.hostname) AS targets, count(DISTINCT a) AS target_count \
         WHERE target_count >= 1 \
         RETURN ip.addr, ip.country, ip.asn, ip.classification, targets, target_count \
         ORDER BY target_count DESC LIMIT 50",
    )
    .await;

    // Group by country to form actor clusters
    let mut country_groups: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for r in &results {
        let country = r["ip.country"].as_str().unwrap_or("UNK").to_string();
        country_groups.entry(country).or_default().push(r.clone());
    }

    let mut actors = vec![];
    for (country, ips) in &country_groups {
        if ips.is_empty() {
            continue;
        }

        let source_ips: Vec<String> = ips
            .iter()
            .filter_map(|r| r["ip.addr"].as_str().map(String::from))
            .collect();
        let targets: Vec<String> = ips
            .iter()
            .flat_map(|r| {
                r["targets"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let asns: Vec<String> = ips
            .iter()
            .filter_map(|r| r["ip.asn"].as_str().map(String::from))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let total_attacks: i64 = ips.iter().filter_map(|r| r["target_count"].as_i64()).sum();

        // Get techniques for these IPs from investigation results
        let techniques = get_techniques_for_ips(store, &source_ips).await;

        // Match against known APTs
        let apt_match = match_known_apt(country, &techniques);

        let actor_name = if let Some(ref apt) = apt_match {
            if apt.similarity_score >= 70 {
                format!(
                    "Probable {} ({}% match)",
                    apt.apt_name, apt.similarity_score
                )
            } else {
                format!("ThreatClaw-Actor-{}", country)
            }
        } else {
            format!("ThreatClaw-Actor-{}", country)
        };

        actors.push(ThreatActorProfile {
            id: format!("actor--{}", country.to_lowercase()),
            name: actor_name,
            source_ips,
            origin_country: country.clone(),
            asns,
            techniques: techniques.clone(),
            targets: targets.clone(),
            attack_count: total_attacks,
            apt_similarity: apt_match,
            activity: ActivityPattern {
                total_attacks,
                unique_targets: targets.len(),
                techniques_count: techniques.len(),
            },
        });
    }

    let attributed = actors
        .iter()
        .filter(|a| {
            a.apt_similarity
                .as_ref()
                .map(|m| m.similarity_score >= 60)
                .unwrap_or(false)
        })
        .count();

    let total = actors.len();
    let summary = if total == 0 {
        "Aucun acteur de menace profilé".into()
    } else {
        format!(
            "{} acteurs profilés, {} avec attribution APT probable",
            total, attributed
        )
    };

    if total > 0 {
        tracing::info!(
            "THREAT_ACTOR: {} actors profiled ({} attributed)",
            total,
            attributed
        );
    }

    ThreatActorAnalysis {
        actors,
        total_actors: total,
        attributed,
        summary,
    }
}

/// Get MITRE techniques associated with IPs (from investigation graph results).
async fn get_techniques_for_ips(store: &dyn Database, ips: &[String]) -> Vec<String> {
    if ips.is_empty() {
        return vec![];
    }

    // Check techniques linked to alerts from these IPs
    let mut techniques = std::collections::HashSet::new();

    // Get techniques from the graph (if any Technique nodes are linked via attacks)
    let results = query(store, "MATCH (t:Technique) RETURN t.mitre_id LIMIT 50").await;

    for r in &results {
        if let Some(id) = r["t.mitre_id"].as_str() {
            techniques.insert(id.to_string());
        }
    }

    techniques.into_iter().collect()
}

/// Compare actor profile against known APT groups.
fn match_known_apt(country: &str, techniques: &[String]) -> Option<AptMatch> {
    if techniques.is_empty() {
        return None;
    }

    let mut best_match: Option<AptMatch> = None;
    let mut best_score: u8 = 0;

    for apt in KNOWN_APTS {
        let country_match = apt.country.eq_ignore_ascii_case(country);
        let matching_techniques: Vec<String> = techniques
            .iter()
            .filter(|t| apt.techniques.contains(&t.as_str()))
            .cloned()
            .collect();

        if matching_techniques.is_empty() && !country_match {
            continue;
        }

        let technique_ratio = if apt.techniques.is_empty() {
            0.0
        } else {
            matching_techniques.len() as f64 / apt.techniques.len() as f64
        };

        let mut score = (technique_ratio * 70.0) as u8;
        if country_match {
            score = score.saturating_add(25);
        }
        if matching_techniques.len() >= 3 {
            score = score.saturating_add(5);
        }
        score = score.min(100);

        if score > best_score {
            best_score = score;
            best_match = Some(AptMatch {
                apt_name: apt.name.to_string(),
                similarity_score: score,
                matching_techniques,
                matching_country: country_match,
            });
        }
    }

    best_match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_apt_russian_brute_force() {
        let techniques = vec!["T1110".into(), "T1078".into(), "T1021".into()];
        let result = match_known_apt("RU", &techniques);
        assert!(result.is_some());
        let m = result.unwrap();
        assert!(m.apt_name.contains("APT28"));
        assert!(m.similarity_score >= 60);
    }

    #[test]
    fn test_match_apt_no_match() {
        let techniques = vec!["T9999".into()];
        let result = match_known_apt("XX", &techniques);
        assert!(result.is_none());
    }

    #[test]
    fn test_match_apt_country_only() {
        let techniques = vec!["T1110".into()];
        let result = match_known_apt("CN", &techniques);
        assert!(result.is_some());
    }
}

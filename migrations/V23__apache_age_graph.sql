-- V23: Apache AGE — Graph Intelligence for ThreatClaw
-- Adds graph-based threat correlation, investigation paths, and STIX data model.
-- Requires Apache AGE extension (compiled from https://github.com/apache/age PG16 branch).
--
-- The graph 'threat_graph' stores:
-- - IP addresses, assets, CVEs, alerts, findings as vertices
-- - Relationships (attacks, targets, exploits, etc.) as edges
-- - MITRE ATT&CK techniques as navigable graph
-- - Investigation trails as subgraphs

-- Enable AGE extension
CREATE EXTENSION IF NOT EXISTS age;
LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- Create the main threat graph
SELECT create_graph('threat_graph');

-- Vertex labels (STIX-inspired node types)
SELECT create_vlabel('threat_graph', 'IP');           -- IP addresses (external/internal)
SELECT create_vlabel('threat_graph', 'Asset');         -- Servers, workstations, firewalls
SELECT create_vlabel('threat_graph', 'CVE');           -- Vulnerabilities
SELECT create_vlabel('threat_graph', 'Alert');         -- Sigma alerts
SELECT create_vlabel('threat_graph', 'Finding');       -- Skill findings
SELECT create_vlabel('threat_graph', 'ThreatActor');   -- Known threat actors (APT groups)
SELECT create_vlabel('threat_graph', 'Technique');     -- MITRE ATT&CK techniques
SELECT create_vlabel('threat_graph', 'UserAccount');   -- System users
SELECT create_vlabel('threat_graph', 'Domain');        -- Domain names
SELECT create_vlabel('threat_graph', 'FileHash');      -- File hashes (SHA-256, MD5)
SELECT create_vlabel('threat_graph', 'Investigation'); -- Investigation trails

-- Edge labels (relationship types)
SELECT create_elabel('threat_graph', 'ATTACKS');           -- IP attacks Asset
SELECT create_elabel('threat_graph', 'TARGETS');           -- Alert targets Asset
SELECT create_elabel('threat_graph', 'SOURCE_IP');         -- Alert source IP
SELECT create_elabel('threat_graph', 'AFFECTS');           -- CVE affects Asset
SELECT create_elabel('threat_graph', 'REFERENCES_CVE');    -- Finding references CVE
SELECT create_elabel('threat_graph', 'USES_TECHNIQUE');    -- Attack uses MITRE technique
SELECT create_elabel('threat_graph', 'EXPLOITED_BY');      -- CVE exploited by ThreatActor
SELECT create_elabel('threat_graph', 'LOGGED_INTO');       -- User logged into Asset
SELECT create_elabel('threat_graph', 'RUNS_SERVICE');      -- Asset runs vulnerable service
SELECT create_elabel('threat_graph', 'RESOLVES_TO');       -- Domain resolves to IP
SELECT create_elabel('threat_graph', 'KNOWN_C2');          -- Domain/IP known C2 for actor
SELECT create_elabel('threat_graph', 'FOUND_ON');          -- Hash found on Asset
SELECT create_elabel('threat_graph', 'PART_OF');           -- Step part of Investigation
SELECT create_elabel('threat_graph', 'MITIGATED_BY');      -- Technique mitigated by countermeasure
SELECT create_elabel('threat_graph', 'NEXT_STEP');         -- ATT&CK technique leads to next technique

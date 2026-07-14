-- V106 — Align the stored ATT&CK vocabulary on Enterprise v19.
--
-- Backfills two distinct defects, both in data WE derived. Data a third party DECLARED is left
-- alone on purpose: the Sentinel connector's mitre_tactics/mitre_techniques mirror what Microsoft
-- Sentinel told us, and we do not rewrite someone else's declaration.
--
-- 1. RETIRED TACTIC + REVOKED TECHNIQUES (ATT&CK v19)
--    v19 retired `defense-evasion`, splitting it into `stealth` (hide the activity) and
--    `defense-impairment` (break the defenses), and REVOKED the technique ids that moved:
--        T1070.001 -> T1685.005   Clear Windows Event Logs
--        T1070.002 -> T1685.006   Clear Linux or Mac System Logs
--        T1562     -> T1685       Disable or Modify Tools
--        T1562.001 -> T1685
--        T1562.004 -> T1686       Disable or Modify System Firewall
--    Rows kept pointing at ids that no longer resolve on attack.mitre.org — a dead link for the
--    RSSI. In ATT&CK a `revoked-by` relation means "same thing, renamed", so following it updates a
--    reference; it does not falsify history.
--    The tactic is derived FROM the technique wherever we have one, so the stealth /
--    defense-impairment split is resolved from data instead of guessed.
--
-- 2. TWO SPELLINGS OF THE SAME TACTIC (pre-existing, nothing to do with v19)
--    Two producers wrote `mitre_tactic` and disagreed: sigma_engine passed the Sigma tag through
--    verbatim (`credential_access`, underscore) while dfir_triage emitted its own literals
--    (`credential-access`, hyphen). risk_aggregator collects that column into a set to score
--    TACTIC DIVERSITY — so one tactic counted as TWO, inflating the risk of any asset both engines
--    saw, and able to fire a notable that should never have fired. The code now funnels both
--    through mitre_mapping::canonical_tactic(); this normalises the rows already on disk.
--    (RBA's window is a rolling 7d so it would self-heal there, but the history stays wrong on
--    screen — and a scoring artefact you know about is one you fix.)
--
-- No BEGIN/COMMIT: refinery already wraps each migration in its own transaction, and committing
-- here would close it before refinery records the version.
-- Idempotent AND write-free on re-run: every UPDATE is guarded by IS DISTINCT FROM, so a second
-- pass touches zero rows (no dead tuples, no WAL churn).

-- Helpers live in pg_temp: session-local, so they vanish when the migration's connection closes —
-- nothing is left behind in the schema, and the mapping is written once instead of once per table.

CREATE FUNCTION pg_temp.canon_technique(technique TEXT) RETURNS TEXT AS $$
    SELECT CASE technique
        WHEN 'T1070.001' THEN 'T1685.005'
        WHEN 'T1070.002' THEN 'T1685.006'
        WHEN 'T1562'     THEN 'T1685'
        WHEN 'T1562.001' THEN 'T1685'
        WHEN 'T1562.004' THEN 'T1686'
        ELSE technique
    END
$$ LANGUAGE sql IMMUTABLE;

-- Same rule as mitre_mapping::canonical_tactic(): lowercase + hyphenate, then resolve the v19
-- split from the technique when we have one, else fold the retired name onto `stealth` (the larger
-- successor). Takes the ALREADY-CANONICAL technique, so callers must normalise that first.
CREATE FUNCTION pg_temp.canon_tactic(tactic TEXT, technique TEXT) RETURNS TEXT AS $$
    SELECT CASE
        WHEN tactic IS NULL OR tactic = '' THEN tactic
        WHEN technique LIKE 'T1685%' OR technique LIKE 'T1686%' THEN 'defense-impairment'
        WHEN lower(replace(tactic, '_', '-')) = 'defense-evasion' THEN 'stealth'
        ELSE lower(replace(tactic, '_', '-'))
    END
$$ LANGUAGE sql IMMUTABLE;

-- Array elements are either a bare id ('T1070.001') or the descriptive form written by
-- baseline_for_rule / the L2 LLM ('T1070.001 Indicator Removal: Clear Windows Event Logs').
-- Anchor on the leading id and keep whatever trails it, so a human- or LLM-written description
-- survives verbatim. Longest ids first: T1562.001 must not be eaten by the T1562 rule.
CREATE FUNCTION pg_temp.canon_technique_str(e TEXT) RETURNS TEXT AS $$
    SELECT regexp_replace(
             regexp_replace(
               regexp_replace(
                 regexp_replace(
                   regexp_replace(e, '^T1070\.001', 'T1685.005'),
                                      '^T1070\.002', 'T1685.006'),
                                      '^T1562\.001', 'T1685'),
                                      '^T1562\.004', 'T1686'),
                                      '^T1562(?![.\d])', 'T1685')
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.canon_technique_arr(arr TEXT[]) RETURNS TEXT[] AS $$
    SELECT ARRAY(SELECT pg_temp.canon_technique_str(e) FROM unnest(arr) AS e)
$$ LANGUAGE sql IMMUTABLE;

-- ── Scalar columns: technique first, then derive the tactic from the NEW id ──────────────────

UPDATE risk_events
   SET mitre_technique = pg_temp.canon_technique(mitre_technique)
 WHERE mitre_technique IS DISTINCT FROM pg_temp.canon_technique(mitre_technique);

UPDATE risk_events
   SET mitre_tactic = pg_temp.canon_tactic(mitre_tactic, mitre_technique)
 WHERE mitre_tactic IS DISTINCT FROM pg_temp.canon_tactic(mitre_tactic, mitre_technique);

UPDATE forensic_timeline
   SET mitre_technique = pg_temp.canon_technique(mitre_technique)
 WHERE mitre_technique IS DISTINCT FROM pg_temp.canon_technique(mitre_technique);

UPDATE forensic_timeline
   SET mitre_tactic = pg_temp.canon_tactic(mitre_tactic, mitre_technique)
 WHERE mitre_tactic IS DISTINCT FROM pg_temp.canon_tactic(mitre_tactic, mitre_technique);

-- ── Technique arrays ─────────────────────────────────────────────────────────────────────────

UPDATE incidents
   SET mitre_techniques = pg_temp.canon_technique_arr(mitre_techniques)
 WHERE mitre_techniques IS DISTINCT FROM pg_temp.canon_technique_arr(mitre_techniques);

UPDATE attack_paths
   SET mitre_techniques = pg_temp.canon_technique_arr(mitre_techniques)
 WHERE mitre_techniques IS DISTINCT FROM pg_temp.canon_technique_arr(mitre_techniques);

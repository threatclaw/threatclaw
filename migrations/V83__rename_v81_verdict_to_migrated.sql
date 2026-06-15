-- migrations/V83__rename_v81_verdict_to_migrated.sql
--
-- Safety net for early adopters of v1.0.37-beta and v1.0.38-beta.
-- V81 originally wrote verdict='false_positive' and status='false_positive'
-- on the rows it reclassified. v1.0.39 renames that disposition to
-- 'migrated' (more accurate semantic, avoids stigmatising rows that
-- correspond to legitimate evaluation traffic with a misleading title).
--
-- V81 in v1.0.39+ already writes 'migrated' directly, so for fresh
-- v1.0.36 → v1.0.39 upgrades this migration is a no-op. It only
-- rewrites rows that were touched by V81 under the previous label.
--
-- Strict scope: only rows authored by the V81 migration are touched.
-- Operator-triaged FPs (resolved_by NOT LIKE 'system:v1.0.37-engine-fix%')
-- are left as-is — never re-label an analyst decision.

BEGIN;

UPDATE sigma_alerts
SET status = 'migrated'
WHERE status = 'false_positive'
  AND resolved_by = 'system:v1.0.37-engine-fix-migration';

UPDATE incidents
SET verdict = 'migrated'
WHERE verdict = 'false_positive'
  AND status = 'resolved'
  AND notes::text LIKE '%system:v1.0.37-engine-fix-migration%';

COMMIT;

-- Sprint 5 #2 — touch_incident dedup pattern tracking.
--
-- `touch_incident(id, delta)` was bumping `alert_count` on every dedup
-- hit, including the SAME pattern firing repeatedly (same rule, same
-- graph). On a noisy asset the count grew unbounded for a single root
-- cause, distorting the "how spicy is this incident" signal.
--
-- We now record the most recent pattern key (sigma rule_id or graph
-- name) and only bump the count when the pattern actually changes —
-- i.e. when it's *new evidence*, not the same alert re-firing.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_pattern_key TEXT;

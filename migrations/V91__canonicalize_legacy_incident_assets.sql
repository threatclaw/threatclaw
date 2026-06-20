-- One-time: collapse case-fragmented legacy incident assets onto the canonical id.
--
-- The asset-key code fix (resolve_asset_key) keys NEW incidents by the canonical
-- (lowercased) asset id, but legacy incidents were written under the asset's
-- original-case name/hostname (e.g. SRV-CYBE06-001 alongside srv-cybe06-001),
-- splitting one host's incident history across two keys in the dashboard.
--
-- Rewrite incidents.asset to the matching asset id when they differ only by case.
-- Unambiguous: asset ids are the primary key (unique) and already lowercase, so
-- lower(i.asset) can match at most one asset id. Validated read-only on cyb06
-- (2026-06-20): SRV-CYBE06-001 -> srv-cybe06-001 (10), SRV-VALO01-001 ->
-- srv-valo01-001 (3); no other matches.
--
-- Out of scope (deeper, riskier): the `syslog-observed-<host>` legacy id artifact,
-- which would require renormalizing the asset id itself and every string FK that
-- references it. The enrol path no longer creates such ids. See detection-chain audit.
UPDATE incidents i
   SET asset = a.id, updated_at = NOW()
  FROM assets a
 WHERE i.asset <> a.id
   AND lower(i.asset) = lower(a.id);

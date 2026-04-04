-- V31: Asset enrichment columns — multi-source tracking, software inventory, user edit protection

-- Track which discovery sources have contributed to this asset
-- e.g. ["wazuh", "nmap", "glpi", "dhcp"]
ALTER TABLE assets ADD COLUMN IF NOT EXISTS sources TEXT[] DEFAULT '{}';

-- Software inventory from various sources (Trivy, GLPI, Nmap service detection)
-- Format: [{"name": "nginx", "version": "1.21.6", "source": "trivy", "detected_at": "2026-04-04T..."}]
ALTER TABLE assets ADD COLUMN IF NOT EXISTS software JSONB DEFAULT '[]';

-- Tracks which fields the user has manually edited via dashboard
-- These fields are protected from being overwritten by auto-discovery merges
-- e.g. ["name", "hostname", "owner", "tags"]
ALTER TABLE assets ADD COLUMN IF NOT EXISTS user_modified TEXT[] DEFAULT '{}';

-- Backfill sources from existing single source field
UPDATE assets SET sources = ARRAY[source] WHERE sources = '{}' AND source IS NOT NULL AND source != '';

-- Indexes for hostname resolution (case-insensitive) used by IE alert-asset mapping
CREATE INDEX IF NOT EXISTS idx_assets_hostname_lower ON assets (LOWER(hostname));
CREATE INDEX IF NOT EXISTS idx_assets_name_lower ON assets (LOWER(name));

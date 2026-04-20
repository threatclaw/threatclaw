-- Graph storage normalisé — typed edges + catalog + pg_notify trigger.
--
-- Voir internal/ADR/ADR-045 pour le rationale. Prérequis pour le
-- blast radius auto-trigger (ADR-048) et les outcome rules v1.1.
--
-- Backward-compatible :
--  - Tables nouvelles, aucune table existante modifiée en v1.0.8.
--  - Les modules src/graph/* existants continuent de fonctionner sur
--    leurs anciennes sources (assets, identities…) pendant la fenêtre
--    de shadow-mode (2 semaines). Switch complet en v1.0.9.
--  - Les ids de nodes réutilisent le format existant `"<kind>:<value>"`
--    (ex: `host:prod-sql01`, `user:alice@corp.fr`).

-- ── graph_nodes ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_nodes (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    properties   JSONB NOT NULL DEFAULT '{}'::jsonb,
    criticality  SMALLINT NOT NULL DEFAULT 0
                 CHECK (criticality BETWEEN 0 AND 10),
    fqdn         TEXT,
    display_name TEXT,
    source_skill TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_kind
    ON graph_nodes (kind);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_fqdn
    ON graph_nodes (fqdn) WHERE fqdn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_graph_nodes_props
    ON graph_nodes USING GIN (properties jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_updated
    ON graph_nodes (updated_at DESC);

-- ── graph_edges ─────────────────────────────────────────────
-- Pas de FK sur graph_edge_catalog.kind : le catalog est seed-only
-- pour référence, on préfère tolérer les kinds extensibles par les
-- skills premium (cf. ADR-045 rationale).

CREATE TABLE IF NOT EXISTS graph_edges (
    src_id       TEXT NOT NULL
                 REFERENCES graph_nodes(id) ON DELETE CASCADE,
    dst_id       TEXT NOT NULL
                 REFERENCES graph_nodes(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    weight       SMALLINT NOT NULL DEFAULT 1
                 CHECK (weight BETWEEN 1 AND 10),
    properties   JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_skill TEXT,
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    PRIMARY KEY (src_id, dst_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_dst
    ON graph_edges (dst_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_kind_src
    ON graph_edges (src_id, kind);
CREATE INDEX IF NOT EXISTS idx_graph_edges_expires
    ON graph_edges (expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_graph_edges_observed
    ON graph_edges (observed_at DESC);

-- ── graph_edge_catalog ──────────────────────────────────────
-- Catalog de référence. UI l'utilise pour les dropdowns de création
-- d'outcome rules (v1.1). Alimenté au seed + par les skills lors
-- de l'installation.

CREATE TABLE IF NOT EXISTS graph_edge_catalog (
    kind              TEXT PRIMARY KEY,
    abuse_description TEXT NOT NULL,
    default_weight    SMALLINT NOT NULL DEFAULT 1
                      CHECK (default_weight BETWEEN 1 AND 10),
    source_skills     TEXT[] NOT NULL DEFAULT '{}'::text[],
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed initial — couvre AD, Azure AD, AWS, Cloudflare, Proxmox,
-- réseau, data. Voir ADR-045 §"Edges to model".
INSERT INTO graph_edge_catalog (kind, abuse_description, default_weight, source_skills)
VALUES
    ('MemberOf',       'Inherited AD group permissions',        1, '{skill-active-directory}'),
    ('AdminTo',        'Local admin rights on target host',     1, '{skill-active-directory,skill-osquery}'),
    ('HasSession',     'Active user session on target host',    2, '{skill-active-directory,skill-osquery}'),
    ('GenericAll',     'Full ACL control over target object',   1, '{skill-active-directory}'),
    ('GenericWrite',   'Write ACL on target object',            1, '{skill-active-directory}'),
    ('WriteDACL',      'Modify DACL of target',                 1, '{skill-active-directory}'),
    ('Owns',           'AD object ownership',                   1, '{skill-active-directory}'),
    ('CanRDP',         'RDP access permitted',                  2, '{skill-active-directory}'),
    ('CanPSRemote',    'PowerShell remoting permitted',         2, '{skill-active-directory}'),
    ('ForceChangePwd', 'Can reset password without knowing it', 1, '{skill-active-directory}'),
    ('AddMember',      'Can add members to group',              1, '{skill-active-directory}'),
    ('AZOwns',         'Azure owner role assignment',           1, '{skill-active-directory}'),
    ('AZContributor',  'Azure contributor role',                1, '{skill-active-directory}'),
    ('AZUserAccessAdmin', 'Azure UserAccessAdministrator role', 1, '{skill-active-directory}'),
    ('AZAddSecret',    'Azure add secret to app',               1, '{skill-active-directory}'),
    ('AssumeRole',     'AWS role assumption permitted',         1, '{}'),
    ('S3Access',       'AWS S3 bucket read/write',              2, '{}'),
    ('ZeroTrustAccess','Cloudflare Access policy allow',        2, '{skill-cloudflare}'),
    ('HypervisorOf',   'Proxmox hypervisor of VM',              1, '{skill-proxmox}'),
    ('VMConsole',      'VM console access equals root',         1, '{skill-proxmox}'),
    ('DbCredsIn',      'App config contains DB credentials',    3, '{skill-osquery}'),
    ('ReachableOn',    'Network L4 reachability on port',       3, '{skill-nmap-discovery,skill-suricata}'),
    ('ResolvesTo',     'DNS resolution',                        3, '{skill-suricata,skill-zeek}'),
    ('Stores',         'Asset stores data class',               1, '{skill-classifier}')
ON CONFLICT (kind) DO NOTHING;

-- ── updated_at trigger on graph_nodes ───────────────────────
CREATE OR REPLACE FUNCTION graph_nodes_set_updated()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_graph_nodes_updated ON graph_nodes;
CREATE TRIGGER trg_graph_nodes_updated
    BEFORE UPDATE ON graph_nodes
    FOR EACH ROW
    EXECUTE FUNCTION graph_nodes_set_updated();

-- ── LISTEN/NOTIFY pour cache invalidation ───────────────────
-- Payload = JSON minimal : { "op": "...", "kind": "node|edge", "id": "..." }
-- Le cache petgraph in-memory (ADR-045) LISTEN 'graph_update' et
-- refresh les éléments touchés.

CREATE OR REPLACE FUNCTION graph_notify_change()
RETURNS TRIGGER AS $$
DECLARE
    payload JSON;
    obj_id  TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF TG_TABLE_NAME = 'graph_nodes' THEN
            obj_id := OLD.id;
        ELSE
            obj_id := OLD.src_id || '->' || OLD.dst_id || ':' || OLD.kind;
        END IF;
    ELSE
        IF TG_TABLE_NAME = 'graph_nodes' THEN
            obj_id := NEW.id;
        ELSE
            obj_id := NEW.src_id || '->' || NEW.dst_id || ':' || NEW.kind;
        END IF;
    END IF;

    payload := json_build_object(
        'op',   TG_OP,
        'kind', CASE WHEN TG_TABLE_NAME = 'graph_nodes' THEN 'node' ELSE 'edge' END,
        'id',   obj_id
    );
    PERFORM pg_notify('graph_update', payload::text);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_graph_nodes_notify ON graph_nodes;
CREATE TRIGGER trg_graph_nodes_notify
    AFTER INSERT OR UPDATE OR DELETE ON graph_nodes
    FOR EACH ROW
    EXECUTE FUNCTION graph_notify_change();

DROP TRIGGER IF EXISTS trg_graph_edges_notify ON graph_edges;
CREATE TRIGGER trg_graph_edges_notify
    AFTER INSERT OR UPDATE OR DELETE ON graph_edges
    FOR EACH ROW
    EXECUTE FUNCTION graph_notify_change();

-- ── View pratique pour les requêtes de blast radius ─────────
-- Joint edge avec catalog pour récupérer abuse_description à l'affichage.

CREATE OR REPLACE VIEW graph_edges_with_catalog AS
SELECT
    e.src_id, e.dst_id, e.kind, e.weight, e.properties,
    e.source_skill, e.observed_at, e.expires_at,
    c.abuse_description,
    c.default_weight
FROM graph_edges e
LEFT JOIN graph_edge_catalog c ON c.kind = e.kind
WHERE e.expires_at IS NULL OR e.expires_at > NOW();

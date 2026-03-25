-- V24: Assets Management — full asset inventory with categories, roles, fingerprinting
-- This is the foundation for intelligent asset-based security analysis.

-- ═══════════════════════════════════════════════════════════════
-- ASSETS TABLE — every device/service the client owns or discovers
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS assets (
    id              TEXT PRIMARY KEY,               -- UUID or user-defined ID
    name            TEXT NOT NULL,                   -- Human-readable name ("srv-web-01", "monsite.fr")
    category        TEXT NOT NULL DEFAULT 'unknown', -- server, workstation, mobile, website, network, printer, iot, ot, cloud, unknown
    subcategory     TEXT,                            -- web, db, mail, dns, ad, wordpress, plc, camera...
    role            TEXT,                            -- "Serveur de base de données production"
    criticality     TEXT NOT NULL DEFAULT 'medium',  -- critical, high, medium, low

    -- Network identifiers
    ip_addresses    TEXT[] DEFAULT '{}',             -- Can have multiple IPs
    mac_address     TEXT,                            -- Primary MAC address
    hostname        TEXT,                            -- Hostname (from DHCP, Nmap, AD)
    fqdn            TEXT,                            -- Fully qualified domain name
    url             TEXT,                            -- For websites/apps

    -- Fingerprint data
    os              TEXT,                            -- "Linux Ubuntu 22.04", "Windows Server 2022"
    os_confidence   REAL DEFAULT 0.0,               -- 0.0-1.0
    mac_vendor      TEXT,                            -- "Apple Inc.", "Dell Technologies" (from OUI lookup)
    services        JSONB DEFAULT '[]',             -- [{port: 80, service: "http", product: "nginx"}]

    -- Provenance
    source          TEXT NOT NULL DEFAULT 'manual',  -- manual, nmap, pfsense, dhcp, alert-auto, ad, wazuh
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Context
    owner           TEXT,                            -- "Jean Dupont" or "Equipe Dev"
    location        TEXT,                            -- "Bureau Paris", "Datacenter OVH"
    tags            TEXT[] DEFAULT '{}',             -- Custom tags
    notes           TEXT,                            -- RSSI notes

    -- Classification
    classification_method  TEXT DEFAULT 'manual',    -- manual, fingerprint, ml, nmap
    classification_confidence REAL DEFAULT 1.0,      -- 1.0 for manual, 0.0-1.0 for auto

    -- Status
    status          TEXT NOT NULL DEFAULT 'active',  -- active, inactive, decommissioned
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_category ON assets (category);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets (criticality);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets (status);
CREATE INDEX IF NOT EXISTS idx_assets_ips ON assets USING GIN (ip_addresses);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets (mac_address);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_assets_source ON assets (source);

-- ═══════════════════════════════════════════════════════════════
-- ASSET CATEGORIES — default + custom categories
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS asset_categories (
    id              TEXT PRIMARY KEY,               -- "server", "workstation", "medical"
    label           TEXT NOT NULL,                   -- "Serveur", "Poste client", "Médical"
    label_en        TEXT,                            -- "Server", "Workstation", "Medical"
    icon            TEXT DEFAULT 'server',           -- lucide icon name
    color           TEXT DEFAULT 'var(--tc-blue)',   -- CSS color
    subcategories   TEXT[] DEFAULT '{}',             -- ["web", "db", "mail", "dns", "ad"]
    is_builtin      BOOLEAN NOT NULL DEFAULT false,  -- true for default categories
    sort_order      INTEGER DEFAULT 100,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Default categories
INSERT INTO asset_categories (id, label, label_en, icon, color, subcategories, is_builtin, sort_order) VALUES
    ('server',      'Serveur',              'Server',            'server',       '#3080d0', ARRAY['web','db','mail','dns','ad','file','backup','proxy','voip','app'], true, 1),
    ('workstation', 'Poste client',         'Workstation',       'monitor',      '#30a050', ARRAY['desktop','laptop','tablette'], true, 2),
    ('mobile',      'Mobile',               'Mobile',            'smartphone',   '#9060d0', ARRAY['smartphone','tablette'], true, 3),
    ('website',     'Site web / App',       'Website / App',     'globe',        '#d09020', ARRAY['wordpress','prestashop','drupal','custom','saas','api'], true, 4),
    ('network',     'Equipement réseau',    'Network Device',    'network',      '#d06020', ARRAY['firewall','switch','routeur','wifi-ap','vpn','load-balancer'], true, 5),
    ('printer',     'Imprimante / MFP',     'Printer / MFP',     'printer',      '#708090', ARRAY['imprimante','scanner','copieur'], true, 6),
    ('iot',         'IoT',                  'IoT',               'cpu',          '#20b0b0', ARRAY['camera','badge','capteur','thermostat','tv','assistant-vocal'], true, 7),
    ('ot',          'OT / Industriel',      'OT / Industrial',   'factory',      '#b04020', ARRAY['plc','hmi','scada','capteur-industriel','rtu','variateur'], true, 8),
    ('cloud',       'Cloud',                'Cloud',             'cloud',        '#6060d0', ARRAY['vm','container','serverless','saas-account','storage','database'], true, 9),
    ('unknown',     'Inconnu',              'Unknown',           'help-circle',  'var(--tc-text-muted)', ARRAY[]::TEXT[], true, 99)
ON CONFLICT (id) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════
-- INTERNAL NETWORKS — client's declared network ranges
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS internal_networks (
    id              SERIAL PRIMARY KEY,
    cidr            TEXT NOT NULL,                   -- "192.168.1.0/24"
    label           TEXT,                            -- "LAN principal", "VPN", "DMZ"
    vlan            INTEGER,                         -- VLAN ID if applicable
    zone            TEXT DEFAULT 'lan',              -- lan, dmz, vpn, wifi, ot, guest
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_internal_networks_cidr ON internal_networks (cidr);

-- ═══════════════════════════════════════════════════════════════
-- COMPANY PROFILE — client's business context for ML tuning
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS company_profile (
    id              INTEGER PRIMARY KEY DEFAULT 1,   -- Singleton (one row)
    company_name    TEXT,
    nace_code       TEXT,                            -- EU industry classification (e.g. "C.26", "Q.86")
    sector          TEXT,                            -- industry, healthcare, finance, retail, government, services, transport, energy, education, other
    company_size    TEXT DEFAULT 'small',            -- micro (<10), small (<50), medium (50-250), large (250+)
    employee_count  INTEGER,
    country         TEXT DEFAULT 'FR',

    -- Operating context
    business_hours  TEXT DEFAULT 'office',           -- office (8h-18h), 24x7, shifts, seasonal
    business_hours_start TEXT DEFAULT '08:00',
    business_hours_end   TEXT DEFAULT '18:00',
    work_days       TEXT[] DEFAULT ARRAY['mon','tue','wed','thu','fri'],

    -- Geographic scope
    geo_scope       TEXT DEFAULT 'france',           -- france, europe, international
    allowed_countries TEXT[] DEFAULT ARRAY['FR'],    -- ISO 3166 country codes
    blocked_countries TEXT[] DEFAULT '{}',           -- Countries that should trigger alerts

    -- Critical assets (free text list)
    critical_systems TEXT[] DEFAULT '{}',            -- ["ERP", "base clients", "paye", "site web"]

    -- Compliance
    compliance_frameworks TEXT[] DEFAULT '{}',       -- ["nis2", "iso27001", "pci-dss", "hipaa", "rgpd"]

    -- ML tuning
    anomaly_sensitivity TEXT DEFAULT 'medium',       -- low, medium, high (affects Isolation Forest threshold)

    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create default singleton row
INSERT INTO company_profile (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

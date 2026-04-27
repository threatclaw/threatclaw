-- V59: Sigma rules for OPNsense control-plane logs.
--
-- Source: skill-opnsense ingests /api/diagnostics/log/core/<scope> into
-- the `logs` table tagged `opnsense.<scope>` (audit, system, filter,
-- suricata, configd, dnsmasq, wireguard, resolver). Each row is the
-- OPNsense queryLog.py shape:
--   { timestamp, severity, facility, process_name, pid, line }
--
-- Same intent as the FortiGate rules (V58) and Proxmox rules (V57): a
-- SOC needs to know who logged in to the firewall, what they changed,
-- and what Suricata has seen — without the operator having to set up
-- syslog forwarding.
--
-- All rules use `logsource_category = 'opnsense'` so the engine's tag
-- filter (`tag.contains(cat)`) matches `opnsense.audit`, `opnsense.system`,
-- `opnsense.suricata`, `opnsense.configd`, etc.

-- 1. Failed admin login. The audit + system scopes both report auth
--    failures via lighttpd / pam. Burst signals brute force or stolen
--    credentials.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-001', 'OPNsense auth failed',
        'Authentication failure against OPNsense GUI / SSH / API. Burst = brute force or stolen-token probing.',
        'medium', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.credential_access', 'attack.t1110'], '',
        '{"selection": {"line|contains": ["authentication failure", "Failed password", "auth denied", "action denied"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 2. Admin successfully logged in. Not malicious per se, but every
--    admin login on a properly operated firewall is auditable. Surface
--    for review against authorized operator window.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-002', 'OPNsense admin login',
        'Successful admin login on OPNsense (GUI, SSH, or API). Verify it matches an authorized operator window.',
        'low', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.initial_access', 'attack.t1078'], '',
        '{"selection": {"line|contains": ["successful login", "Accepted password", "Accepted publickey", "user ''root'' logged"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 3. Sensitive configd action — firmware upgrade, config restore, user
--    delete, package install. Persistence / impact pattern after admin
--    compromise. Audit trail looks like:
--      " action allowed system.firmware.upgrade for user root"
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-003', 'OPNsense sensitive admin action',
        'A sensitive control-plane action ran on OPNsense (firmware upgrade, config restore, user delete, package install). Verify the operator was authorized.',
        'high', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.persistence', 'attack.t1098'], '',
        '{"selection": {"line|contains": ["system.firmware.upgrade", "system.config.restore", "system.user.delete", "firmware.poweroff", "firmware.reboot", "system.halt", "openvpn.set", "system.user.add"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 4. Suricata raised an alert. The OPNsense IDS log is JSON-in-line; the
--    word "alert" appears in `event_type":"alert"`. Single hit = a rule
--    matched live traffic. Volumetric noise is filtered server-side by
--    the ruleset, so a hit here is already significant.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-004', 'OPNsense IDS alert',
        'Suricata IDS raised an alert on traffic crossing the firewall. Investigate the embedded rule and src/dst pair.',
        'high', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.discovery', 'attack.t1046'], '',
        '{"selection": {"line|contains": "\"event_type\":\"alert\""}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 5. Kernel-level severity event (panic, link flap on a critical iface,
--    pf rule reload failure). Severity from queryLog.py is one of the
--    syslog levels — Emergency / Alert / Critical / Error.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-005', 'OPNsense critical system event',
        'Severity Emergency / Alert / Critical event on the OPNsense host. Often kernel panics, link drops, pf reload failure.',
        'high', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.impact'], '',
        '{"selection": {"severity": ["Emergency", "Alert", "Critical"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 6. Hostwatch detected a MAC migration on a port — host moved between
--    interfaces. On a stable LAN this is a strong ARP-spoofing /
--    rogue-device signal. The hostwatch line shape is:
--      "ethernet address host 10.77.0.254 moved from xx:xx:.. to yy:yy:.."
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-006', 'OPNsense MAC moved between interfaces',
        'Hostwatch detected an IP whose MAC migrated between interfaces — ARP spoofing or rogue device on the LAN.',
        'medium', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.lateral_movement', 'attack.t1557.002'], '',
        '{"selection": {"line|contains": "moved from"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

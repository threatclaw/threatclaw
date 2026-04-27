-- V58: Sigma rules for FortiGate event logs.
--
-- Source: skill-fortinet ingests `/api/v2/log/memory/event/<user|system>/select`
-- into the `logs` table tagged `fortinet.event.user` and
-- `fortinet.event.system`. Each row has the FortiGate log schema:
-- `logid`, `type`, `subtype`, `level`, `user`, `srcip`, `msg`, ...
--
-- Same control-plane logic as the Proxmox audit rules (V57): a SOC
-- needs to know who logged in, when, and what they touched on the
-- firewall. A compromised firewall admin = compromise of every host
-- the firewall sees.
--
-- All rules use `logsource_category = 'fortinet'` so the engine's tag
-- filter (`tag.contains(cat)`) matches both `fortinet.event.user` and
-- `fortinet.event.system`.

-- 1. Failed admin login. FortiOS uses logid 32002 / msg containing
--    "login failed" for GUI/SSH/API auth failures.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('fortinet-001', 'FortiGate auth failed',
        'Authentication failure on FortiGate (admin GUI / SSH / API). Burst signals brute force or stolen-token probing.',
        'medium', 'ThreatClaw', 'fortinet', 'fortigate',
        ARRAY['attack.credential_access', 'attack.t1110'], '',
        '{"selection": {"msg|contains": ["login failed", "auth failed", "Login disabled"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'fortinet',
                                logsource_product = 'fortigate',
                                enabled = true;

-- 2. Admin login successful. Not malicious per se, but on a properly
--    operated firewall every login is auditable. Surface for review.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('fortinet-002', 'FortiGate admin login',
        'Successful admin login on FortiGate. Verify it matches an authorized operator window.',
        'low', 'ThreatClaw', 'fortinet', 'fortigate',
        ARRAY['attack.initial_access', 'attack.t1078'], '',
        '{"selection": {"msg|contains": ["Administrator login successful", "User login successful"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'fortinet',
                                logsource_product = 'fortigate',
                                enabled = true;

-- 3. Configuration change. FortiOS emits "Edit" / "Add" / "Delete"
--    events for any cmdb modification. Persistence pattern after
--    admin compromise.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('fortinet-003', 'FortiGate config changed',
        'A configuration change was applied (rule edit, address add, user create). Verify the operator was authorized.',
        'medium', 'ThreatClaw', 'fortinet', 'fortigate',
        ARRAY['attack.persistence', 'attack.t1098'], '',
        '{"selection": {"msg|contains": ["Edit", "Add", "Delete"], "subtype": "config"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'fortinet',
                                logsource_product = 'fortigate',
                                enabled = true;

-- 4. Firewall policy disabled. An attacker with admin will turn
--    rules off before pivoting; legitimate ops should never need this.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('fortinet-004', 'FortiGate policy disabled',
        'A firewall policy was disabled — likely pre-pivot defense evasion.',
        'critical', 'ThreatClaw', 'fortinet', 'fortigate',
        ARRAY['attack.defense_evasion', 'attack.t1562.004'], '',
        '{"selection": {"msg|contains": ["status disable", "policy disable"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'fortinet',
                                logsource_product = 'fortigate',
                                enabled = true;

-- 5. New admin/api user added. Persistence pattern.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('fortinet-005', 'FortiGate admin/API user created',
        'A new admin or API user was created. Verify it was authorized — common backdoor pattern after token compromise.',
        'high', 'ThreatClaw', 'fortinet', 'fortigate',
        ARRAY['attack.persistence', 'attack.t1136'], '',
        '{"selection": {"msg|contains": ["Add system.admin", "Add system.api-user"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'fortinet',
                                logsource_product = 'fortigate',
                                enabled = true;

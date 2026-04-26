-- V57: Sigma rules for Proxmox VE audit log.
--
-- Source: cluster/log entries ingested by skill-proxmox into the
-- `logs` table with tag `proxmox.audit`. Each row is one administrative
-- action on the hypervisor (login, VM create/destroy, user add, ...).
-- Compromise of a Proxmox admin = compromise of every guest VM, so
-- this is the highest-priority audit surface in any homelab/SMB
-- virtualization stack.
--
-- All rules use `logsource_category = 'proxmox'` so the engine's tag
-- filter matches `proxmox.audit`. Field names follow the cluster/log
-- payload shape: `tag`, `user`, `msg`, `pri`, `node`.

-- 1. Failed authentication on Proxmox UI/API. A handful is normal
--    operator typos; the alert level catches the first burst before
--    a brute-force aggregator would (Proxmox doesn't lock accounts
--    by default).
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('proxmox-001', 'Proxmox auth failed',
        'Authentication failure on Proxmox VE GUI/API — burst signals brute force or stolen-token probing',
        'medium', 'ThreatClaw', 'proxmox', 'pve',
        ARRAY['attack.credential_access', 'attack.t1110'], '',
        '{"selection": {"msg|contains": "authentication failure"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'proxmox',
                                logsource_product = 'pve',
                                enabled = true;

-- 2. Successful root login. Not necessarily malicious but on a
--    well-managed cluster root@pam should NEVER log in (everything
--    goes via tokens / personal users). A successful root@pam auth
--    is therefore worth surfacing.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('proxmox-002', 'Proxmox root@pam login',
        'Interactive root@pam login on Proxmox — should be replaced by per-operator users + tokens',
        'medium', 'ThreatClaw', 'proxmox', 'pve',
        ARRAY['attack.initial_access', 'attack.t1078.003'], '',
        '{"selection": {"user": "root@pam", "msg|contains": "successful auth"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'proxmox',
                                logsource_product = 'pve',
                                enabled = true;

-- 3. New Proxmox user added. Privilege creation is a classic
--    persistence step after compromising an admin token.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('proxmox-003', 'Proxmox user added',
        'New PVE user created — verify it was authorized; attacker persistence pattern',
        'high', 'ThreatClaw', 'proxmox', 'pve',
        ARRAY['attack.persistence', 'attack.t1136.003'], '',
        '{"selection": {"msg|contains": ["create user", "useradd"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'proxmox',
                                logsource_product = 'pve',
                                enabled = true;

-- 4. VM destroyed. Single most destructive action on a Proxmox
--    cluster — wipes a guest including its disks. Anomalous outside
--    a documented decommission window.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('proxmox-004', 'Proxmox VM/CT destroyed',
        'A guest VM or container was destroyed — irreversible, verify the operator was authorized',
        'high', 'ThreatClaw', 'proxmox', 'pve',
        ARRAY['attack.impact', 'attack.t1485'], '',
        '{"selection": {"msg|contains": ["destroy VM", "destroy CT", "qmdestroy", "pct destroy"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'proxmox',
                                logsource_product = 'pve',
                                enabled = true;

-- 5. Firewall disabled at cluster or guest level. An attacker who
--    landed on the Proxmox admin will turn the firewall off before
--    pivoting to guests; legitimate ops should never need this.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('proxmox-005', 'Proxmox firewall disabled',
        'Proxmox firewall was disabled (cluster or guest scope) — likely pre-pivot defense evasion',
        'critical', 'ThreatClaw', 'proxmox', 'pve',
        ARRAY['attack.defense_evasion', 'attack.t1562.004'], '',
        '{"selection": {"msg|contains": ["firewall disable", "fw disable"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'proxmox',
                                logsource_product = 'pve',
                                enabled = true;

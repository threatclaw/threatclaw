-- Windows authentication and AD attack detection rules.
-- Source: Wazuh alerts stored as logs (tag: wazuh.alert).
-- logsource_category = 'alert' matches tag 'wazuh.alert' via substring.
-- Detection uses full JSON body search (Sigma engine falls back to log body).

-- 1. Kerberoasting — TGS request with RC4 encryption (Event 4769)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-001', 'Kerberoasting — RC4 TGS Request', 'Detects TGS service ticket requests using RC4 encryption (etype 0x17), typical of Kerberoasting attacks', 'high', 'ThreatClaw', 'alert', ARRAY['attack.credential_access', 'attack.t1558.003'], '', '{
  "selection": {"commandline|contains": ["4769"]},
  "filter_rc4": {"commandline|contains": ["0x17", "RC4"]},
  "condition": "selection and filter_rc4"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 2. Brute force — Multiple failed logins (Wazuh rule 5551)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-002', 'Brute Force Authentication', 'Detects brute force login attempts via Wazuh rules 5551/5503/5710', 'high', 'ThreatClaw', 'alert', ARRAY['attack.credential_access', 'attack.t1110.001'], '', '{
  "selection": {"commandline|contains": ["5551", "5503", "5710", "Multiple authentication failures", "brute force"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 3. DCSync attack — DRS replication request (Event 4662)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-003', 'DCSync — Directory Replication', 'Detects DCSync attack via directory replication requests', 'critical', 'ThreatClaw', 'alert', ARRAY['attack.credential_access', 'attack.t1003.006'], '', '{
  "selection": {"commandline|contains": ["4662", "DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 4. Golden Ticket — TGT request with suspicious attributes (Event 4768/4769)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-004', 'Golden Ticket — Suspicious TGT', 'Detects potential Golden Ticket usage via anomalous Kerberos TGT', 'critical', 'ThreatClaw', 'alert', ARRAY['attack.credential_access', 'attack.t1558.001'], '', '{
  "selection": {"commandline|contains": ["4768", "4769"]},
  "suspicious": {"commandline|contains": ["0x17", "RC4", "krbtgt", "golden"]},
  "condition": "selection and suspicious"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 5. Pass-the-Hash — NTLM authentication from unusual source (Event 4624 type 3)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-005', 'Pass-the-Hash — NTLM Logon', 'Detects NTLM network logon that may indicate pass-the-hash', 'high', 'ThreatClaw', 'alert', ARRAY['attack.lateral_movement', 'attack.t1550.002'], '', '{
  "selection": {"commandline|contains": ["4624", "NTLM", "NtLmSsp"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 6. Account created — New user account (Event 4720)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-006', 'User Account Created', 'Detects new user account creation', 'medium', 'ThreatClaw', 'alert', ARRAY['attack.persistence', 'attack.t1136.001'], '', '{
  "selection": {"commandline|contains": ["4720", "user account was created", "A user account was created"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 7. Admin group modification (Event 4728, 4732, 4756)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-007', 'Admin Group Membership Change', 'Detects user added to admin/privileged group', 'high', 'ThreatClaw', 'alert', ARRAY['attack.persistence', 'attack.t1098'], '', '{
  "selection": {"commandline|contains": ["4728", "4732", "4756", "added to", "Administrators", "Domain Admins", "Enterprise Admins"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 8. Service installed — Persistence via service (Event 7045)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-008', 'Suspicious Service Installed', 'Detects new service installation for persistence', 'high', 'ThreatClaw', 'alert', ARRAY['attack.persistence', 'attack.t1543.003'], '', '{
  "selection": {"commandline|contains": ["7045", "service was installed", "A service was installed"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 9. Security log cleared (Event 1102)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-009', 'Security Log Cleared', 'Detects Windows security event log clearing — anti-forensics', 'critical', 'ThreatClaw', 'alert', ARRAY['attack.defense_evasion', 'attack.t1070.001'], '', '{
  "selection": {"commandline|contains": ["1102", "audit log was cleared", "The audit log was cleared", "Log clear"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

-- 10. RDP lateral movement (Event 4624 type 10)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('win-auth-010', 'RDP Lateral Movement', 'Detects Remote Desktop logon events', 'medium', 'ThreatClaw', 'alert', ARRAY['attack.lateral_movement', 'attack.t1021.001'], '', '{
  "selection": {"commandline|contains": ["4624", "RemoteInteractive", "Type 10", "RDP"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'alert', enabled = true;

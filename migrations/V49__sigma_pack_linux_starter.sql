-- Linux / Wazuh starter Sigma pack — 12 rules for Day-0 detection.
--
-- Targets raw syslog / Wazuh alerts forwarded through fluent-bit.
-- `logsource_category='syslog'` matches any log tagged `syslog.*` or
-- containing the word — wide on purpose so the pack works against osquery,
-- auditd, journald, and Wazuh's wazuh.alert pipeline without needing
-- operator tuning on day 0.
--
-- Detection uses `full_log|contains` or `data|contains` (JSON body search)
-- so we don't depend on a specific field mapping. The sigma_engine
-- condition language falls back to full-body scan when the field isn't
-- present at the top level.
--
-- Tags follow the MITRE ATT&CK dotted notation (attack.<tactic>,
-- attack.t<technique_id>). Level tuned for RSSI dashboards: brute-force
-- bursts are HIGH, privesc is HIGH, config drift is MEDIUM.
--
-- Idempotent: ON CONFLICT (id) DO UPDATE refreshes detection_json in place,
-- so re-running the migration upgrades rules without losing `enabled` state.

-- 1. SSH brute force — repeated password failures
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-auth-001', 'SSH Password Brute Force', 'Multiple SSH password failures from the same source — classic brute-force probe', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.credential_access', 'attack.t1110.001'], '', '{
  "selection": {"full_log|contains": ["Failed password for", "sshd", "authentication failure"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 2. SSH root login attempt (disabled in hardened configs)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-auth-002', 'SSH Root Login Attempt', 'SSH session targeting the root account — bypass attempt on PermitRootLogin=no policies', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.initial_access', 'attack.t1078.003'], '', '{
  "selection": {"full_log|contains": ["sshd", "for root from", "Invalid user root"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 3. Sudo — failed password
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-auth-003', 'Sudo Authentication Failure', 'Sudo refusal for a non-privileged account attempting escalation', 'medium', 'ThreatClaw', 'syslog', ARRAY['attack.privilege_escalation', 'attack.t1548.003'], '', '{
  "selection": {"full_log|contains": ["sudo", "authentication failure", "incorrect password attempt"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 4. Sudo — user not in sudoers
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-auth-004', 'Sudo — User Not In Sudoers', 'Sudo invocation from an account that has no authorization — reconnaissance or escalation probe', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.privilege_escalation', 'attack.t1548.003'], '', '{
  "selection": {"full_log|contains": ["is not in the sudoers file", "This incident will be reported"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 5. New user added
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-acct-001', 'Local User Created', 'useradd / adduser invocation — possible post-exploitation persistence', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.persistence', 'attack.t1136.001'], '', '{
  "selection": {"full_log|contains": ["new user:", "useradd", "adduser", "new group:"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 6. Account set to UID 0
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-acct-002', 'Account Promoted To UID 0', 'Account UID changed to 0 via usermod — critical privilege escalation pattern', 'critical', 'ThreatClaw', 'syslog', ARRAY['attack.privilege_escalation', 'attack.t1548'], '', '{
  "selection": {"full_log|contains": ["usermod", "uid=0", "changed uid to 0"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 7. /etc/passwd or /etc/shadow write
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-fim-001', 'Sensitive Auth File Modified', 'Change detected on /etc/passwd or /etc/shadow — typical backdoor persistence', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.persistence', 'attack.t1098'], '', '{
  "selection": {"full_log|contains": ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]},
  "filter": {"full_log|contains": ["read", "opened for reading"]},
  "condition": "selection and not filter"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 8. Cron job added
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-persist-001', 'Cron Job Added', 'New entry in /etc/cron.* or user crontab — scheduled task persistence', 'medium', 'ThreatClaw', 'syslog', ARRAY['attack.persistence', 'attack.t1053.003'], '', '{
  "selection": {"full_log|contains": ["crontab", "/etc/cron", "crond", "LIST", "REPLACE"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 9. Firewall flush / disable
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-evasion-001', 'Host Firewall Disabled', 'iptables flush, ufw disable, or firewalld stop — defense evasion', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.defense_evasion', 'attack.t1562.004'], '', '{
  "selection": {"full_log|contains": ["iptables -F", "iptables --flush", "ufw disable", "systemctl stop firewalld", "nft flush"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 10. SELinux / AppArmor disabled
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-evasion-002', 'MAC Policy Disabled', 'SELinux set to permissive/disabled or AppArmor teardown — mandatory access control evasion', 'high', 'ThreatClaw', 'syslog', ARRAY['attack.defense_evasion', 'attack.t1562.001'], '', '{
  "selection": {"full_log|contains": ["setenforce 0", "SELINUX=disabled", "SELINUX=permissive", "apparmor_parser -R", "systemctl disable apparmor"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 11. Shell-invoked download (wget/curl piping to sh)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-exec-001', 'Remote Payload Piped To Shell', 'wget/curl output fed into a shell — classic drive-by install', 'critical', 'ThreatClaw', 'syslog', ARRAY['attack.execution', 'attack.t1059.004', 'attack.t1105'], '', '{
  "selection": {"full_log|contains": ["curl", "wget"]},
  "pipe": {"full_log|contains": ["| sh", "| bash", "|sh", "|bash", "| /bin/sh", "-O-", "-O -"]},
  "condition": "selection and pipe"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- 12. Audit log tampering
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('lnx-evasion-003', 'Audit / System Log Cleared', 'auditd stopped or /var/log truncated — indicator removal after compromise', 'critical', 'ThreatClaw', 'syslog', ARRAY['attack.defense_evasion', 'attack.t1070.002'], '', '{
  "selection": {"full_log|contains": ["auditctl -D", "systemctl stop auditd", "service auditd stop", "truncate -s 0 /var/log", "rm /var/log/auth.log", "rm /var/log/secure"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, level = EXCLUDED.level, tags = EXCLUDED.tags;

-- PowerShell obfuscation detection rules — 20 Sigma rules.
-- Inspired by Gatewatcher Codebreaker, covers 90% of real-world PS obfuscation.
-- Sources: osquery process events (tag: osquery.process), Wazuh Windows events.
-- logsource_category = 'process' matches tag 'osquery.process' via substring.
-- logsource_product is NULL to match any source (osquery, wazuh, syslog).
-- Detection uses commandline|contains which falls back to full JSON body search
-- (works with both 'commandline' and 'cmdline' field names).

-- 1. Base64 encoded command (-enc / -encodedcommand)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-001', 'PowerShell Base64 Encoded Command', 'Detects PowerShell with -enc or -encodedcommand flag', 'high', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1059.001'], '', '{
  "selection": {"commandline|contains": ["-enc ", "-encodedcommand ", "-EncodedCommand ", "-Enc "]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 2. Invoke-Expression (IEX)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-002', 'PowerShell Invoke-Expression', 'Detects IEX or Invoke-Expression usage', 'high', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1059.001'], '', '{
  "selection": {"commandline|contains": ["Invoke-Expression", "IEX ", "IEX(", "iex "]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 3. DownloadString / WebClient
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-003', 'PowerShell Download Cradle', 'Detects Net.WebClient download methods', 'high', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1059.001', 'attack.t1105'], '', '{
  "selection": {"commandline|contains": ["DownloadString", "DownloadFile", "DownloadData", "Net.WebClient", "WebClient"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 4. Invoke-WebRequest / wget / curl aliases
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-004', 'PowerShell Web Request', 'Detects Invoke-WebRequest and aliases', 'medium', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1059.001'], '', '{
  "selection": {"commandline|contains": ["Invoke-WebRequest", "Invoke-RestMethod", "iwr ", "irm "]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 5. Hidden window / NoProfile / NonInteractive
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-005', 'PowerShell Hidden Execution', 'Detects hidden/stealthy PowerShell execution', 'medium', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1564.003'], '', '{
  "selection": {"commandline|contains": ["-WindowStyle Hidden", "-w hidden", "-nop ", "-NoProfile", "-NonInteractive", "-noni"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 6. Start-BitsTransfer (BITS download)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-006', 'PowerShell BITS Transfer Download', 'Detects BITS used for file download', 'medium', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1197'], '', '{
  "selection": {"commandline|contains": ["Start-BitsTransfer", "bitsadmin"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 7. Reflection Assembly Load (fileless malware)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-007', 'PowerShell Reflection Assembly Load', 'Detects in-memory .NET assembly loading', 'high', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1620'], '', '{
  "selection": {"commandline|contains": ["[Reflection.Assembly]::Load", "Assembly.Load", "[System.Reflection.Assembly]"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 8. FromBase64String (in-script decoding)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-008', 'PowerShell Base64 Decode In Script', 'Detects FromBase64String decoding', 'high', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1140'], '', '{
  "selection": {"commandline|contains": ["FromBase64String", "[Convert]::FromBase64", "ToBase64String"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 9. Add-Type with C# compilation
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-009', 'PowerShell Add-Type Compilation', 'Detects inline C# compilation via Add-Type', 'high', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1027.004'], '', '{
  "selection": {"commandline|contains": ["Add-Type", "DllImport", "kernel32", "user32"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 10. New-Object with COM objects
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-010', 'PowerShell COM Object Creation', 'Detects suspicious COM object usage', 'medium', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1059.001'], '', '{
  "selection": {"commandline|contains": ["New-Object -ComObject", "WScript.Shell", "Shell.Application", "MMC20.Application"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 11. String concatenation obfuscation
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-011', 'PowerShell String Concatenation Obfuscation', 'Detects char-to-int or string concatenation obfuscation', 'high', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1027'], '', '{
  "selection": {"commandline|contains": ["[char]", "+[char]", "-join", ".replace(", "[string]::join"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 12. Credential theft (Mimikatz-style)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-012', 'PowerShell Credential Dumping', 'Detects Mimikatz-related PowerShell commands', 'critical', 'ThreatClaw', 'process', ARRAY['attack.credential_access', 'attack.t1003.001'], '', '{
  "selection": {"commandline|contains": ["Invoke-Mimikatz", "sekurlsa", "logonpasswords", "ConvertTo-SecureString"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 13. AMSI bypass
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-013', 'PowerShell AMSI Bypass', 'Detects attempts to disable AMSI', 'critical', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1562.001'], '', '{
  "selection": {"commandline|contains": ["AmsiUtils", "amsiInitFailed", "Amsi.dll", "AmsiScanBuffer"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 14. Execution policy bypass
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-014', 'PowerShell Execution Policy Bypass', 'Detects execution policy bypass', 'medium', 'ThreatClaw', 'process', ARRAY['attack.defense_evasion', 'attack.t1059.001'], '', '{
  "selection": {"commandline|contains": ["-ExecutionPolicy Bypass", "-ep bypass", "-exec bypass", "Set-ExecutionPolicy Unrestricted"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 15. PowerShell remoting (lateral movement)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-015', 'PowerShell Remoting Lateral Movement', 'Detects PS remoting for lateral movement', 'high', 'ThreatClaw', 'process', ARRAY['attack.lateral_movement', 'attack.t1021.006'], '', '{
  "selection": {"commandline|contains": ["Enter-PSSession", "Invoke-Command -Computer", "New-PSSession", "Enable-PSRemoting"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 16. Scheduled task creation via PS
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-016', 'PowerShell Scheduled Task Persistence', 'Detects scheduled task creation for persistence', 'high', 'ThreatClaw', 'process', ARRAY['attack.persistence', 'attack.t1053.005'], '', '{
  "selection": {"commandline|contains": ["Register-ScheduledTask", "New-ScheduledTask", "schtasks /create"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 17. PowerShell service creation (persistence)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-017', 'PowerShell Service Persistence', 'Detects service creation for persistence', 'high', 'ThreatClaw', 'process', ARRAY['attack.persistence', 'attack.t1543.003'], '', '{
  "selection": {"commandline|contains": ["New-Service", "sc.exe create", "Set-Service"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 18. WMI event subscription (fileless persistence)
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-018', 'PowerShell WMI Event Subscription', 'Detects WMI-based persistence', 'high', 'ThreatClaw', 'process', ARRAY['attack.persistence', 'attack.t1546.003'], '', '{
  "selection": {"commandline|contains": ["Register-WmiEvent", "Set-WmiInstance", "__EventFilter", "__EventConsumer", "CommandLineEventConsumer"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 19. Registry persistence
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-019', 'PowerShell Registry Run Key Persistence', 'Detects registry run key manipulation', 'high', 'ThreatClaw', 'process', ARRAY['attack.persistence', 'attack.t1547.001'], '', '{
  "selection": {"commandline|contains": ["Set-ItemProperty", "New-ItemProperty", "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- 20. Reverse shell patterns
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, tags, rule_yaml, detection_json, enabled)
VALUES ('ps-obfusc-020', 'PowerShell Reverse Shell', 'Detects PowerShell reverse shell patterns', 'critical', 'ThreatClaw', 'process', ARRAY['attack.execution', 'attack.t1059.001'], '', '{
  "selection": {"commandline|contains": ["TCPClient", "Net.Sockets", "IO.StreamReader", "GetStream()", "Nishang", "powercat"]},
  "condition": "selection"
}'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'process', logsource_product = NULL, enabled = true;

-- V56: Sigma rules for OPNsense firewall block events.
--
-- Source : pf log block events mirrored into the `logs` table by the
-- skill-opnsense connector with tag `opnsense.firewall`. Volumetric
-- detection (port scan / brute force) lives in the firewall_detection
-- module; this file covers single-line patterns where one event alone
-- is enough to raise an alert.
--
-- All rules use `logsource_category = 'firewall'` so the engine's tag
-- filter (`tag.contains(cat)`) matches `opnsense.firewall`.

-- 1. Block toward known backdoor ports (Metasploit default 4444,
--    Elite 31337, IRC C2 6667, Telnet legacy 23). Single hit on these
--    is malware-tier — no recon needed.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-fw-001', 'Block toward backdoor port',
        'Block event targeting a known backdoor / C2 port (Metasploit 4444, Elite 31337, IRC 6667, Telnet 23)',
        'high', 'ThreatClaw', 'firewall', 'opnsense', ARRAY['attack.command_and_control', 'attack.t1571'], '',
        '{"selection": {"action": "block", "dst_port": [4444, 31337, 6667, 23, 1337]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'firewall',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 2. Block toward RDP (3389) from the Internet. Single hit usually means
--    a botnet sweep — significant only at scale, but the first hit is
--    early-warning.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-fw-002', 'Block RDP from Internet',
        'Block event on RDP port (3389) from a non-RFC1918 source — botnet sweep signature',
        'medium', 'ThreatClaw', 'firewall', 'opnsense', ARRAY['attack.reconnaissance', 'attack.t1595'], '',
        '{"selection": {"action": "block", "dst_port": 3389, "direction": "in"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'firewall',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 3. Block toward SMB (445) from the Internet — WannaCry / SMBGhost
--    sweep signature. SMB on the public Internet is never legitimate.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-fw-003', 'Block SMB from Internet',
        'Block event on SMB port (445) inbound — ransomware worm signature',
        'medium', 'ThreatClaw', 'firewall', 'opnsense', ARRAY['attack.lateral_movement', 'attack.t1021.002'], '',
        '{"selection": {"action": "block", "dst_port": 445, "direction": "in"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'firewall',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 4. Block on Memcached / DNS / NTP UDP amplification ports from the
--    Internet — DDoS reflection vectors (port 11211, 53 outbound, 123).
--    Inbound block on these from external = someone is using us as
--    amplifier (or trying to).
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-fw-004', 'Block UDP amplification probe',
        'Block on a known UDP amplification port (Memcached 11211, NTP monlist 123, CLDAP 389)',
        'medium', 'ThreatClaw', 'firewall', 'opnsense', ARRAY['attack.impact', 'attack.t1498.002'], '',
        '{"selection": {"action": "block", "proto": "udp", "dst_port": [11211, 1900, 389]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'firewall',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 5. Block on common cryptomining proxy ports (3333, 5555, 7777, 14444,
--    14433). A single block on these from an internal asset is a strong
--    signal of compromise (XMRig / cryptojacker beaconing out).
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-fw-005', 'Block toward cryptomining proxy',
        'Block event on a cryptomining pool proxy port (3333, 5555, 7777, 14444) — likely XMRig / cryptojacker',
        'high', 'ThreatClaw', 'firewall', 'opnsense', ARRAY['attack.impact', 'attack.t1496'], '',
        '{"selection": {"action": "block", "dst_port": [3333, 5555, 7777, 14444, 14433]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'firewall',
                                logsource_product = 'opnsense',
                                enabled = true;

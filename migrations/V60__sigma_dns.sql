-- V60: Sigma rules for OPNsense DNS scopes (dnsmasq + resolver/unbound).
--
-- Source: skill-opnsense ingests `/api/diagnostics/log/core/{dnsmasq,resolver}`
-- → tagged `opnsense.dnsmasq` and `opnsense.resolver`. Both share the
-- same row shape `{ timestamp, severity, process_name, line, ... }`.
--
-- Why these rules: DNS is the most common control channel for malware
-- (DGA, fast-flux, exfiltration) and the easiest to abuse on a corporate
-- LAN (DHCP poisoning to point clients at a rogue resolver). OPNsense's
-- DNS side was a SIEM blind spot until C27 wired the API ingestion —
-- these rules close that gap with high-signal, low-noise patterns.
--
-- All rules use `logsource_category='opnsense'` so the engine's tag
-- filter (`tag.contains(cat)`) matches `opnsense.dnsmasq` and
-- `opnsense.resolver` (both contain the substring "opnsense").

-- 1. Unbound got an unwanted DNS reply — classic Kaminsky-style
--    spoofing attempt or upstream cache poisoning. Single-hit rule
--    because unbound is conservative about what it flags.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-001', 'OPNsense unbound unwanted reply',
        'unbound dropped a DNS reply that did not match any outstanding query — fingerprint of cache-poisoning / DNS spoofing attempt against the resolver.',
        'high', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.command_and_control', 'attack.t1071.004'], '',
        '{"selection": {"line|contains": "unwanted reply"}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 2. DNSSEC validation failed. unbound emits "validation failure" /
--    "validator: failed validation" when a signed zone fails — most
--    commonly a MitM / hijack of the upstream resolver's response.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-002', 'OPNsense DNSSEC validation failed',
        'unbound rejected a DNSSEC-signed answer because the chain of trust did not validate — possible MitM / hijack of the upstream DNS path.',
        'high', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.collection', 'attack.t1557'], '',
        '{"selection": {"line|contains": ["validation failure", "failed validation", "bogus"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 3. SERVFAIL response — the resolver could not satisfy the query.
--    Single SERVFAIL is normal noise; volumetric detection of SERVFAIL
--    bursts is handled at the dashboard layer. This rule fires on the
--    explicit "rrset bogus" / "blacklisted" markers that point to
--    abuse rather than network failure.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-003', 'OPNsense resolver blacklist hit',
        'unbound refused to answer a query because the target was on a configured blocklist (Mozilla anti-malware / corporate blocklist / configd block list).',
        'medium', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.command_and_control', 'attack.t1071.004'], '',
        '{"selection": {"line|contains": ["blocked by", "blacklisted", "is blocked"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 4. unbound config / restart — control plane event. Same intent as
--    the configd rule: a DNS resolver restart on a stable site is rare
--    and worth surfacing once.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-004', 'OPNsense resolver restarted / reconfigured',
        'unbound was started or reloaded — verify the operator was authorized. On a stable site this should happen at most once a quarter.',
        'low', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.defense_evasion'], '',
        '{"selection": {"line|contains": ["start of service", "service stopped", "config file", "reading config"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 5. dnsmasq DHCP starvation — repeated "no address range available"
--    or "no free addresses" lines. Either the pool is genuinely full
--    (capacity issue worth flagging) OR an attacker is exhausting it
--    on purpose to redirect new clients to a rogue DHCP. We fire on
--    the keyword and let the operator triage.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-005', 'OPNsense DHCP pool exhausted',
        'dnsmasq could not assign an address — pool genuinely full OR DHCP starvation attack (Yersinia / dhcpig). Verify against the LAN client count.',
        'medium', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.impact', 'attack.t1499.004'], '',
        '{"selection": {"line|contains": ["no address range available", "no free addresses", "DHCPNAK"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 6. dnsmasq spoofed reply detected. dnsmasq's DNS-over-DHCP
--    cross-checking emits "possible DNS-rebind attack" / "ignored
--    REFUSED" when an answer points to an internal IP for an external
--    name. Strong indicator of DNS rebinding / pivot.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-006', 'OPNsense possible DNS-rebind attack',
        'dnsmasq filtered an answer that resolved an external domain to an internal IP — classic DNS-rebinding signature.',
        'high', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.command_and_control', 'attack.t1071.004'], '',
        '{"selection": {"line|contains": ["DNS-rebind", "rebind protection", "stop-dns-rebind"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

-- 7. unbound query rate limit exceeded (`ratelimit ... rejected`) —
--    another defense unbound builds in. Fires at a single hit; the
--    operator decides if it's an internal misbehaving app or an attempt
--    to abuse the resolver as an open relay.
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('opnsense-dns-007', 'OPNsense resolver rate-limited',
        'unbound rejected DNS queries via its rate limiter. Most often: misbehaving internal app loop. Sometimes: attacker probing the resolver.',
        'low', 'ThreatClaw', 'opnsense', 'opnsense',
        ARRAY['attack.discovery'], '',
        '{"selection": {"line|contains": ["rejected by ip ratelimiting", "ratelimit", "exceeded the rate limit"]}, "condition": "selection"}'::jsonb,
        true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json,
                                logsource_category = 'opnsense',
                                logsource_product = 'opnsense',
                                enabled = true;

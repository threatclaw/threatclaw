-- Shadow AI detection — dedicated feed + Sigma rules.
--
-- Goal: detect unauthorized use of commercial LLM APIs (ChatGPT, Claude, Gemini,
-- Mistral, etc.) and self-hosted LLM runtimes (Ollama, vLLM, LM Studio, etc.)
-- from Zeek-observed network traffic, plus emerging AI coding assistants.
--
-- Scope: passive network detection (ssl.log, dns.log, conn.log, http.log).
-- Endpoint-side detection (processes, ports, files .gguf/.safetensors) is
-- covered by osquery packs shipped separately.
--
-- Regulatory alignment: EU AI Act art. 12 (logging high-risk AI usage),
-- NIS2 art. 21 §2(d-e) (supply chain / risk management), ISO 42001 A.5.2 +
-- A.10 (AI policy + third-party AI monitoring), NIST AI RMF 2025 (shadow AI
-- explicitly named in inventory control).

-- ── Feed table ─────────────────────────────────────────────
-- Separate from ioc_feed (V36) because semantics differ: LLM endpoints are
-- not threats, they are governance-relevant services. Each row is classified
-- by provider / category / tier so the skill can weight severity per org
-- policy (some orgs allow Mistral on-prem but not ChatGPT, etc.).

CREATE TABLE IF NOT EXISTS llm_endpoint_feed (
    id              BIGSERIAL PRIMARY KEY,
    detection_type  TEXT NOT NULL,                  -- fqdn | port | url_pattern
    value           TEXT NOT NULL,                  -- FQDN, port number (text), or URL path pattern
    provider        TEXT,                           -- OpenAI, Anthropic, Mistral, Ollama, vLLM, ...
    category        TEXT NOT NULL,                  -- commercial | self-hosted | coding-assistant | hub | hyperscaler
    tier            SMALLINT NOT NULL DEFAULT 3,    -- 1 (mainstream) … 7 (niche)
    tags            TEXT[] DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active          BOOLEAN NOT NULL DEFAULT true,
    notes           TEXT,
    UNIQUE(detection_type, value)
);

CREATE INDEX IF NOT EXISTS idx_llm_feed_value ON llm_endpoint_feed (value);
CREATE INDEX IF NOT EXISTS idx_llm_feed_type_value ON llm_endpoint_feed (detection_type, value);
CREATE INDEX IF NOT EXISTS idx_llm_feed_active ON llm_endpoint_feed (active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_llm_feed_category ON llm_endpoint_feed (category);
CREATE INDEX IF NOT EXISTS idx_llm_feed_provider ON llm_endpoint_feed (provider) WHERE provider IS NOT NULL;

CREATE OR REPLACE VIEW llm_endpoint_feed_stats AS
SELECT
    category,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE detection_type = 'fqdn') AS fqdns,
    COUNT(*) FILTER (WHERE detection_type = 'port') AS ports,
    COUNT(*) FILTER (WHERE detection_type = 'url_pattern') AS url_patterns,
    COUNT(DISTINCT provider) AS providers
FROM llm_endpoint_feed
WHERE active = true
GROUP BY category;

-- ── Seed data — tier 1 to 7 ────────────────────────────────
-- Curated from open community lists (abixb/llm-hosts-blocklist, MIT) and
-- vendor API documentation as of 2026-04-20. Keep in sync with the public
-- feed at feeds.threatclaw.io/llm-endpoints.json (cron refresh, see skill
-- shadow-ai-monitor).

-- Tier 1 — Commercial LLM mainstream
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags) VALUES
  ('fqdn', 'api.openai.com',               'OpenAI',    'commercial', 1, ARRAY['api','us']),
  ('fqdn', 'chatgpt.com',                  'OpenAI',    'commercial', 1, ARRAY['webapp']),
  ('fqdn', 'chat.openai.com',              'OpenAI',    'commercial', 1, ARRAY['webapp','legacy']),
  ('fqdn', 'platform.openai.com',          'OpenAI',    'commercial', 1, ARRAY['console']),
  ('fqdn', 'auth.openai.com',              'OpenAI',    'commercial', 1, ARRAY['auth']),
  ('fqdn', 'oaistatic.com',                'OpenAI',    'commercial', 1, ARRAY['cdn']),
  ('fqdn', 'oaiusercontent.com',           'OpenAI',    'commercial', 1, ARRAY['cdn','uploads']),
  ('fqdn', 'api.anthropic.com',            'Anthropic', 'commercial', 1, ARRAY['api','us']),
  ('fqdn', 'claude.ai',                    'Anthropic', 'commercial', 1, ARRAY['webapp']),
  ('fqdn', 'console.anthropic.com',        'Anthropic', 'commercial', 1, ARRAY['console']),
  ('fqdn', 'generativelanguage.googleapis.com', 'Google', 'commercial', 1, ARRAY['api']),
  ('fqdn', 'gemini.google.com',            'Google',    'commercial', 1, ARRAY['webapp']),
  ('fqdn', 'aistudio.google.com',          'Google',    'commercial', 1, ARRAY['console']),
  ('fqdn', 'copilot.microsoft.com',        'Microsoft', 'commercial', 1, ARRAY['webapp']),
  ('fqdn', 'api.mistral.ai',               'Mistral',   'commercial', 1, ARRAY['api','eu']),
  ('fqdn', 'chat.mistral.ai',              'Mistral',   'commercial', 1, ARRAY['webapp']),
  ('fqdn', 'le-chat.mistral.ai',           'Mistral',   'commercial', 1, ARRAY['webapp'])
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- Tier 2 — Providers and aggregators
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags) VALUES
  ('fqdn', 'api.cohere.ai',        'Cohere',     'commercial', 2, ARRAY['api']),
  ('fqdn', 'api.cohere.com',       'Cohere',     'commercial', 2, ARRAY['api']),
  ('fqdn', 'openrouter.ai',        'OpenRouter', 'commercial', 2, ARRAY['aggregator']),
  ('fqdn', 'api.together.xyz',     'Together',   'commercial', 2, ARRAY['api']),
  ('fqdn', 'api.together.ai',      'Together',   'commercial', 2, ARRAY['api']),
  ('fqdn', 'api.groq.com',         'Groq',       'commercial', 2, ARRAY['api','inference']),
  ('fqdn', 'api.fireworks.ai',     'Fireworks',  'commercial', 2, ARRAY['api']),
  ('fqdn', 'api.replicate.com',    'Replicate',  'commercial', 2, ARRAY['api']),
  ('fqdn', 'replicate.com',        'Replicate',  'commercial', 2, ARRAY['webapp']),
  ('fqdn', 'api.perplexity.ai',    'Perplexity', 'commercial', 2, ARRAY['api','search']),
  ('fqdn', 'perplexity.ai',        'Perplexity', 'commercial', 2, ARRAY['webapp']),
  ('fqdn', 'api.x.ai',             'xAI',        'commercial', 2, ARRAY['api','grok']),
  ('fqdn', 'grok.com',             'xAI',        'commercial', 2, ARRAY['webapp']),
  ('fqdn', 'api.deepseek.com',     'DeepSeek',   'commercial', 2, ARRAY['api','cn']),
  ('fqdn', 'chat.deepseek.com',    'DeepSeek',   'commercial', 2, ARRAY['webapp','cn'])
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- Tier 3 — Model hubs
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags) VALUES
  ('fqdn', 'huggingface.co',                  'HuggingFace', 'hub', 3, ARRAY['hub']),
  ('fqdn', 'api-inference.huggingface.co',    'HuggingFace', 'hub', 3, ARRAY['inference']),
  ('fqdn', 'endpoints.huggingface.cloud',     'HuggingFace', 'hub', 3, ARRAY['managed']),
  ('fqdn', 'replicate.delivery',              'Replicate',   'hub', 3, ARRAY['cdn']),
  ('fqdn', 'modelscope.cn',                   'ModelScope',  'hub', 3, ARRAY['hub','cn'])
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- Tier 4 — AI gateways / LLM-as-a-Service
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags) VALUES
  ('fqdn', 'api.anyscale.com',     'Anyscale',   'commercial', 4, ARRAY['gateway']),
  ('fqdn', 'api.deepinfra.com',    'DeepInfra',  'commercial', 4, ARRAY['gateway']),
  ('fqdn', 'api.lepton.ai',        'Lepton',     'commercial', 4, ARRAY['gateway']),
  ('fqdn', 'api.novita.ai',        'Novita',     'commercial', 4, ARRAY['gateway']),
  ('fqdn', 'api.sambanova.ai',     'SambaNova',  'commercial', 4, ARRAY['gateway']),
  ('fqdn', 'api.cerebras.ai',      'Cerebras',   'commercial', 4, ARRAY['gateway'])
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- Tier 5 — Hyperscaler AI (caution: partial match, may raise FPs on broad cloud usage)
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags, notes) VALUES
  ('fqdn', 'openai.azure.com',     'Microsoft', 'hyperscaler', 5, ARRAY['azure','enterprise'], 'Tenant-specific subdomains'),
  ('fqdn', 'bedrock-runtime',      'AWS',       'hyperscaler', 5, ARRAY['aws','enterprise'],   'Region-specific FQDN, partial match'),
  ('fqdn', 'aiplatform.googleapis.com', 'Google', 'hyperscaler', 5, ARRAY['gcp','vertex'],     'Vertex AI endpoints')
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- Tier 6 — Self-hosted LLM runtimes (ports on internal networks)
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags, notes) VALUES
  ('port', '11434', 'Ollama',               'self-hosted', 6, ARRAY['default'],        'Ollama default HTTP API port'),
  ('port', '1234',  'LM Studio',            'self-hosted', 6, ARRAY['default'],        'LM Studio local server'),
  ('port', '43411', 'LM Studio',            'self-hosted', 6, ARRAY['alternate'],      'LM Studio alternate API port'),
  ('port', '8000',  'vLLM',                 'self-hosted', 6, ARRAY['default'],        'vLLM OpenAI-compatible server'),
  ('port', '8080',  'llama.cpp / LocalAI',  'self-hosted', 6, ARRAY['default','ambiguous'], 'Conflicts with many HTTP apps'),
  ('port', '3000',  'Open WebUI',           'self-hosted', 6, ARRAY['default','ambiguous'], 'Also common for Node apps'),
  ('port', '7860',  'Text Generation WebUI', 'self-hosted', 6, ARRAY['gradio'],        'Gradio default'),
  ('port', '5000',  'Text Generation WebUI', 'self-hosted', 6, ARRAY['alternate'],     'Also Flask default'),
  ('port', '1337',  'Jan.ai',               'self-hosted', 6, ARRAY['default'],        'Jan.ai local server'),
  ('port', '4891',  'GPT4All',              'self-hosted', 6, ARRAY['default'],        'GPT4All API server')
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- URL patterns — OpenAI-compatible APIs (cover Ollama, vLLM, LM Studio, llama.cpp, LiteLLM)
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags, notes) VALUES
  ('url_pattern', '/v1/chat/completions',   'OpenAI-compatible', 'self-hosted', 6, ARRAY['api'], 'Universal LLM API path'),
  ('url_pattern', '/v1/completions',        'OpenAI-compatible', 'self-hosted', 6, ARRAY['api','legacy'], NULL),
  ('url_pattern', '/v1/embeddings',         'OpenAI-compatible', 'self-hosted', 6, ARRAY['api'], NULL),
  ('url_pattern', '/api/generate',          'Ollama',            'self-hosted', 6, ARRAY['api'], 'Ollama native API'),
  ('url_pattern', '/api/chat',              'Ollama',            'self-hosted', 6, ARRAY['api'], 'Ollama native API'),
  ('url_pattern', '/api/tags',              'Ollama',            'self-hosted', 6, ARRAY['api'], 'Ollama model list')
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- Tier 7 — AI coding assistants (high IP leak risk: code → prompt)
INSERT INTO llm_endpoint_feed (detection_type, value, provider, category, tier, tags) VALUES
  ('fqdn', 'api.cursor.sh',         'Cursor',        'coding-assistant', 7, ARRAY['ide']),
  ('fqdn', 'cursor.com',            'Cursor',        'coding-assistant', 7, ARRAY['webapp']),
  ('fqdn', 'api.githubcopilot.com', 'GitHub Copilot','coding-assistant', 7, ARRAY['ide','ms']),
  ('fqdn', 'api.tabnine.com',       'Tabnine',       'coding-assistant', 7, ARRAY['ide']),
  ('fqdn', 'api.codeium.com',       'Codeium',       'coding-assistant', 7, ARRAY['ide']),
  ('fqdn', 'windsurf.com',          'Windsurf',      'coding-assistant', 7, ARRAY['ide','codeium'])
ON CONFLICT (detection_type, value) DO UPDATE SET tier = EXCLUDED.tier, active = true, last_seen = NOW();

-- ── Sigma rules ────────────────────────────────────────────
-- 4 rules covering ssl.log / dns.log / conn.log / http.log from Zeek.
-- logsource_category='zeek' matches tag zeek.* via substring (see sigma_engine.rs:190-205).
-- Rule IDs reserved range: shadow-ai-001 .. shadow-ai-099.

-- shadow-ai-001 — TLS SNI targeting a commercial LLM provider
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('shadow-ai-001', 'Shadow AI — Commercial LLM API (TLS SNI)',
  'Detects TLS handshake (ssl.log) with SNI targeting a known commercial LLM endpoint. May indicate unauthorized ChatGPT/Claude/Gemini/Mistral/Copilot usage. Qualified by skill shadow-ai-monitor against policy whitelist.',
  'medium', 'ThreatClaw', 'zeek', 'ssl',
  ARRAY['attack.exfiltration','attack.t1567.004','ai.governance','ai.shadow','ai.commercial'],
  '',
  '{
    "selection": {"server_name|contains": [
      "api.openai.com","chatgpt.com","chat.openai.com","oaiusercontent.com","platform.openai.com",
      "api.anthropic.com","claude.ai","console.anthropic.com",
      "generativelanguage.googleapis.com","gemini.google.com","aistudio.google.com",
      "api.mistral.ai","chat.mistral.ai","le-chat.mistral.ai",
      "copilot.microsoft.com",
      "api.cohere.ai","openrouter.ai","api.together.xyz","api.together.ai","api.groq.com",
      "api.fireworks.ai","api.perplexity.ai","perplexity.ai",
      "api.x.ai","grok.com","api.deepseek.com","chat.deepseek.com",
      "api-inference.huggingface.co","endpoints.huggingface.cloud",
      "api.cursor.sh","api.githubcopilot.com","api.codeium.com","api.tabnine.com","windsurf.com"
    ]},
    "condition": "selection"
  }'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'zeek', logsource_product = 'ssl', enabled = true;

-- shadow-ai-002 — DNS resolution of a known LLM endpoint
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('shadow-ai-002', 'Shadow AI — DNS query for LLM endpoint',
  'Detects DNS query (dns.log) for a known LLM provider FQDN. Catches usage even when TLS fails or SNI is encrypted (ECH). Lower severity than ssl.log hit because resolution does not confirm actual connection.',
  'low', 'ThreatClaw', 'zeek', 'dns',
  ARRAY['attack.exfiltration','attack.t1567.004','ai.governance','ai.shadow','ai.commercial'],
  '',
  '{
    "selection": {"query|contains": [
      "openai.com","anthropic.com","claude.ai","mistral.ai","cohere.ai",
      "generativelanguage.googleapis.com","gemini.google.com","aistudio.google.com","copilot.microsoft.com",
      "openrouter.ai","together.xyz","groq.com","fireworks.ai","perplexity.ai",
      "x.ai","grok.com","deepseek.com","huggingface.co","replicate.com","cursor.sh",
      "githubcopilot.com","codeium.com","tabnine.com","windsurf.com"
    ]},
    "condition": "selection"
  }'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'zeek', logsource_product = 'dns', enabled = true;

-- shadow-ai-003 — Internal connection to a self-hosted LLM default port
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('shadow-ai-003', 'Shadow AI — Self-hosted LLM runtime port',
  'Detects TCP connection (conn.log) targeting a default port used by Ollama (11434), vLLM (8000), LM Studio (1234/43411), Jan.ai (1337), GPT4All (4891) or Text Generation WebUI (7860). Indicates possible undeclared LLM server on the LAN. Ports 8080/3000/5000 are intentionally excluded (too noisy).',
  'medium', 'ThreatClaw', 'zeek', 'conn',
  ARRAY['discovery','ai.governance','ai.shadow','ai.self_hosted'],
  '',
  '{
    "selection": {"id.resp_p": [11434, 1234, 43411, 8000, 7860, 1337, 4891]},
    "condition": "selection"
  }'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'zeek', logsource_product = 'conn', enabled = true;

-- shadow-ai-004 — HTTP request to an OpenAI-compatible API path
INSERT INTO sigma_rules (id, title, description, level, author, logsource_category, logsource_product, tags, rule_yaml, detection_json, enabled)
VALUES ('shadow-ai-004', 'Shadow AI — OpenAI-compatible API path (HTTP)',
  'Detects clear-text HTTP request (http.log) targeting /v1/chat/completions, /v1/completions, /v1/embeddings, /api/generate, /api/chat or /api/tags. Fires on LAN-local LLM runtimes behind plain HTTP (Ollama, vLLM, LM Studio without TLS).',
  'medium', 'ThreatClaw', 'zeek', 'http',
  ARRAY['attack.exfiltration','attack.t1567.004','ai.governance','ai.shadow','ai.self_hosted'],
  '',
  '{
    "selection": {"uri|contains": [
      "/v1/chat/completions","/v1/completions","/v1/embeddings",
      "/api/generate","/api/chat","/api/tags"
    ]},
    "condition": "selection"
  }'::jsonb, true)
ON CONFLICT (id) DO UPDATE SET detection_json = EXCLUDED.detection_json, logsource_category = 'zeek', logsource_product = 'http', enabled = true;

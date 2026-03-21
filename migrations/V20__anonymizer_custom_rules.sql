-- V20: Custom anonymization rules (RSSI-defined patterns)
--
-- Allows the RSSI to add custom regex patterns for anonymizing
-- company-specific data before sending to cloud LLMs.

CREATE TABLE IF NOT EXISTS anonymizer_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label       TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    token_prefix TEXT NOT NULL DEFAULT 'CUSTOM',
    capture_group INTEGER NOT NULL DEFAULT 0,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_by  TEXT NOT NULL DEFAULT '_system',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE anonymizer_rules IS 'Custom anonymization rules defined by the RSSI for cloud LLM calls';
COMMENT ON COLUMN anonymizer_rules.pattern IS 'Rust-compatible regex pattern';
COMMENT ON COLUMN anonymizer_rules.token_prefix IS 'Token prefix, e.g. PROJECT → [PROJECT-001]';
COMMENT ON COLUMN anonymizer_rules.capture_group IS '0 = full match, 1+ = capture group N';

CREATE INDEX idx_anonymizer_rules_enabled ON anonymizer_rules(enabled) WHERE enabled = true;

-- Web chat streaming support for the L0 conversational bot. See roadmap §3.6.
--
-- Reuses the IronClaw conversations + conversation_messages tables and adds
-- the columns a streaming web client needs:
--
--   conversations.title         — short human label for the sidebar list
--   conversation_messages.status — 'streaming' | 'complete' | 'failed' | 'orphaned'
--   conversation_messages.tool_calls JSONB — AI SDK ToolCall array
--   conversation_messages.citations JSONB — grounding citations
--   conversation_messages.updated_at TIMESTAMPTZ — last streamed write
--
-- Backward-compatible: all additions are nullable or have a default. Existing
-- rows default to status='complete' because they were written synchronously
-- by the Telegram path before this migration existed.
--
-- Orphan sweeper: a streamed message whose updated_at is older than 2 minutes
-- can be presumed abandoned (server crash mid-stream, client gone, etc.) and
-- its status is flipped to 'orphaned' so the UI can show it explicitly rather
-- than spinning forever. The sweeper is implemented two ways: a SQL function
-- plus pg_cron if the extension is available, and fall back to a Rust-side
-- tokio task invoked from the backend (kept in src/agent/chat_sweeper.rs).

ALTER TABLE conversations
    ADD COLUMN IF NOT EXISTS title TEXT;

ALTER TABLE conversation_messages
    ADD COLUMN IF NOT EXISTS status     TEXT        NOT NULL DEFAULT 'complete'
        CHECK (status IN ('streaming', 'complete', 'failed', 'orphaned')),
    ADD COLUMN IF NOT EXISTS tool_calls JSONB,
    ADD COLUMN IF NOT EXISTS citations  JSONB,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Touch updated_at on every content write so the sweeper can recognize
-- abandoned streams. Created on ALTER so libSQL stays in sync by re-creating
-- the index on the equivalent column.
CREATE INDEX IF NOT EXISTS idx_conversation_messages_streaming
    ON conversation_messages (updated_at)
    WHERE status = 'streaming';

CREATE INDEX IF NOT EXISTS idx_conversation_messages_created
    ON conversation_messages (conversation_id, created_at);

-- Pure SQL sweeper. Safe to call repeatedly; idempotent.
CREATE OR REPLACE FUNCTION sweep_orphan_streaming_messages(stale_after INTERVAL DEFAULT INTERVAL '2 minutes')
RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE
    affected INTEGER;
BEGIN
    UPDATE conversation_messages
       SET status = 'orphaned', updated_at = NOW()
     WHERE status = 'streaming'
       AND updated_at < NOW() - stale_after;
    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected;
END;
$$;

-- pg_cron schedule. Wrapped in a DO block because pg_cron is an optional
-- extension and we don't want the migration to fail on installs without it.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        PERFORM cron.schedule(
            'sweep_orphan_streaming_messages',
            '*/2 * * * *',
            $CRON$ SELECT sweep_orphan_streaming_messages(); $CRON$
        );
    END IF;
EXCEPTION WHEN OTHERS THEN
    -- pg_cron exists but is not in this DB, or the user is not a superuser.
    -- Fallback sweeper lives in the Rust process, so this is non-fatal.
    RAISE NOTICE 'pg_cron not configured: web chat orphan sweeper will run from the Rust backend';
END $$;

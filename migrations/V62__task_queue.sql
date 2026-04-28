-- V62: Task queue + graph executions for Investigation Graphs (Phase G1b).
--
-- L'`investigation_graph` runtime (G1a, src/agent/investigation_graph/)
-- traverse un DAG en mode synchrone. Quand il rencontre un step async
-- (call LLM, call skill, fan-out parallel), il s'arrête sur un verdict
-- `PendingAsync` — c'est ici que la queue prend le relais :
--
--   executor → push task au task_queue → workers pull → résultat → resume executor
--
-- Bénéfices :
-- - Crash-resistant : si le core meurt en plein graph, on recover via les
--   tasks `running` qu'on remet en `queued`.
-- - Scalable : pool de workers avec Semaphore borne la concurrence par
--   type (LLM = 1-2, skills = 50, graphs = 20).
-- - Backpressure : si task_queue dépasse seuil, on refuse les nouveaux
--   graphs gracieusement plutôt que de saturer Ollama.
--
-- Modèle inspiré de V51 scan_queue, généralisé pour des tasks arbitraires.

-- ── Header table : un graph en exécution ──
--
-- Une row par run de graph (sigma_alert → graph). Mise à jour quand le
-- graph progresse (status, trace). Permet :
-- - de retrouver tous les tasks d'un graph (graph_run_id FK)
-- - d'afficher l'onglet "Enquêtes en cours" de la refonte UI (statut +
--   step actuel + durée)
-- - de loguer le verdict final pour les rapports / archive UI
CREATE TABLE IF NOT EXISTS graph_executions (
    id              BIGSERIAL PRIMARY KEY,
    graph_name      TEXT NOT NULL,                  -- ex: 'backdoor-port-block-handled'
    sigma_alert_id  BIGINT,                         -- FK logique vers sigma_alerts
    asset_id        TEXT,                           -- assets.id (si applicable)
    status          TEXT NOT NULL DEFAULT 'running',
    -- statuts possibles :
    --   running     : le graph est en cours (au moins un task non-fini)
    --   archived    : terminé en branche `archive` (motif dans archive_reason)
    --   incident    : terminé en branche `emit_incident` (FK incident_id)
    --   inconclusive: terminé sans verdict utile (graph End sans action)
    --   failed      : erreur d'exécution (CEL malformée, max steps, ...)
    archive_reason  TEXT,                           -- si status='archived'
    incident_id     INTEGER,                        -- si status='incident'
    trace           JSONB,                          -- ExecutionTrace complète (G1a)
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    duration_ms     INTEGER,
    error           TEXT                            -- si status='failed'
);

-- Pour l'onglet "Enquêtes en cours" : list les running, par durée décroissante.
CREATE INDEX IF NOT EXISTS graph_executions_running_idx
    ON graph_executions (status, started_at DESC)
    WHERE status = 'running';

-- Pour l'onglet "Archives" : filtre par motif + asset.
CREATE INDEX IF NOT EXISTS graph_executions_archive_idx
    ON graph_executions (archive_reason, finished_at DESC)
    WHERE status = 'archived';

CREATE INDEX IF NOT EXISTS graph_executions_asset_idx
    ON graph_executions (asset_id, started_at DESC)
    WHERE asset_id IS NOT NULL;

COMMENT ON TABLE graph_executions IS
    'En-tête d''une exécution de graph (Phase G). Une row par run.';
COMMENT ON COLUMN graph_executions.status IS
    'running | archived | incident | inconclusive | failed';

-- ── Task queue : les unités de travail des workers ──
--
-- Chaque PendingAsync de l'executor pousse une row ici. Les workers
-- pullent par priorité + ancienneté, exécutent l'action, écrivent le
-- résultat, puis le superviseur du graph reprend l'exécution.
CREATE TABLE IF NOT EXISTS task_queue (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,                  -- skill_call | llm_call | graph_step
    graph_run_id    BIGINT REFERENCES graph_executions(id) ON DELETE CASCADE,
    payload         JSONB NOT NULL,                 -- params (skill_name, prompt, ...)
    status          TEXT NOT NULL DEFAULT 'queued', -- queued | running | done | error
    priority        SMALLINT NOT NULL DEFAULT 5,    -- 0=high, 9=low (enforced via index ordering)
    attempts        SMALLINT NOT NULL DEFAULT 0,
    max_attempts    SMALLINT NOT NULL DEFAULT 3,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    worker_id       TEXT,                           -- 'worker-llm-1' | 'worker-skill-7' | ...
    result          JSONB,                          -- output structuré (verdict LLM, response skill, ...)
    error           TEXT
);

-- Hot path : workers pull queued par priorité + ancienneté.
-- SELECT FOR UPDATE SKIP LOCKED côté worker pour éviter les races.
CREATE INDEX IF NOT EXISTS task_queue_pull_idx
    ON task_queue (kind, priority, created_at)
    WHERE status = 'queued';

-- Recovery : au boot, on recherche les tasks `running` plus vieilles que
-- N minutes (worker mort sans nettoyage) et on les remet en `queued`.
CREATE INDEX IF NOT EXISTS task_queue_running_idx
    ON task_queue (status, started_at)
    WHERE status = 'running';

-- Per-graph : "tous les tasks de l'enquête X"
CREATE INDEX IF NOT EXISTS task_queue_graph_idx
    ON task_queue (graph_run_id, created_at);

-- Backpressure : compter rapidement les rows par status pour décider si
-- on accepte de nouveaux graphs (vs refuser avec "system overloaded").
CREATE INDEX IF NOT EXISTS task_queue_status_idx
    ON task_queue (status)
    WHERE status IN ('queued', 'running');

COMMENT ON TABLE task_queue IS
    'Queue async des steps d''Investigation Graph (Phase G). Workers pullent par kind + priority.';
COMMENT ON COLUMN task_queue.kind IS
    'skill_call (call enrichment skill) | llm_call (L1/L2) | graph_step (sub-graph)';
COMMENT ON COLUMN task_queue.priority IS
    '0 (high) à 9 (low). Workers triés ASC sur cette colonne avant created_at.';

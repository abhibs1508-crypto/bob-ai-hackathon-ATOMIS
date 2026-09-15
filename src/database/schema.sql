-- =============================================================================
-- CyberFusion — PostgreSQL (Supabase) Schema
-- =============================================================================
-- Run this file against your Supabase SQL Editor.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- threat_events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_events (
    id              UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    event_id        VARCHAR(128)    NOT NULL UNIQUE,
    source          VARCHAR(64)     NOT NULL,
    timestamp       TIMESTAMP       NOT NULL,
    event_type      VARCHAR(64)     NOT NULL,
    source_ip       VARCHAR(45)     NULL,
    target          VARCHAR(255)    NULL,
    indicator_type  VARCHAR(32)     NULL,
    indicator_value VARCHAR(512)    NULL,
    severity        TEXT            NOT NULL DEFAULT 'low' CHECK (severity IN ('low','medium','high','critical')),
    confidence      SMALLINT        NOT NULL DEFAULT 50,
    location        VARCHAR(128)    NULL,
    raw_data        JSONB           NULL,
    ingested_at     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_source_ip ON threat_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_target ON threat_events (target);
CREATE INDEX IF NOT EXISTS idx_timestamp ON threat_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type ON threat_events (event_type);

-- ---------------------------------------------------------------------------
-- indicators
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS indicators (
    id              UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    indicator_type  VARCHAR(32)     NOT NULL,
    indicator_value VARCHAR(512)    NOT NULL,
    threat_type     VARCHAR(64)     NULL,
    confidence      SMALLINT        NOT NULL DEFAULT 50,
    source          VARCHAR(128)    NULL,
    first_seen      TIMESTAMP       NULL,
    last_seen       TIMESTAMP       NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (indicator_type, indicator_value)
);

CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators (indicator_value);

-- ---------------------------------------------------------------------------
-- entities
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entities (
    id              UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    name            VARCHAR(255)    NOT NULL UNIQUE,
    entity_type     VARCHAR(32)     NOT NULL DEFAULT 'server',
    criticality     SMALLINT        NOT NULL DEFAULT 50,
    description     TEXT            NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- correlations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlations (
    id                      UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    correlation_key         VARCHAR(128)    NOT NULL UNIQUE,
    title                   VARCHAR(255)    NOT NULL,
    description             TEXT            NULL,
    event_count             INTEGER         NOT NULL DEFAULT 0,
    correlation_factors     JSONB           NOT NULL DEFAULT '{}',
    correlation_score       SMALLINT        NOT NULL DEFAULT 0,
    correlation_strength    TEXT            NOT NULL DEFAULT 'none' CHECK (correlation_strength IN ('none','weak','moderate','strong','definitive')),
    status                  TEXT            NOT NULL DEFAULT 'active' CHECK (status IN ('active','resolved','dismissed')),
    first_seen              TIMESTAMP       NULL,
    last_seen               TIMESTAMP       NULL,
    source_ips              JSONB           NULL DEFAULT '[]',
    targets                 JSONB           NULL DEFAULT '[]',
    source_types            JSONB           NULL DEFAULT '[]',
    attack_stages           JSONB           NULL DEFAULT '[]',
    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_created_at ON correlations (created_at);
CREATE INDEX IF NOT EXISTS idx_status ON correlations (status);


-- ---------------------------------------------------------------------------
-- correlation_events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation_events (
    correlation_id  UUID        NOT NULL,
    event_id        UUID        NOT NULL,
    PRIMARY KEY (correlation_id, event_id),
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id)       REFERENCES threat_events(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- risk_scores
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_scores (
    id                      UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    correlation_id          UUID        NOT NULL UNIQUE,
    score                   SMALLINT    NOT NULL DEFAULT 0,
    priority                TEXT        NOT NULL DEFAULT 'low' CHECK (priority IN ('low','medium','high','critical')),
    severity_component      SMALLINT    NOT NULL DEFAULT 0,
    ioc_match_component     SMALLINT    NOT NULL DEFAULT 0,
    asset_criticality_component SMALLINT NOT NULL DEFAULT 0,
    correlation_strength_component SMALLINT NOT NULL DEFAULT 0,
    recency_component       SMALLINT    NOT NULL DEFAULT 0,
    calculated_at           TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- alerts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    correlation_id  UUID            NOT NULL,
    title           VARCHAR(255)    NOT NULL,
    priority        TEXT            NOT NULL CHECK (priority IN ('low','medium','high','critical')),
    status          TEXT            NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','closed')),
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_priority ON alerts (priority);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at);

-- ---------------------------------------------------------------------------
-- intelligence_reports
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS intelligence_reports (
    id                  UUID            NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    correlation_id      UUID            NOT NULL UNIQUE,
    bluf                TEXT            NOT NULL,
    threat_assessment   TEXT            NULL,
    possible_intent     TEXT            NULL,
    reasoning           TEXT            NULL,
    evidence_summary    TEXT            NULL,
    recommended_actions JSONB           NULL,
    ai_provider         VARCHAR(32)     NULL,
    ai_model            VARCHAR(64)     NULL,
    confidence_score    SMALLINT        NULL,
    categorization      TEXT            NULL CHECK (categorization IN ('Critical','Medium','Low')),
    is_false_positive   BOOLEAN         NOT NULL DEFAULT FALSE,
    generated_at        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE
);

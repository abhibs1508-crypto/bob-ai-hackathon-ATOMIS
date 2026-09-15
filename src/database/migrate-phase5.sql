-- =============================================================================
-- CyberFusion — Phase 5 Migration: AI Intelligence Reports
-- =============================================================================
-- Run AFTER schema.sql, migrate-phase3.sql, and migrate-phase4.sql.
-- Idempotent: uses IF NOT EXISTS / IF NOT EXISTS guards throughout.
-- =============================================================================

-- intelligence_reports --------------------------------------------------------
-- Stores the AI-generated (or fallback) assessment for each correlation.
-- One row per correlation_id enforced by the UNIQUE constraint.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS intelligence_reports (
  id                 CHAR(36)       NOT NULL,
  correlation_id     CHAR(36)       NOT NULL,

  -- Core intelligence output
  bluf               TEXT           NOT NULL,
  threat_assessment  TEXT           NOT NULL,
  possible_intent    TEXT           NOT NULL,
  reasoning          TEXT           NOT NULL,
  evidence_summary   TEXT           NOT NULL,

  -- Stored as a JSON array of strings; parsed in application layer
  recommended_actions LONGTEXT      NOT NULL DEFAULT ('[]'),

  -- Provenance
  ai_provider        VARCHAR(64)    NOT NULL DEFAULT 'unknown',
  ai_model           VARCHAR(128)   NULL,
  confidence_score   TINYINT UNSIGNED NOT NULL DEFAULT 60,

  generated_at       DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                                    ON UPDATE CURRENT_TIMESTAMP(3),

  PRIMARY KEY (id),
  UNIQUE KEY uq_intelligence_correlation (correlation_id),
  CONSTRAINT fk_intelligence_correlation
    FOREIGN KEY (correlation_id) REFERENCES correlations (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Index to speed up dashboard queries that filter by confidence and provider
CREATE INDEX IF NOT EXISTS idx_intel_confidence
  ON intelligence_reports (confidence_score);

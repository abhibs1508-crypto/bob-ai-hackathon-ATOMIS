-- =============================================================================
-- CyberFusion — Phase 4 Local Schema Repair
-- =============================================================================
-- Repairs databases where the Phase 4 migration was not previously applied.
-- This is additive and idempotent: it neither recreates risk_scores nor changes
-- existing risk-score rows.
-- =============================================================================

USE cyberfusion_db;

ALTER TABLE risk_scores
  ADD COLUMN IF NOT EXISTS risk_evidence JSON NULL COMMENT 'Structured explainability evidence for the risk calculation';

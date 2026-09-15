-- =============================================================================
-- CyberFusion — Phase 3 Schema Migration
-- =============================================================================
-- Adds Phase 3 columns to the correlations table.
-- Safe to run multiple times (uses IF NOT EXISTS / IGNORE patterns).
-- Run AFTER schema.sql has been applied.
-- =============================================================================

USE cyberfusion_db;

-- Add correlation_score (0-100) to correlations
ALTER TABLE correlations
  ADD COLUMN IF NOT EXISTS correlation_score   TINYINT UNSIGNED NOT NULL DEFAULT 0     COMMENT '0-100 bounded correlation score',
  ADD COLUMN IF NOT EXISTS correlation_strength VARCHAR(16)     NOT NULL DEFAULT 'weak' COMMENT 'weak|moderate|strong|very_strong',
  ADD COLUMN IF NOT EXISTS status              VARCHAR(16)     NOT NULL DEFAULT 'active' COMMENT 'active|resolved|dismissed',
  ADD COLUMN IF NOT EXISTS first_seen          DATETIME(3)     NULL                     COMMENT 'Timestamp of earliest correlated event',
  ADD COLUMN IF NOT EXISTS last_seen           DATETIME(3)     NULL                     COMMENT 'Timestamp of latest correlated event',
  ADD COLUMN IF NOT EXISTS source_ips          JSON            NULL                     COMMENT 'Array of unique source IPs in cluster',
  ADD COLUMN IF NOT EXISTS targets             JSON            NULL                     COMMENT 'Array of unique targets in cluster',
  ADD COLUMN IF NOT EXISTS source_types        JSON            NULL                     COMMENT 'Array of unique source types (siem|sensor|etc)',
  ADD COLUMN IF NOT EXISTS attack_stages       JSON            NULL                     COMMENT 'Detected MITRE-aligned attack stages';

-- Add index on status and score for dashboard queries (Phase 4+)
CREATE INDEX IF NOT EXISTS idx_correlations_status ON correlations(status);
CREATE INDEX IF NOT EXISTS idx_correlations_score  ON correlations(correlation_score);

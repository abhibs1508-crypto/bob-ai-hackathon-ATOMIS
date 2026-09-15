-- =============================================================================
-- CyberFusion — Phase 4 Schema Migration
-- =============================================================================
-- Adds risk_evidence JSON column to risk_scores.
-- Safe to execute more than once: uses IF NOT EXISTS guard.
-- Run AFTER schema.sql and migrate-phase3.sql have been applied.
-- =============================================================================

USE cyberfusion_db;

ALTER TABLE risk_scores
  ADD COLUMN IF NOT EXISTS risk_evidence JSON NULL COMMENT 'Structured explainability evidence for the risk calculation';

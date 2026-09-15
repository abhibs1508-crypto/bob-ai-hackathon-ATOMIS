-- =============================================================================
-- CyberFusion — MySQL Schema
-- =============================================================================
-- Run this file against a MySQL 8+ instance to initialise the database.
-- Credentials must be provided via environment variables; never hardcode them.
-- =============================================================================

-- Use cyberfusion_db to match local XAMPP development environment (DB_NAME env var).
-- Change the database name here OR use the DB_NAME env var in application config.
CREATE DATABASE IF NOT EXISTS cyberfusion_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cyberfusion_db;

-- ---------------------------------------------------------------------------
-- threat_events
-- Normalised representation of every ingested threat event regardless of
-- the original source format (SIEM, sensor, TI feed, intelligence report).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_events (
    id              CHAR(36)        NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    event_id        VARCHAR(128)    NOT NULL UNIQUE,          -- original source ID
    source          VARCHAR(64)     NOT NULL,                 -- e.g. "siem", "sensor", "ti_feed"
    timestamp       DATETIME(3)     NOT NULL,
    event_type      VARCHAR(64)     NOT NULL,                 -- e.g. "port_scan", "failed_login"
    source_ip       VARCHAR(45)     NULL,                     -- IPv4 or IPv6
    target          VARCHAR(255)    NULL,                     -- hostname / IP / URL
    indicator_type  VARCHAR(32)     NULL,                     -- e.g. "ip", "domain", "hash"
    indicator_value VARCHAR(512)    NULL,
    severity        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'low',
    confidence      TINYINT UNSIGNED NOT NULL DEFAULT 50,     -- 0-100
    location        VARCHAR(128)    NULL,
    raw_data        JSON            NULL,
    ingested_at     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    INDEX idx_source_ip (source_ip),
    INDEX idx_target    (target(64)),
    INDEX idx_timestamp (timestamp),
    INDEX idx_event_type (event_type)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- indicators
-- Threat intelligence indicators (IOCs) from TI feeds or manual input.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS indicators (
    id              CHAR(36)        NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    indicator_type  VARCHAR(32)     NOT NULL,
    indicator_value VARCHAR(512)    NOT NULL,
    threat_type     VARCHAR(64)     NULL,                     -- e.g. "malware", "c2", "scanner"
    confidence      TINYINT UNSIGNED NOT NULL DEFAULT 50,
    source          VARCHAR(128)    NULL,
    first_seen      DATETIME        NULL,
    last_seen       DATETIME        NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uq_indicator (indicator_type, indicator_value(128)),
    INDEX idx_indicator_value (indicator_value(64))
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- entities
-- High-value assets / targets so the risk engine can apply criticality weight.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entities (
    id              CHAR(36)        NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    name            VARCHAR(255)    NOT NULL UNIQUE,
    entity_type     VARCHAR(32)     NOT NULL DEFAULT 'server', -- server|workstation|network|service
    criticality     TINYINT UNSIGNED NOT NULL DEFAULT 50,      -- 0-100
    description     TEXT            NULL,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- correlations
-- A correlation groups related threat_events into one logical threat cluster.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlations (
    id                  CHAR(36)        NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    correlation_key     VARCHAR(128)    NOT NULL UNIQUE,       -- deterministic hash of grouping criteria
    title               VARCHAR(255)    NOT NULL,
    description         TEXT            NULL,
    event_count         SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    correlation_factors JSON            NOT NULL,             -- which rules fired and why
    created_at          DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- correlation_events (join table)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation_events (
    correlation_id  CHAR(36)    NOT NULL,
    event_id        CHAR(36)    NOT NULL,
    PRIMARY KEY (correlation_id, event_id),
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id)       REFERENCES threat_events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- risk_scores
-- One risk score record per correlation (or standalone event if uncorrelated).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_scores (
    id                      CHAR(36)    NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    correlation_id          CHAR(36)    NOT NULL UNIQUE,
    score                   TINYINT UNSIGNED NOT NULL DEFAULT 0,  -- 0-100
    priority                ENUM('low','medium','high','critical') NOT NULL DEFAULT 'low',
    severity_component      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    ioc_match_component     TINYINT UNSIGNED NOT NULL DEFAULT 0,
    asset_criticality_component TINYINT UNSIGNED NOT NULL DEFAULT 0,
    correlation_strength_component TINYINT UNSIGNED NOT NULL DEFAULT 0,
    recency_component       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    calculated_at           DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- alerts
-- Analyst-facing alerts derived from high/critical risk_scores.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              CHAR(36)        NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    correlation_id  CHAR(36)        NOT NULL,
    title           VARCHAR(255)    NOT NULL,
    priority        ENUM('low','medium','high','critical') NOT NULL,
    status          ENUM('open','acknowledged','closed') NOT NULL DEFAULT 'open',
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE,
    INDEX idx_status   (status),
    INDEX idx_priority (priority),
    INDEX idx_created  (created_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- intelligence_reports
-- AI-generated assessments attached to a correlation.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS intelligence_reports (
    id                  CHAR(36)        NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    correlation_id      CHAR(36)        NOT NULL UNIQUE,
    bluf                TEXT            NOT NULL,             -- Bottom Line Up Front
    threat_assessment   TEXT            NULL,
    possible_intent     TEXT            NULL,
    reasoning           TEXT            NULL,
    evidence_summary    TEXT            NULL,
    recommended_actions JSON            NULL,                 -- array of action strings
    ai_provider         VARCHAR(32)     NULL,
    ai_model            VARCHAR(64)     NULL,
    confidence_score    TINYINT UNSIGNED NULL,               -- 0-100
    generated_at        DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

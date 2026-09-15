'use strict';

/**
 * CyberFusion — Correlation Engine Configuration
 *
 * All weights, thresholds, and time windows for the correlation engine.
 * Values are read from environment variables where overrides are useful,
 * with sensible defaults built in.
 *
 * Changing these values only requires an environment variable change — no
 * code edits. The engine remains deterministic and fully explainable.
 */

const config = require('../../config');

// ---------------------------------------------------------------------------
// Temporal windows (minutes)
// ---------------------------------------------------------------------------
const WINDOWS = Object.freeze({
  /** Events this close together are considered immediate activity */
  IMMEDIATE: parseInt(process.env.CORR_WINDOW_IMMEDIATE || '5', 10),
  /** Short attack sequence — recon → auth attack */
  SHORT:     parseInt(process.env.CORR_WINDOW_SHORT     || '15', 10),
  /** Extended campaign — multi-stage over longer period */
  EXTENDED:  parseInt(process.env.CORR_WINDOW_EXTENDED  || '60', 10),
  /** IOC / intelligence relationship — can span longer period */
  CAMPAIGN:  parseInt(process.env.CORR_WINDOW_CAMPAIGN  || '1440', 10), // 24 h
});

// ---------------------------------------------------------------------------
// Rule weights (must sum ≤ 100 to keep score bounded)
// ---------------------------------------------------------------------------
const WEIGHTS = Object.freeze({
  SAME_SOURCE:       parseInt(process.env.CORR_W_SAME_SOURCE       || '10', 10),
  SAME_TARGET:       parseInt(process.env.CORR_W_SAME_TARGET       || '10', 10),
  SOURCE_TARGET:     parseInt(process.env.CORR_W_SOURCE_TARGET     || '15', 10),
  TEMPORAL:          parseInt(process.env.CORR_W_TEMPORAL          || '10', 10),
  IOC_MATCH:         parseInt(process.env.CORR_W_IOC_MATCH         || '20', 10),
  CROSS_SOURCE:      parseInt(process.env.CORR_W_CROSS_SOURCE      || '15', 10),
  REPEATED_ACTIVITY: parseInt(process.env.CORR_W_REPEATED_ACTIVITY || '5',  10),
  ENTITY_RELATION:   parseInt(process.env.CORR_W_ENTITY_RELATION   || '5',  10),
  ATTACK_SEQUENCE:   parseInt(process.env.CORR_W_ATTACK_SEQUENCE   || '10', 10),
  // Max possible = 100; weights above sum to 100
});

// ---------------------------------------------------------------------------
// Strength thresholds (lower bounds, inclusive)
// ---------------------------------------------------------------------------
const STRENGTH = Object.freeze({
  VERY_STRONG: 75,
  STRONG:      50,
  MODERATE:    25,
  WEAK:        0,
});

// ---------------------------------------------------------------------------
// Candidate scan: max events to consider per correlation run
// Keeps the engine O(N) not O(N²) for the hackathon prototype
// ---------------------------------------------------------------------------
const CANDIDATE_LIMIT = parseInt(process.env.CORR_CANDIDATE_LIMIT || '200', 10);

// ---------------------------------------------------------------------------
// Minimum evidence threshold — a correlation must have at least this many
// matched rules before it is persisted
// ---------------------------------------------------------------------------
const MIN_RULES_MATCHED = parseInt(process.env.CORR_MIN_RULES || '1', 10);

module.exports = { WINDOWS, WEIGHTS, STRENGTH, CANDIDATE_LIMIT, MIN_RULES_MATCHED };

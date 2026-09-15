'use strict';

/**
 * CyberFusion — Risk Engine Configuration
 *
 * All weights, thresholds and tuning parameters for Phase 4.
 * Every value is env-overridable so the model can be tuned without code edits.
 *
 * FACTOR WEIGHTS (must sum to 1.0):
 *   severity              20%
 *   iocRisk               20%
 *   assetCriticality      20%
 *   correlationStrength   20%
 *   recency               10%
 *   attackProgression      5%
 *   crossSource            5%
 */

// ---------------------------------------------------------------------------
// Factor weights (expressed as fractions, sum = 1.0)
// ---------------------------------------------------------------------------
const FACTOR_WEIGHTS = Object.freeze({
  severity:            parseFloat(process.env.RISK_W_SEVERITY              || '0.20'),
  iocRisk:             parseFloat(process.env.RISK_W_IOC_RISK              || '0.20'),
  assetCriticality:    parseFloat(process.env.RISK_W_ASSET_CRITICALITY     || '0.20'),
  correlationStrength: parseFloat(process.env.RISK_W_CORRELATION_STRENGTH  || '0.20'),
  recency:             parseFloat(process.env.RISK_W_RECENCY               || '0.10'),
  attackProgression:   parseFloat(process.env.RISK_W_ATTACK_PROGRESSION    || '0.05'),
  crossSource:         parseFloat(process.env.RISK_W_CROSS_SOURCE          || '0.05'),
});

// ---------------------------------------------------------------------------
// Priority thresholds (lower-bound inclusive)
// ---------------------------------------------------------------------------
const PRIORITY_THRESHOLDS = Object.freeze({
  CRITICAL: 75,
  HIGH:     50,
  MEDIUM:   25,
  LOW:      0,
});

// ---------------------------------------------------------------------------
// Severity score mapping (from normalised threat_events.severity values)
// ---------------------------------------------------------------------------
const SEVERITY_SCORES = Object.freeze({
  critical: 100,
  high:      75,
  medium:    50,
  low:       25,
});

// ---------------------------------------------------------------------------
// IOC reputation scores
// ---------------------------------------------------------------------------
const IOC_SCORES = Object.freeze({
  KNOWN_MALICIOUS: 100,
  HIGH_CONFIDENCE:  90,
  SUSPICIOUS:       70,
  UNKNOWN:          25,
  NONE:              0,
});

// Confidence threshold above which an indicator is treated as HIGH_CONFIDENCE
const IOC_HIGH_CONFIDENCE_THRESHOLD = parseInt(process.env.RISK_IOC_HIGH_CONF || '80', 10);

// ---------------------------------------------------------------------------
// Recency decay — exponential half-life in minutes
// ---------------------------------------------------------------------------
const RECENCY_HALF_LIFE_MINUTES = parseInt(process.env.RECENCY_HALF_LIFE_MINUTES || '120', 10);

// ---------------------------------------------------------------------------
// Default asset criticality when no entity metadata is available
// ---------------------------------------------------------------------------
const DEFAULT_ASSET_CRITICALITY = parseInt(process.env.RISK_DEFAULT_ASSET_CRITICALITY || '25', 10);

// ---------------------------------------------------------------------------
// Attack progression stage scores
// ---------------------------------------------------------------------------
const ATTACK_PROGRESSION_SCORES = Object.freeze({
  0: 0,
  1: 25,
  2: 55,
  3: 75,
  4: 100,  // 4+ stages → 100
});

// Stages that count as meaningful attack progression
// THREAT_INTEL is an intelligence source category, not an attack stage.
const MEANINGFUL_ATTACK_STAGES = new Set([
  'RECONNAISSANCE',
  'INITIAL_ACCESS',
  'CREDENTIAL_ATTACK',
  'EXPLOITATION',
  'PERSISTENCE',
  'PRIVILEGE_ESCALATION',
  'LATERAL_MOVEMENT',
  'COMMAND_AND_CONTROL',
  'EXFILTRATION',
]);

// ---------------------------------------------------------------------------
// Cross-source score table (keyed by distinct source count)
// ---------------------------------------------------------------------------
const CROSS_SOURCE_SCORES = Object.freeze({
  0: 0,
  1: 20,
  2: 50,
  3: 80,
  4: 100,  // 4+ sources → 100
});

module.exports = {
  FACTOR_WEIGHTS,
  PRIORITY_THRESHOLDS,
  SEVERITY_SCORES,
  IOC_SCORES,
  IOC_HIGH_CONFIDENCE_THRESHOLD,
  RECENCY_HALF_LIFE_MINUTES,
  DEFAULT_ASSET_CRITICALITY,
  ATTACK_PROGRESSION_SCORES,
  MEANINGFUL_ATTACK_STAGES,
  CROSS_SOURCE_SCORES,
};

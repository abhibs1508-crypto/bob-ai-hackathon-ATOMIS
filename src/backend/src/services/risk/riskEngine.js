'use strict';

/**
 * CyberFusion — Risk Engine
 *
 * Pure function — no I/O, no database calls, fully unit-testable.
 * Receives a RiskContext containing all data needed for the seven factors
 * and returns a RiskResult with score, priority, component scores, and
 * structured explainability evidence.
 *
 * Architecture:
 *   RiskService loads data from DB → builds RiskContext → calls runRiskEngine()
 *   → persists RiskResult via RiskRepository → creates/updates Alert
 *
 * @typedef {Object} RiskContext
 * @property {Object}   correlation        — row from correlations table (with Phase 3 columns)
 * @property {Object[]} events             — threat_events rows in the correlation
 * @property {Object[]} matchedIndicators  — rows from indicators table
 * @property {Object[]} targetEntities     — rows from entities table
 *
 * @typedef {Object} RiskResult
 * @property {number}   score
 * @property {string}   priority           — low|medium|high|critical
 * @property {number}   severityComponent
 * @property {number}   iocMatchComponent
 * @property {number}   assetCriticalityComponent
 * @property {number}   correlationStrengthComponent
 * @property {number}   recencyComponent
 * @property {Object}   riskEvidence       — full structured evidence JSON
 */

const {
  calcSeverity,
  calcIocRisk,
  calcAssetCriticality,
  calcCorrelationStrength,
  calcRecency,
  calcAttackProgression,
  calcCrossSource,
} = require('./riskFactors');

const { FACTOR_WEIGHTS } = require('./riskConfig');
const { classifyPriority } = require('./priorityClassifier');
const { buildRiskEvidence } = require('./riskEvidence');

/**
 * Runs the full seven-factor risk calculation.
 * @param {RiskContext} ctx
 * @returns {RiskResult}
 */
function runRiskEngine(ctx) {
  // ── 1. Calculate each factor ────────────────────────────────────────────
  const severity            = calcSeverity(ctx);
  const iocRisk             = calcIocRisk(ctx);
  const assetCriticality    = calcAssetCriticality(ctx);
  const correlationStrength = calcCorrelationStrength(ctx);
  const recency             = calcRecency(ctx);
  const attackProgression   = calcAttackProgression(ctx);
  const crossSource         = calcCrossSource(ctx);

  // ── 2. Apply weights and sum ─────────────────────────────────────────────
  const w = FACTOR_WEIGHTS;

  const weightedSum =
    severity.score            * w.severity            +
    iocRisk.score             * w.iocRisk             +
    assetCriticality.score    * w.assetCriticality    +
    correlationStrength.score * w.correlationStrength +
    recency.score             * w.recency             +
    attackProgression.score   * w.attackProgression   +
    crossSource.score         * w.crossSource;

  // ── 3. Round and clamp to 0–100 ──────────────────────────────────────────
  const score = Math.max(0, Math.min(100, Math.round(weightedSum)));

  // ── 4. Classify priority ─────────────────────────────────────────────────
  const priority = classifyPriority(score);

  // ── 5. Build evidence (contributions must be mathematically consistent) ──
  const factorResults = {
    severity,
    iocRisk,
    assetCriticality,
    correlationStrength,
    recency,
    attackProgression,
    crossSource,
  };

  const riskEvidence = buildRiskEvidence(factorResults, FACTOR_WEIGHTS, score, priority);

  // ── 6. Return flat result matching the DB columns + evidence ─────────────
  return {
    score,
    priority,
    // Named components matching risk_scores table columns
    severityComponent:            severity.score,
    iocMatchComponent:            iocRisk.score,
    assetCriticalityComponent:    assetCriticality.score,
    correlationStrengthComponent: correlationStrength.score,
    recencyComponent:             recency.score,
    // Extra Phase 4 components (stored in risk_evidence JSON)
    attackProgressionComponent:   attackProgression.score,
    crossSourceComponent:         crossSource.score,
    riskEvidence,
  };
}

module.exports = { runRiskEngine };

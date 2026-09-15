'use strict';

/**
 * CyberFusion — Correlation Scoring
 *
 * Combines rule results into a bounded 0–100 correlation score.
 * Score is normalised against the theoretical maximum so that adding more
 * rules never inflates past 100.
 *
 * Strength classification:
 *   VERY_STRONG  ≥ 75
 *   STRONG       ≥ 50
 *   MODERATE     ≥ 25
 *   WEAK         ≥ 0
 */

const { STRENGTH, WEIGHTS } = require('./correlationConfig');

/**
 * Theoretical maximum score (sum of all rule weights).
 * Used to normalise raw score to 0–100.
 */
const MAX_RAW_SCORE = Object.values(WEIGHTS).reduce((a, b) => a + b, 0);

/**
 * @typedef {Object} ScoringResult
 * @property {number}   score       — 0–100
 * @property {string}   strength    — weak | moderate | strong | very_strong
 * @property {string[]} factors     — rule IDs that contributed
 * @property {number}   rawScore    — un-normalised sum
 * @property {number}   maxScore    — theoretical maximum
 */

/**
 * Calculates the bounded correlation score from an array of rule results.
 *
 * @param {Array<import('./correlationEngine').RuleResult>} ruleResults
 * @returns {ScoringResult}
 */
function calculateScore(ruleResults) {
  const matched = ruleResults.filter(r => r.matched);

  let rawScore = 0;
  const factors = [];

  for (const r of matched) {
    const weight     = r.weight || 0;
    const confidence = r.confidence !== undefined ? r.confidence : 1.0;
    rawScore += weight * confidence;
    factors.push(r.ruleId);
  }

  // Normalise to 0–100
  const score = MAX_RAW_SCORE > 0
    ? Math.round(Math.min(100, (rawScore / MAX_RAW_SCORE) * 100))
    : 0;

  const strength = classifyStrength(score);

  return { score, strength, factors, rawScore: Math.round(rawScore), maxScore: MAX_RAW_SCORE };
}

/**
 * Classifies a 0–100 score into a human-readable strength label.
 * @param {number} score
 * @returns {'very_strong'|'strong'|'moderate'|'weak'}
 */
function classifyStrength(score) {
  if (score >= STRENGTH.VERY_STRONG) return 'very_strong';
  if (score >= STRENGTH.STRONG)      return 'strong';
  if (score >= STRENGTH.MODERATE)    return 'moderate';
  return 'weak';
}

module.exports = { calculateScore, classifyStrength, MAX_RAW_SCORE };

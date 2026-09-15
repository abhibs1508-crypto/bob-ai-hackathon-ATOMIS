'use strict';

/**
 * CyberFusion — Risk Evidence Builder
 *
 * Assembles the structured JSON evidence that explains every risk calculation.
 * The evidence is stored in risk_scores.risk_evidence and returned in API responses.
 *
 * Contributions are mathematically consistent with the weights:
 *   contribution = round(factorScore * weight)
 *   sum(contributions) ≈ finalScore (within ±1 due to rounding)
 */

/**
 * @param {Object} factorResults  — keyed by factor name, each { score, reason, detail }
 * @param {Object} weights        — FACTOR_WEIGHTS object
 * @param {number} finalScore
 * @param {string} priority
 * @returns {Object}
 */
function buildRiskEvidence(factorResults, weights, finalScore, priority) {
  const factors = Object.entries(factorResults).map(([name, result]) => {
    const weight       = weights[name] || 0;
    const contribution = Math.round(result.score * weight);
    return {
      name,
      score:        result.score,
      weight,
      contribution,
      reason:       result.reason,
      detail:       result.detail || null,
    };
  });

  // Attack progression and cross-source have their own detail blocks
  const attackProgressionResult = factorResults.attackProgression;
  const crossSourceResult       = factorResults.crossSource;

  return {
    version:   '1.0',
    factors,
    attackProgression: {
      score:          attackProgressionResult ? attackProgressionResult.score  : 0,
      stagesObserved: attackProgressionResult && attackProgressionResult.detail
        ? (attackProgressionResult.detail.meaningfulStages || [])
        : [],
    },
    crossSource: {
      score:          crossSourceResult ? crossSourceResult.score : 0,
      distinctSources: crossSourceResult && crossSourceResult.detail
        ? (crossSourceResult.detail.distinctSources || [])
        : [],
    },
    finalScore,
    priority,
  };
}

module.exports = { buildRiskEvidence };

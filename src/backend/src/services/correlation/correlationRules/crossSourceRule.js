'use strict';

/**
 * Rule: CROSS_SOURCE
 *
 * Fires when the same related activity is observed across 2+ independent
 * source types. Multi-source corroboration is one of the strongest signals
 * because independent systems independently flagging the same actor significantly
 * reduces false-positive probability.
 *
 * SIEM + SENSOR + THREAT_INTEL > three SIEM records alone.
 *
 * Weight: 15
 */

const { WEIGHTS } = require('../correlationConfig');

const RULE_ID = 'CROSS_SOURCE';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const sourceTypes = [...new Set(events.map(e => e.source).filter(Boolean))];

  if (sourceTypes.length < 2) {
    return {
      matched: false,
      ruleId: RULE_ID,
      reason: `All events are from the same source type (${sourceTypes[0] || 'unknown'})`,
    };
  }

  // Confidence scales with the number of independent sources
  const confidence = Math.min(1.0, (sourceTypes.length - 1) / 3);

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.CROSS_SOURCE,
    confidence,
    reason:     `Related evidence observed across ${sourceTypes.length} independent source types: ${sourceTypes.join(', ')}`,
    evidence:   {
      sourceTypes,
      sourceTypeCount: sourceTypes.length,
      eventCountPerSource: sourceTypes.reduce((acc, src) => {
        acc[src] = events.filter(e => e.source === src).length;
        return acc;
      }, {}),
    },
  };
}

module.exports = { RULE_ID, evaluate };

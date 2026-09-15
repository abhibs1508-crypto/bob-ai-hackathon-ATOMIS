'use strict';

/**
 * Rule: IOC_MATCH
 *
 * Fires when any event in the candidate set contains an indicator_value that
 * matches a known malicious indicator in the indicators table.
 *
 * The indicators table is pre-populated by the seed loader or TI ingestion.
 * This is one of the highest-weight rules — a known-bad IOC is explicit
 * threat intelligence, not just inference.
 *
 * Weight: 20
 */

const { WEIGHTS } = require('../correlationConfig');

const RULE_ID = 'IOC_MATCH';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events, matchedIndicators } = ctx;

  if (!matchedIndicators || matchedIndicators.length === 0) {
    return { matched: false, ruleId: RULE_ID, reason: 'No indicators matched' };
  }

  // Find which events have indicator values that appear in matchedIndicators
  const indicatorValues = new Set(matchedIndicators.map(i => i.indicator_value));
  const matchedEvents = (events || []).filter(e =>
    e.indicator_value && indicatorValues.has(e.indicator_value)
  );

  if (matchedEvents.length === 0) {
    return { matched: false, ruleId: RULE_ID };
  }

  const topIndicator = matchedIndicators[0];
  const maxConfidence = Math.max(...matchedIndicators.map(i => i.confidence || 50)) / 100;

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.IOC_MATCH,
    confidence: maxConfidence,
    reason:     `Event indicator matches a known malicious threat-intelligence indicator (${topIndicator.indicator_type}:${topIndicator.indicator_value})`,
    evidence:   {
      matchedIndicators: matchedIndicators.map(i => ({
        type:       i.indicator_type,
        value:      i.indicator_value,
        threatType: i.threat_type,
        confidence: i.confidence,
        source:     i.source,
      })),
      matchedEventIds: matchedEvents.map(e => e.event_id),
    },
  };
}

module.exports = { RULE_ID, evaluate };

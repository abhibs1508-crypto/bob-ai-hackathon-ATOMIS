'use strict';

/**
 * Rule: SAME_TARGET
 *
 * Fires when 2+ events in the candidate set share the same target asset.
 * Multiple independent attacks against the same asset warrant correlation.
 *
 * Weight: 10
 */

const { WEIGHTS } = require('../correlationConfig');

const RULE_ID = 'SAME_TARGET';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const withTarget = events.filter(e => e.target);
  if (withTarget.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  // Find most targeted asset
  const targetCounts = {};
  for (const e of withTarget) {
    targetCounts[e.target] = (targetCounts[e.target] || 0) + 1;
  }
  const topTarget = Object.entries(targetCounts).sort((a, b) => b[1] - a[1])[0];
  const [sharedTarget, count] = topTarget;

  if (count < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const matchedEvents = withTarget.filter(e => e.target === sharedTarget);
  const uniqueSources = [...new Set(matchedEvents.map(e => e.source_ip).filter(Boolean))];

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.SAME_TARGET,
    confidence: Math.min(1.0, count / 4),
    reason:     `${count} events targeted the same asset (${sharedTarget})`,
    evidence:   {
      sharedTarget,
      eventCount:      count,
      sourceCount:     uniqueSources.length,
      uniqueSources,
      matchedEventIds: matchedEvents.map(e => e.event_id),
    },
  };
}

module.exports = { RULE_ID, evaluate };

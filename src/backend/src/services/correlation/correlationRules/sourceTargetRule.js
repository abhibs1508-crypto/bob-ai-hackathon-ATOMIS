'use strict';

/**
 * Rule: SOURCE_TARGET
 *
 * Fires when the same source_ip attacks the same target across 2+ events
 * within a reasonable time window. This is stronger than either SAME_SOURCE
 * or SAME_TARGET alone because it establishes a directed attacker→victim path.
 *
 * Weight: 15
 */

const { WEIGHTS, WINDOWS } = require('../correlationConfig');

const RULE_ID = 'SOURCE_TARGET';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  // Build (source_ip → target) pairs
  const pairs = {};
  for (const e of events) {
    if (e.source_ip && e.target) {
      const key = `${e.source_ip}→${e.target}`;
      if (!pairs[key]) pairs[key] = [];
      pairs[key].push(e);
    }
  }

  // Find pair with most events
  const topPair = Object.entries(pairs).sort((a, b) => b[1].length - a[1].length)[0];
  if (!topPair || topPair[1].length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const [pairKey, pairEvents] = topPair;
  const [sourceIp, target] = pairKey.split('→');
  const count = pairEvents.length;

  // Temporal check — pair must be within the EXTENDED window
  const timestamps = pairEvents.map(e => new Date(e.timestamp).getTime()).sort();
  const durationMin = (timestamps[timestamps.length - 1] - timestamps[0]) / 60000;

  if (durationMin > WINDOWS.CAMPAIGN) {
    return {
      matched: false,
      ruleId: RULE_ID,
      reason: `Source→target pair found but outside time window (${durationMin.toFixed(0)} min)`,
    };
  }

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.SOURCE_TARGET,
    confidence: Math.min(1.0, count / 4),
    reason:     `${count} events trace the same attacker (${sourceIp}) to the same target (${target})`,
    evidence:   {
      sourceIp,
      target,
      eventCount:      count,
      durationMinutes: Math.round(durationMin),
      matchedEventIds: pairEvents.map(e => e.event_id),
    },
  };
}

module.exports = { RULE_ID, evaluate };

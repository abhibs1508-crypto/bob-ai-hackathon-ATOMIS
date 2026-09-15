'use strict';

/**
 * Rule: SAME_SOURCE
 *
 * Fires when 2+ events in the candidate set share the same source_ip.
 * One shared attacker IP across multiple events is a basic but important signal.
 *
 * Weight: 10
 * Window: EXTENDED (60 min default)
 */

const { WEIGHTS, WINDOWS } = require('../correlationConfig');

const RULE_ID = 'SAME_SOURCE';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  // Collect events with a non-null source_ip
  const withIp = events.filter(e => e.source_ip);
  if (withIp.length < 2) {
    return { matched: false, ruleId: RULE_ID, reason: 'Fewer than 2 events have a source_ip' };
  }

  // Find the most common source_ip
  const ipCounts = {};
  for (const e of withIp) {
    ipCounts[e.source_ip] = (ipCounts[e.source_ip] || 0) + 1;
  }
  const topIp    = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
  const [sharedIp, count] = topIp;

  if (count < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const matchedEvents = withIp.filter(e => e.source_ip === sharedIp);

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.SAME_SOURCE,
    confidence: Math.min(1.0, count / 5),  // scales up to 5 events
    reason:     `${count} suspicious events originated from the same source IP`,
    evidence:   {
      sharedSourceIp: sharedIp,
      eventCount:     count,
      matchedEventIds: matchedEvents.map(e => e.event_id),
    },
  };
}

module.exports = { RULE_ID, evaluate };

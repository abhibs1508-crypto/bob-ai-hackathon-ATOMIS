'use strict';

/**
 * Rule: TEMPORAL_PROXIMITY
 *
 * Fires when events cluster within a short time window.
 * High event density in a short period is a meaningful signal.
 * Distinguishes tight attack sequences from coincidental daily events.
 *
 * Weight: 10
 */

const { WEIGHTS, WINDOWS } = require('../correlationConfig');

const RULE_ID = 'TEMPORAL_PROXIMITY';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const timestamps = events
    .map(e => new Date(e.timestamp).getTime())
    .filter(t => !isNaN(t))
    .sort();

  if (timestamps.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  const firstSeen  = new Date(timestamps[0]);
  const lastSeen   = new Date(timestamps[timestamps.length - 1]);
  const durationMs = timestamps[timestamps.length - 1] - timestamps[0];
  const durationMin = durationMs / 60000;

  // Determine which window the cluster fits within
  let windowLabel;
  let confidence;
  if (durationMin <= WINDOWS.IMMEDIATE) {
    windowLabel = 'IMMEDIATE';
    confidence  = 1.0;
  } else if (durationMin <= WINDOWS.SHORT) {
    windowLabel = 'SHORT';
    confidence  = 0.85;
  } else if (durationMin <= WINDOWS.EXTENDED) {
    windowLabel = 'EXTENDED';
    confidence  = 0.65;
  } else if (durationMin <= WINDOWS.CAMPAIGN) {
    windowLabel = 'CAMPAIGN';
    confidence  = 0.35;
  } else {
    return {
      matched: false,
      ruleId: RULE_ID,
      reason: `Events span ${durationMin.toFixed(0)} min — outside all correlation windows`,
    };
  }

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.TEMPORAL,
    confidence,
    reason:     `${events.length} events occurred within ${durationMin.toFixed(0)} minutes (${windowLabel} window)`,
    evidence:   {
      windowLabel,
      firstSeen:       firstSeen.toISOString(),
      lastSeen:        lastSeen.toISOString(),
      durationMinutes: Math.round(durationMin),
      eventCount:      events.length,
    },
  };
}

module.exports = { RULE_ID, evaluate };

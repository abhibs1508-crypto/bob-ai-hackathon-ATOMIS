'use strict';

/**
 * Rule: REPEATED_ACTIVITY
 *
 * Fires when the same event_type (e.g., failed_login) appears multiple times
 * in the candidate set. Repetition indicates persistence and raises the signal.
 *
 * 1 failed login    → noise
 * 25 failed logins  → brute force evidence
 *
 * Score contribution is bounded — repetition alone cannot inflate the total
 * score unboundedly.
 *
 * Weight: 5
 */

const { WEIGHTS } = require('../correlationConfig');

const RULE_ID = 'REPEATED_ACTIVITY';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 3) {
    return { matched: false, ruleId: RULE_ID, reason: 'Fewer than 3 events in set' };
  }

  // Count occurrences of each event_type
  const typeCounts = {};
  for (const e of events) {
    typeCounts[e.event_type] = (typeCounts[e.event_type] || 0) + 1;
  }

  // Find the most repeated type
  const topEntry = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0];
  const [topType, topCount] = topEntry;

  if (topCount < 3) {
    return { matched: false, ruleId: RULE_ID, reason: 'No event type repeated ≥3 times' };
  }

  // Confidence: saturates at ~10 repetitions
  const confidence = Math.min(1.0, topCount / 10);

  // Identify unique targets and sources for the repeated type
  const repeated = events.filter(e => e.event_type === topType);
  const distinctTargets = [...new Set(repeated.map(e => e.target).filter(Boolean))];
  const distinctSources = [...new Set(repeated.map(e => e.source_ip).filter(Boolean))];

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.REPEATED_ACTIVITY,
    confidence,
    reason:     `${topType} was observed ${topCount} times — possible automated or persistent activity`,
    evidence:   {
      repeatedEventType:  topType,
      repetitionCount:    topCount,
      distinctTargets,
      distinctSources,
      allEventTypeCounts: typeCounts,
    },
  };
}

module.exports = { RULE_ID, evaluate };

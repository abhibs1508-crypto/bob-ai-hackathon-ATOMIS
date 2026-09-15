'use strict';

/**
 * Rule: ATTACK_SEQUENCE
 *
 * Detects meaningful multi-stage attack progressions by classifying event types
 * into kill-chain stages and checking for chronological progression.
 *
 * A port_scan → failed_login → ioc_match sequence represents RECONNAISSANCE →
 * CREDENTIAL_ATTACK → THREAT_INTEL — a classic pre-intrusion pattern.
 *
 * This is one of the highest-signal rules because it transforms a list of
 * independent events into an attack narrative.
 *
 * Weight: 10
 */

const { WEIGHTS } = require('../correlationConfig');
const { classifyStages, isMeaningfulProgression, STAGE_ORDER } = require('../attackStageClassifier');

const RULE_ID = 'ATTACK_SEQUENCE';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events } = ctx;
  if (!events || events.length < 2) {
    return { matched: false, ruleId: RULE_ID };
  }

  // Sort events chronologically
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const eventTypes     = sorted.map(e => e.event_type);
  const orderedStages  = classifyStages(eventTypes);
  const uniqueKnown    = orderedStages.filter(s => s !== 'UNKNOWN');

  if (!isMeaningfulProgression(orderedStages)) {
    return {
      matched: false,
      ruleId: RULE_ID,
      reason: `Stages detected (${orderedStages.join(', ')}) do not form a meaningful progression`,
    };
  }

  // Sequence confidence: more stages = higher confidence, capped at 1.0
  const sequenceConfidence = Math.min(1.0, uniqueKnown.length / 3);

  // Build ordered stage-to-event mapping for evidence
  const stageEvents = {};
  for (const e of sorted) {
    const { classifyStage } = require('../attackStageClassifier');
    const stage = classifyStage(e.event_type);
    if (!stageEvents[stage]) stageEvents[stage] = [];
    stageEvents[stage].push(e.event_id);
  }

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.ATTACK_SEQUENCE,
    confidence: sequenceConfidence,
    reason:     `Attack stage progression detected: ${orderedStages.join(' → ')}`,
    evidence:   {
      orderedStages,
      stageCount:         uniqueKnown.length,
      stageEventMapping:  stageEvents,
      chronologicalTypes: eventTypes,
    },
  };
}

module.exports = { RULE_ID, evaluate };

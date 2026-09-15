'use strict';

/**
 * Rule: ENTITY_RELATION
 *
 * Fires when a target in the candidate set matches a known high-value entity.
 * Entity criticality is factored into confidence so that attacks against
 * critical production servers score higher than dev/test hosts.
 *
 * Weight: 5
 */

const { WEIGHTS } = require('../correlationConfig');

const RULE_ID = 'ENTITY_RELATION';

/**
 * @param {import('../correlationEngine').CorrelationContext} ctx
 * @returns {import('../correlationEngine').RuleResult}
 */
function evaluate(ctx) {
  const { events, targetEntities } = ctx;

  if (!targetEntities || targetEntities.length === 0) {
    return { matched: false, ruleId: RULE_ID, reason: 'No known entities matched targets' };
  }

  // Find events whose target matches a known entity
  const entityNames = new Set(targetEntities.map(e => e.name));
  const matchedEvents = (events || []).filter(e => e.target && entityNames.has(e.target));

  if (matchedEvents.length === 0) {
    return { matched: false, ruleId: RULE_ID };
  }

  const highestCriticality = Math.max(...targetEntities.map(e => e.criticality || 50));
  // Confidence scales with entity criticality (0–100 → 0–1)
  const confidence = highestCriticality / 100;

  return {
    matched:    true,
    ruleId:     RULE_ID,
    weight:     WEIGHTS.ENTITY_RELATION,
    confidence,
    reason:     `Attack targets a known entity (highest criticality: ${highestCriticality}/100)`,
    evidence:   {
      entities:        targetEntities.map(e => ({ name: e.name, criticality: e.criticality, type: e.entity_type })),
      highestCriticality,
      matchedEventIds: matchedEvents.map(e => e.event_id),
    },
  };
}

module.exports = { RULE_ID, evaluate };

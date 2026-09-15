'use strict';

/**
 * CyberFusion — Correlation Engine
 *
 * The engine orchestrates the rule pipeline. It is completely database-agnostic:
 * it takes a CorrelationContext (plain objects) and returns a CorrelationResult.
 *
 * This design makes the engine fully unit-testable without any database connection.
 * The CorrelationService (correlationService.js) is responsible for loading data
 * from MySQL and passing it here.
 *
 * Rule pipeline:
 *   1. SAME_SOURCE
 *   2. SAME_TARGET
 *   3. SOURCE_TARGET
 *   4. TEMPORAL_PROXIMITY
 *   5. IOC_MATCH
 *   6. ENTITY_RELATION
 *   7. REPEATED_ACTIVITY
 *   8. CROSS_SOURCE
 *   9. ATTACK_SEQUENCE
 */

const sameSourceRule       = require('./correlationRules/sameSourceRule');
const sameTargetRule       = require('./correlationRules/sameTargetRule');
const sourceTargetRule     = require('./correlationRules/sourceTargetRule');
const temporalRule         = require('./correlationRules/temporalRule');
const indicatorRule        = require('./correlationRules/indicatorRule');
const entityRule           = require('./correlationRules/entityRule');
const repeatedActivityRule = require('./correlationRules/repeatedActivityRule');
const crossSourceRule      = require('./correlationRules/crossSourceRule');
const attackSequenceRule   = require('./correlationRules/attackSequenceRule');

const { calculateScore }           = require('./correlationScoring');
const { buildCorrelationFactors, buildCorrelationTitle } = require('./correlationEvidence');
const { classifyStages }           = require('./attackStageClassifier');
const { MIN_RULES_MATCHED }        = require('./correlationConfig');

// Ordered rule registry — add future rules here
const RULE_REGISTRY = [
  sameSourceRule,
  sameTargetRule,
  sourceTargetRule,
  temporalRule,
  indicatorRule,
  entityRule,
  repeatedActivityRule,
  crossSourceRule,
  attackSequenceRule,
];

// ---------------------------------------------------------------------------
// Typedefs
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} CorrelationEvent   — a row from threat_events
 * @property {string}      id
 * @property {string}      event_id
 * @property {string}      source
 * @property {string}      timestamp
 * @property {string}      event_type
 * @property {string|null} source_ip
 * @property {string|null} target
 * @property {string|null} indicator_type
 * @property {string|null} indicator_value
 * @property {string}      severity
 * @property {number}      confidence
 * @property {string|null} location
 * @property {Object|null} raw_data
 */

/**
 * @typedef {Object} CorrelationContext
 * @property {CorrelationEvent[]}  events              — candidate events
 * @property {Object[]}            matchedIndicators   — rows from indicators table
 * @property {Object[]}            targetEntities      — rows from entities table
 */

/**
 * @typedef {Object} RuleResult
 * @property {boolean}     matched
 * @property {string}      ruleId
 * @property {number}      [weight]
 * @property {number}      [confidence]  — 0.0–1.0
 * @property {string}      [reason]
 * @property {Object}      [evidence]
 */

/**
 * @typedef {Object} CorrelationResult
 * @property {boolean}   shouldPersist
 * @property {string}    correlationKey
 * @property {string}    title
 * @property {string}    description
 * @property {number}    score
 * @property {string}    strength
 * @property {string}    status
 * @property {string[]}  factors
 * @property {Object}    correlationFactors
 * @property {string[]}  attackStages
 * @property {string|null} firstSeen
 * @property {string|null} lastSeen
 * @property {string[]}  sourceIps
 * @property {string[]}  targets
 * @property {string[]}  sourceTypes
 * @property {RuleResult[]} ruleResults
 */

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/**
 * Runs the full rule pipeline against the provided correlation context.
 * Pure function — no I/O, no side effects, fully testable.
 *
 * @param {CorrelationContext} ctx
 * @returns {CorrelationResult}
 */
function runEngine(ctx) {
  const { events, matchedIndicators = [], targetEntities = [] } = ctx;

  if (!events || events.length === 0) {
    return { shouldPersist: false, reason: 'No candidate events' };
  }

  // --- Execute all rules --------------------------------------------------
  const ruleResults = RULE_REGISTRY.map(rule => {
    try {
      return rule.evaluate(ctx);
    } catch (err) {
      console.error(`[correlation-engine] Rule ${rule.RULE_ID} threw:`, err.message);
      return { matched: false, ruleId: rule.RULE_ID, error: err.message };
    }
  });

  const matchedCount = ruleResults.filter(r => r.matched).length;

  if (matchedCount < MIN_RULES_MATCHED) {
    return {
      shouldPersist: false,
      reason: `Only ${matchedCount} rules matched (minimum: ${MIN_RULES_MATCHED})`,
      ruleResults,
    };
  }

  // --- Score ---------------------------------------------------------------
  const scoring = calculateScore(ruleResults);

  // --- Evidence ------------------------------------------------------------
  const correlationFactors = buildCorrelationFactors(ruleResults, scoring, ctx);
  const title              = buildCorrelationTitle(ctx, scoring.factors);

  // --- Aggregate metadata --------------------------------------------------
  const timestamps  = events.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t)).sort();
  const firstSeen   = timestamps.length ? new Date(timestamps[0]).toISOString()                           : null;
  const lastSeen    = timestamps.length ? new Date(timestamps[timestamps.length - 1]).toISOString()       : null;
  const sourceIps   = [...new Set(events.map(e => e.source_ip).filter(Boolean))];
  const targets     = [...new Set(events.map(e => e.target).filter(Boolean))];
  const sourceTypes = [...new Set(events.map(e => e.source).filter(Boolean))];
  const attackStages = classifyStages(events.map(e => e.event_type));

  // --- Deterministic key ---------------------------------------------------
  const correlationKey = buildCorrelationKey(events, sourceIps, targets);

  const description = buildDescription(scoring, sourceIps, targets, attackStages);

  return {
    shouldPersist:      true,
    correlationKey,
    title,
    description,
    score:              scoring.score,
    strength:           scoring.strength,
    status:             'active',
    factors:            scoring.factors,
    correlationFactors,
    attackStages,
    firstSeen,
    lastSeen,
    sourceIps,
    targets,
    sourceTypes,
    ruleResults,
    eventCount:         events.length,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Builds a stable, deterministic correlation key from the event cluster.
 * Key is used for duplicate detection — re-running on the same cluster
 * produces the same key and updates rather than inserts.
 *
 * Format: sha256(sorted_event_ids + primary_source_ip + primary_target)
 * @param {CorrelationEvent[]} events
 * @param {string[]} sourceIps
 * @param {string[]} targets
 * @returns {string}
 */
function buildCorrelationKey(events, sourceIps, targets) {
  const crypto   = require('crypto');
  const sortedIds = [...events.map(e => e.event_id)].sort().join('|');
  const primaryIp = sourceIps[0] || '';
  const primaryTarget = targets[0] || '';
  const raw = `${sortedIds}::${primaryIp}::${primaryTarget}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 64);
}

/**
 * Builds a one-line description of the correlation cluster.
 */
function buildDescription(scoring, sourceIps, targets, attackStages) {
  const parts = [];
  if (sourceIps.length)   parts.push(`attacker: ${sourceIps[0]}`);
  if (targets.length)     parts.push(`target: ${targets[0]}`);
  if (attackStages.length) parts.push(`stages: ${attackStages.join('→')}`);
  parts.push(`score: ${scoring.score} (${scoring.strength})`);
  return parts.join('; ');
}

module.exports = { runEngine, RULE_REGISTRY, buildCorrelationKey };

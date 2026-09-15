'use strict';

/**
 * CyberFusion — Correlation Evidence Builder
 *
 * Assembles the structured evidence object that is stored in
 * correlations.correlation_factors and returned to API consumers.
 *
 * Every correlation is fully explainable — the analyst can see exactly which
 * rules fired, why, and what evidence supports each rule.
 */

/**
 * Builds the structured correlation_factors JSON from rule results,
 * scoring output, and aggregate event metadata.
 *
 * @param {Array<import('./correlationEngine').RuleResult>} ruleResults
 * @param {import('./correlationScoring').ScoringResult}    scoring
 * @param {import('./correlationEngine').CorrelationContext} ctx
 * @returns {Object}  — serialisable JSON suitable for DB storage
 */
function buildCorrelationFactors(ruleResults, scoring, ctx) {
  const { events, matchedIndicators, targetEntities } = ctx;

  // ── Aggregate event metadata ────────────────────────────────────────────
  const timestamps  = events.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t)).sort();
  const firstSeen   = timestamps.length ? new Date(timestamps[0]).toISOString()                           : null;
  const lastSeen    = timestamps.length ? new Date(timestamps[timestamps.length - 1]).toISOString()       : null;
  const durationMin = timestamps.length >= 2
    ? Math.round((timestamps[timestamps.length - 1] - timestamps[0]) / 60000)
    : 0;

  const sourceIps   = [...new Set(events.map(e => e.source_ip).filter(Boolean))];
  const targets     = [...new Set(events.map(e => e.target).filter(Boolean))];
  const sourceTypes = [...new Set(events.map(e => e.source).filter(Boolean))];

  // ── Rule evidence list ────────────────────────────────────────────────────
  const matchedRules = ruleResults
    .filter(r => r.matched)
    .map(r => ({
      rule:        r.ruleId,
      description: r.reason,
      weight:      r.weight,
      confidence:  r.confidence !== undefined ? Math.round(r.confidence * 100) : null,
      evidence:    r.evidence || null,
    }));

  return {
    // Scoring summary
    score:    scoring.score,
    strength: scoring.strength,
    factors:  scoring.factors,

    // Temporal summary
    firstSeen,
    lastSeen,
    durationMinutes: durationMin,
    eventCount:      events.length,

    // Actor / target summary
    sourceIps,
    targets,
    sourceTypes,

    // Indicators
    matchedIndicators: (matchedIndicators || []).map(i => ({
      type:       i.indicator_type,
      value:      i.indicator_value,
      threatType: i.threat_type,
      confidence: i.confidence,
    })),

    // Entities
    targetEntities: (targetEntities || []).map(e => ({
      name:        e.name,
      criticality: e.criticality,
      type:        e.entity_type,
    })),

    // Per-rule evidence
    rules: matchedRules,
  };
}

/**
 * Generates a human-readable title for the correlation.
 * @param {import('./correlationEngine').CorrelationContext} ctx
 * @param {string[]} factors  — matched rule IDs
 * @returns {string}
 */
function buildCorrelationTitle(ctx, factors) {
  const { events } = ctx;
  const targets   = [...new Set(events.map(e => e.target).filter(Boolean))];
  const sourceIps = [...new Set(events.map(e => e.source_ip).filter(Boolean))];
  const n         = events.length;

  if (targets.length && sourceIps.length) {
    return `${n}-event attack cluster: ${sourceIps[0]} → ${targets[0]}`;
  }
  if (targets.length) {
    return `${n} events targeting ${targets[0]}`;
  }
  if (sourceIps.length) {
    return `${n} events from ${sourceIps[0]}`;
  }
  const types = [...new Set(events.map(e => e.event_type))];
  return `${n}-event cluster: ${types.slice(0, 3).join(', ')}`;
}

module.exports = { buildCorrelationFactors, buildCorrelationTitle };

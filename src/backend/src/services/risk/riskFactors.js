'use strict';

/**
 * CyberFusion — Risk Factor Calculators
 *
 * Seven pure functions, one per risk factor.
 * Each receives a RiskContext and returns { score: number, reason: string, detail: Object }.
 * All return a score normalised to 0–100.
 *
 * RiskContext fields consumed here:
 *   correlation.correlation_score     — Phase 3 score (0-100)
 *   correlation.attack_stages         — JSON array from Phase 3
 *   correlation.source_types          — JSON array from Phase 3
 *   correlation.last_seen             — ISO datetime string
 *   events[]                          — threat_events rows
 *   matchedIndicators[]               — indicators table rows
 *   targetEntities[]                  — entities table rows
 */

const {
  SEVERITY_SCORES,
  IOC_SCORES,
  IOC_HIGH_CONFIDENCE_THRESHOLD,
  RECENCY_HALF_LIFE_MINUTES,
  DEFAULT_ASSET_CRITICALITY,
  ATTACK_PROGRESSION_SCORES,
  MEANINGFUL_ATTACK_STAGES,
  CROSS_SOURCE_SCORES,
} = require('./riskConfig');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function clamp(value, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

function toNum(v, def = 0) {
  const n = Number(v);
  return isNaN(n) ? def : n;
}

// ---------------------------------------------------------------------------
// Factor 1 — Severity
// ---------------------------------------------------------------------------

/**
 * Severity factor.
 *
 * Uses the highest severity event in the correlation as the base. Each
 * additional high-confidence severe event adds a small boost (capped at 100)
 * so that a barrage of confirmed high-severity events is distinguishable from
 * a single marginal high-severity event.
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcSeverity(ctx) {
  const events = ctx.events || [];
  if (events.length === 0) {
    return { score: 0, reason: 'No events in correlation', detail: { eventCount: 0 } };
  }

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const sorted = [...events].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
  });

  const topSev   = sorted[0].severity;
  const baseScore = SEVERITY_SCORES[topSev] || SEVERITY_SCORES.low;

  // Boost: each confirmed high/critical event (confidence >= 80) beyond the first
  // adds up to +2 points each, capped so the total never exceeds 100.
  const supportingCount = events.filter(
    e => (e.severity === 'critical' || e.severity === 'high') &&
         toNum(e.confidence) >= 80 &&
         e !== sorted[0]
  ).length;
  const boost = Math.min(supportingCount * 2, 10);

  const score = clamp(baseScore + boost);

  return {
    score,
    reason: `Highest severity in correlation is ${topSev}` +
            (supportingCount ? ` with ${supportingCount} additional high-confidence severe event(s)` : ''),
    detail: {
      topSeverity: topSev,
      baseScore,
      supportingHighCount: supportingCount,
      boost,
      severityCounts: severityOrder.reduce((acc, s) => {
        acc[s] = events.filter(e => e.severity === s).length;
        return acc;
      }, {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Factor 2 — IOC Reputation / Match
// ---------------------------------------------------------------------------

/**
 * IOC risk factor.
 *
 * Uses the matchedIndicators array from the correlation context.
 * Selects the highest-confidence/most-severe indicator as the primary signal.
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcIocRisk(ctx) {
  const indicators = ctx.matchedIndicators || [];
  const events     = ctx.events || [];

  // Check if any event even has an indicator_value
  const hasIocEvents = events.some(e => e.indicator_value);
  if (!hasIocEvents) {
    return {
      score: IOC_SCORES.NONE,
      reason: 'No indicator values present in correlated events',
      detail: { hasIocEvents: false },
    };
  }

  if (indicators.length === 0) {
    return {
      score: IOC_SCORES.UNKNOWN,
      reason: 'Events contain indicator values but no matching IOC found in threat intelligence database',
      detail: { hasIocEvents: true, matchCount: 0 },
    };
  }

  // Find the most threatening matched indicator
  const bestIndicator = indicators.reduce((best, ind) => {
    const conf = toNum(ind.confidence, 50);
    if (!best || conf > toNum(best.confidence, 50)) return ind;
    return best;
  }, null);

  const conf = toNum(bestIndicator.confidence, 50);
  let score;
  let reason;

  if (conf >= IOC_HIGH_CONFIDENCE_THRESHOLD) {
    score  = IOC_SCORES.KNOWN_MALICIOUS;
    reason = `Known malicious indicator (${bestIndicator.indicator_type}:${bestIndicator.indicator_value}) with confidence ${conf}`;
  } else if (conf >= 60) {
    score  = IOC_SCORES.HIGH_CONFIDENCE;
    reason = `High-confidence malicious indicator (${bestIndicator.indicator_type}:${bestIndicator.indicator_value}) with confidence ${conf}`;
  } else {
    score  = IOC_SCORES.SUSPICIOUS;
    reason = `Suspicious indicator (${bestIndicator.indicator_type}:${bestIndicator.indicator_value}) with confidence ${conf}`;
  }

  return {
    score,
    reason,
    detail: {
      matchCount:    indicators.length,
      bestIndicator: {
        type:       bestIndicator.indicator_type,
        value:      bestIndicator.indicator_value,
        threatType: bestIndicator.threat_type,
        confidence: conf,
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Factor 3 — Asset Criticality
// ---------------------------------------------------------------------------

/**
 * Asset criticality factor.
 *
 * Identifies the highest-criticality entity in the correlation's targets.
 * Does NOT average across entities — a critical prod asset must not be
 * diluted by co-presence of low-value dev assets.
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcAssetCriticality(ctx) {
  const entities = ctx.targetEntities || [];

  if (entities.length === 0) {
    return {
      score:  DEFAULT_ASSET_CRITICALITY,
      reason: `No entity intelligence available; using default criticality (${DEFAULT_ASSET_CRITICALITY})`,
      detail: { entityCount: 0, usingDefault: true },
    };
  }

  const sorted = [...entities].sort((a, b) => toNum(b.criticality) - toNum(a.criticality));
  const top    = sorted[0];
  const score  = clamp(toNum(top.criticality));

  return {
    score,
    reason: `Highest target criticality: ${top.name} (${score}/100, type: ${top.entity_type || 'unknown'})`,
    detail: {
      topEntity:    { name: top.name, criticality: score, type: top.entity_type },
      entityCount:  entities.length,
      allEntities:  sorted.map(e => ({ name: e.name, criticality: toNum(e.criticality) })),
    },
  };
}

// ---------------------------------------------------------------------------
// Factor 4 — Correlation Strength
// ---------------------------------------------------------------------------

/**
 * Correlation strength factor.
 *
 * Directly reuses Phase 3's correlation score (0–100).
 * Phase 3 = relationship strength. Phase 4 = danger level. They are distinct.
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcCorrelationStrength(ctx) {
  const corrScore = toNum(ctx.correlation && ctx.correlation.correlation_score, 0);
  const strength  = ctx.correlation && ctx.correlation.correlation_strength
    ? ctx.correlation.correlation_strength
    : 'unknown';

  return {
    score:  clamp(corrScore),
    reason: `Phase 3 correlation score is ${corrScore} (${strength})`,
    detail: { correlationScore: corrScore, correlationStrength: strength },
  };
}

// ---------------------------------------------------------------------------
// Factor 5 — Recency
// ---------------------------------------------------------------------------

/**
 * Recency factor using exponential decay.
 *
 * score = 100 * exp(−ageMinutes / halfLife)
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcRecency(ctx) {
  const lastSeenStr = ctx.correlation && ctx.correlation.last_seen;
  if (!lastSeenStr) {
    return {
      score:  0,
      reason: 'No last_seen timestamp available on correlation',
      detail: { lastSeen: null },
    };
  }

  const lastSeenMs = new Date(lastSeenStr).getTime();
  if (isNaN(lastSeenMs)) {
    return {
      score:  0,
      reason: 'Invalid last_seen timestamp',
      detail: { lastSeen: lastSeenStr },
    };
  }

  const ageMinutes = (Date.now() - lastSeenMs) / 60000;
  const raw  = 100 * Math.exp(-ageMinutes / RECENCY_HALF_LIFE_MINUTES);
  const score = clamp(Math.round(raw));

  return {
    score,
    reason: `Activity last seen ${ageMinutes.toFixed(0)} minutes ago (half-life: ${RECENCY_HALF_LIFE_MINUTES} min)`,
    detail: {
      lastSeen:         lastSeenStr,
      ageMinutes:       Math.round(ageMinutes),
      halfLifeMinutes:  RECENCY_HALF_LIFE_MINUTES,
      decayFormula:     `100 * exp(−${ageMinutes.toFixed(0)} / ${RECENCY_HALF_LIFE_MINUTES})`,
    },
  };
}

// ---------------------------------------------------------------------------
// Factor 6 — Attack Progression
// ---------------------------------------------------------------------------

/**
 * Attack progression factor.
 *
 * Uses attack_stages from the Phase 3 correlation.
 * Only MEANINGFUL_ATTACK_STAGES count (THREAT_INTEL is excluded as it is an
 * intelligence source category, not an attack technique stage).
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcAttackProgression(ctx) {
  let stages = [];
  if (ctx.correlation && ctx.correlation.attack_stages) {
    stages = Array.isArray(ctx.correlation.attack_stages)
      ? ctx.correlation.attack_stages
      : (typeof ctx.correlation.attack_stages === 'string'
          ? JSON.parse(ctx.correlation.attack_stages)
          : []);
  }

  const meaningful = stages.filter(s => MEANINGFUL_ATTACK_STAGES.has(s));
  const count      = meaningful.length;
  const scoreKey   = Math.min(count, 4);  // cap at 4 for lookup
  const score      = ATTACK_PROGRESSION_SCORES[scoreKey] || 0;

  if (count === 0) {
    return {
      score: 0,
      reason: 'No meaningful attack progression stages detected',
      detail: { allStages: stages, meaningfulStages: [], stageCount: 0 },
    };
  }

  return {
    score,
    reason: `${count} meaningful attack stage${count > 1 ? 's' : ''} detected: ${meaningful.join(' → ')}`,
    detail: {
      allStages:      stages,
      meaningfulStages: meaningful,
      stageCount:     count,
    },
  };
}

// ---------------------------------------------------------------------------
// Factor 7 — Cross-Source Corroboration
// ---------------------------------------------------------------------------

/**
 * Cross-source corroboration factor.
 *
 * Counts DISTINCT source types from the correlation's source_types array.
 * Duplicate events from the same source type do not inflate the score.
 *
 * @param {Object} ctx
 * @returns {{ score: number, reason: string, detail: Object }}
 */
function calcCrossSource(ctx) {
  let sourceTypes = [];
  if (ctx.correlation && ctx.correlation.source_types) {
    sourceTypes = Array.isArray(ctx.correlation.source_types)
      ? ctx.correlation.source_types
      : (typeof ctx.correlation.source_types === 'string'
          ? JSON.parse(ctx.correlation.source_types)
          : []);
  }

  // Also accumulate from events in case source_types column is missing
  if (sourceTypes.length === 0 && ctx.events) {
    sourceTypes = [...new Set(ctx.events.map(e => e.source).filter(Boolean))];
  }

  const distinct = [...new Set(sourceTypes.map(s => String(s).toLowerCase()))];
  const count    = distinct.length;
  const scoreKey = Math.min(count, 4);
  const score    = CROSS_SOURCE_SCORES[scoreKey] || 0;

  if (count <= 1) {
    return {
      score,
      reason: count === 0
        ? 'No source type information available'
        : `Single source type (${distinct[0]}) — no cross-source corroboration`,
      detail: { distinctSources: distinct, sourceCount: count },
    };
  }

  return {
    score,
    reason: `${count} distinct independent source types: ${distinct.join(', ')}`,
    detail: { distinctSources: distinct, sourceCount: count },
  };
}

module.exports = {
  calcSeverity,
  calcIocRisk,
  calcAssetCriticality,
  calcCorrelationStrength,
  calcRecency,
  calcAttackProgression,
  calcCrossSource,
};

'use strict';

const MAX_SCORE = 100;

function score(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(MAX_SCORE, Math.round(parsed)));
}

function confidence(value) {
  return score(value);
}

function string(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function safeArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function uniqueStrings(values) {
  return [...new Set(values.map(string).filter(Boolean))];
}

function safeObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  if (typeof value !== 'string') return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function sanitizeEvent(event = {}) {
  return {
    eventId: string(event.event_id),
    source: string(event.source),
    timestamp: event.timestamp || null,
    eventType: string(event.event_type),
    sourceIp: string(event.source_ip),
    target: string(event.target),
    indicatorType: string(event.indicator_type),
    indicatorValue: string(event.indicator_value),
    severity: string(event.severity),
    confidence: confidence(event.confidence),
    location: string(event.location),
  };
}

function sanitizeIndicator(indicator = {}) {
  return {
    type: string(indicator.indicator_type || indicator.type),
    value: string(indicator.indicator_value || indicator.value),
    threatType: string(indicator.threat_type || indicator.threatType),
    confidence: confidence(indicator.confidence),
  };
}

function sanitizeEntity(entity = {}) {
  return {
    name: string(entity.name),
    entityType: string(entity.entity_type || entity.entityType),
    criticality: score(entity.criticality),
  };
}

function uniqueObjects(items, fields) {
  const seen = new Set();
  return items.filter(item => {
    const key = fields.map(field => item[field]).join('\u0000');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function sanitizeRiskEvidence(value) {
  const evidence = safeObject(value);
  const factors = safeArray(evidence.factors).map(factor => ({
    name: string(factor && factor.name),
    score: score(factor && factor.score),
    weight: Number.isFinite(Number(factor && factor.weight)) ? Number(factor.weight) : 0,
    contribution: score(factor && factor.contribution),
    reason: string(factor && factor.reason),
  })).filter(factor => factor.name);
  const attackProgression = safeObject(evidence.attackProgression);
  const crossSource = safeObject(evidence.crossSource);

  return {
    factors,
    attackProgression: {
      score: score(attackProgression.score),
      stagesObserved: uniqueStrings(safeArray(attackProgression.stagesObserved)),
    },
    crossSource: {
      score: score(crossSource.score),
      distinctSources: uniqueStrings(safeArray(crossSource.distinctSources)),
    },
  };
}

/**
 * Builds the only context shape permitted to reach the AI prompt. Inputs are
 * service/database records, but every output field is selected explicitly.
 */
function buildIntelligenceContext({ correlation = {}, risk = {}, events = [], indicators = [], entities = [] } = {}) {
  correlation = safeObject(correlation);
  risk = safeObject(risk);
  const safeEvents = safeArray(events).map(sanitizeEvent);
  const riskEvidence = sanitizeRiskEvidence(risk.risk_evidence || risk.riskEvidence);
  const correlationSourceIps = uniqueStrings(safeArray(correlation.source_ips || correlation.sourceIps));
  const correlationTargets = uniqueStrings(safeArray(correlation.targets));
  const correlationSources = uniqueStrings(safeArray(correlation.source_types || correlation.sourceTypes));
  const correlationStages = uniqueStrings(safeArray(correlation.attack_stages || correlation.attackStages));
  const eventIndicators = safeEvents
    .filter(event => event.indicatorType && event.indicatorValue)
    .map(event => ({ type: event.indicatorType, value: event.indicatorValue, threatType: '', confidence: event.confidence }));
  const attackProgressionFactor = riskEvidence.factors.find(factor => factor.name === 'attackProgression');
  const crossSourceFactor = riskEvidence.factors.find(factor => factor.name === 'crossSource');

  return {
    campaign: {
      id: string(correlation.id),
      title: string(correlation.title),
      description: string(correlation.description),
      eventCount: Math.max(0, Math.round(Number(correlation.event_count || correlation.eventCount) || safeEvents.length)),
      correlationScore: score(correlation.correlation_score || correlation.correlationScore),
      correlationStrength: string(correlation.correlation_strength || correlation.correlationStrength),
    },
    risk: {
      score: score(risk.score),
      priority: string(risk.priority),
      severityComponent: score(risk.severity_component || risk.severityComponent),
      iocMatchComponent: score(risk.ioc_match_component || risk.iocMatchComponent),
      assetCriticalityComponent: score(risk.asset_criticality_component || risk.assetCriticalityComponent),
      correlationStrengthComponent: score(risk.correlation_strength_component || risk.correlationStrengthComponent),
      recencyComponent: score(risk.recency_component || risk.recencyComponent),
      attackProgressionComponent: attackProgressionFactor ? attackProgressionFactor.score : riskEvidence.attackProgression.score,
      crossSourceComponent: crossSourceFactor ? crossSourceFactor.score : riskEvidence.crossSource.score,
      evidence: riskEvidence,
    },
    timeline: { firstSeen: correlation.first_seen || correlation.firstSeen || null, lastSeen: correlation.last_seen || correlation.lastSeen || null },
    sources: uniqueStrings([...correlationSources, ...safeEvents.map(event => event.source)]),
    targets: uniqueStrings([...correlationTargets, ...safeEvents.map(event => event.target)]),
    sourceIps: uniqueStrings([...correlationSourceIps, ...safeEvents.map(event => event.sourceIp)]),
    attackStages: uniqueStrings([...correlationStages, ...riskEvidence.attackProgression.stagesObserved]),
    indicators: uniqueObjects([...safeArray(indicators).map(sanitizeIndicator), ...eventIndicators], ['type', 'value']),
    entities: uniqueObjects(safeArray(entities).map(sanitizeEntity), ['name', 'entityType']),
    events: safeEvents,
  };
}

module.exports = { buildIntelligenceContext };

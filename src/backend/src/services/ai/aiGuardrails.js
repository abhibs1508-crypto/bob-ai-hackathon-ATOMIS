'use strict';

const { AIProviderError } = require('./aiProvider');

const REQUIRED_STRING_FIELDS = ['bluf', 'threat_assessment', 'possible_intent', 'reasoning', 'evidence_summary'];
const FORBIDDEN_AUTHORITY_FIELDS = ['risk_score', 'riskScore', 'priority', 'severity', 'correlation_score', 'correlationScore'];
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const CONFIRMED_CLAIMS = /\bconfirmed\s+(?:compromise|data\s+exfiltration|credential\s+theft|malware\s+execution)\b/i;
const OFFENSIVE_ACTIONS = /\b(?:exploit\s+(?:the\s+)?target|deploy\s+malware|steal\s+credentials|exfiltrate\s+data|evade\s+detection)\b/i;

class AIGuardrailError extends AIProviderError {
  constructor(message) {
    super(message);
    this.name = 'AIGuardrailError';
    this.code = 'AI_GUARDRAIL_REJECTED';
  }
}

function nonEmptyString(value) {
  return typeof value === 'string' && Boolean(value.trim());
}

function assessmentText(assessment) {
  return [...REQUIRED_STRING_FIELDS.map(field => assessment[field]), ...assessment.recommended_actions].join('\n');
}

function authoritativeIps(context) {
  const sourceIps = Array.isArray(context.sourceIps) ? context.sourceIps : [];
  const indicatorIps = Array.isArray(context.indicators) ? context.indicators
    .filter(indicator => indicator && String(indicator.type).toLowerCase() === 'ip')
    .map(indicator => indicator.value) : [];
  return new Set([...sourceIps, ...indicatorIps].filter(nonEmptyString));
}

function assertExpectedStructure(assessment) {
  if (!assessment || typeof assessment !== 'object' || Array.isArray(assessment)) {
    throw new AIGuardrailError('AI assessment has an invalid structure');
  }
  if (FORBIDDEN_AUTHORITY_FIELDS.some(field => Object.prototype.hasOwnProperty.call(assessment, field))) {
    throw new AIGuardrailError('AI assessment contains authoritative risk fields');
  }
  if (REQUIRED_STRING_FIELDS.some(field => !nonEmptyString(assessment[field]))
    || !Array.isArray(assessment.recommended_actions) || assessment.recommended_actions.length === 0
    || assessment.recommended_actions.some(action => !nonEmptyString(action))
    || typeof assessment.confidence_score !== 'number' || !Number.isFinite(assessment.confidence_score) || !Number.isInteger(assessment.confidence_score)
    || assessment.confidence_score < 0 || assessment.confidence_score > 100) {
    throw new AIGuardrailError('AI assessment does not meet the required contract');
  }
}

function assertKnownIps(text, context) {
  const knownIps = authoritativeIps(context);
  const mentionedIps = text.match(IPV4_PATTERN) || [];
  if (mentionedIps.some(ip => !knownIps.has(ip))) {
    throw new AIGuardrailError('AI assessment contains an unsupported IP address');
  }
}

function assertKnownAssetIdentifiers(text, context) {
  const targets = Array.isArray(context.targets) ? context.targets : [];
  const entities = Array.isArray(context.entities) ? context.entities.map(entity => entity && entity.name) : [];
  const known = new Set([...targets, ...entities].filter(nonEmptyString).map(value => value.toLowerCase()));
  // Hostnames and sufficiently specific asset IDs with digits are checked.
  // A compact identifier must be at least four characters so generic security
  // shorthand such as "C2" is not misclassified as an invented hostname.
  const candidates = text.match(/\b(?:[A-Za-z0-9-]+\.(?:internal|local|corp|com|net|org)|(?=[A-Za-z0-9_-]{4,}\b)[A-Za-z][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)\b/g) || [];
  if (candidates.some(candidate => !known.has(candidate.toLowerCase()) && !IPV4_PATTERN.test(candidate))) {
    throw new AIGuardrailError('AI assessment contains an unsupported target identifier');
  }
}

function assertSafeClaimsAndActions(text, assessment) {
  if (CONFIRMED_CLAIMS.test(text)) {
    throw new AIGuardrailError('AI assessment makes an unsupported confirmed claim');
  }
  if (assessment.recommended_actions.some(action => OFFENSIVE_ACTIONS.test(action))) {
    throw new AIGuardrailError('AI assessment contains an unsafe recommended action');
  }
}

/** Validates a parsed assessment against the immutable, sanitized context. */
function validateAssessment(assessment, intelligenceContext = {}) {
  assertExpectedStructure(assessment);
  const text = assessmentText(assessment);
  assertKnownIps(text, intelligenceContext || {});
  assertKnownAssetIdentifiers(text, intelligenceContext || {});
  assertSafeClaimsAndActions(text, assessment);

  return Object.freeze({
    safe: true,
    assessment: Object.freeze({
      bluf: assessment.bluf,
      threat_assessment: assessment.threat_assessment,
      possible_intent: assessment.possible_intent,
      reasoning: assessment.reasoning,
      evidence_summary: assessment.evidence_summary,
      recommended_actions: [...assessment.recommended_actions],
      confidence_score: assessment.confidence_score,
    }),
  });
}

module.exports = { AIGuardrailError, validateAssessment };

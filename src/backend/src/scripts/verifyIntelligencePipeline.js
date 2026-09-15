'use strict';

/*
 * Local-only, controlled verification for the complete Phase 5 intelligence
 * pipeline. This file is intentionally not registered with Express.
 */

const config = require('../config');
const correlationRepository = require('../db/correlationRepository');
const riskRepository = require('../db/riskRepository');
const intelligenceRepository = require('../db/intelligenceRepository');
const { getPool } = require('../db/pool');
const { createIntelligenceService } = require('../services/ai/intelligenceService');
const { GroqProvider } = require('../services/ai/groqProvider');
const { parseResponse } = require('../services/ai/responseParser');
const { validateAssessment } = require('../services/ai/aiGuardrails');

const SCENARIO_A_EVENT_IDS = new Set(['siem-001', 'sensor-001', 'sensor-002', 'ti-001']);
const REQUIRED_FIELDS = [
  'bluf', 'threat_assessment', 'possible_intent', 'reasoning', 'evidence_summary',
  'recommended_actions', 'confidence_score',
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function hasScenarioAEvents(events) {
  const ids = new Set(events.map(event => event.event_id));
  return SCENARIO_A_EVENT_IDS.size === ids.size
    && [...SCENARIO_A_EVENT_IDS].every(eventId => ids.has(eventId));
}

async function findScenarioACorrelation() {
  const correlations = await correlationRepository.listCorrelations({ limit: 200 });
  for (const correlation of correlations) {
    const events = await correlationRepository.getEventsByCorrelationId(correlation.id);
    if (hasScenarioAEvents(events)) return { correlation, events };
  }
  throw new Error('Scenario A correlation was not found. Load the existing demo data and Phase 3/4 results first.');
}

function immutableSnapshot(correlation, risk, events) {
  return JSON.stringify({
    correlationScore: correlation.correlation_score,
    correlationStrength: correlation.correlation_strength,
    riskScore: risk.score,
    riskPriority: risk.priority,
    events: events.map(event => ({
      id: event.id, event_id: event.event_id, source: event.source, timestamp: event.timestamp,
      event_type: event.event_type, source_ip: event.source_ip, target: event.target,
      indicator_type: event.indicator_type, indicator_value: event.indicator_value,
      severity: event.severity, confidence: event.confidence, location: event.location,
    })),
  });
}

function validateReport(report) {
  assert(report && typeof report === 'object', 'No intelligence report was returned');
  for (const field of REQUIRED_FIELDS) assert(Object.prototype.hasOwnProperty.call(report, field), `Missing report field: ${field}`);
  for (const field of REQUIRED_FIELDS.slice(0, 5)) assert(typeof report[field] === 'string' && report[field].trim(), `Invalid report field: ${field}`);
  assert(Array.isArray(report.recommended_actions) && report.recommended_actions.length > 0
    && report.recommended_actions.every(action => typeof action === 'string' && action.trim()), 'recommended_actions must be a non-empty string array');
  assert(Number.isInteger(report.confidence_score) && report.confidence_score >= 0 && report.confidence_score <= 100,
    'confidence_score must be an integer from 0 to 100');
  assert(report.generated_at, 'generated_at was not persisted');
}

function safeBluf(bluf) {
  return String(bluf).replace(/[\r\n]+/g, ' ').trim();
}

function diagnosticCode(stage, error) {
  const code = String(error && error.code || 'UNKNOWN_ERROR');
  if (stage === 'provider') return code === 'AI_CONFIGURATION_ERROR' ? 'GROQ_CONFIGURATION_ERROR' : 'GROQ_REQUEST_FAILED';
  if (stage === 'parser') return 'AI_RESPONSE_INVALID';
  if (stage === 'guardrails') return 'AI_GUARDRAIL_REJECTED';
  return 'AI_PIPELINE_FAILED';
}

const SAFE_DIAGNOSTIC_MESSAGES = new Set([
  'GROQ_API_KEY is not configured',
  'Unsupported AI provider: groq',
  'AI provider request failed',
  'AI provider returned an empty response',
  'AI response content is invalid',
  'AI response is not valid JSON',
  'AI response must be a JSON object',
  'AI response field "recommended_actions" must be a non-empty array of strings',
  'AI response field "confidence_score" must be an integer from 0 to 100',
  'AI assessment has an invalid structure',
  'AI assessment contains authoritative risk fields',
  'AI assessment does not meet the required contract',
  'AI assessment contains an unsupported IP address',
  'AI assessment contains an unsupported target identifier',
  'AI assessment makes an unsupported confirmed claim',
  'AI assessment contains an unsafe recommended action',
]);

function diagnosticMessage(error) {
  return SAFE_DIAGNOSTIC_MESSAGES.has(error && error.message) ? error.message : 'Sanitized failure detail unavailable';
}

function unsupportedIdentifierClass(assessment, context) {
  const text = [
    assessment.bluf, assessment.threat_assessment, assessment.possible_intent,
    assessment.reasoning, assessment.evidence_summary, ...(assessment.recommended_actions || []),
  ].join('\n');
  const known = new Set([
    ...(context.targets || []), ...(context.entities || []).map(entity => entity && entity.name),
  ].filter(Boolean).map(value => value.toLowerCase()));
  const candidates = text.match(/\b(?:[A-Za-z0-9-]+\.(?:internal|local|corp|com|net|org)|[A-Za-z][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*)\b/g) || [];
  const unsupported = candidates.find(candidate => !known.has(candidate.toLowerCase()));
  if (!unsupported) return null;
  if (unsupported.includes('.')) return 'hostname';
  if (/^T\d{4,5}$/i.test(unsupported)) return 'attack_technique_id';
  if (/^[A-Za-z]+\d+$/.test(unsupported)) return 'generic_alphanumeric';
  return 'asset_style_identifier';
}

/**
 * Uses the existing injectable service boundary to expose only the failed
 * pipeline stage during local verification. It does not log prompts, provider
 * content, credentials, or arbitrary provider error messages.
 */
function createDiagnosticIntelligenceService(diagnostic) {
  const recordFailure = (stage, error) => {
    diagnostic.code = diagnosticCode(stage, error);
    diagnostic.stage = stage;
    diagnostic.message = diagnosticMessage(error);
  };

  return createIntelligenceService({
    providerFactory: () => {
      const provider = new GroqProvider();
      return {
        async generateAssessment(prompt) {
          try { return await provider.generateAssessment(prompt); }
          catch (error) { recordFailure('provider', error); throw error; }
        },
      };
    },
    parseResponse(response) {
      try { return parseResponse(response); }
      catch (error) { recordFailure('parser', error); throw error; }
    },
    validateAssessment(assessment, context) {
      try { return validateAssessment(assessment, context); }
      catch (error) {
        recordFailure('guardrails', error);
        if (error && error.code === 'AI_GUARDRAIL_REJECTED') {
          diagnostic.identifierClass = unsupportedIdentifierClass(assessment, context);
        }
        throw error;
      }
    },
  });
}

async function main() {
  assert(config.ai.provider.toLowerCase() === 'groq', 'AI_PROVIDER must be groq for this verification');
  assert(config.ai.groq.apiKey, 'GROQ_API_KEY is not configured');
  assert(config.ai.groq.model === 'openai/gpt-oss-120b', 'GROQ_MODEL must be openai/gpt-oss-120b');

  const { correlation, events } = await findScenarioACorrelation();
  const riskBefore = await riskRepository.getRiskScoreByCorrelationId(correlation.id);
  assert(riskBefore, 'Scenario A has no authoritative Phase 4 risk score');
  const beforeSnapshot = immutableSnapshot(correlation, riskBefore, events);
  const beforeCount = await intelligenceRepository.countByCorrelationId(correlation.id);
  const diagnostic = { code: null, stage: null, message: null, identifierClass: null };
  const intelligenceService = createDiagnosticIntelligenceService(diagnostic);

  const firstReport = await intelligenceService.generateIntelligence(correlation.id);
  const afterFirstGenerationCount = await intelligenceRepository.countByCorrelationId(correlation.id);
  validateReport(firstReport);
  diagnostic.code = null;
  diagnostic.stage = null;
  diagnostic.message = null;
  diagnostic.identifierClass = null;
  const secondReport = await intelligenceService.generateIntelligence(correlation.id);
  const afterSecondGenerationCount = await intelligenceRepository.countByCorrelationId(correlation.id);
  validateReport(secondReport);

  const [correlationAfter, riskAfter, eventsAfter, persisted] = await Promise.all([
    correlationRepository.getCorrelationById(correlation.id),
    riskRepository.getRiskScoreByCorrelationId(correlation.id),
    correlationRepository.getEventsByCorrelationId(correlation.id),
    intelligenceRepository.findByCorrelationId(correlation.id),
  ]);
  assert(immutableSnapshot(correlationAfter, riskAfter, eventsAfter) === beforeSnapshot,
    'Risk or correlation/event authoritative data changed during intelligence generation');
  validateReport(persisted);
  assert(afterFirstGenerationCount === 1 && afterSecondGenerationCount === 1,
    `Expected one intelligence report; observed ${afterFirstGenerationCount} then ${afterSecondGenerationCount}`);

  const groqSucceeded = persisted.ai_provider === 'groq';
  assert(groqSucceeded || persisted.ai_provider === 'fallback', 'Unexpected AI provider persisted');
  if (groqSucceeded) assert(persisted.ai_model === config.ai.groq.model, 'Persisted Groq model does not match configuration');

  console.log('========================================');
  console.log('CYBERFUSION AI INTELLIGENCE VERIFICATION');
  console.log('========================================');
  console.log(`Correlation: ${correlation.id}`);
  console.log(`Correlation Score: ${correlation.correlation_score}`);
  console.log(`Correlation Strength: ${correlation.correlation_strength}`);
  console.log(`Risk Score: ${riskBefore.score}`);
  console.log(`Risk Priority: ${riskBefore.priority}`);
  console.log(`AI Provider: ${persisted.ai_provider}`);
  console.log(`AI Model: ${persisted.ai_model || 'not applicable (fallback)'}`);
  console.log(`AI Confidence: ${persisted.confidence_score}`);
  console.log(`BLUF: ${safeBluf(persisted.bluf)}`);
  console.log('Recommended Actions:');
  persisted.recommended_actions.slice(0, 3).forEach((action, index) => console.log(`${index + 1}. ${action}`));
  console.log('Persistence: PASS');
  console.log(`Idempotency: PASS (before=${beforeCount}, afterFirst=${afterFirstGenerationCount}, afterSecond=${afterSecondGenerationCount})`);
  console.log('Risk Integrity: PASS');
  console.log(`Guardrails: ${groqSucceeded ? 'PASS' : 'FALLBACK REPORT PERSISTED (provider/parser/guardrail failure is intentionally not exposed by the service)'}`);
  if (!groqSucceeded) {
    const identifierDetail = diagnostic.identifierClass ? `; identifier class: ${diagnostic.identifierClass}` : '';
    console.log(`Diagnostic: ${diagnostic.code || 'AI_PIPELINE_FAILED'} (stage: ${diagnostic.stage || 'unknown'}; ${diagnostic.message || 'Sanitized failure detail unavailable'}${identifierDetail})`);
  }
  console.log('========================================');
  console.log('PIPELINE VERIFICATION COMPLETE');
  console.log('========================================');
  if (!groqSucceeded) process.exitCode = 2;
}

main()
  .catch(error => {
    console.error(`Intelligence pipeline verification failed: ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    try { await getPool().end(); } catch { /* connection setup may have failed */ }
  });

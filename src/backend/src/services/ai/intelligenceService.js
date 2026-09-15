'use strict';

const correlationRepository = require('../../db/correlationRepository');
const riskRepository = require('../../db/riskRepository');
const indicatorsRepository = require('../../db/indicatorsRepository');
const entitiesRepository = require('../../db/entitiesRepository');
const intelligenceRepository = require('../../db/intelligenceRepository');
const { buildIntelligenceContext } = require('./intelligenceContext');
const { buildPrompt } = require('./promptBuilder');
const { GroqProvider } = require('./groqProvider');
const { parseResponse } = require('./responseParser');
const { validateAssessment } = require('./aiGuardrails');
const { AIProviderError } = require('./aiProvider');

class IntelligenceServiceError extends AIProviderError {
  constructor(message, statusCode) {
    super(message);
    this.name = 'IntelligenceServiceError';
    this.code = 'INTELLIGENCE_SERVICE_ERROR';
    this.statusCode = statusCode;
  }
}

function strings(values) {
  return [...new Set((values || []).filter(value => typeof value === 'string' && value))];
}

function fallbackAssessment(context) {
  const priority = String((context.risk && context.risk.priority) || 'unknown').toUpperCase();
  return {
    bluf: `${priority}: A correlated threat pattern requires analyst review based on authoritative evidence.`,
    threat_assessment: 'Automated AI assessment is unavailable. This fallback is based only on authoritative correlation and risk evidence.',
    possible_intent: 'Possible intent cannot be confidently determined from the available evidence.',
    reasoning: 'The correlation and risk engines identified related activity using structured indicators, sources, and asset evidence.',
    evidence_summary: 'Assessment generated from authoritative correlation and risk evidence.',
    recommended_actions: [
      'Investigate the correlated events.',
      'Validate the affected asset and indicators.',
      'Review relevant authentication and network logs.',
      'Escalate according to the organization\'s incident response procedure.',
    ],
    confidence_score: 60,
    categorization: 'Medium',
    is_false_positive: false,
  };
}

function toPersistable(correlationId, assessment, provider, model) {
  return {
    correlationId,
    bluf: assessment.bluf,
    threatAssessment: assessment.threat_assessment,
    possibleIntent: assessment.possible_intent,
    reasoning: assessment.reasoning,
    evidenceSummary: assessment.evidence_summary,
    recommendedActions: assessment.recommended_actions,
    aiProvider: provider,
    aiModel: model || null,
    confidenceScore: assessment.confidence_score,
    categorization: assessment.categorization,
    isFalsePositive: assessment.is_false_positive,
  };
}

/**
 * Creates an injectable orchestration service. Dependency injection keeps this
 * boundary testable without a database or a live AI provider.
 */
function createIntelligenceService(dependencies = {}) {
  const deps = {
    correlationRepository, riskRepository, indicatorsRepository, entitiesRepository,
    intelligenceRepository, buildIntelligenceContext, buildPrompt, parseResponse,
    validateAssessment, providerFactory: () => new GroqProvider(),
    ...dependencies,
  };

  async function generateIntelligence(correlationId) {
    if (typeof correlationId !== 'string' || !correlationId.trim()) {
      throw new IntelligenceServiceError('Correlation identifier is required', 400);
    }

    const correlation = await deps.correlationRepository.getCorrelationById(correlationId);
    if (!correlation) throw new IntelligenceServiceError('Correlation not found', 404);
    const risk = await deps.riskRepository.getRiskScoreByCorrelationId(correlationId);
    if (!risk) throw new IntelligenceServiceError('Risk assessment not found', 404);

    const events = (await deps.correlationRepository.getEventsByCorrelationId(correlationId)) || [];
    const indicatorValues = strings(events.map(event => event.indicator_value));
    const targetNames = strings([
      ...events.map(event => event.target),
      ...(Array.isArray(correlation.targets) ? correlation.targets : []),
    ]);
    const [indicators, entities] = await Promise.all([
      deps.indicatorsRepository.findByValues(indicatorValues),
      deps.entitiesRepository.findByNames(targetNames),
    ]);
    const context = deps.buildIntelligenceContext({ correlation, risk, events, indicators, entities });
    const prompt = deps.buildPrompt(context);

    let report;
    try {
      const provider = deps.provider || deps.providerFactory();
      const rawResponse = await provider.generateAssessment(prompt);
      const parsedAssessment = deps.parseResponse(rawResponse);
      const guarded = deps.validateAssessment(parsedAssessment, context);
      report = toPersistable(correlationId, guarded.assessment, rawResponse.provider || 'groq', rawResponse.model);
    } catch (_error) {
      report = toPersistable(correlationId, fallbackAssessment(context), 'fallback', null);
    }

    return deps.intelligenceRepository.upsert(report);
  }

  return { generateIntelligence };
}

const defaultService = createIntelligenceService();

module.exports = { IntelligenceServiceError, createIntelligenceService, generateIntelligence: defaultService.generateIntelligence };

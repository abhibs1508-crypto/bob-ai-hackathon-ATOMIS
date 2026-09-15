'use strict';

const { createIntelligenceService } = require('../../src/services/ai/intelligenceService');

const correlation = { id: 'corr-1', title: 'Campaign', targets: ['db-01.internal'] };
const risk = { score: 91, priority: 'critical' };
const events = [{ event_id: 'event-1', target: 'db-01.internal', indicator_value: '185.220.101.47' }];
const context = { risk: { score: 91, priority: 'critical' }, targets: ['db-01.internal'], sourceIps: ['185.220.101.47'], indicators: [{ type: 'ip', value: '185.220.101.47' }], entities: [] };
const assessment = {
  bluf: 'Critical activity requires review.', threat_assessment: 'Evidence is consistent with reconnaissance.',
  possible_intent: 'May indicate reconnaissance.', reasoning: 'The supplied evidence is related.',
  evidence_summary: 'One event was observed.', recommended_actions: ['Investigate the host.'], confidence_score: 82,
};

function createDependencies(overrides = {}) {
  const upsert = jest.fn(report => Promise.resolve({ id: 'report-1', correlation_id: report.correlationId, ...report }));
  return {
    correlationRepository: { getCorrelationById: jest.fn().mockResolvedValue(correlation), getEventsByCorrelationId: jest.fn().mockResolvedValue(events) },
    riskRepository: { getRiskScoreByCorrelationId: jest.fn().mockResolvedValue(risk) },
    indicatorsRepository: { findByValues: jest.fn().mockResolvedValue([{ indicator_value: '185.220.101.47' }]) },
    entitiesRepository: { findByNames: jest.fn().mockResolvedValue([{ name: 'db-01.internal' }]) },
    intelligenceRepository: { upsert },
    buildIntelligenceContext: jest.fn().mockReturnValue(context),
    buildPrompt: jest.fn().mockReturnValue({ system: 'system', user: 'user' }),
    provider: { generateAssessment: jest.fn().mockResolvedValue({ provider: 'groq', model: 'openai/gpt-oss-120b', content: '{"bluf":"raw"}' }) },
    parseResponse: jest.fn().mockReturnValue(assessment),
    validateAssessment: jest.fn().mockReturnValue({ safe: true, assessment }),
    ...overrides,
  };
}

describe('intelligence service', () => {
  test('orchestrates a safe AI report from authoritative inputs and persists it', async () => {
    const deps = createDependencies();
    const result = await createIntelligenceService(deps).generateIntelligence('corr-1');

    expect(deps.buildIntelligenceContext).toHaveBeenCalledWith(expect.objectContaining({ correlation, risk, events }));
    expect(deps.buildPrompt).toHaveBeenCalledWith(context);
    expect(deps.provider.generateAssessment).toHaveBeenCalledWith({ system: 'system', user: 'user' });
    expect(deps.parseResponse).toHaveBeenCalledWith(expect.objectContaining({ content: '{"bluf":"raw"}' }));
    expect(deps.validateAssessment).toHaveBeenCalledWith(assessment, context);
    expect(deps.intelligenceRepository.upsert).toHaveBeenCalledWith(expect.objectContaining({
      correlationId: 'corr-1', aiProvider: 'groq', aiModel: 'openai/gpt-oss-120b', confidenceScore: 82,
    }));
    expect(result.id).toBe('report-1');
  });

  test('uses repository upsert so repeat calls update rather than duplicate the report', async () => {
    const deps = createDependencies();
    const service = createIntelligenceService(deps);
    await service.generateIntelligence('corr-1');
    await service.generateIntelligence('corr-1');
    expect(deps.intelligenceRepository.upsert).toHaveBeenCalledTimes(2);
    expect(deps.intelligenceRepository.upsert.mock.calls[0][0].correlationId).toBe('corr-1');
  });

  test.each([
    ['provider failure', deps => deps.provider.generateAssessment.mockRejectedValue(new Error('provider unavailable'))],
    ['invalid response', deps => deps.parseResponse.mockImplementation(() => { throw new Error('invalid response'); })],
    ['guardrail rejection', deps => deps.validateAssessment.mockImplementation(() => { throw new Error('unsafe output'); })],
  ])('persists a labelled fallback for %s without persisting raw AI output', async (_label, prepare) => {
    const deps = createDependencies();
    prepare(deps);
    await createIntelligenceService(deps).generateIntelligence('corr-1');
    const report = deps.intelligenceRepository.upsert.mock.calls[0][0];
    expect(report.aiProvider).toBe('fallback');
    expect(report.aiModel).toBeNull();
    expect(report.confidenceScore).toBe(60);
    expect(JSON.stringify(report)).not.toContain('raw');
  });

  test('keeps risk danger separate from AI confidence and does not mutate authoritative risk', async () => {
    const deps = createDependencies();
    await createIntelligenceService(deps).generateIntelligence('corr-1');
    const report = deps.intelligenceRepository.upsert.mock.calls[0][0];
    expect(risk).toEqual({ score: 91, priority: 'critical' });
    expect(report.confidenceScore).toBe(82);
    expect(report).not.toHaveProperty('riskScore');
    expect(report).not.toHaveProperty('priority');
  });

  test('handles missing correlation and risk with controlled errors', async () => {
    const missingCorrelation = createDependencies({ correlationRepository: { getCorrelationById: jest.fn().mockResolvedValue(null), getEventsByCorrelationId: jest.fn() } });
    await expect(createIntelligenceService(missingCorrelation).generateIntelligence('corr-1')).rejects.toMatchObject({ code: 'INTELLIGENCE_SERVICE_ERROR', statusCode: 404 });

    const missingRisk = createDependencies({ riskRepository: { getRiskScoreByCorrelationId: jest.fn().mockResolvedValue(null) } });
    await expect(createIntelligenceService(missingRisk).generateIntelligence('corr-1')).rejects.toMatchObject({ code: 'INTELLIGENCE_SERVICE_ERROR', statusCode: 404 });
  });

  test('propagates persistence errors without converting them to fallback reports', async () => {
    const deps = createDependencies({ intelligenceRepository: { upsert: jest.fn().mockRejectedValue(new Error('database unavailable')) } });
    await expect(createIntelligenceService(deps).generateIntelligence('corr-1')).rejects.toThrow('database unavailable');
  });
});

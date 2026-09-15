'use strict';

const { validateAssessment } = require('../../src/services/ai/aiGuardrails');

const context = {
  risk: { score: 91, priority: 'critical' }, targets: ['db-01.internal'], sourceIps: ['185.220.101.47'],
  indicators: [{ type: 'ip', value: '185.220.101.47' }], attackStages: ['RECONNAISSANCE'],
  entities: [{ name: 'db-01.internal', entityType: 'database', criticality: 100 }],
};
const assessment = overrides => ({
  bluf: 'Activity from 185.220.101.47 targets db-01.internal.',
  threat_assessment: 'Observed evidence is consistent with reconnaissance.',
  possible_intent: 'This may indicate reconnaissance.', reasoning: 'The supplied IP and target are related.',
  evidence_summary: 'The known IP was observed.', recommended_actions: ['Investigate and review logs.'], confidence_score: 80,
  ...overrides,
});

describe('AI guardrails', () => {
  test('accepts a valid evidence-grounded assessment without modifying context', () => {
    const result = validateAssessment(assessment(), context);
    expect(result.safe).toBe(true);
    expect(result.assessment.confidence_score).toBe(80);
    expect(context.risk.score).toBe(91);
  });

  test('accepts confidence boundary values', () => {
    expect(validateAssessment(assessment({ confidence_score: 0 }), context).safe).toBe(true);
    expect(validateAssessment(assessment({ confidence_score: 100 }), context).safe).toBe(true);
  });

  test('rejects unsupported and accepts supported IPv4 addresses', () => {
    expect(() => validateAssessment(assessment({ bluf: 'Activity from 10.20.30.40 was detected.' }), context)).toThrow(/IP address/);
    expect(validateAssessment(assessment({ bluf: 'Activity from 185.220.101.47 was detected.' }), context).safe).toBe(true);
  });

  test('rejects unsupported explicit targets and accepts supplied targets', () => {
    expect(() => validateAssessment(assessment({ bluf: 'Activity targets db-99.internal.' }), context)).toThrow(/target identifier/);
    expect(validateAssessment(assessment({ bluf: 'Activity targets db-01.internal.' }), context).safe).toBe(true);
  });

  test('rejects unsupported certainty while allowing qualified inference', () => {
    expect(() => validateAssessment(assessment({ threat_assessment: 'This is confirmed compromise.' }), context)).toThrow(/confirmed claim/);
    expect(validateAssessment(assessment({ threat_assessment: 'This may indicate compromise.' }), context).safe).toBe(true);
    expect(() => validateAssessment(assessment({ threat_assessment: 'Confirmed data exfiltration occurred.' }), context)).toThrow(/confirmed claim/);
    expect(validateAssessment(assessment({ threat_assessment: 'This could indicate exfiltration.' }), context).safe).toBe(true);
  });

  test('rejects offensive actions while allowing defensive actions', () => {
    expect(() => validateAssessment(assessment({ recommended_actions: ['Exploit the target.'] }), context)).toThrow(/unsafe recommended action/);
    expect(validateAssessment(assessment({ recommended_actions: ['Isolate the affected host if corroborated.'] }), context).safe).toBe(true);
  });

  test.each(['risk_score', 'priority', 'correlationScore'])('rejects generated authoritative field %s', field => {
    expect(() => validateAssessment(assessment({ [field]: field === 'priority' ? 'low' : 1 }), context)).toThrow(/authoritative risk fields/);
  });
});

'use strict';

const { parseResponse } = require('../../src/services/ai/responseParser');

const valid = {
  bluf: 'Observed related activity.', threat_assessment: 'Evidence indicates a possible campaign.',
  possible_intent: 'May indicate reconnaissance.', reasoning: 'The supplied sources align.',
  evidence_summary: 'One event was observed.', recommended_actions: ['Investigate the host.'], confidence_score: 80,
};
const response = overrides => JSON.stringify({ ...valid, ...overrides });

describe('AI response parser', () => {
  test('parses valid JSON and strips untrusted extra fields', () => {
    const parsed = parseResponse(response({ risk_score: 99, extra: 'ignored' }));
    expect(parsed).toEqual(valid);
    expect(parsed).not.toHaveProperty('risk_score');
  });

  test('parses a complete Markdown JSON fence', () => {
    expect(parseResponse(`\`\`\`json\n${response()}\n\`\`\``)).toEqual(valid);
  });

  test.each(['bluf', 'threat_assessment', 'possible_intent', 'reasoning', 'evidence_summary', 'recommended_actions', 'confidence_score'])('rejects missing %s', field => {
    const input = { ...valid };
    delete input[field];
    expect(() => parseResponse(JSON.stringify(input))).toThrow(/AI response/);
  });

  test.each(['', '   ', null, {}, []])('rejects invalid string fields', value => {
    expect(() => parseResponse(response({ bluf: value }))).toThrow(/bluf/);
  });

  test.each([[], [''], [1], 'investigate'])('rejects invalid recommended actions', value => {
    expect(() => parseResponse(response({ recommended_actions: value }))).toThrow(/recommended_actions/);
  });

  test.each([-1, 101, '80', null, NaN, Infinity])('rejects invalid confidence %p', value => {
    expect(() => parseResponse(response({ confidence_score: value }))).toThrow(/confidence_score/);
  });

  test('rejects invalid JSON without reflecting raw response content', () => {
    expect(() => parseResponse('{secret-model-output')).toThrow('AI response is not valid JSON');
    try { parseResponse('{secret-model-output'); } catch (error) { expect(error.message).not.toContain('secret-model-output'); }
  });
});

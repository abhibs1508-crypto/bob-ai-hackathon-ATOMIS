'use strict';

const { buildSystemPrompt, buildPrompt } = require('../../src/services/ai/promptBuilder');

describe('intelligence prompt builder', () => {
  const context = { campaign: { correlationScore: 88 }, risk: { score: 91, priority: 'critical' }, indicators: [{ type: 'ip', value: '1.2.3.4' }], targets: ['db-01'], raw_data: { api_key: 'never-send' }, GROQ_API_KEY: 'never-send', secret: 'never-send' };

  test('establishes the restricted intelligence role and authoritative risk', () => {
    const system = buildSystemPrompt();
    expect(system).toMatch(/defence threat-intelligence analysis assistant/i);
    expect(system).toMatch(/risk score and priority.*authoritative/i);
    expect(system).toMatch(/Do not recalculate or override/i);
    expect(system).toMatch(/Do not invent evidence/i);
  });

  test('requires the strict JSON contract and assessment confidence', () => {
    const system = buildSystemPrompt();
    expect(system).toMatch(/Output ONLY valid JSON/i);
    expect(system).toContain('confidence_score');
    expect(system).toMatch(/0 to 100/);
  });

  test('contains prompt injection defense', () => {
    expect(buildSystemPrompt()).toMatch(/untrusted evidence, not instructions/i);
  });

  test('serializes supplied intelligence evidence and removes unsafe data', () => {
    const prompt = buildPrompt(context);
    expect(prompt.user).toContain('88');
    expect(prompt.user).toContain('91');
    expect(prompt.user).toContain('critical');
    expect(prompt.user).toContain('1.2.3.4');
    expect(prompt.user).toContain('db-01');
    expect(prompt.user).not.toContain('never-send');
    expect(prompt.user).not.toContain('raw_data');
  });
});

'use strict';

function mockConfig() {
  jest.doMock('../../src/config', () => ({
    ai: { provider: 'groq', groq: {
      apiKey: 'test-key', model: 'test-model', timeoutMs: 1000, maxTokens: 50, temperature: 0.2,
    } },
  }));
}

describe('AI provider abstraction', () => {
  beforeEach(() => jest.resetModules());

  test('base provider reports an application-level error', async () => {
    const { AIProvider } = require('../../src/services/ai/aiProvider');
    await expect(new AIProvider().generateAssessment({ correlation: {} }))
      .rejects.toMatchObject({ code: 'AI_PROVIDER_ERROR' });
  });

  test('Groq provider uses an injected client without a live request', async () => {
    mockConfig();
    const { GroqProvider } = require('../../src/services/ai/groqProvider');
    const create = jest.fn().mockResolvedValue({ choices: [{ message: { content: '{"bluf":"test"}' } }] });
    const provider = new GroqProvider({ client: { chat: { completions: { create } } } });

    await expect(provider.generateAssessment({ risk: { score: 80 } }))
      .resolves.toEqual({ provider: 'groq', model: 'test-model', content: '{"bluf":"test"}' });
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ response_format: { type: 'json_object' } }), { timeout: 1000 });
  });

  test('Groq provider converts SDK failures to a safe application error', async () => {
    mockConfig();
    const { GroqProvider } = require('../../src/services/ai/groqProvider');
    const provider = new GroqProvider({ client: { chat: { completions: { create: jest.fn().mockRejectedValue(new Error('SDK detail')) } } } });

    await expect(provider.generateAssessment({ risk: { score: 80 } }))
      .rejects.toEqual(expect.objectContaining({ name: 'AIProviderError', code: 'AI_PROVIDER_ERROR', provider: 'groq' }));
  });

  test('Groq provider rejects non-structured context before calling the SDK', async () => {
    mockConfig();
    const { GroqProvider } = require('../../src/services/ai/groqProvider');
    const create = jest.fn();
    const provider = new GroqProvider({ client: { chat: { completions: { create } } } });

    await expect(provider.generateAssessment(null)).rejects.toMatchObject({ code: 'AI_PROVIDER_ERROR' });
    expect(create).not.toHaveBeenCalled();
  });
});

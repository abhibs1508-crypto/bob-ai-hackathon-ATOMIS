'use strict';

const Groq = require('groq-sdk');
const { getAIConfig } = require('./aiConfig');
const { AIProvider, AIProviderError, assertStructuredContext } = require('./aiProvider');

const SYSTEM_INSTRUCTION = [
  'You are a cybersecurity intelligence assistant.',
  'Explain only the structured evidence supplied by the user.',
  'Do not invent facts or alter risk, severity, priority, indicators, targets, or events.',
  'Return a JSON object.',
].join(' ');

class GroqProvider extends AIProvider {
  constructor(options = {}) {
    super();
    const configured = getAIConfig();
    this.config = { ...configured, ...options };
    this.client = options.client || new Groq({ apiKey: this.config.apiKey });
  }

  /** Submits only a sanitized intelligence context; parsing is a later step. */
  async generateAssessment(context) {
    assertStructuredContext(context);
    const isPrompt = typeof context.system === 'string' && typeof context.user === 'string';
    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: isPrompt ? context.system : SYSTEM_INSTRUCTION },
          { role: 'user', content: isPrompt ? context.user : JSON.stringify(context) },
        ],
        response_format: { type: 'json_object' },
        temperature: this.config.temperature,
        max_tokens: this.config.maxTokens,
      }, { timeout: this.config.timeoutMs });

      const content = response && response.choices && response.choices[0]
        && response.choices[0].message && response.choices[0].message.content;
      if (!content) throw new AIProviderError('AI provider returned an empty response', { provider: 'groq' });
      return Object.freeze({ provider: 'groq', model: this.config.model, content });
    } catch (error) {
      if (error instanceof AIProviderError) throw error;
      throw new AIProviderError('AI provider request failed', { provider: 'groq' });
    }
  }
}

module.exports = { GroqProvider, SYSTEM_INSTRUCTION };

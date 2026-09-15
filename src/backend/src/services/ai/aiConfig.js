'use strict';

const config = require('../../config');

const DEFAULTS = Object.freeze({
  provider: 'groq',
  model: 'openai/gpt-oss-120b',
  timeoutMs: 30000,
  maxTokens: 1200,
  temperature: 0.2,
});

class AIConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AIConfigurationError';
    this.code = 'AI_CONFIGURATION_ERROR';
  }
}

function positiveInteger(value, name, fallback) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    if (value === undefined || value === null || value === '') return fallback;
    throw new AIConfigurationError(`${name} must be a positive integer`);
  }
  return parsed;
}

function parseTemperature(value) {
  if (value === undefined || value === null || value === '') return DEFAULTS.temperature;
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed)) {
    throw new AIConfigurationError('GROQ_TEMPERATURE must be a number between 0 and 2');
  }
  if (parsed < 0 || parsed > 2) {
    throw new AIConfigurationError('GROQ_TEMPERATURE must be between 0 and 2');
  }
  return parsed;
}

/** Returns server-only configuration. Callers must never log or return apiKey. */
function getAIConfig() {
  const groq = config.ai && config.ai.groq ? config.ai.groq : {};
  const provider = String((config.ai && config.ai.provider) || process.env.AI_PROVIDER || DEFAULTS.provider)
    .trim()
    .toLowerCase();

  if (provider !== 'groq') {
    throw new AIConfigurationError(`Unsupported AI provider: ${provider || 'not configured'}`);
  }

  const apiKey = groq.apiKey || process.env.GROQ_API_KEY;
  if (!apiKey) throw new AIConfigurationError('GROQ_API_KEY is not configured');

  return Object.freeze({
    provider,
    apiKey,
    model: groq.model || process.env.GROQ_MODEL || DEFAULTS.model,
    timeoutMs: positiveInteger(groq.timeoutMs, 'GROQ_TIMEOUT_MS', DEFAULTS.timeoutMs),
    maxTokens: positiveInteger(groq.maxTokens, 'GROQ_MAX_TOKENS', DEFAULTS.maxTokens),
    temperature: parseTemperature(groq.temperature),
  });
}

module.exports = { AIConfigurationError, getAIConfig };

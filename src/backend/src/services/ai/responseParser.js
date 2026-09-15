'use strict';

const { AIProviderError } = require('./aiProvider');

const REQUIRED_STRING_FIELDS = ['bluf', 'threat_assessment', 'possible_intent', 'reasoning', 'evidence_summary', 'categorization'];

class AIResponseError extends AIProviderError {
  constructor(message) {
    super(message);
    this.name = 'AIResponseError';
    this.code = 'AI_RESPONSE_INVALID';
  }
}

function extractContent(response) {
  if (typeof response === 'string') return response;
  if (response && typeof response.content === 'string') return response.content;
  throw new AIResponseError('AI response content is invalid');
}

function removeJsonFence(content) {
  const trimmed = content.trim();
  const match = trimmed.match(/^```json\s*\r?\n([\s\S]*?)\r?\n?```$/i);
  return match ? match[1].trim() : trimmed;
}

function parseResponse(response) {
  let parsed;
  try {
    parsed = JSON.parse(removeJsonFence(extractContent(response)));
  } catch {
    throw new AIResponseError('AI response is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new AIResponseError('AI response must be a JSON object');
  }

  const result = {};
  for (const field of REQUIRED_STRING_FIELDS) {
    if (typeof parsed[field] !== 'string' || !parsed[field].trim()) {
      throw new AIResponseError(`AI response field "${field}" must be a non-empty string`);
    }
    result[field] = parsed[field].trim();
  }

  if (!Array.isArray(parsed.recommended_actions) || parsed.recommended_actions.length === 0
    || parsed.recommended_actions.some(action => typeof action !== 'string' || !action.trim())) {
    throw new AIResponseError('AI response field "recommended_actions" must be a non-empty array of strings');
  }
  result.recommended_actions = parsed.recommended_actions.map(action => action.trim());

  if (typeof parsed.confidence_score !== 'number' || !Number.isInteger(parsed.confidence_score)
    || !Number.isFinite(parsed.confidence_score) || parsed.confidence_score < 0 || parsed.confidence_score > 100) {
    throw new AIResponseError('AI response field "confidence_score" must be an integer from 0 to 100');
  }
  result.confidence_score = parsed.confidence_score;

  if (!['Critical', 'Medium', 'Low'].includes(result.categorization)) {
    throw new AIResponseError('AI response field "categorization" must be Critical, Medium, or Low');
  }

  if (typeof parsed.is_false_positive !== 'boolean') {
    throw new AIResponseError('AI response field "is_false_positive" must be a boolean');
  }
  result.is_false_positive = parsed.is_false_positive;

  return Object.freeze(result);
}

module.exports = { AIResponseError, parseResponse };

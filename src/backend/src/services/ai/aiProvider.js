'use strict';

class AIProviderError extends Error {
  constructor(message, metadata = {}) {
    super(message);
    this.name = 'AIProviderError';
    this.code = 'AI_PROVIDER_ERROR';
    this.provider = metadata.provider;
  }
}

class AIProvider {
  async generateAssessment() {
    throw new AIProviderError('AI provider does not implement generateAssessment');
  }
}

function assertStructuredContext(context) {
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    throw new AIProviderError('AI assessment context must be a structured object');
  }
}

module.exports = { AIProvider, AIProviderError, assertStructuredContext };

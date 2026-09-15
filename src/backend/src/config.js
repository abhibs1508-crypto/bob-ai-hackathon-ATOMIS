'use strict';

/**
 * CyberFusion — Centralized Configuration
 *
 * Loads environment variables from .env (via dotenv) and exports a single
 * frozen config object. All application code must import config values from
 * here — never call process.env directly outside this module.
 *
 * Missing required variables throw at startup so the app fails fast with a
 * clear message rather than failing silently at runtime.
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

/**
 * Reads an environment variable. Throws if it is required and missing.
 * @param {string} key
 * @param {string|undefined} defaultValue
 * @param {boolean} required
 * @returns {string}
 */
function env(key, defaultValue = undefined, required = false) {
  const value = process.env[key];
  if ((value === undefined || value === '') && required) {
    throw new Error(`[config] Required environment variable "${key}" is not set. Check your .env file.`);
  }
  return value !== undefined && value !== '' ? value : defaultValue;
}

const config = Object.freeze({
  /** Node environment */
  nodeEnv: env('NODE_ENV', 'development'),

  /** HTTP server port */
  port: parseInt(env('BACKEND_PORT', '4000'), 10),

  /** Supabase connection settings */
  supabase: Object.freeze({
    url: env('SUPABASE_URL', '', true),
    serviceKey: env('SUPABASE_SERVICE_ROLE_KEY', env('SUPABASE_ANON_KEY', ''), true),
  }),

  /** AI provider (Phase 4) — read here so config is the single source */
  ai: Object.freeze({
    provider: env('AI_PROVIDER', 'mock'),
    groq: Object.freeze({
      apiKey: env('GROQ_API_KEY'),
      model: env('GROQ_MODEL', 'openai/gpt-oss-120b'),
      timeoutMs: parseInt(env('GROQ_TIMEOUT_MS', '30000'), 10),
      maxTokens: parseInt(env('GROQ_MAX_TOKENS', '1200'), 10),
      temperature: parseFloat(env('GROQ_TEMPERATURE', '0.2')),
    }),
  }),
});

module.exports = config;

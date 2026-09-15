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

  /** MySQL connection settings */
  db: Object.freeze({
    host:     env('DB_HOST', 'localhost'),
    port:     parseInt(env('DB_PORT', '3306'), 10),
    user:     env('DB_USER', 'root'),
    // password intentionally has no default — empty string is valid for XAMPP
    password: env('DB_PASSWORD', ''),
    name:     env('DB_NAME', 'cyberfusion_db'),
    // SSL support: set DB_SSL=true for Aiven; not required for local XAMPP
    ssl:      env('DB_SSL', 'false') === 'true',
    connectionLimit: parseInt(env('DB_POOL_LIMIT', '10'), 10),
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

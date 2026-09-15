'use strict';

/**
 * Unit tests — Config Module
 *
 * Tests that the config module reads env vars correctly.
 *
 * We manipulate process.env directly and re-require config fresh each time
 * by clearing the module registry. dotenv is mocked so no real .env file
 * interferes with the test environment.
 */

const path = require('path');

// Keys we manipulate in tests — saved and restored around each test
const TEST_ENV_KEYS = [
  'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
  'DB_SSL', 'DB_POOL_LIMIT', 'BACKEND_PORT', 'NODE_ENV', 'AI_PROVIDER',
];

describe('config', () => {
  const savedEnv = {};

  beforeEach(() => {
    // Full module reset so every test gets a fresh require of config.js
    jest.resetModules();
    // Save original values of keys we will touch
    TEST_ENV_KEYS.forEach(k => { savedEnv[k] = process.env[k]; });
  });

  afterEach(() => {
    // Restore env to pre-test state
    TEST_ENV_KEYS.forEach(k => {
      if (savedEnv[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = savedEnv[k];
      }
    });
  });

  /** Load config fresh after env has been configured for the test */
  function freshConfig() {
    // Provide a no-op dotenv so the real .env file is never consulted
    jest.doMock('dotenv', () => ({ config: jest.fn() }));
    return require(path.resolve(__dirname, '../../src/config'));
  }

  test('reads DB_HOST from environment', () => {
    process.env.DB_HOST = 'test-host';
    const config = freshConfig();
    expect(config.db.host).toBe('test-host');
  });

  test('reads DB_PORT from environment as integer', () => {
    process.env.DB_PORT = '3307';
    const config = freshConfig();
    expect(config.db.port).toBe(3307);
  });

  test('defaults DB_HOST to localhost when not set', () => {
    delete process.env.DB_HOST;
    const config = freshConfig();
    expect(config.db.host).toBe('localhost');
  });

  test('defaults BACKEND_PORT to 4000 when not set', () => {
    delete process.env.BACKEND_PORT;
    const config = freshConfig();
    expect(config.port).toBe(4000);
  });

  test('defaults DB_NAME to cyberfusion_db when not set', () => {
    delete process.env.DB_NAME;
    const config = freshConfig();
    expect(config.db.name).toBe('cyberfusion_db');
  });

  test('config object is frozen', () => {
    const config = freshConfig();
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.db)).toBe(true);
  });

  test('DB_SSL is false by default', () => {
    delete process.env.DB_SSL;
    const config = freshConfig();
    expect(config.db.ssl).toBe(false);
  });

  test('DB_SSL is true when set to "true"', () => {
    process.env.DB_SSL = 'true';
    const config = freshConfig();
    expect(config.db.ssl).toBe(true);
  });

  test('reads AI_PROVIDER from environment', () => {
    process.env.AI_PROVIDER = 'openai';
    const config = freshConfig();
    expect(config.ai.provider).toBe('openai');
  });

  test('defaults AI_PROVIDER to mock', () => {
    delete process.env.AI_PROVIDER;
    const config = freshConfig();
    expect(config.ai.provider).toBe('mock');
  });
});

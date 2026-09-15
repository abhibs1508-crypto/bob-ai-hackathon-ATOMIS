'use strict';

/**
 * Integration tests — Intelligence API (Phase 6)
 *
 * Tests the HTTP layer only. The AI intelligence service and repository are
 * fully mocked — no running MySQL or live AI provider is required.
 */

const request = require('supertest');
const app     = require('../../src/app');

// ---------------------------------------------------------------------------
// Mock the intelligence service (generateIntelligence)
// ---------------------------------------------------------------------------
jest.mock('../../src/services/ai/intelligenceService', () => {
  const { AIProviderError } = jest.requireActual('../../src/services/ai/aiProvider');

  class IntelligenceServiceError extends AIProviderError {
    constructor(message, statusCode) {
      super(message);
      this.name = 'IntelligenceServiceError';
      this.code = 'INTELLIGENCE_SERVICE_ERROR';
      this.statusCode = statusCode;
    }
  }

  return {
    IntelligenceServiceError,
    generateIntelligence: jest.fn(),
  };
});

// ---------------------------------------------------------------------------
// Mock the intelligence repository (findByCorrelationId)
// ---------------------------------------------------------------------------
jest.mock('../../src/db/intelligenceRepository', () => ({
  findByCorrelationId: jest.fn(),
}));

// ---------------------------------------------------------------------------
// Mock pool.getPool() used in GET /:id inline query
// ---------------------------------------------------------------------------
jest.mock('../../src/db/pool', () => ({
  getPool: jest.fn(),
}));

const { generateIntelligence, IntelligenceServiceError } = require('../../src/services/ai/intelligenceService');
const intelligenceRepository = require('../../src/db/intelligenceRepository');
const { getPool } = require('../../src/db/pool');

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------
const CORR_UUID   = '4fa85f64-5717-4562-b3fc-2c963f66afa7';
const REPORT_UUID = '5fa85f64-5717-4562-b3fc-2c963f66afa8';

function mockReport() {
  return {
    id:                 REPORT_UUID,
    correlation_id:     CORR_UUID,
    bluf:               'CRITICAL: Coordinated reconnaissance detected.',
    threat_assessment:  'Multiple correlated events indicate a targeted attack.',
    possible_intent:    'Credential harvesting and lateral movement.',
    reasoning:          'Port scan followed by brute-force SSH attempts matching a known malicious IP.',
    evidence_summary:   'Three correlated events; IOC match; critical asset targeted.',
    recommended_actions: ['Isolate the affected host', 'Reset credentials', 'Escalate to SOC'],
    ai_provider:        'groq',
    ai_model:           'openai/gpt-oss-120b',
    confidence_score:   85,
    generated_at:       new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// POST /api/intelligence/generate/:correlationId
// ---------------------------------------------------------------------------
describe('POST /api/intelligence/generate/:correlationId', () => {
  test('returns 201 with report on success', async () => {
    generateIntelligence.mockResolvedValueOnce(mockReport());
    const res = await request(app)
      .post(`/api/intelligence/generate/${CORR_UUID}`)
      .expect(201);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toMatch(/generated/i);
    expect(res.body.data.report.bluf).toMatch(/CRITICAL/);
    expect(res.body.data.report.confidence_score).toBe(85);
    expect(generateIntelligence).toHaveBeenCalledWith(CORR_UUID);
  });

  test('returns 400 for invalid UUID', async () => {
    const res = await request(app)
      .post('/api/intelligence/generate/not-a-uuid')
      .expect(400);
    expect(res.body.success).toBe(false);
    expect(res.body.errors).toBeDefined();
  });

  test('returns 404 when correlation does not exist', async () => {
    const err = new IntelligenceServiceError('Correlation not found', 404);
    generateIntelligence.mockRejectedValueOnce(err);
    const res = await request(app)
      .post(`/api/intelligence/generate/${CORR_UUID}`)
      .expect(404);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toMatch(/not found/i);
  });

  test('returns 404 when risk assessment does not exist', async () => {
    const err = new IntelligenceServiceError('Risk assessment not found', 404);
    generateIntelligence.mockRejectedValueOnce(err);
    const res = await request(app)
      .post(`/api/intelligence/generate/${CORR_UUID}`)
      .expect(404);
    expect(res.body.success).toBe(false);
  });

  test('returns 400 when service rejects with 400', async () => {
    const err = new IntelligenceServiceError('Correlation identifier is required', 400);
    generateIntelligence.mockRejectedValueOnce(err);
    const res = await request(app)
      .post(`/api/intelligence/generate/${CORR_UUID}`)
      .expect(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 500 for unexpected service error', async () => {
    generateIntelligence.mockRejectedValueOnce(new Error('Database connection lost'));
    const res = await request(app)
      .post(`/api/intelligence/generate/${CORR_UUID}`)
      .expect(500);
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GET /api/intelligence/correlation/:correlationId
// ---------------------------------------------------------------------------
describe('GET /api/intelligence/correlation/:correlationId', () => {
  test('returns 200 with report when found', async () => {
    intelligenceRepository.findByCorrelationId.mockResolvedValueOnce(mockReport());
    const res = await request(app)
      .get(`/api/intelligence/correlation/${CORR_UUID}`)
      .expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.report.correlation_id).toBe(CORR_UUID);
    expect(Array.isArray(res.body.data.report.recommended_actions)).toBe(true);
  });

  test('returns 404 when no report exists', async () => {
    intelligenceRepository.findByCorrelationId.mockResolvedValueOnce(null);
    const res = await request(app)
      .get(`/api/intelligence/correlation/${CORR_UUID}`)
      .expect(404);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toMatch(/no intelligence report/i);
  });

  test('returns 400 for invalid correlation UUID', async () => {
    const res = await request(app)
      .get('/api/intelligence/correlation/bad-uuid')
      .expect(400);
    expect(res.body.success).toBe(false);
    expect(res.body.errors[0].field).toBe('correlationId');
  });

  test('propagates unexpected DB error to error handler', async () => {
    intelligenceRepository.findByCorrelationId.mockRejectedValueOnce(new Error('DB down'));
    const res = await request(app)
      .get(`/api/intelligence/correlation/${CORR_UUID}`)
      .expect(500);
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GET /api/intelligence/:id
// Route ordering check: "correlation" sub-path must not be captured by /:id
// ---------------------------------------------------------------------------
describe('GET /api/intelligence/:id — route ordering', () => {
  test('"correlation" sub-path is NOT swallowed by /:id — receives 400 for bad UUID suffix', async () => {
    // /api/intelligence/correlation/<bad-uuid> should hit the /correlation/:correlationId
    // route and return 400 (not be captured by /:id which would also return 400 but
    // with field "id" not "correlationId")
    const res = await request(app)
      .get('/api/intelligence/correlation/not-a-uuid')
      .expect(400);
    expect(res.body.errors[0].field).toBe('correlationId');
  });
});

describe('GET /api/intelligence/:id', () => {
  beforeEach(() => {
    // Provide a mock execute function on the pool
    getPool.mockReturnValue({
      execute: jest.fn(),
    });
  });

  test('returns 200 with report when found', async () => {
    const row = { ...mockReport(), recommended_actions: JSON.stringify(mockReport().recommended_actions) };
    getPool().execute.mockResolvedValueOnce([[row]]);
    const res = await request(app)
      .get(`/api/intelligence/${REPORT_UUID}`)
      .expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.report.id).toBe(REPORT_UUID);
    // recommended_actions must be parsed back to an array
    expect(Array.isArray(res.body.data.report.recommended_actions)).toBe(true);
  });

  test('returns 404 when report not found', async () => {
    getPool().execute.mockResolvedValueOnce([[]]);
    const res = await request(app)
      .get(`/api/intelligence/${REPORT_UUID}`)
      .expect(404);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toMatch(/not found/i);
  });

  test('returns 400 for invalid UUID', async () => {
    const res = await request(app)
      .get('/api/intelligence/not-a-uuid')
      .expect(400);
    expect(res.body.success).toBe(false);
  });

  test('propagates DB error to error handler', async () => {
    getPool().execute.mockRejectedValueOnce(new Error('DB timeout'));
    const res = await request(app)
      .get(`/api/intelligence/${REPORT_UUID}`)
      .expect(500);
    expect(res.body.success).toBe(false);
  });
});

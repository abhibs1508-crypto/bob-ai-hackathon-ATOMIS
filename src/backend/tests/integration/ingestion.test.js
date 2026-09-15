'use strict';

/**
 * Integration tests — Ingestion API
 *
 * Tests the full HTTP request → validation → normalization → response pipeline.
 * The database layer is mocked so these tests do not require a running MySQL instance.
 *
 * Covers:
 *   - 201 success for all 4 source types
 *   - 400 validation failures (missing fields, bad confidence, bad severity)
 *   - 400 malformed JSON
 *   - 409 duplicate event
 *   - 404 unknown route
 */

const request  = require('supertest');
const app      = require('../../src/app');

// ---------------------------------------------------------------------------
// Mock the ingestion service so the DB is not needed
// ---------------------------------------------------------------------------
jest.mock('../../src/services/ingestion/ingestionService', () => ({
  ingestEvent: jest.fn(),
}));

const { ingestEvent } = require('../../src/services/ingestion/ingestionService');

// Helper: default mock response for a successful ingestion
function mockSuccess(source, eventId = 'EVT-TEST-001') {
  ingestEvent.mockResolvedValueOnce({
    success:    true,
    event_id:   eventId,
    source:     source.toLowerCase(),
    normalized: true,
    stored:     true,
    message:    'Threat event ingested successfully',
  });
}

// ---------------------------------------------------------------------------
// Valid payloads (one per source type)
// ---------------------------------------------------------------------------
const VALID_SIEM = {
  event_type:  'AUTH_FAILURE',
  source_ip:   '185.10.10.20',
  target:      'critical-command-server',
  severity:    'high',
  confidence:  88,
  timestamp:   '2025-01-01T10:00:00.000Z',
  raw_data:    { failed_attempts: 17, protocol: 'SSH' },
};

const VALID_SENSOR = {
  event_type: 'PORT_SCAN',
  source_ip:  '185.10.10.20',
  target:     'critical-command-server',
  severity:   'medium',
  confidence: 82,
  timestamp:  '2025-01-01T10:05:00.000Z',
  raw_data:   { ports_scanned: 42, protocol: 'TCP' },
};

const VALID_THREAT_INTEL = {
  event_type:      'MALICIOUS_IOC',
  source_ip:       '185.10.10.20',
  indicator_type:  'ip',
  indicator_value: '185.10.10.20',
  severity:        'critical',
  confidence:      96,
  timestamp:       '2025-01-01T10:10:00.000Z',
  raw_data:        { ioc_status: 'malicious' },
};

const VALID_REPORT = {
  event_type: 'THREAT_REPORT',
  severity:   'high',
  confidence: 75,
  timestamp:  '2025-01-01T10:15:00.000Z',
  raw_data:   { title: 'Suspicious activity', summary: 'Multiple indicators detected.' },
};

// ---------------------------------------------------------------------------
// POST /api/ingestion/siem
// ---------------------------------------------------------------------------
describe('POST /api/ingestion/siem', () => {
  test('returns 201 with valid payload', async () => {
    mockSuccess('siem');
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send(VALID_SIEM)
      .expect('Content-Type', /json/)
      .expect(201);

    expect(res.body.success).toBe(true);
    expect(res.body.source).toBe('siem');
    expect(res.body.event_id).toBeTruthy();
  });

  test('returns 400 when event_type is missing', async () => {
    const { event_type, ...incomplete } = VALID_SIEM;
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send(incomplete)
      .expect(400);

    expect(res.body.success).toBe(false);
    expect(res.body.errors).toEqual(expect.arrayContaining([
      expect.objectContaining({ field: 'event_type' }),
    ]));
  });

  test('returns 400 when timestamp is missing', async () => {
    const { timestamp, ...incomplete } = VALID_SIEM;
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send(incomplete)
      .expect(400);

    expect(res.body.success).toBe(false);
  });

  test('returns 400 when confidence is out of range (>100)', async () => {
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send({ ...VALID_SIEM, confidence: 150 })
      .expect(400);

    expect(res.body.success).toBe(false);
    expect(res.body.errors.some(e => e.field === 'confidence')).toBe(true);
  });

  test('returns 400 when confidence is negative', async () => {
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send({ ...VALID_SIEM, confidence: -1 })
      .expect(400);

    expect(res.body.success).toBe(false);
  });

  test('returns 400 for invalid severity', async () => {
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send({ ...VALID_SIEM, severity: 'extreme' })
      .expect(400);

    expect(res.body.success).toBe(false);
    expect(res.body.errors.some(e => e.field === 'severity')).toBe(true);
  });

  test('returns 400 for invalid source_ip', async () => {
    const res = await request(app)
      .post('/api/ingestion/siem')
      .send({ ...VALID_SIEM, source_ip: 'not-an-ip' })
      .expect(400);

    expect(res.body.success).toBe(false);
  });

  test('returns 400 for malformed JSON', async () => {
    const res = await request(app)
      .post('/api/ingestion/siem')
      .set('Content-Type', 'application/json')
      .send('{ bad json }')
      .expect(400);

    expect(res.body.success).toBe(false);
  });

  test('returns 409 for duplicate event', async () => {
    const dupErr = new Error('Event already ingested');
    dupErr.code = 'DUPLICATE_EVENT';
    dupErr.statusCode = 409;
    ingestEvent.mockRejectedValueOnce(dupErr);

    const res = await request(app)
      .post('/api/ingestion/siem')
      .send(VALID_SIEM)
      .expect(409);

    expect(res.body.success).toBe(false);
    expect(res.body.code).toBe('DUPLICATE_EVENT');
  });
});

// ---------------------------------------------------------------------------
// POST /api/ingestion/sensor
// ---------------------------------------------------------------------------
describe('POST /api/ingestion/sensor', () => {
  test('returns 201 with valid payload', async () => {
    mockSuccess('sensor');
    const res = await request(app)
      .post('/api/ingestion/sensor')
      .send(VALID_SENSOR)
      .expect(201);

    expect(res.body.success).toBe(true);
    expect(res.body.source).toBe('sensor');
  });

  test('returns 400 when severity is missing', async () => {
    const { severity, ...incomplete } = VALID_SENSOR;
    const res = await request(app)
      .post('/api/ingestion/sensor')
      .send(incomplete)
      .expect(400);

    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// POST /api/ingestion/threat-intel
// ---------------------------------------------------------------------------
describe('POST /api/ingestion/threat-intel', () => {
  test('returns 201 with valid payload', async () => {
    mockSuccess('threat_intel');
    const res = await request(app)
      .post('/api/ingestion/threat-intel')
      .send(VALID_THREAT_INTEL)
      .expect(201);

    expect(res.body.success).toBe(true);
  });

  test('returns 400 when indicator_type is missing', async () => {
    const { indicator_type, ...incomplete } = VALID_THREAT_INTEL;
    const res = await request(app)
      .post('/api/ingestion/threat-intel')
      .send(incomplete)
      .expect(400);

    expect(res.body.errors.some(e => e.field === 'indicator_type')).toBe(true);
  });

  test('returns 400 when indicator_value is missing', async () => {
    const { indicator_value, ...incomplete } = VALID_THREAT_INTEL;
    const res = await request(app)
      .post('/api/ingestion/threat-intel')
      .send(incomplete)
      .expect(400);

    expect(res.body.errors.some(e => e.field === 'indicator_value')).toBe(true);
  });

  test('returns 400 for invalid indicator_type', async () => {
    const res = await request(app)
      .post('/api/ingestion/threat-intel')
      .send({ ...VALID_THREAT_INTEL, indicator_type: 'certificate' })
      .expect(400);

    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// POST /api/ingestion/report
// ---------------------------------------------------------------------------
describe('POST /api/ingestion/report', () => {
  test('returns 201 with valid payload', async () => {
    mockSuccess('intelligence_report');
    const res = await request(app)
      .post('/api/ingestion/report')
      .send(VALID_REPORT)
      .expect(201);

    expect(res.body.success).toBe(true);
  });

  test('returns 400 when confidence is missing', async () => {
    const { confidence, ...incomplete } = VALID_REPORT;
    const res = await request(app)
      .post('/api/ingestion/report')
      .send(incomplete)
      .expect(400);

    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GET /api/health
// ---------------------------------------------------------------------------
describe('GET /api/health', () => {
  test('returns JSON with status and database fields', async () => {
    // Health route connects to DB — mock pool to avoid needing MySQL
    jest.mock('../../src/db/pool', () => ({
      getPool: () => ({
        getConnection: async () => ({
          query: async () => {},
          release: () => {},
        }),
      }),
      checkDatabaseConnection: async () => {},
    }));

    const res = await request(app)
      .get('/api/health')
      .expect('Content-Type', /json/);

    expect(res.body).toHaveProperty('status');
    expect(res.body).toHaveProperty('database');
    expect(res.body).toHaveProperty('timestamp');
  });
});

// ---------------------------------------------------------------------------
// Unknown route
// ---------------------------------------------------------------------------
describe('Unknown routes', () => {
  test('returns 404 for undefined route', async () => {
    const res = await request(app)
      .get('/api/does-not-exist')
      .expect(404);

    expect(res.body.success).toBe(false);
  });
});

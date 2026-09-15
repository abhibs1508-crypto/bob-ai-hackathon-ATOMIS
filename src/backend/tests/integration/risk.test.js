'use strict';

/**
 * Integration tests — Risk & Alert API (Phase 4)
 *
 * Tests the HTTP layer. The risk service + DB layer are mocked so no
 * running MySQL is required.
 */

const request = require('supertest');
const app     = require('../../src/app');

// ---------------------------------------------------------------------------
// Mock the risk service entirely
// ---------------------------------------------------------------------------
jest.mock('../../src/services/risk/riskService', () => ({
  evaluateCorrelation: jest.fn(),
  runRiskAll:          jest.fn(),
  getRiskScores:       jest.fn(),
  getRiskScore:        jest.fn(),
  getAlerts:           jest.fn(),
  getAlert:            jest.fn(),
  patchAlertStatus:    jest.fn(),
}));

const {
  evaluateCorrelation,
  runRiskAll,
  getRiskScores,
  getRiskScore,
  getAlerts,
  getAlert,
  patchAlertStatus,
} = require('../../src/services/risk/riskService');

const MOCK_UUID = '3fa85f64-5717-4562-b3fc-2c963f66afa6';
const CORR_UUID = '4fa85f64-5717-4562-b3fc-2c963f66afa7';

function mockRiskResult() {
  return {
    isNew: true,
    risk:  {
      id: MOCK_UUID, correlationId: CORR_UUID,
      score: 88, priority: 'critical',
      severityComponent: 100, iocMatchComponent: 100, assetCriticalityComponent: 95,
      correlationStrengthComponent: 90, recencyComponent: 97,
    },
    alert:    { id: MOCK_UUID, priority: 'critical', status: 'open', title: 'Critical threat' },
    evidence: { version: '1.0', factors: [], finalScore: 88, priority: 'critical' },
  };
}

function mockRiskScoreRow() {
  return {
    id: MOCK_UUID, correlation_id: CORR_UUID,
    score: 88, priority: 'critical',
    severity_component: 100, ioc_match_component: 100,
    asset_criticality_component: 95, correlation_strength_component: 90,
    recency_component: 97, risk_evidence: { version: '1.0', factors: [], finalScore: 88, priority: 'critical' },
    calculated_at: new Date().toISOString(),
  };
}

function mockAlertRow() {
  return {
    id: MOCK_UUID, correlation_id: CORR_UUID,
    title: 'Critical coordinated threat', priority: 'critical',
    status: 'open', created_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// POST /api/risk/run
// ---------------------------------------------------------------------------
describe('POST /api/risk/run', () => {
  test('returns 200 with summary', async () => {
    runRiskAll.mockResolvedValueOnce([
      { success: true, isNew: true,  correlationId: CORR_UUID, risk: { score: 88, priority: 'critical' } },
      { success: true, isNew: false, correlationId: CORR_UUID, risk: { score: 30, priority: 'medium' } },
    ]);
    const res = await request(app).post('/api/risk/run').expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.summary.total).toBe(2);
    expect(res.body.summary.created).toBe(1);
    expect(res.body.summary.updated).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// POST /api/risk/correlation/:correlationId
// ---------------------------------------------------------------------------
describe('POST /api/risk/correlation/:correlationId', () => {
  test('returns 201 for valid UUID', async () => {
    evaluateCorrelation.mockResolvedValueOnce(mockRiskResult());
    const res = await request(app)
      .post(`/api/risk/correlation/${CORR_UUID}`)
      .expect(201);
    expect(res.body.success).toBe(true);
    expect(res.body.risk.score).toBe(88);
    expect(res.body.risk.priority).toBe('critical');
    expect(res.body.alert.status).toBe('open');
  });

  test('returns 400 for invalid UUID', async () => {
    const res = await request(app)
      .post('/api/risk/correlation/not-a-uuid')
      .expect(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 404 when correlation not found', async () => {
    const err = new Error('Correlation not found'); err.statusCode = 404;
    evaluateCorrelation.mockRejectedValueOnce(err);
    const res = await request(app)
      .post(`/api/risk/correlation/${CORR_UUID}`)
      .expect(404);
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GET /api/risk
// ---------------------------------------------------------------------------
describe('GET /api/risk', () => {
  test('returns list of risk scores', async () => {
    getRiskScores.mockResolvedValueOnce([mockRiskScoreRow()]);
    const res = await request(app).get('/api/risk').expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.count).toBe(1);
    expect(res.body.riskScores[0].score).toBe(88);
  });

  test('accepts priority filter', async () => {
    getRiskScores.mockResolvedValueOnce([]);
    await request(app).get('/api/risk?priority=critical').expect(200);
    expect(getRiskScores).toHaveBeenCalledWith(expect.objectContaining({ priority: 'critical' }));
  });

  test('returns 400 for invalid priority', async () => {
    const res = await request(app).get('/api/risk?priority=extreme').expect(400);
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GET /api/risk/:id
// ---------------------------------------------------------------------------
describe('GET /api/risk/:id', () => {
  test('returns risk score for valid UUID', async () => {
    getRiskScore.mockResolvedValueOnce(mockRiskScoreRow());
    const res = await request(app).get(`/api/risk/${MOCK_UUID}`).expect(200);
    expect(res.body.riskScore.score).toBe(88);
  });

  test('returns 404 when not found', async () => {
    getRiskScore.mockResolvedValueOnce(null);
    await request(app).get(`/api/risk/${MOCK_UUID}`).expect(404);
  });

  test('returns 400 for invalid UUID', async () => {
    await request(app).get('/api/risk/not-a-uuid').expect(400);
  });
});

// ---------------------------------------------------------------------------
// GET /api/risk/:id/evidence
// ---------------------------------------------------------------------------
describe('GET /api/risk/:id/evidence', () => {
  test('returns evidence JSON', async () => {
    getRiskScore.mockResolvedValueOnce(mockRiskScoreRow());
    const res = await request(app).get(`/api/risk/${MOCK_UUID}/evidence`).expect(200);
    expect(res.body.evidence).toHaveProperty('version', '1.0');
    expect(res.body.score).toBe(88);
  });
});

// ---------------------------------------------------------------------------
// GET /api/alerts
// ---------------------------------------------------------------------------
describe('GET /api/alerts', () => {
  test('returns alert list', async () => {
    getAlerts.mockResolvedValueOnce([mockAlertRow()]);
    const res = await request(app).get('/api/alerts').expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.count).toBe(1);
    expect(res.body.alerts[0].priority).toBe('critical');
  });

  test('accepts status filter', async () => {
    getAlerts.mockResolvedValueOnce([]);
    await request(app).get('/api/alerts?status=open').expect(200);
    expect(getAlerts).toHaveBeenCalledWith(expect.objectContaining({ status: 'open' }));
  });

  test('returns 400 for invalid status filter', async () => {
    await request(app).get('/api/alerts?status=resolved_idk').expect(400);
  });
});

// ---------------------------------------------------------------------------
// GET /api/alerts/:id
// ---------------------------------------------------------------------------
describe('GET /api/alerts/:id', () => {
  test('returns alert', async () => {
    getAlert.mockResolvedValueOnce(mockAlertRow());
    const res = await request(app).get(`/api/alerts/${MOCK_UUID}`).expect(200);
    expect(res.body.alert.priority).toBe('critical');
  });

  test('returns 404 when not found', async () => {
    getAlert.mockResolvedValueOnce(null);
    await request(app).get(`/api/alerts/${MOCK_UUID}`).expect(404);
  });
});

// ---------------------------------------------------------------------------
// PATCH /api/alerts/:id/status
// ---------------------------------------------------------------------------
describe('PATCH /api/alerts/:id/status', () => {
  test('accepts valid status update', async () => {
    getAlert.mockResolvedValueOnce(mockAlertRow());
    patchAlertStatus.mockResolvedValueOnce();
    const res = await request(app)
      .patch(`/api/alerts/${MOCK_UUID}/status`)
      .send({ status: 'acknowledged' })
      .expect(200);
    expect(res.body.status).toBe('acknowledged');
  });

  test('returns 400 for invalid status', async () => {
    const res = await request(app)
      .patch(`/api/alerts/${MOCK_UUID}/status`)
      .send({ status: 'resolved_idk' })
      .expect(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 400 when status is missing', async () => {
    const res = await request(app)
      .patch(`/api/alerts/${MOCK_UUID}/status`)
      .send({})
      .expect(400);
    expect(res.body.success).toBe(false);
  });

  test('returns 404 when alert not found', async () => {
    getAlert.mockResolvedValueOnce(null);
    const res = await request(app)
      .patch(`/api/alerts/${MOCK_UUID}/status`)
      .send({ status: 'closed' })
      .expect(404);
    expect(res.body.success).toBe(false);
  });
});

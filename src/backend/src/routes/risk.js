'use strict';

/**
 * CyberFusion — Risk Routes
 *
 * POST /api/risk/run                          — batch evaluate all pending correlations
 * POST /api/risk/correlation/:correlationId   — evaluate one correlation
 * GET  /api/risk                              — list risk scores
 * GET  /api/risk/:id                          — get risk score by UUID
 * GET  /api/risk/:id/evidence                 — get risk evidence JSON
 */

const { Router } = require('express');
const { param, query, validationResult } = require('express-validator');
const {
  evaluateCorrelation,
  runRiskAll,
  getRiskScores,
  getRiskScore,
} = require('../services/risk/riskService');

const router = Router();

function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// POST /api/risk/run
// ---------------------------------------------------------------------------
router.post('/run', async (req, res, next) => {
  try {
    const force   = req.body && req.body.force === true;
    const results = await runRiskAll({ force });
    const created = results.filter(r => r.isNew).length;
    const updated = results.filter(r => r.success && !r.isNew).length;
    const errors  = results.filter(r => !r.success).length;
    res.json({
      success: true,
      message: 'Risk evaluation run complete',
      summary: { created, updated, errors, total: results.length },
      results,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/risk/correlation/:correlationId
// ---------------------------------------------------------------------------
router.post(
  '/correlation/:correlationId',
  [param('correlationId').isUUID().withMessage('correlationId must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const force  = req.body && req.body.force === true;
      const result = await evaluateCorrelation(req.params.correlationId, { force });
      res.status(201).json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/risk
// ---------------------------------------------------------------------------
router.get(
  '/',
  [
    query('priority').optional().isIn(['low','medium','high','critical']),
    query('minScore').optional().isInt({ min: 0, max: 100 }),
    query('limit').optional().isInt({ min: 1, max: 200 }),
  ],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const { priority, minScore, limit } = req.query;
      const rows = await getRiskScores({
        priority,
        minScore: minScore ? parseInt(minScore, 10) : undefined,
        limit:    limit    ? parseInt(limit, 10)    : 50,
      });
      res.json({ success: true, count: rows.length, riskScores: rows });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/risk/:id
// ---------------------------------------------------------------------------
router.get(
  '/:id',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const rs = await getRiskScore(req.params.id);
      if (!rs) return res.status(404).json({ success: false, message: 'Risk score not found' });
      res.json({ success: true, riskScore: rs });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/risk/:id/evidence
// ---------------------------------------------------------------------------
router.get(
  '/:id/evidence',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const rs = await getRiskScore(req.params.id);
      if (!rs) return res.status(404).json({ success: false, message: 'Risk score not found' });
      res.json({
        success:  true,
        id:       rs.id,
        score:    rs.score,
        priority: rs.priority,
        evidence: rs.risk_evidence,
      });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

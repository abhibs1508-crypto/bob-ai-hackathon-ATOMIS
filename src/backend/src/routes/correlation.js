'use strict';

/**
 * CyberFusion — Correlation Routes
 *
 * POST /api/correlation/run                — batch: correlate all recent events
 * POST /api/correlation/event/:eventId     — correlate a specific event
 * GET  /api/correlations                   — list all correlations
 * GET  /api/correlations/:id               — get one correlation by UUID
 * GET  /api/correlations/:id/events        — get events in a correlation
 * GET  /api/correlations/:id/evidence      — get evidence (correlation_factors)
 */

const { Router }    = require('express');
const { param, query, validationResult } = require('express-validator');
const {
  correlateEvent,
  runCorrelationAll,
  getCorrelations,
  getCorrelation,
  getCorrelationEvents,
} = require('../services/correlation/correlationService');

const router = Router();

// ---------------------------------------------------------------------------
// Helper: validate and respond on failure
// ---------------------------------------------------------------------------
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
// POST /api/correlation/run  — batch run across all recent events
// ---------------------------------------------------------------------------
router.post('/run', async (_req, res, next) => {
  try {
    const results = await runCorrelationAll();
    const created  = results.filter(r => r.correlated && r.isNew).length;
    const updated  = results.filter(r => r.correlated && !r.isNew).length;
    const skipped  = results.filter(r => !r.correlated).length;
    const errors   = results.filter(r => !r.success).length;

    res.json({
      success: true,
      message: 'Correlation run complete',
      summary: { created, updated, skipped, errors, total: results.length },
      results,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /api/correlation/event/:eventId  — correlate a specific event
// ---------------------------------------------------------------------------
router.post(
  '/event/:eventId',
  [param('eventId').notEmpty().withMessage('eventId is required').isString().isLength({ max: 128 })],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const result = await correlateEvent(req.params.eventId);
      res.status(result.correlated ? 200 : 202).json({ success: true, ...result });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/correlations  — list correlations
// ---------------------------------------------------------------------------
router.get(
  '/',
  [
    query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('limit must be 1–200'),
    query('status').optional().isIn(['active', 'resolved', 'dismissed']),
  ],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const limit  = req.query.limit  ? parseInt(req.query.limit, 10)  : 50;
      const status = req.query.status || undefined;
      const rows   = await getCorrelations({ limit, status });
      res.json({ success: true, count: rows.length, correlations: rows });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/correlations/:id  — single correlation
// ---------------------------------------------------------------------------
router.get(
  '/:id',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const correlation = await getCorrelation(req.params.id);
      if (!correlation) {
        return res.status(404).json({ success: false, message: 'Correlation not found' });
      }
      res.json({ success: true, correlation });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/correlations/:id/events  — events in a correlation
// ---------------------------------------------------------------------------
router.get(
  '/:id/events',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const events = await getCorrelationEvents(req.params.id);
      res.json({ success: true, count: events.length, events });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/correlations/:id/evidence  — evidence / correlation_factors
// ---------------------------------------------------------------------------
router.get(
  '/:id/evidence',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const correlation = await getCorrelation(req.params.id);
      if (!correlation) {
        return res.status(404).json({ success: false, message: 'Correlation not found' });
      }
      res.json({
        success: true,
        correlationId: correlation.id,
        score:    correlation.correlation_score,
        strength: correlation.correlation_strength,
        evidence: correlation.correlation_factors,
      });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

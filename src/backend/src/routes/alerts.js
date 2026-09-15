'use strict';

/**
 * CyberFusion — Alert Routes
 *
 * GET   /api/alerts                — list alerts
 * GET   /api/alerts/:id            — get one alert
 * PATCH /api/alerts/:id/status     — update alert status
 */

const { Router } = require('express');
const { param, body, query, validationResult } = require('express-validator');
const { getAlerts, getAlert, patchAlertStatus } = require('../services/risk/riskService');

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
// GET /api/alerts
// ---------------------------------------------------------------------------
router.get(
  '/',
  [
    query('priority').optional().isIn(['low','medium','high','critical']),
    query('status').optional().isIn(['open','acknowledged','closed']),
    query('limit').optional().isInt({ min: 1, max: 200 }),
  ],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const { priority, status, limit } = req.query;
      const rows = await getAlerts({
        priority,
        status,
        limit: limit ? parseInt(limit, 10) : 50,
      });
      res.json({ success: true, count: rows.length, alerts: rows });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/alerts/:id
// ---------------------------------------------------------------------------
router.get(
  '/:id',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const alert = await getAlert(req.params.id);
      if (!alert) return res.status(404).json({ success: false, message: 'Alert not found' });
      res.json({ success: true, alert });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// PATCH /api/alerts/:id/status
// ---------------------------------------------------------------------------
router.patch(
  '/:id/status',
  [
    param('id').isUUID().withMessage('id must be a valid UUID'),
    body('status')
      .notEmpty().withMessage('status is required')
      .isIn(['open','acknowledged','closed']).withMessage('status must be open, acknowledged, or closed'),
  ],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const alert = await getAlert(req.params.id);
      if (!alert) return res.status(404).json({ success: false, message: 'Alert not found' });
      await patchAlertStatus(req.params.id, req.body.status);
      res.json({ success: true, id: req.params.id, status: req.body.status });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

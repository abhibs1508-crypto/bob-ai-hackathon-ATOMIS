'use strict';

/**
 * CyberFusion — Intelligence Routes  (Phase 6)
 *
 * POST /api/intelligence/generate/:correlationId  — run AI pipeline for one correlation
 * GET  /api/intelligence/correlation/:correlationId — retrieve report by correlation UUID
 * GET  /api/intelligence/:id                        — retrieve report by report UUID
 *
 * IMPORTANT: static sub-path /correlation/:correlationId MUST be registered
 * before the catch-all /:id route so Express does not capture "correlation"
 * as the :id parameter.
 *
 * The route layer contains NO business logic. All orchestration is handled
 * by intelligenceService.generateIntelligence() and the repository directly.
 */

const { Router } = require('express');
const { param, validationResult } = require('express-validator');
const { generateIntelligence, IntelligenceServiceError } = require('../services/ai/intelligenceService');
const intelligenceRepository = require('../db/intelligenceRepository');

const router = Router();

// ---------------------------------------------------------------------------
// Helper — express-validator check
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
// Helper — map IntelligenceServiceError statusCode to HTTP response
// ---------------------------------------------------------------------------
function handleServiceError(err, res, next) {
  if (err instanceof IntelligenceServiceError) {
    return res.status(err.statusCode || 500).json({ success: false, message: err.message });
  }
  return next(err);
}

// ---------------------------------------------------------------------------
// POST /api/intelligence/generate/:correlationId
// Triggers the full AI pipeline for the given correlation and persists the
// resulting intelligence report (upsert — safe to call multiple times).
// ---------------------------------------------------------------------------
router.post(
  '/generate/:correlationId',
  [param('correlationId').isUUID().withMessage('correlationId must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const report = await generateIntelligence(req.params.correlationId);
      res.status(201).json({
        success: true,
        message: 'Intelligence report generated',
        data: { report },
      });
    } catch (err) {
      return handleServiceError(err, res, next);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/intelligence/correlation/:correlationId
// Returns the most recent intelligence report for a correlation UUID.
// Must be registered BEFORE /:id to avoid route shadowing.
// ---------------------------------------------------------------------------
router.get(
  '/correlation/:correlationId',
  [param('correlationId').isUUID().withMessage('correlationId must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      const report = await intelligenceRepository.findByCorrelationId(req.params.correlationId);
      if (!report) {
        return res.status(404).json({
          success: false,
          message: 'No intelligence report found for this correlation',
        });
      }
      res.json({ success: true, data: { report } });
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /api/intelligence/:id
// Returns a report by its own UUID (the intelligence_reports.id column).
// Registered AFTER /correlation/:correlationId to avoid shadowing.
// ---------------------------------------------------------------------------
router.get(
  '/:id',
  [param('id').isUUID().withMessage('id must be a valid UUID')],
  async (req, res, next) => {
    if (!handleValidation(req, res)) return;
    try {
      // The repository only exposes findByCorrelationId; we look the row up by
      // its own id via a small inline query handled through the repository's
      // pool directly so no business logic leaks into the route.
      const pool = require('../db/pool').getPool();
      const [rows] = await pool.execute(
        `SELECT id, correlation_id, bluf, threat_assessment, possible_intent,
                reasoning, evidence_summary, recommended_actions,
                ai_provider, ai_model, confidence_score, generated_at
         FROM intelligence_reports WHERE id = ? LIMIT 1`,
        [req.params.id]
      );
      if (!rows.length) {
        return res.status(404).json({ success: false, message: 'Intelligence report not found' });
      }
      const row = rows[0];
      if (typeof row.recommended_actions === 'string') {
        try { row.recommended_actions = JSON.parse(row.recommended_actions); } catch { row.recommended_actions = []; }
      }
      res.json({ success: true, data: { report: row } });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

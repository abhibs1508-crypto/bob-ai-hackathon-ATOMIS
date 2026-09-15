'use strict';

/**
 * CyberFusion — Ingestion Routes
 *
 * Four POST endpoints, one per source type:
 *
 *   POST /api/ingestion/siem
 *   POST /api/ingestion/sensor
 *   POST /api/ingestion/threat-intel
 *   POST /api/ingestion/report
 *
 * Each route:
 *   1. Validates the request body with source-specific rules.
 *   2. Attaches the canonical source label to the payload.
 *   3. Delegates to ingestionService.ingestEvent().
 *   4. Returns a 201 IngestionResult on success.
 *
 * Route handlers contain no business logic — that lives in the service layer.
 */

const { Router } = require('express');
const {
  siemRules,
  sensorRules,
  threatIntelRules,
  intelligenceReportRules,
  handleValidationErrors,
} = require('../middleware/validators');
const { ingestEvent } = require('../services/ingestion/ingestionService');

const router = Router();

// ---------------------------------------------------------------------------
// POST /api/ingestion  — generic route (auto-routes by source field)
// ---------------------------------------------------------------------------
router.post(
  '/',
  async (req, res, next) => {
    try {
      const result = await ingestEvent(req.body);
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/ingestion/siem
// ---------------------------------------------------------------------------
router.post(
  '/siem',
  siemRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const result = await ingestEvent({ ...req.body, source: 'SIEM' });
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/ingestion/sensor
// ---------------------------------------------------------------------------
router.post(
  '/sensor',
  sensorRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const result = await ingestEvent({ ...req.body, source: 'SENSOR' });
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/ingestion/threat-intel
// ---------------------------------------------------------------------------
router.post(
  '/threat-intel',
  threatIntelRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const result = await ingestEvent({ ...req.body, source: 'THREAT_INTEL' });
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// POST /api/ingestion/report
// ---------------------------------------------------------------------------
router.post(
  '/report',
  intelligenceReportRules,
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const result = await ingestEvent({ ...req.body, source: 'INTELLIGENCE_REPORT' });
      res.status(201).json(result);
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

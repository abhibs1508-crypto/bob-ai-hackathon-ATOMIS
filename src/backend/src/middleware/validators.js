'use strict';

/**
 * CyberFusion — Ingestion Validators
 *
 * express-validator rule sets for each of the four source-type ingestion
 * endpoints. Each exported array is used directly in the route definition.
 *
 * Shared rules (timestamp, severity, confidence) are defined once and spread
 * into each source-specific rule set.
 */

const { body, validationResult } = require('express-validator');

// ---------------------------------------------------------------------------
// Shared rules applied to ALL ingestion endpoints
// ---------------------------------------------------------------------------

const sharedRules = [
  body('timestamp')
    .notEmpty().withMessage('timestamp is required')
    .isISO8601().withMessage('timestamp must be a valid ISO 8601 date-time string'),

  body('event_type')
    .notEmpty().withMessage('event_type is required')
    .isString().withMessage('event_type must be a string')
    .isLength({ max: 64 }).withMessage('event_type must be 64 characters or fewer'),

  body('severity')
    .notEmpty().withMessage('severity is required')
    .isIn(['low', 'medium', 'high', 'critical', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    .withMessage('severity must be one of: low, medium, high, critical'),

  body('confidence')
    .notEmpty().withMessage('confidence is required')
    .isInt({ min: 0, max: 100 }).withMessage('confidence must be an integer between 0 and 100'),
];

// ---------------------------------------------------------------------------
// Source-specific rules
// ---------------------------------------------------------------------------

/**
 * SIEM — source_ip and target are expected but not always present.
 */
const siemRules = [
  body('source_ip')
    .optional({ nullable: true, checkFalsy: false })
    .isIP().withMessage('source_ip must be a valid IP address'),

  body('target')
    .optional({ nullable: true })
    .isString().isLength({ max: 255 }),

  ...sharedRules,
];

/**
 * SENSOR — source_ip is strongly recommended.
 */
const sensorRules = [
  body('source_ip')
    .optional({ nullable: true, checkFalsy: false })
    .isIP().withMessage('source_ip must be a valid IP address'),

  body('target')
    .optional({ nullable: true })
    .isString().isLength({ max: 255 }),

  ...sharedRules,
];

/**
 * THREAT_INTEL — indicator_type and indicator_value are required.
 */
const threatIntelRules = [
  body('indicator_type')
    .notEmpty().withMessage('indicator_type is required for THREAT_INTEL events')
    .isIn(['ip', 'IP', 'domain', 'DOMAIN', 'hash', 'HASH', 'url', 'URL'])
    .withMessage('indicator_type must be one of: ip, domain, hash, url'),

  body('indicator_value')
    .notEmpty().withMessage('indicator_value is required for THREAT_INTEL events')
    .isString().isLength({ max: 512 }),

  body('source_ip')
    .optional({ nullable: true, checkFalsy: false })
    .isIP().withMessage('source_ip must be a valid IP address'),

  ...sharedRules,
];

/**
 * INTELLIGENCE_REPORT — free-form; raw_data carries title/summary.
 */
const intelligenceReportRules = [
  body('raw_data')
    .optional({ nullable: true })
    .isObject().withMessage('raw_data must be an object when provided'),

  ...sharedRules,
];

// ---------------------------------------------------------------------------
// Middleware: validate and respond on failure
// ---------------------------------------------------------------------------

/**
 * Express middleware that checks validation results and sends a 400 response
 * if any validation rule failed. Call this after the rule array in the route.
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
  }
  next();
}

module.exports = {
  siemRules,
  sensorRules,
  threatIntelRules,
  intelligenceReportRules,
  handleValidationErrors,
};

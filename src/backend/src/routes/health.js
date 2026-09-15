'use strict';

/**
 * CyberFusion — Health Route
 *
 * GET /api/health
 *
 * Returns the liveness status of the backend and reports whether the database
 * connection is available. No credentials are exposed.
 *
 * Response shape:
 * {
 *   "status": "ok" | "degraded",
 *   "database": "connected" | "unavailable",
 *   "ai_available": false,   ← Phase 4: will reflect actual provider status
 *   "timestamp": "ISO 8601"
 * }
 */

const { Router } = require('express');
const { getPool } = require('../db/pool');
const config = require('../config');

const router = Router();

/**
 * Returns whether an AI provider is configured — checks only that the
 * provider name and API key are set. Never exposes the key itself.
 */
function detectAIAvailable() {
  try {
    const provider = config.ai && config.ai.provider && String(config.ai.provider).toLowerCase();
    if (provider === 'groq') {
      return !!(config.ai.groq && config.ai.groq.apiKey);
    }
    return false;
  } catch {
    return false;
  }
}

router.get('/', async (_req, res) => {
  let dbStatus = 'unavailable';

  try {
    const conn = await getPool().getConnection();
    try {
      await conn.query('SELECT 1');
      dbStatus = 'connected';
    } finally {
      conn.release();
    }
  } catch {
    // Swallow — status already set to 'unavailable'
  }

  const aiAvailable = detectAIAvailable();
  const overall = dbStatus === 'connected' ? 'ok' : 'degraded';

  res.status(overall === 'ok' ? 200 : 503).json({
    status:        overall,
    database:      dbStatus,
    ai_available:  aiAvailable,
    ai_provider:   aiAvailable ? String(config.ai.provider).toLowerCase() : null,
    timestamp:     new Date().toISOString(),
  });
});

module.exports = router;

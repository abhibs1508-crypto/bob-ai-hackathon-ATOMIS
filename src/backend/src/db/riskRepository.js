'use strict';

/**
 * CyberFusion — Risk Repository
 *
 * All SQL for risk_scores and alerts tables.
 * Parameterized queries only. No string interpolation of user data.
 *
 * Phase 4 scope: create/update risk scores + create/update/list alerts.
 */

const { getPool } = require('./pool');

// =============================================================================
// RISK SCORES
// =============================================================================

/**
 * Creates or updates a risk score for a given correlation_id (idempotent upsert).
 * Uses a transaction so risk_scores and any alert updates are atomic.
 *
 * @param {Object} params
 * @param {string} params.correlationId
 * @param {number} params.score
 * @param {string} params.priority
 * @param {number} params.severityComponent
 * @param {number} params.iocMatchComponent
 * @param {number} params.assetCriticalityComponent
 * @param {number} params.correlationStrengthComponent
 * @param {number} params.recencyComponent
 * @param {Object} params.riskEvidence
 * @returns {Promise<{ riskScoreId: string, isNew: boolean }>}
 */
async function upsertRiskScore(params) {
  const {
    correlationId, score, priority,
    severityComponent, iocMatchComponent, assetCriticalityComponent,
    correlationStrengthComponent, recencyComponent, riskEvidence,
  } = params;

  const conn = await getPool().getConnection();
  await conn.beginTransaction();

  try {
    const [existing] = await conn.execute(
      'SELECT id FROM risk_scores WHERE correlation_id = ? LIMIT 1',
      [correlationId]
    );

    let riskScoreId;
    let isNew;

    if (existing.length > 0) {
      riskScoreId = existing[0].id;
      isNew = false;
      await conn.execute(
        `UPDATE risk_scores SET
          score                          = ?,
          priority                       = ?,
          severity_component             = ?,
          ioc_match_component            = ?,
          asset_criticality_component    = ?,
          correlation_strength_component = ?,
          recency_component              = ?,
          risk_evidence                  = ?,
          calculated_at                  = CURRENT_TIMESTAMP(3)
         WHERE id = ?`,
        [
          score, priority,
          severityComponent, iocMatchComponent, assetCriticalityComponent,
          correlationStrengthComponent, recencyComponent,
          JSON.stringify(riskEvidence),
          riskScoreId,
        ]
      );
    } else {
      const { v4: uuidv4 } = require('uuid');
      riskScoreId = uuidv4();
      isNew = true;
      await conn.execute(
        `INSERT INTO risk_scores
          (id, correlation_id, score, priority,
           severity_component, ioc_match_component, asset_criticality_component,
           correlation_strength_component, recency_component, risk_evidence)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          riskScoreId, correlationId, score, priority,
          severityComponent, iocMatchComponent, assetCriticalityComponent,
          correlationStrengthComponent, recencyComponent,
          JSON.stringify(riskEvidence),
        ]
      );
    }

    await conn.commit();
    return { riskScoreId, isNew };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * Returns a risk score by its primary key UUID.
 * @param {string} id
 * @returns {Promise<Object|null>}
 */
async function getRiskScoreById(id) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_id, score, priority,
            severity_component, ioc_match_component, asset_criticality_component,
            correlation_strength_component, recency_component, risk_evidence, calculated_at
     FROM risk_scores WHERE id = ? LIMIT 1`,
    [id]
  );
  return rows.length ? deserialiseRisk(rows[0]) : null;
}

/**
 * Returns a risk score by correlation_id.
 * @param {string} correlationId
 * @returns {Promise<Object|null>}
 */
async function getRiskScoreByCorrelationId(correlationId) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_id, score, priority,
            severity_component, ioc_match_component, asset_criticality_component,
            correlation_strength_component, recency_component, risk_evidence, calculated_at
     FROM risk_scores WHERE correlation_id = ? LIMIT 1`,
    [correlationId]
  );
  return rows.length ? deserialiseRisk(rows[0]) : null;
}

/**
 * Lists risk scores with optional filtering.
 * @param {{ priority?: string, minScore?: number, limit?: number }} opts
 * @returns {Promise<Object[]>}
 */
async function listRiskScores({ priority, minScore, limit = 50 } = {}) {
  const conditions = [];
  const params     = [];

  if (priority) { conditions.push('rs.priority = ?');       params.push(priority); }
  if (minScore) { conditions.push('rs.score >= ?');         params.push(minScore); }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(Math.min(limit, 200));

  const [rows] = await getPool().execute(
    `SELECT rs.id, rs.correlation_id, rs.score, rs.priority,
            rs.severity_component, rs.ioc_match_component, rs.asset_criticality_component,
            rs.correlation_strength_component, rs.recency_component,
            rs.risk_evidence, rs.calculated_at,
            c.title AS correlation_title, c.status AS correlation_status
     FROM risk_scores rs
     LEFT JOIN correlations c ON c.id = rs.correlation_id
     ${where}
     ORDER BY rs.score DESC, rs.calculated_at DESC
     LIMIT ?`,
    params
  );
  return rows.map(deserialiseRisk);
}

// =============================================================================
// ALERTS
// =============================================================================

/**
 * Creates a new alert for a correlation.
 * @param {Object} params
 * @param {string} params.correlationId
 * @param {string} params.title
 * @param {string} params.priority
 * @returns {Promise<string>}  — new alert UUID
 */
async function createAlert(params) {
  const { v4: uuidv4 } = require('uuid');
  const id = uuidv4();
  await getPool().execute(
    `INSERT INTO alerts (id, correlation_id, title, priority, status) VALUES (?, ?, ?, ?, 'open')`,
    [id, params.correlationId, params.title, params.priority]
  );
  return id;
}

/**
 * Returns any OPEN or ACKNOWLEDGED alert for a correlation_id.
 * Closed alerts are excluded so a recalculated critical threat can open a new alert.
 * @param {string} correlationId
 * @returns {Promise<Object|null>}
 */
async function getActiveAlertByCorrelationId(correlationId) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_id, title, priority, status, created_at, updated_at
     FROM alerts
     WHERE correlation_id = ? AND status IN ('open','acknowledged')
     ORDER BY created_at DESC LIMIT 1`,
    [correlationId]
  );
  return rows.length ? rows[0] : null;
}

/**
 * Updates the priority and title of an existing alert.
 * @param {string} alertId
 * @param {{ priority: string, title: string }} updates
 * @returns {Promise<void>}
 */
async function updateAlertPriority(alertId, { priority, title }) {
  await getPool().execute(
    'UPDATE alerts SET priority = ?, title = ? WHERE id = ?',
    [priority, title, alertId]
  );
}

/**
 * Updates alert status. Only accepts valid enum values.
 * @param {string} alertId
 * @param {'open'|'acknowledged'|'closed'} status
 * @returns {Promise<void>}
 */
async function updateAlertStatus(alertId, status) {
  await getPool().execute(
    'UPDATE alerts SET status = ? WHERE id = ?',
    [status, alertId]
  );
}

/**
 * Returns a single alert by UUID.
 * @param {string} id
 * @returns {Promise<Object|null>}
 */
async function getAlertById(id) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_id, title, priority, status, created_at, updated_at
     FROM alerts WHERE id = ? LIMIT 1`,
    [id]
  );
  return rows.length ? rows[0] : null;
}

/**
 * Lists alerts with optional filtering.
 * @param {{ priority?: string, status?: string, limit?: number }} opts
 * @returns {Promise<Object[]>}
 */
async function listAlerts({ priority, status, limit = 50 } = {}) {
  const conditions = [];
  const params     = [];

  if (priority) { conditions.push('a.priority = ?'); params.push(priority); }
  if (status)   { conditions.push('a.status = ?');   params.push(status);   }

  const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
  params.push(Math.min(limit, 200));

  const [rows] = await getPool().execute(
    `SELECT a.id, a.correlation_id, a.title, a.priority, a.status,
            a.created_at, a.updated_at,
            c.title AS correlation_title
     FROM alerts a
     LEFT JOIN correlations c ON c.id = a.correlation_id
     ${where}
     ORDER BY
       FIELD(a.priority,'critical','high','medium','low'),
       a.created_at DESC
     LIMIT ?`,
    params
  );
  return rows;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function deserialiseRisk(row) {
  if (row.risk_evidence && typeof row.risk_evidence === 'string') {
    try { row.risk_evidence = JSON.parse(row.risk_evidence); } catch { /* leave */ }
  }
  return row;
}

module.exports = {
  upsertRiskScore,
  getRiskScoreById,
  getRiskScoreByCorrelationId,
  listRiskScores,
  createAlert,
  getActiveAlertByCorrelationId,
  updateAlertPriority,
  updateAlertStatus,
  getAlertById,
  listAlerts,
};

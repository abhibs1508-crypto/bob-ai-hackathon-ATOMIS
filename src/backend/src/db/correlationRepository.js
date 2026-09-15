'use strict';

/**
 * CyberFusion — Correlation Database Repository
 *
 * All SQL for correlations and correlation_events lives here.
 * Uses parameterized queries exclusively.
 *
 * Phase 3 scope: create, update, fetch correlations + manage event membership.
 */

const { getPool } = require('./pool');

// ---------------------------------------------------------------------------
// WRITE — correlations
// ---------------------------------------------------------------------------

/**
 * Inserts a new correlation or updates an existing one (identified by
 * correlation_key) if the event cluster has grown or scores have changed.
 *
 * Uses a transaction to keep correlations + correlation_events consistent.
 *
 * @param {Object} params
 * @param {string} params.correlationKey
 * @param {string} params.title
 * @param {string} params.description
 * @param {number} params.eventCount
 * @param {Object} params.correlationFactors   — the full evidence JSON
 * @param {number} params.correlationScore
 * @param {string} params.correlationStrength
 * @param {string} params.status
 * @param {string|null} params.firstSeen
 * @param {string|null} params.lastSeen
 * @param {string[]|null} params.sourceIps
 * @param {string[]|null} params.targets
 * @param {string[]|null} params.sourceTypes
 * @param {string[]|null} params.attackStages
 * @param {string[]} params.threatEventIds   — `id` (UUID pk) values from threat_events
 * @returns {Promise<{ correlationId: string, isNew: boolean }>}
 */
async function upsertCorrelation(params) {
  const {
    correlationKey, title, description, eventCount,
    correlationFactors, correlationScore, correlationStrength, status,
    firstSeen, lastSeen, sourceIps, targets, sourceTypes, attackStages,
    threatEventIds,
  } = params;

  const conn = await getPool().getConnection();
  await conn.beginTransaction();

  try {
    // 1. Attempt to find existing correlation by its deterministic key
    const [existing] = await conn.execute(
      'SELECT id FROM correlations WHERE correlation_key = ? LIMIT 1',
      [correlationKey]
    );

    let correlationId;
    let isNew;

    if (existing.length > 0) {
      // UPDATE existing
      correlationId = existing[0].id;
      isNew = false;

      await conn.execute(
        `UPDATE correlations
         SET title                 = ?,
             description           = ?,
             event_count           = ?,
             correlation_factors   = ?,
             correlation_score     = ?,
             correlation_strength  = ?,
             status                = ?,
             first_seen            = ?,
             last_seen             = ?,
             source_ips            = ?,
             targets               = ?,
             source_types          = ?,
             attack_stages         = ?
         WHERE id = ?`,
        [
          title, description, eventCount,
          JSON.stringify(correlationFactors),
          correlationScore, correlationStrength, status,
          firstSeen, lastSeen,
          JSON.stringify(sourceIps || []),
          JSON.stringify(targets || []),
          JSON.stringify(sourceTypes || []),
          JSON.stringify(attackStages || []),
          correlationId,
        ]
      );
    } else {
      // INSERT new
      isNew = true;
      const { v4: uuidv4 } = require('uuid');
      correlationId = uuidv4();

      await conn.execute(
        `INSERT INTO correlations
           (id, correlation_key, title, description, event_count,
            correlation_factors, correlation_score, correlation_strength, status,
            first_seen, last_seen, source_ips, targets, source_types, attack_stages)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          correlationId, correlationKey, title, description, eventCount,
          JSON.stringify(correlationFactors),
          correlationScore, correlationStrength, status,
          firstSeen, lastSeen,
          JSON.stringify(sourceIps || []),
          JSON.stringify(targets || []),
          JSON.stringify(sourceTypes || []),
          JSON.stringify(attackStages || []),
        ]
      );
    }

    // 2. Upsert correlation_events (ignore duplicates)
    for (const evtId of threatEventIds) {
      await conn.execute(
        `INSERT IGNORE INTO correlation_events (correlation_id, event_id)
         VALUES (?, ?)`,
        [correlationId, evtId]
      );
    }

    await conn.commit();
    return { correlationId, isNew };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// ---------------------------------------------------------------------------
// READ — correlations
// ---------------------------------------------------------------------------

/**
 * Returns all correlations, newest first, with optional limit.
 * @param {{ limit?: number, status?: string }} opts
 * @returns {Promise<Object[]>}
 */
async function listCorrelations({ limit = 50, status } = {}) {
  const params = [];
  let where = '';

  if (status) {
    where = 'WHERE status = ?';
    params.push(status);
  }

  params.push(Math.min(limit, 200));  // cap at 200

  const [rows] = await getPool().execute(
    `SELECT id, correlation_key, title, description, event_count,
            correlation_factors, correlation_score, correlation_strength,
            status, first_seen, last_seen, source_ips, targets, source_types,
            attack_stages, created_at, updated_at
     FROM correlations
     ${where}
     ORDER BY updated_at DESC
     LIMIT ?`,
    params
  );
  return rows.map(deserialise);
}

/**
 * Returns a single correlation by its UUID.
 * @param {string} id
 * @returns {Promise<Object|null>}
 */
async function getCorrelationById(id) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_key, title, description, event_count,
            correlation_factors, correlation_score, correlation_strength,
            status, first_seen, last_seen, source_ips, targets, source_types,
            attack_stages, created_at, updated_at
     FROM correlations
     WHERE id = ?`,
    [id]
  );
  if (!rows.length) return null;
  return deserialise(rows[0]);
}

/**
 * Returns the threat_events linked to a correlation.
 * @param {string} correlationId
 * @returns {Promise<Object[]>}
 */
async function getEventsByCorrelationId(correlationId) {
  const [rows] = await getPool().execute(
    `SELECT te.id, te.event_id, te.source, te.timestamp, te.event_type,
            te.source_ip, te.target, te.indicator_type, te.indicator_value,
            te.severity, te.confidence, te.location, te.raw_data, te.ingested_at
     FROM threat_events te
     JOIN correlation_events ce ON ce.event_id = te.id
     WHERE ce.correlation_id = ?
     ORDER BY te.timestamp ASC`,
    [correlationId]
  );
  return rows;
}

/**
 * Returns a correlation by its deterministic key (used for duplicate check).
 * @param {string} correlationKey
 * @returns {Promise<Object|null>}
 */
async function getCorrelationByKey(correlationKey) {
  const [rows] = await getPool().execute(
    'SELECT id, correlation_key, correlation_score, status FROM correlations WHERE correlation_key = ? LIMIT 1',
    [correlationKey]
  );
  return rows.length ? rows[0] : null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parses JSON fields that MySQL2 may return as strings (depends on driver config).
 * @param {Object} row
 * @returns {Object}
 */
function deserialise(row) {
  const jsonCols = ['correlation_factors', 'source_ips', 'targets', 'source_types', 'attack_stages'];
  for (const col of jsonCols) {
    if (row[col] && typeof row[col] === 'string') {
      try { row[col] = JSON.parse(row[col]); } catch { /* leave as-is */ }
    }
  }
  return row;
}

module.exports = {
  upsertCorrelation,
  listCorrelations,
  getCorrelationById,
  getEventsByCorrelationId,
  getCorrelationByKey,
};

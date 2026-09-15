'use strict';

/**
 * CyberFusion — Threat Events Database Repository
 *
 * All SQL for the threat_events table lives here.
 * Uses parameterized queries exclusively — no string concatenation of user data.
 *
 * Phase 2 scope: insert + existence check.
 * Correlation / risk queries will be added in Phase 3.
 */

const { getPool } = require('./pool');

/**
 * Persists a NormalizedThreatEvent to threat_events.
 * Wraps the insert in a connection acquired from the pool; the connection is
 * released back to the pool regardless of success or failure.
 *
 * @param {import('../../services/normalization/normalizer').NormalizedThreatEvent} event
 * @returns {Promise<{ insertId: string, event_id: string }>}
 * @throws if the database is unreachable or a unique constraint is violated
 */
async function insertThreatEvent(event) {
  const sql = `
    INSERT INTO threat_events
      (event_id, source, timestamp, event_type, source_ip, target,
       indicator_type, indicator_value, severity, confidence, location, raw_data)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const params = [
    event.event_id,
    event.source,
    event.timestamp,
    event.event_type,
    event.source_ip   || null,
    event.target      || null,
    event.indicator_type  ? event.indicator_type.toLowerCase()  : null,
    event.indicator_value || null,
    event.severity,
    event.confidence,
    event.location    || null,
    event.raw_data ? JSON.stringify(event.raw_data) : null,
  ];

  const conn = await getPool().getConnection();
  try {
    const [result] = await conn.execute(sql, params);
    return { insertId: result.insertId, event_id: event.event_id };
  } finally {
    conn.release();
  }
}

/**
 * Returns true if a threat event with the given event_id already exists.
 * Used to detect duplicate submissions without letting the INSERT fail.
 *
 * @param {string} eventId
 * @returns {Promise<boolean>}
 */
async function threatEventExists(eventId) {
  const [rows] = await getPool().execute(
    'SELECT 1 FROM threat_events WHERE event_id = ? LIMIT 1',
    [eventId]
  );
  return rows.length > 0;
}

module.exports = { insertThreatEvent, threatEventExists };

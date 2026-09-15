'use strict';

/**
 * CyberFusion — Indicators Database Repository (Phase 2)
 *
 * Provides upsert support for the indicators table so that demo seed IOCs
 * (DEMO_INDICATORS) can be loaded before ingestion without duplicates.
 */

const { getPool } = require('./pool');

/**
 * Inserts an indicator or updates confidence/last_seen if the
 * (indicator_type, indicator_value) pair already exists (idempotent upsert).
 *
 * @param {{ indicator_type: string, indicator_value: string, threat_type: string, confidence: number, source: string }} indicator
 * @returns {Promise<void>}
 */
async function upsertIndicator(indicator) {
  const sql = `
    INSERT INTO indicators (indicator_type, indicator_value, threat_type, confidence, source, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, NOW(), NOW())
    ON DUPLICATE KEY UPDATE
      threat_type = VALUES(threat_type),
      confidence  = VALUES(confidence),
      source      = VALUES(source),
      last_seen   = NOW()
  `;
  await getPool().execute(sql, [
    indicator.indicator_type.toLowerCase(),
    indicator.indicator_value,
    indicator.threat_type || null,
    indicator.confidence  || 50,
    indicator.source      || null,
  ]);
}

/** Returns indicator metadata for a bounded set of observed values. */
async function findByValues(values) {
  const uniqueValues = [...new Set((values || []).filter(Boolean))];
  if (!uniqueValues.length) return [];
  const placeholders = uniqueValues.map(() => '?').join(', ');
  const [rows] = await getPool().execute(
    `SELECT indicator_type, indicator_value, threat_type, confidence
     FROM indicators WHERE indicator_value IN (${placeholders})`,
    uniqueValues
  );
  return rows;
}

module.exports = { upsertIndicator, findByValues };

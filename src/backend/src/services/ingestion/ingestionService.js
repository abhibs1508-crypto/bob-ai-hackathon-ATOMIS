'use strict';

/**
 * CyberFusion — Ingestion Service
 *
 * Orchestrates the ingestion pipeline for a single validated threat event:
 *
 *   validated payload
 *       ↓
 *   normalise()           — source-specific field mapping
 *       ↓
 *   insertThreatEvent()   — persist to threat_events table
 *       ↓
 *   IngestionResult       — returned to route handler
 *
 * Phase 2 scope only: no correlation, no risk scoring, no AI calls.
 * Those will be added in Phases 3 and 4.
 */

const { normalise }         = require('../normalization/normalizer');
const { insertThreatEvent, threatEventExists } = require('../../db/threatEventsRepository');

/**
 * @typedef {Object} IngestionResult
 * @property {boolean} success
 * @property {string}  event_id
 * @property {string}  source
 * @property {boolean} normalized
 * @property {boolean} stored
 * @property {string}  [message]
 */

/**
 * Ingests a single validated threat-event payload.
 *
 * @param {Object} payload  — validated inbound request body
 * @returns {Promise<IngestionResult>}
 * @throws {DuplicateEventError} if the event_id already exists in the database
 */
async function ingestEvent(payload) {
  // 1. Normalise
  const normalized = normalise(payload);

  // 2. Duplicate check — return a descriptive error rather than letting MySQL
  //    throw a cryptic unique-constraint violation to the client
  if (payload.event_id) {
    const exists = await threatEventExists(normalized.event_id);
    if (exists) {
      const err = new Error(`Event "${normalized.event_id}" has already been ingested.`);
      err.code = 'DUPLICATE_EVENT';
      err.statusCode = 409;
      throw err;
    }
  }

  // 3. Persist
  await insertThreatEvent(normalized);

  return {
    success:    true,
    event_id:   normalized.event_id,
    source:     normalized.source,
    normalized: true,
    stored:     true,
    message:    'Threat event ingested successfully',
  };
}

module.exports = { ingestEvent };

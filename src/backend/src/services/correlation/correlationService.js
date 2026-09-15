'use strict';

/**
 * CyberFusion — Correlation Service
 *
 * Orchestrates the complete correlation pipeline for a single trigger event:
 *
 *   1. Load the trigger event from threat_events
 *   2. Find candidate events (bounded window query)
 *   3. Load matched indicators from indicators table
 *   4. Load target entities from entities table
 *   5. Build CorrelationContext
 *   6. Run the rule engine (deterministic, no AI)
 *   7. Persist/update correlation + correlation_events
 *   8. Return structured CorrelationResult
 *
 * Also exposes runCorrelationAll() for batch runs across recent events.
 */

const { getPool }            = require('../../db/pool');
const { runEngine }          = require('./correlationEngine');
const { upsertCorrelation, listCorrelations, getCorrelationById,
        getEventsByCorrelationId } = require('../../db/correlationRepository');
const { WINDOWS, CANDIDATE_LIMIT } = require('./correlationConfig');

// ---------------------------------------------------------------------------
// Main: correlate a single trigger event
// ---------------------------------------------------------------------------

/**
 * Runs the correlation pipeline triggered by a specific event_id.
 *
 * @param {string} triggerEventId  — the event_id column value (not the PK uuid)
 * @returns {Promise<Object>}
 */
async function correlateEvent(triggerEventId) {
  console.log(`[correlation] Starting correlation for event: ${triggerEventId}`);

  // 1. Load trigger event
  const triggerEvent = await loadEventByEventId(triggerEventId);
  if (!triggerEvent) {
    const err = new Error(`Event "${triggerEventId}" not found in threat_events.`);
    err.statusCode = 404;
    throw err;
  }

  // 2. Find candidates
  const candidates = await findCandidateEvents(triggerEvent);
  console.log(`[correlation] Found ${candidates.length} candidate events`);

  if (candidates.length === 0) {
    return { success: true, correlated: false, reason: 'No candidate events found', event_id: triggerEventId };
  }

  // 3. Load matched indicators
  const matchedIndicators = await loadMatchedIndicators(candidates);
  console.log(`[correlation] Matched ${matchedIndicators.length} indicators`);

  // 4. Load target entities
  const targetEntities = await loadTargetEntities(candidates);
  console.log(`[correlation] Matched ${targetEntities.length} entities`);

  // 5. Build context
  const ctx = { events: candidates, matchedIndicators, targetEntities };

  // 6. Run rule engine
  const result = runEngine(ctx);

  if (!result.shouldPersist) {
    console.log(`[correlation] No correlation to persist: ${result.reason}`);
    return { success: true, correlated: false, reason: result.reason, event_id: triggerEventId };
  }

  console.log(`[correlation] Score: ${result.score} (${result.strength}), factors: ${result.factors.join(', ')}`);

  // 7. Persist
  const threatEventUuids = candidates.map(e => e.id);  // uuid PK column

  const { correlationId, isNew } = await upsertCorrelation({
    correlationKey:      result.correlationKey,
    title:               result.title,
    description:         result.description,
    eventCount:          candidates.length,
    correlationFactors:  result.correlationFactors,
    correlationScore:    result.score,
    correlationStrength: result.strength,
    status:              result.status,
    firstSeen:           result.firstSeen,
    lastSeen:            result.lastSeen,
    sourceIps:           result.sourceIps,
    targets:             result.targets,
    sourceTypes:         result.sourceTypes,
    attackStages:        result.attackStages,
    threatEventIds:      threatEventUuids,
  });

  console.log(`[correlation] ${isNew ? 'Created' : 'Updated'} correlation ${correlationId}`);

  return {
    success:       true,
    correlated:    true,
    isNew,
    correlationId,
    score:         result.score,
    strength:      result.strength,
    factors:       result.factors,
    eventCount:    candidates.length,
    attackStages:  result.attackStages,
    sourceIps:     result.sourceIps,
    targets:       result.targets,
    sourceTypes:   result.sourceTypes,
    firstSeen:     result.firstSeen,
    lastSeen:      result.lastSeen,
  };
}

// ---------------------------------------------------------------------------
// Batch: run correlation across all recent events
// ---------------------------------------------------------------------------

/**
 * Runs correlateEvent() for all events ingested within the CAMPAIGN window.
 * Returns an array of results. Errors per event are caught and logged but
 * do not abort the batch.
 *
 * @returns {Promise<Object[]>}
 */
async function runCorrelationAll() {
  console.log('[correlation] Starting batch correlation run');

  const windowMs = WINDOWS.CAMPAIGN * 60 * 1000;
  const since = new Date(Date.now() - windowMs).toISOString().slice(0, 19).replace('T', ' ');

  const [events] = await getPool().execute(
    'SELECT event_id FROM threat_events WHERE timestamp >= ? ORDER BY timestamp ASC LIMIT ?',
    [since, CANDIDATE_LIMIT]
  );

  console.log(`[correlation] Batch: ${events.length} events in window`);

  const results = [];
  const seen = new Set();  // deduplicate correlation keys

  for (const { event_id } of events) {
    try {
      const result = await correlateEvent(event_id);
      if (result.correlated && !seen.has(result.correlationId)) {
        seen.add(result.correlationId);
        results.push(result);
      }
    } catch (err) {
      console.error(`[correlation] Batch error for ${event_id}:`, err.message);
      results.push({ success: false, event_id, error: err.message });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Query helpers (used by routes)
// ---------------------------------------------------------------------------

const getCorrelations = (opts) => listCorrelations(opts);
const getCorrelation  = (id)   => getCorrelationById(id);
const getCorrelationEvents = (id) => getEventsByCorrelationId(id);

// ---------------------------------------------------------------------------
// DB query helpers (internal)
// ---------------------------------------------------------------------------

async function loadEventByEventId(eventId) {
  const [rows] = await getPool().execute(
    `SELECT id, event_id, source, timestamp, event_type, source_ip, target,
            indicator_type, indicator_value, severity, confidence, location, raw_data
     FROM threat_events WHERE event_id = ? LIMIT 1`,
    [eventId]
  );
  return rows[0] || null;
}

/**
 * Finds candidate events related to the trigger event using indexed fields.
 * Bounded by CANDIDATE_LIMIT to avoid O(N²) scans.
 */
async function findCandidateEvents(triggerEvent) {
  const windowMs = WINDOWS.CAMPAIGN * 60 * 1000;
  const since = new Date(new Date(triggerEvent.timestamp).getTime() - windowMs)
    .toISOString().slice(0, 23).replace('T', ' ');
  const until = new Date(new Date(triggerEvent.timestamp).getTime() + windowMs)
    .toISOString().slice(0, 23).replace('T', ' ');

  // Build OR conditions for candidate matching:
  // same source_ip OR same target OR same indicator_value
  const conditions = ['te.timestamp BETWEEN ? AND ?'];
  const params     = [since, until];

  const hasIp  = !!triggerEvent.source_ip;
  const hasTgt = !!triggerEvent.target;
  const hasIoc = !!triggerEvent.indicator_value;

  if (hasIp)  { conditions.push('te.source_ip = ?');        params.push(triggerEvent.source_ip); }
  if (hasTgt) { conditions.push('te.target = ?');            params.push(triggerEvent.target); }
  if (hasIoc) { conditions.push('te.indicator_value = ?');   params.push(triggerEvent.indicator_value); }

  // Combine: time window AND (at least one shared field)
  let sql;
  if (hasIp || hasTgt || hasIoc) {
    const fieldConditions = conditions.slice(1).join(' OR ');
    sql = `SELECT id, event_id, source, timestamp, event_type, source_ip, target,
                  indicator_type, indicator_value, severity, confidence, location, raw_data
           FROM threat_events te
           WHERE (${conditions[0]}) AND (${fieldConditions})
           ORDER BY te.timestamp ASC
           LIMIT ?`;
  } else {
    // Trigger event has no useful grouping fields — return just itself
    sql = `SELECT id, event_id, source, timestamp, event_type, source_ip, target,
                  indicator_type, indicator_value, severity, confidence, location, raw_data
           FROM threat_events te
           WHERE te.event_id = ?
           LIMIT 1`;
    return (await getPool().execute(sql, [triggerEvent.event_id]))[0];
  }

  params.push(CANDIDATE_LIMIT);
  const [rows] = await getPool().execute(sql, params);
  return rows;
}

/**
 * Loads indicators matching any indicator_value in the candidate set.
 */
async function loadMatchedIndicators(events) {
  const values = [...new Set(events.map(e => e.indicator_value).filter(Boolean))];
  if (values.length === 0) return [];

  const placeholders = values.map(() => '?').join(', ');
  const [rows] = await getPool().execute(
    `SELECT indicator_type, indicator_value, threat_type, confidence, source
     FROM indicators WHERE indicator_value IN (${placeholders})`,
    values
  );
  return rows;
}

/**
 * Loads entity records matching any target in the candidate set.
 */
async function loadTargetEntities(events) {
  const targetList = [...new Set(events.map(e => e.target).filter(Boolean))];
  if (targetList.length === 0) return [];

  const placeholders = targetList.map(() => '?').join(', ');
  const [rows] = await getPool().execute(
    `SELECT name, entity_type, criticality, description
     FROM entities WHERE name IN (${placeholders})`,
    targetList
  );
  return rows;
}

module.exports = {
  correlateEvent,
  runCorrelationAll,
  getCorrelations,
  getCorrelation,
  getCorrelationEvents,
};

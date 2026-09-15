'use strict';

/**
 * CyberFusion — Correlation Service (Supabase)
 */

const { getPool }            = require('../../db/pool');
const { runEngine }          = require('./correlationEngine');
const { upsertCorrelation, listCorrelations, getCorrelationById,
        getEventsByCorrelationId } = require('../../db/correlationRepository');
const { WINDOWS, CANDIDATE_LIMIT } = require('./correlationConfig');

async function correlateEvent(triggerEventId) {
  console.log(`[correlation] Starting correlation for event: ${triggerEventId}`);

  const triggerEvent = await loadEventByEventId(triggerEventId);
  if (!triggerEvent) {
    const err = new Error(`Event "${triggerEventId}" not found in threat_events.`);
    err.statusCode = 404;
    throw err;
  }

  const candidates = await findCandidateEvents(triggerEvent);
  console.log(`[correlation] Found ${candidates.length} candidate events`);

  if (candidates.length === 0) {
    return { success: true, correlated: false, reason: 'No candidate events found', event_id: triggerEventId };
  }

  const matchedIndicators = await loadMatchedIndicators(candidates);
  console.log(`[correlation] Matched ${matchedIndicators.length} indicators`);

  const targetEntities = await loadTargetEntities(candidates);
  console.log(`[correlation] Matched ${targetEntities.length} entities`);

  const ctx = { events: candidates, matchedIndicators, targetEntities };
  const result = runEngine(ctx);

  if (!result.shouldPersist) {
    console.log(`[correlation] No correlation to persist: ${result.reason}`);
    return { success: true, correlated: false, reason: result.reason, event_id: triggerEventId };
  }

  console.log(`[correlation] Score: ${result.score} (${result.strength}), factors: ${result.factors.join(', ')}`);

  const threatEventUuids = candidates.map(e => e.id);

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

async function runCorrelationAll() {
  console.log('[correlation] Starting batch correlation run');

  const windowMs = WINDOWS.CAMPAIGN * 60 * 1000;
  const since = new Date(Date.now() - windowMs).toISOString();

  const { data: events, error } = await getPool().from('threat_events')
    .select('event_id').gte('timestamp', since)
    .order('timestamp', { ascending: true }).limit(CANDIDATE_LIMIT);
  
  if (error) throw error;

  console.log(`[correlation] Batch: ${events.length} events in window`);

  const results = [];
  const seen = new Set();

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

const getCorrelations = (opts) => listCorrelations(opts);
const getCorrelation  = (id)   => getCorrelationById(id);
const getCorrelationEvents = (id) => getEventsByCorrelationId(id);

async function loadEventByEventId(eventId) {
  const { data, error } = await getPool().from('threat_events').select('*').eq('event_id', eventId).single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function findCandidateEvents(triggerEvent) {
  const windowMs = WINDOWS.CAMPAIGN * 60 * 1000;
  const since = new Date(new Date(triggerEvent.timestamp).getTime() - windowMs).toISOString();
  const until = new Date(new Date(triggerEvent.timestamp).getTime() + windowMs).toISOString();

  let query = getPool().from('threat_events').select('*')
    .gte('timestamp', since).lte('timestamp', until);

  const orConditions = [];
  if (triggerEvent.source_ip) orConditions.push(`source_ip.eq.${triggerEvent.source_ip}`);
  if (triggerEvent.target) orConditions.push(`target.eq.${triggerEvent.target}`);
  if (triggerEvent.indicator_value) orConditions.push(`indicator_value.eq.${triggerEvent.indicator_value}`);

  if (orConditions.length > 0) {
    query = query.or(orConditions.join(','));
  } else {
    query = getPool().from('threat_events').select('*').eq('event_id', triggerEvent.event_id).limit(1);
  }

  const { data, error } = await query.order('timestamp', { ascending: true }).limit(CANDIDATE_LIMIT);
  if (error) throw error;
  return data || [];
}

async function loadMatchedIndicators(events) {
  const values = [...new Set(events.map(e => e.indicator_value).filter(Boolean))];
  if (values.length === 0) return [];
  const { data, error } = await getPool().from('indicators').select('*').in('indicator_value', values);
  if (error) throw error;
  return data || [];
}

async function loadTargetEntities(events) {
  const targetList = [...new Set(events.map(e => e.target).filter(Boolean))];
  if (targetList.length === 0) return [];
  const { data, error } = await getPool().from('entities').select('*').in('name', targetList);
  if (error) throw error;
  return data || [];
}

module.exports = {
  correlateEvent,
  runCorrelationAll,
  getCorrelations,
  getCorrelation,
  getCorrelationEvents,
};

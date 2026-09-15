'use strict';

/**
 * CyberFusion — Correlation Database Repository (Supabase)
 */

const { getPool } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function upsertCorrelation(params) {
  const {
    correlationKey, title, description, eventCount,
    correlationFactors, correlationScore, correlationStrength, status,
    firstSeen, lastSeen, sourceIps, targets, sourceTypes, attackStages,
    threatEventIds,
  } = params;

  let correlationId;
  let isNew;

  // 1. Attempt to find existing correlation
  const { data: existing } = await getPool().from('correlations').select('id').eq('correlation_key', correlationKey).limit(1);
  
  if (existing && existing.length > 0) {
    correlationId = existing[0].id;
    isNew = false;

    const { error } = await getPool().from('correlations').update({
      title, description, event_count: eventCount,
      correlation_factors: correlationFactors,
      correlation_score: correlationScore, correlation_strength: correlationStrength, status,
      first_seen: firstSeen, last_seen: lastSeen,
      source_ips: sourceIps || [], targets: targets || [],
      source_types: sourceTypes || [], attack_stages: attackStages || [],
      updated_at: new Date().toISOString()
    }).eq('id', correlationId);
    if (error) throw error;
  } else {
    isNew = true;
    correlationId = uuidv4();

    const { error } = await getPool().from('correlations').insert({
      id: correlationId, correlation_key: correlationKey, title, description,
      event_count: eventCount, correlation_factors: correlationFactors,
      correlation_score: correlationScore, correlation_strength: correlationStrength, status,
      first_seen: firstSeen, last_seen: lastSeen,
      source_ips: sourceIps || [], targets: targets || [],
      source_types: sourceTypes || [], attack_stages: attackStages || []
    });
    if (error) throw error;
  }

  // 2. Upsert correlation_events
  const correlationEvents = threatEventIds.map(evtId => ({ correlation_id: correlationId, event_id: evtId }));
  if (correlationEvents.length > 0) {
    await getPool().from('correlation_events').upsert(correlationEvents, { onConflict: 'correlation_id,event_id' });
  }

  return { correlationId, isNew };
}

async function listCorrelations({ limit = 50, status } = {}) {
  let query = getPool().from('correlations').select('*').order('updated_at', { ascending: false }).limit(Math.min(limit, 200));
  if (status) query = query.eq('status', status);
  
  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

async function getCorrelationById(id) {
  const { data, error } = await getPool().from('correlations').select('*').eq('id', id).single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function getEventsByCorrelationId(correlationId) {
  const { data, error } = await getPool().from('threat_events')
    .select('*, correlation_events!inner(correlation_id)')
    .eq('correlation_events.correlation_id', correlationId)
    .order('timestamp', { ascending: true });
  if (error) throw error;
  return data || [];
}

async function getCorrelationByKey(correlationKey) {
  const { data, error } = await getPool().from('correlations')
    .select('id, correlation_key, correlation_score, status')
    .eq('correlation_key', correlationKey).limit(1);
  if (error) throw error;
  return data.length ? data[0] : null;
}

module.exports = {
  upsertCorrelation, listCorrelations, getCorrelationById,
  getEventsByCorrelationId, getCorrelationByKey,
};

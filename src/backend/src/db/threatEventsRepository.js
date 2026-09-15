'use strict';

/**
 * CyberFusion — Threat Events Database Repository (Supabase)
 */

const { getPool } = require('./pool');

async function insertThreatEvent(event) {
  const payload = {
    event_id: event.event_id,
    source: event.source,
    timestamp: event.timestamp,
    event_type: event.event_type,
    source_ip: event.source_ip || null,
    target: event.target || null,
    indicator_type: event.indicator_type ? event.indicator_type.toLowerCase() : null,
    indicator_value: event.indicator_value || null,
    severity: event.severity,
    confidence: event.confidence,
    location: event.location || null,
    raw_data: event.raw_data || null,
  };

  const { data, error } = await getPool().from('threat_events').insert(payload).select('id').single();
  if (error) throw error;
  
  return { insertId: data.id, event_id: event.event_id };
}

async function threatEventExists(eventId) {
  const { data, error } = await getPool().from('threat_events').select('id').eq('event_id', eventId).limit(1);
  if (error) throw error;
  return data.length > 0;
}

module.exports = { insertThreatEvent, threatEventExists };

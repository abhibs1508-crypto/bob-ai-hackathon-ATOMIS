'use strict';

/**
 * CyberFusion — Indicators Database Repository (Supabase)
 */

const { getPool } = require('./pool');

async function upsertIndicator(indicator) {
  const payload = {
    indicator_type: indicator.indicator_type.toLowerCase(),
    indicator_value: indicator.indicator_value,
    threat_type: indicator.threat_type || null,
    confidence: indicator.confidence || 50,
    source: indicator.source || null,
    last_seen: new Date().toISOString()
  };

  const { error } = await getPool().from('indicators').upsert(payload, {
    onConflict: 'indicator_type,indicator_value'
  });
  if (error) throw error;
}

async function findByValues(values) {
  const uniqueValues = [...new Set((values || []).filter(Boolean))];
  if (!uniqueValues.length) return [];
  const { data, error } = await getPool().from('indicators')
    .select('indicator_type, indicator_value, threat_type, confidence')
    .in('indicator_value', uniqueValues);
  if (error) throw error;
  return data || [];
}

module.exports = { upsertIndicator, findByValues };

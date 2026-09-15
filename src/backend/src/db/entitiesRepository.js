'use strict';

/**
 * CyberFusion — Entities Database Repository (Supabase)
 */

const { getPool } = require('./pool');

async function upsertEntity(entity) {
  const { error } = await getPool().from('entities').upsert({
    name: entity.name,
    entity_type: entity.entity_type || 'server',
    criticality: entity.criticality,
    description: entity.description || null
  }, { onConflict: 'name' });
  if (error) throw error;
}

async function findByNames(names) {
  const uniqueNames = [...new Set((names || []).filter(Boolean))];
  if (!uniqueNames.length) return [];
  const { data, error } = await getPool().from('entities')
    .select('name, entity_type, criticality')
    .in('name', uniqueNames);
  if (error) throw error;
  return data || [];
}

module.exports = { upsertEntity, findByNames };

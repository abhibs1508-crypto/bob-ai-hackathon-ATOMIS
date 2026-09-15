'use strict';

/**
 * CyberFusion — Entities Database Repository (Phase 2)
 *
 * Provides upsert support for the entities table so that demo seed data
 * (DEMO_ENTITIES) can be loaded before ingestion without duplicates.
 */

const { getPool } = require('./pool');

/**
 * Inserts an entity or updates criticality/description if the name already
 * exists (idempotent upsert).
 *
 * @param {{ name: string, entity_type: string, criticality: number, description: string }} entity
 * @returns {Promise<void>}
 */
async function upsertEntity(entity) {
  const sql = `
    INSERT INTO entities (name, entity_type, criticality, description)
    VALUES (?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      entity_type = VALUES(entity_type),
      criticality = VALUES(criticality),
      description = VALUES(description)
  `;
  await getPool().execute(sql, [
    entity.name,
    entity.entity_type || 'server',
    entity.criticality,
    entity.description || null,
  ]);
}

/** Returns entity metadata for a bounded set of target names. */
async function findByNames(names) {
  const uniqueNames = [...new Set((names || []).filter(Boolean))];
  if (!uniqueNames.length) return [];
  const placeholders = uniqueNames.map(() => '?').join(', ');
  const [rows] = await getPool().execute(
    `SELECT name, entity_type, criticality FROM entities WHERE name IN (${placeholders})`,
    uniqueNames
  );
  return rows;
}

module.exports = { upsertEntity, findByNames };

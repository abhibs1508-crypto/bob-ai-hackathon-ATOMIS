'use strict';

/**
 * CyberFusion — Alert Service
 *
 * Creates and updates alerts based on risk evaluation results.
 * Idempotent: will update an existing open/acknowledged alert rather than
 * creating a duplicate. A closed alert is left closed — analyst decisions
 * are preserved.
 */

const {
  createAlert,
  getActiveAlertByCorrelationId,
  updateAlertPriority,
} = require('../../db/riskRepository');

/**
 * Generates a concise alert title from correlation and risk data.
 * @param {Object} correlation
 * @param {string} priority
 * @returns {string}
 */
function buildAlertTitle(correlation, priority) {
  const targets  = parseJsonArray(correlation.targets);
  const sourceIps = parseJsonArray(correlation.source_ips);
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

  if (targets.length && sourceIps.length) {
    return `${cap(priority)} ${priority === 'critical' || priority === 'high' ? 'coordinated' : ''} threat targeting ${targets[0]}`.trim();
  }
  if (targets.length) {
    return `${cap(priority)} threat targeting ${targets[0]}`;
  }
  return correlation.title || `${cap(priority)} threat detected`;
}

function parseJsonArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { return []; }
  }
  return [];
}

/**
 * Ensures exactly one active alert exists for a correlation after risk evaluation.
 *
 * Logic:
 *   - If no active alert exists → create one.
 *   - If an active alert exists → update priority and title to reflect latest risk.
 *   - If the only existing alert is CLOSED → create a new OPEN alert.
 *     (A re-calculated critical threat justifies a new alert even if the old one was closed.)
 *
 * @param {Object} correlation
 * @param {string} priority
 * @returns {Promise<{ alertId: string, isNew: boolean }>}
 */
async function ensureAlert(correlation, priority) {
  const title = buildAlertTitle(correlation, priority);

  const existing = await getActiveAlertByCorrelationId(correlation.id);

  if (existing) {
    // Update existing alert with latest priority and title
    await updateAlertPriority(existing.id, { priority, title });
    return { alertId: existing.id, isNew: false };
  }

  // Create new alert
  const alertId = await createAlert({ correlationId: correlation.id, title, priority });
  return { alertId, isNew: true };
}

module.exports = { ensureAlert, buildAlertTitle };

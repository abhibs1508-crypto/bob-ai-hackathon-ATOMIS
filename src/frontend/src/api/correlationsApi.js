/**
 * CyberFusion — Correlations API
 *
 * GET  /api/correlations                   — list correlations
 * GET  /api/correlations/:id               — single correlation
 * GET  /api/correlations/:id/events        — events in a correlation
 * GET  /api/correlations/:id/evidence      — evidence / correlation_factors
 *
 * List response: { success, count, correlations: [...] }
 * Single response: { success, correlation: {...} }
 */
import client from './client.js';

/**
 * Fetch paginated list of correlations.
 * @param {{ limit?: number, status?: string }} params
 */
export async function getCorrelations(params = {}) {
  const { data } = await client.get('/correlations', { params });
  return data; // { success, count, correlations }
}

/**
 * Fetch a single correlation by UUID.
 * @param {string} id
 */
export async function getCorrelation(id) {
  const { data } = await client.get(`/correlations/${id}`);
  return data; // { success, correlation }
}

/**
 * Fetch events belonging to a correlation.
 * @param {string} id
 */
export async function getCorrelationEvents(id) {
  const { data } = await client.get(`/correlations/${id}/events`);
  return data; // { success, count, events }
}

/**
 * Fetch evidence / factors for a correlation.
 * @param {string} id
 */
export async function getCorrelationEvidence(id) {
  const { data } = await client.get(`/correlations/${id}/evidence`);
  return data; // { success, correlationId, score, strength, evidence }
}

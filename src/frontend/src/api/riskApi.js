/**
 * CyberFusion — Risk API
 *
 * GET  /api/risk                              — list risk scores
 * GET  /api/risk/:id                          — single risk score
 * GET  /api/risk/:id/evidence                 — risk evidence breakdown
 *
 * List response:   { success, count, riskScores: [...] }
 * Single response: { success, riskScore: {...} }
 * Evidence:        { success, id, score, priority, evidence: {...} }
 */
import client from './client.js';

/**
 * Fetch list of risk scores.
 * @param {{ priority?: string, minScore?: number, limit?: number }} params
 */
export async function getRiskScores(params = {}) {
  const { data } = await client.get('/risk', { params });
  return data; // { success, count, riskScores }
}

/**
 * Fetch a single risk score by UUID.
 * @param {string} id
 */
export async function getRiskScore(id) {
  const { data } = await client.get(`/risk/${id}`);
  return data; // { success, riskScore }
}

/**
 * Fetch detailed risk evidence for a risk score record.
 * @param {string} id
 */
export async function getRiskEvidence(id) {
  const { data } = await client.get(`/risk/${id}/evidence`);
  return data; // { success, id, score, priority, evidence }
}

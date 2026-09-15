/**
 * CyberFusion — Intelligence API
 *
 * POST /api/intelligence/generate/:correlationId  — trigger AI pipeline
 * GET  /api/intelligence/correlation/:correlationId — fetch report by correlation
 * GET  /api/intelligence/:id                       — fetch report by report UUID
 *
 * Report shape:
 * {
 *   id, correlation_id, bluf, threat_assessment, possible_intent,
 *   reasoning, evidence_summary, recommended_actions,
 *   ai_provider, ai_model, confidence_score, generated_at
 * }
 */
import client from './client.js';

/**
 * Trigger AI intelligence generation for a correlation.
 * Returns 201 with the generated report even when AI uses fallback provider.
 * @param {string} correlationId
 */
export async function generateIntelligence(correlationId) {
  const { data } = await client.post(`/intelligence/generate/${correlationId}`);
  return data; // { success, message, data: { report } }
}

/**
 * Fetch the most recent intelligence report for a correlation (read-only).
 * @param {string} correlationId
 */
export async function getIntelligenceByCorrelation(correlationId) {
  const { data } = await client.get(`/intelligence/correlation/${correlationId}`);
  return data; // { success, data: { report } }
}

/**
 * Fetch an intelligence report by its own UUID.
 * @param {string} id
 */
export async function getIntelligenceReport(id) {
  const { data } = await client.get(`/intelligence/${id}`);
  return data; // { success, data: { report } }
}

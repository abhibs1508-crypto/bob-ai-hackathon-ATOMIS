/**
 * CyberFusion — Intelligence API (updated)
 */
import client from './client.js';

/** Trigger AI analysis for a correlation. */
export async function triggerAnalysis(correlationId) {
  const { data } = await client.post(`/intelligence/generate/${correlationId}`);
  return data?.data || data;
}

/** Fetch the most recent intelligence report for a correlation. */
export async function getIntelligenceReport(correlationId) {
  try {
    const { data } = await client.get(`/intelligence/correlation/${correlationId}`);
    return data?.data || data;
  } catch {
    return null;
  }
}

/** Fetch an intelligence report by its own UUID. */
export async function getIntelligenceById(id) {
  const { data } = await client.get(`/intelligence/${id}`);
  return data?.data || data;
}

// Legacy alias
export { triggerAnalysis as generateIntelligence, getIntelligenceReport as getIntelligenceByCorrelation };

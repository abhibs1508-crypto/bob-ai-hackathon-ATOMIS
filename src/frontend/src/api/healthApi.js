/**
 * CyberFusion — Health API
 *
 * GET /api/health
 *
 * Response shape:
 * {
 *   status:       "ok" | "degraded",
 *   database:     "connected" | "unavailable",
 *   ai_available: boolean,
 *   ai_provider:  string | null,
 *   timestamp:    string (ISO 8601)
 * }
 */
import client from './client.js';

export async function getHealth() {
  const { data } = await client.get('/health');
  return data;
}

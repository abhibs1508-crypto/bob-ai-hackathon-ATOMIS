/**
 * CyberFusion — Alerts API
 *
 * GET   /api/alerts                — list alerts
 * GET   /api/alerts/:id            — single alert
 * PATCH /api/alerts/:id/status     — update alert status
 *
 * List response: { success, count, alerts: [...] }
 * Single response: { success, alert: {...} }
 */
import client from './client.js';

/**
 * Fetch list of alerts.
 * @param {{ priority?: string, status?: string, limit?: number }} params
 */
export async function getAlerts(params = {}) {
  const { data } = await client.get('/alerts', { params });
  return data; // { success, count, alerts }
}

/**
 * Fetch a single alert by UUID.
 * @param {string} id
 */
export async function getAlert(id) {
  const { data } = await client.get(`/alerts/${id}`);
  return data; // { success, alert }
}

/**
 * Update the status of an alert.
 * @param {string} id
 * @param {'open' | 'acknowledged' | 'closed'} status
 */
export async function patchAlertStatus(id, status) {
  const { data } = await client.patch(`/alerts/${id}/status`, { status });
  return data; // { success, id, status }
}

'use strict';

const { v4: uuidv4 } = require('uuid');
const { getPool } = require('./pool');

function deserialise(row) {
  if (!row) return null;
  const result = { ...row };
  if (typeof result.recommended_actions === 'string') {
    try { result.recommended_actions = JSON.parse(result.recommended_actions); } catch { result.recommended_actions = []; }
  }
  if (!Array.isArray(result.recommended_actions)) result.recommended_actions = [];
  return result;
}

async function findByCorrelationId(correlationId) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_id, bluf, threat_assessment, possible_intent, reasoning,
            evidence_summary, recommended_actions, ai_provider, ai_model,
            confidence_score, generated_at
     FROM intelligence_reports WHERE correlation_id = ? LIMIT 1`,
    [correlationId]
  );
  return rows.length ? deserialise(rows[0]) : null;
}

/** Returns the number of persisted reports for a correlation for local verification. */
async function countByCorrelationId(correlationId) {
  const [rows] = await getPool().execute(
    'SELECT COUNT(*) AS count FROM intelligence_reports WHERE correlation_id = ?',
    [correlationId]
  );
  return Number(rows[0].count);
}

async function create(report) {
  const id = uuidv4();
  await getPool().execute(
    `INSERT INTO intelligence_reports
       (id, correlation_id, bluf, threat_assessment, possible_intent, reasoning,
        evidence_summary, recommended_actions, ai_provider, ai_model, confidence_score)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id, report.correlationId, report.bluf, report.threatAssessment,
      report.possibleIntent, report.reasoning, report.evidenceSummary,
      JSON.stringify(report.recommendedActions), report.aiProvider, report.aiModel || null,
      report.confidenceScore,
    ]
  );
  return findByCorrelationId(report.correlationId);
}

async function update(report) {
  await getPool().execute(
    `UPDATE intelligence_reports SET bluf = ?, threat_assessment = ?, possible_intent = ?,
       reasoning = ?, evidence_summary = ?, recommended_actions = ?, ai_provider = ?,
       ai_model = ?, confidence_score = ?, generated_at = CURRENT_TIMESTAMP(3)
     WHERE correlation_id = ?`,
    [
      report.bluf, report.threatAssessment, report.possibleIntent, report.reasoning,
      report.evidenceSummary, JSON.stringify(report.recommendedActions), report.aiProvider,
      report.aiModel || null, report.confidenceScore, report.correlationId,
    ]
  );
  return findByCorrelationId(report.correlationId);
}

async function upsert(report) {
  const id = uuidv4();
  await getPool().execute(
    `INSERT INTO intelligence_reports
       (id, correlation_id, bluf, threat_assessment, possible_intent, reasoning,
        evidence_summary, recommended_actions, ai_provider, ai_model, confidence_score)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE bluf = VALUES(bluf),
       threat_assessment = VALUES(threat_assessment), possible_intent = VALUES(possible_intent),
       reasoning = VALUES(reasoning), evidence_summary = VALUES(evidence_summary),
       recommended_actions = VALUES(recommended_actions), ai_provider = VALUES(ai_provider),
       ai_model = VALUES(ai_model), confidence_score = VALUES(confidence_score),
       generated_at = CURRENT_TIMESTAMP(3)`,
    [
      id, report.correlationId, report.bluf, report.threatAssessment,
      report.possibleIntent, report.reasoning, report.evidenceSummary,
      JSON.stringify(report.recommendedActions), report.aiProvider, report.aiModel || null,
      report.confidenceScore,
    ]
  );
  return findByCorrelationId(report.correlationId);
}

module.exports = { findByCorrelationId, countByCorrelationId, create, update, upsert };

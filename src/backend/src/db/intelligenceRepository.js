'use strict';

/**
 * CyberFusion — Intelligence Database Repository (Supabase)
 */

const { getPool } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function findByCorrelationId(correlationId) {
  const { data, error } = await getPool().from('intelligence_reports')
    .select('*')
    .eq('correlation_id', correlationId)
    .single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function countByCorrelationId(correlationId) {
  const { count, error } = await getPool().from('intelligence_reports')
    .select('*', { count: 'exact', head: true })
    .eq('correlation_id', correlationId);
  if (error) throw error;
  return count || 0;
}

async function upsert(report) {
  const payload = {
    correlation_id: report.correlationId,
    bluf: report.bluf,
    threat_assessment: report.threatAssessment,
    possible_intent: report.possibleIntent,
    reasoning: report.reasoning,
    evidence_summary: report.evidenceSummary,
    recommended_actions: report.recommendedActions,
    ai_provider: report.aiProvider,
    ai_model: report.aiModel || null,
    confidence_score: report.confidenceScore,
    categorization: report.categorization,
    is_false_positive: report.isFalsePositive || false,
    generated_at: new Date().toISOString()
  };

  const { data: existing } = await getPool().from('intelligence_reports').select('id').eq('correlation_id', report.correlationId).single();
  
  if (existing) {
    const { error } = await getPool().from('intelligence_reports').update(payload).eq('id', existing.id);
    if (error) throw error;
  } else {
    payload.id = uuidv4();
    const { error } = await getPool().from('intelligence_reports').insert(payload);
    if (error) throw error;
  }

  return findByCorrelationId(report.correlationId);
}

module.exports = { findByCorrelationId, countByCorrelationId, create: upsert, update: upsert, upsert };

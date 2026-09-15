'use strict';

/**
 * CyberFusion — Risk Repository (Supabase)
 */

const { getPool } = require('./pool');
const { v4: uuidv4 } = require('uuid');

async function upsertRiskScore(params) {
  const {
    correlationId, score, priority,
    severityComponent, iocMatchComponent, assetCriticalityComponent,
    correlationStrengthComponent, recencyComponent, riskEvidence,
  } = params;

  let riskScoreId;
  let isNew;

  const { data: existing } = await getPool().from('risk_scores').select('id').eq('correlation_id', correlationId).limit(1);
  
  if (existing && existing.length > 0) {
    riskScoreId = existing[0].id;
    isNew = false;
    const { error } = await getPool().from('risk_scores').update({
      score, priority,
      severity_component: severityComponent, ioc_match_component: iocMatchComponent,
      asset_criticality_component: assetCriticalityComponent,
      correlation_strength_component: correlationStrengthComponent,
      recency_component: recencyComponent,
      calculated_at: new Date().toISOString()
    }).eq('id', riskScoreId);
    if (error) throw error;
  } else {
    isNew = true;
    riskScoreId = uuidv4();
    const { error } = await getPool().from('risk_scores').insert({
      id: riskScoreId, correlation_id: correlationId, score, priority,
      severity_component: severityComponent, ioc_match_component: iocMatchComponent,
      asset_criticality_component: assetCriticalityComponent,
      correlation_strength_component: correlationStrengthComponent,
      recency_component: recencyComponent
    });
    if (error) throw error;
  }

  return { riskScoreId, isNew };
}

async function getRiskScoreById(id) {
  const { data, error } = await getPool().from('risk_scores').select('*').eq('id', id).single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function getRiskScoreByCorrelationId(correlationId) {
  const { data, error } = await getPool().from('risk_scores').select('*').eq('correlation_id', correlationId).single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function listRiskScores({ priority, minScore, limit = 50 } = {}) {
  let query = getPool().from('risk_scores').select('*, correlations!inner(title, status)').order('score', { ascending: false }).order('calculated_at', { ascending: false }).limit(Math.min(limit, 200));
  if (priority) query = query.eq('priority', priority);
  if (minScore) query = query.gte('score', minScore);
  
  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

async function createAlert(params) {
  const id = uuidv4();
  const { error } = await getPool().from('alerts').insert({
    id, correlation_id: params.correlationId, title: params.title, priority: params.priority, status: 'open'
  });
  if (error) throw error;
  return id;
}

async function getActiveAlertByCorrelationId(correlationId) {
  const { data, error } = await getPool().from('alerts')
    .select('*').eq('correlation_id', correlationId).in('status', ['open','acknowledged'])
    .order('created_at', { ascending: false }).limit(1);
  if (error) throw error;
  return data.length ? data[0] : null;
}

async function updateAlertPriority(alertId, { priority, title }) {
  const { error } = await getPool().from('alerts').update({ priority, title, updated_at: new Date().toISOString() }).eq('id', alertId);
  if (error) throw error;
}

async function updateAlertStatus(alertId, status) {
  const { error } = await getPool().from('alerts').update({ status, updated_at: new Date().toISOString() }).eq('id', alertId);
  if (error) throw error;
}

async function getAlertById(id) {
  const { data, error } = await getPool().from('alerts').select('*').eq('id', id).single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function listAlerts({ priority, status, limit = 50 } = {}) {
  let query = getPool().from('alerts').select('*, correlations!inner(title)').order('created_at', { ascending: false }).limit(Math.min(limit, 200));
  if (priority) query = query.eq('priority', priority);
  if (status) query = query.eq('status', status);
  
  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

module.exports = {
  upsertRiskScore, getRiskScoreById, getRiskScoreByCorrelationId, listRiskScores,
  createAlert, getActiveAlertByCorrelationId, updateAlertPriority, updateAlertStatus,
  getAlertById, listAlerts,
};

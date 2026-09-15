'use strict';

/**
 * CyberFusion — Risk Service (Supabase)
 */

const { getPool }                  = require('../../db/pool');
const { runRiskEngine }            = require('./riskEngine');
const { upsertRiskScore,
        listRiskScores,
        getRiskScoreById,
        getRiskScoreByCorrelationId,
        listAlerts,
        getAlertById,
        updateAlertStatus }        = require('../../db/riskRepository');
const { ensureAlert }              = require('./alertService');

async function evaluateCorrelation(correlationId, { force = false } = {}) {
  console.log(`[risk] Evaluating correlation: ${correlationId}`);

  const correlation = await loadCorrelation(correlationId);
  if (!correlation) {
    const err = new Error(`Correlation "${correlationId}" not found.`);
    err.statusCode = 404;
    throw err;
  }

  const existing = await getRiskScoreByCorrelationId(correlationId);
  if (existing && !force) {
    console.log(`[risk] Returning cached risk score for ${correlationId}`);
    const alert = await getAlertByCorrelationId(correlationId);
    return buildResult(existing, alert, false);
  }

  const events            = await loadEventsByCorrelationId(correlationId);
  const matchedIndicators = await loadMatchedIndicators(events);
  const targetEntities    = await loadTargetEntities(events, correlation);

  const ctx = { correlation, events, matchedIndicators, targetEntities };
  const engineResult = runRiskEngine(ctx);
  console.log(`[risk] Score: ${engineResult.score} (${engineResult.priority})`);

  const { riskScoreId, isNew: isNewScore } = await upsertRiskScore({
    correlationId,
    score:                        engineResult.score,
    priority:                     engineResult.priority,
    severityComponent:            engineResult.severityComponent,
    iocMatchComponent:            engineResult.iocMatchComponent,
    assetCriticalityComponent:    engineResult.assetCriticalityComponent,
    correlationStrengthComponent: engineResult.correlationStrengthComponent,
    recencyComponent:             engineResult.recencyComponent,
    riskEvidence:                 engineResult.riskEvidence,
  });

  const { alertId, isNew: isNewAlert } = await ensureAlert(correlation, engineResult.priority);

  const riskScore = await getRiskScoreById(riskScoreId);
  const alert     = await getAlertById(alertId);

  console.log(`[risk] ${isNewScore ? 'Created' : 'Updated'} risk score ${riskScoreId}; ${isNewAlert ? 'Created' : 'Updated'} alert ${alertId}`);

  return buildResult(riskScore, alert, isNewScore);
}

async function runRiskAll({ force = false } = {}) {
  console.log('[risk] Starting batch risk evaluation');

  let query = getPool().from('correlations').select('id, risk_scores(id)').eq('status', 'active').order('updated_at', { ascending: false }).limit(200);
  
  const { data, error } = await query;
  if (error) throw error;

  let rows = data || [];
  if (!force) {
    rows = rows.filter(r => !r.risk_scores || r.risk_scores.length === 0);
  }

  console.log(`[risk] Batch: ${rows.length} correlations to evaluate`);

  const results = [];
  for (const { id } of rows) {
    try {
      const r = await evaluateCorrelation(id, { force });
      results.push({ success: true, correlationId: id, ...r });
    } catch (err) {
      console.error(`[risk] Batch error for ${id}:`, err.message);
      results.push({ success: false, correlationId: id, error: err.message });
    }
  }

  return results;
}

const getRiskScores     = (opts) => listRiskScores(opts);
const getRiskScore      = (id)   => getRiskScoreById(id);
const getAlerts         = (opts) => listAlerts(opts);
const getAlert          = (id)   => getAlertById(id);
const patchAlertStatus  = (id, status) => updateAlertStatus(id, status);

async function loadCorrelation(id) {
  const { data, error } = await getPool().from('correlations').select('*').eq('id', id).single();
  if (error && error.code !== 'PGRST116') throw error;
  return data || null;
}

async function loadEventsByCorrelationId(correlationId) {
  const { data, error } = await getPool().from('threat_events')
    .select('*, correlation_events!inner(correlation_id)')
    .eq('correlation_events.correlation_id', correlationId)
    .order('timestamp', { ascending: true });
  if (error) throw error;
  return data || [];
}

async function loadMatchedIndicators(events) {
  const values = [...new Set(events.map(e => e.indicator_value).filter(Boolean))];
  if (values.length === 0) return [];
  const { data, error } = await getPool().from('indicators').select('*').in('indicator_value', values);
  if (error) throw error;
  return data || [];
}

async function loadTargetEntities(events, correlation) {
  const fromEvents = events.map(e => e.target).filter(Boolean);
  const fromCorr   = Array.isArray(correlation.targets) ? correlation.targets : [];
  const targetList = [...new Set([...fromEvents, ...fromCorr])];
  if (targetList.length === 0) return [];
  const { data, error } = await getPool().from('entities').select('*').in('name', targetList);
  if (error) throw error;
  return data || [];
}

async function getAlertByCorrelationId(correlationId) {
  const { getActiveAlertByCorrelationId } = require('../../db/riskRepository');
  return getActiveAlertByCorrelationId(correlationId);
}

function buildResult(riskScore, alert, isNew) {
  return {
    isNew,
    risk: {
      id:            riskScore.id,
      correlationId: riskScore.correlation_id,
      score:         riskScore.score,
      priority:      riskScore.priority,
      severityComponent:            riskScore.severity_component,
      iocMatchComponent:            riskScore.ioc_match_component,
      assetCriticalityComponent:    riskScore.asset_criticality_component,
      correlationStrengthComponent: riskScore.correlation_strength_component,
      recencyComponent:             riskScore.recency_component,
      calculatedAt:  riskScore.calculated_at,
    },
    alert: alert ? {
      id:       alert.id,
      priority: alert.priority,
      status:   alert.status,
      title:    alert.title,
    } : null,
    evidence: riskScore.risk_evidence || null,
  };
}

module.exports = {
  evaluateCorrelation,
  runRiskAll,
  getRiskScores,
  getRiskScore,
  getAlerts,
  getAlert,
  patchAlertStatus,
};

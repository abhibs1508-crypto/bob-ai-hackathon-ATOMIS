'use strict';

/**
 * CyberFusion — Risk Service
 *
 * Orchestrates the full Phase 4 pipeline for a single correlation:
 *
 *   1. Load correlation row (with Phase 3 columns)
 *   2. Load correlated threat events
 *   3. Load matched indicators
 *   4. Load target entities
 *   5. Build RiskContext
 *   6. Run pure risk engine
 *   7. Persist/update risk score
 *   8. Create/update alert
 *   9. Return structured result
 *
 * Also exposes runRiskAll() for batch evaluation.
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

// ---------------------------------------------------------------------------
// Main: evaluate a single correlation
// ---------------------------------------------------------------------------

/**
 * Evaluates risk for one correlation and persists the result.
 *
 * @param {string} correlationId  — UUID of the correlations row
 * @param {{ force?: boolean }} opts  — force=true recalculates even if score exists
 * @returns {Promise<Object>}
 */
async function evaluateCorrelation(correlationId, { force = false } = {}) {
  console.log(`[risk] Evaluating correlation: ${correlationId}`);

  // 1. Load correlation
  const correlation = await loadCorrelation(correlationId);
  if (!correlation) {
    const err = new Error(`Correlation "${correlationId}" not found.`);
    err.statusCode = 404;
    throw err;
  }

  // 2. Check for existing risk score (idempotency)
  const existing = await getRiskScoreByCorrelationId(correlationId);
  if (existing && !force) {
    console.log(`[risk] Returning cached risk score for ${correlationId}`);
    const alert = await getAlertByCorrelationId(correlationId);
    return buildResult(existing, alert, false);
  }

  // 3. Load events, indicators, entities
  const events            = await loadEventsByCorrelationId(correlationId);
  const matchedIndicators = await loadMatchedIndicators(events);
  const targetEntities    = await loadTargetEntities(events, correlation);

  // 4. Build context and run engine
  const ctx = { correlation, events, matchedIndicators, targetEntities };
  const engineResult = runRiskEngine(ctx);
  console.log(`[risk] Score: ${engineResult.score} (${engineResult.priority})`);

  // 5. Persist risk score
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

  // 6. Create/update alert
  const { alertId, isNew: isNewAlert } = await ensureAlert(correlation, engineResult.priority);

  // 7. Load full records for response
  const riskScore = await getRiskScoreById(riskScoreId);
  const alert     = await getAlertById(alertId);

  console.log(`[risk] ${isNewScore ? 'Created' : 'Updated'} risk score ${riskScoreId}; ${isNewAlert ? 'Created' : 'Updated'} alert ${alertId}`);

  return buildResult(riskScore, alert, isNewScore);
}

// ---------------------------------------------------------------------------
// Batch: evaluate all correlations without a risk score
// ---------------------------------------------------------------------------

/**
 * Evaluates risk for all correlations that currently have no risk score.
 * Returns an array of results.
 * @param {{ force?: boolean }} opts
 * @returns {Promise<Object[]>}
 */
async function runRiskAll({ force = false } = {}) {
  console.log('[risk] Starting batch risk evaluation');

  let sql, rows;
  if (force) {
    [rows] = await getPool().execute(
      'SELECT id FROM correlations WHERE status = ? ORDER BY updated_at DESC LIMIT 200',
      ['active']
    );
  } else {
    // Only correlations that do not yet have a risk score
    [rows] = await getPool().execute(
      `SELECT c.id FROM correlations c
       LEFT JOIN risk_scores rs ON rs.correlation_id = c.id
       WHERE rs.id IS NULL AND c.status = ?
       ORDER BY c.updated_at DESC LIMIT 200`,
      ['active']
    );
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

// ---------------------------------------------------------------------------
// Query delegates
// ---------------------------------------------------------------------------

const getRiskScores     = (opts) => listRiskScores(opts);
const getRiskScore      = (id)   => getRiskScoreById(id);
const getAlerts         = (opts) => listAlerts(opts);
const getAlert          = (id)   => getAlertById(id);
const patchAlertStatus  = (id, status) => updateAlertStatus(id, status);

// ---------------------------------------------------------------------------
// DB helpers (internal)
// ---------------------------------------------------------------------------

async function loadCorrelation(id) {
  const [rows] = await getPool().execute(
    `SELECT id, correlation_key, title, description, event_count,
            correlation_factors, correlation_score, correlation_strength,
            status, first_seen, last_seen, source_ips, targets, source_types,
            attack_stages, created_at, updated_at
     FROM correlations WHERE id = ? LIMIT 1`,
    [id]
  );
  if (!rows.length) return null;
  const row = rows[0];
  // Parse JSON columns if returned as strings
  for (const col of ['correlation_factors','source_ips','targets','source_types','attack_stages']) {
    if (row[col] && typeof row[col] === 'string') {
      try { row[col] = JSON.parse(row[col]); } catch { /* leave */ }
    }
  }
  return row;
}

async function loadEventsByCorrelationId(correlationId) {
  const [rows] = await getPool().execute(
    `SELECT te.id, te.event_id, te.source, te.timestamp, te.event_type,
            te.source_ip, te.target, te.indicator_type, te.indicator_value,
            te.severity, te.confidence, te.location, te.raw_data
     FROM threat_events te
     JOIN correlation_events ce ON ce.event_id = te.id
     WHERE ce.correlation_id = ?
     ORDER BY te.timestamp ASC`,
    [correlationId]
  );
  return rows;
}

async function loadMatchedIndicators(events) {
  const values = [...new Set(events.map(e => e.indicator_value).filter(Boolean))];
  if (values.length === 0) return [];
  const placeholders = values.map(() => '?').join(', ');
  const [rows] = await getPool().execute(
    `SELECT indicator_type, indicator_value, threat_type, confidence, source
     FROM indicators WHERE indicator_value IN (${placeholders})`,
    values
  );
  return rows;
}

async function loadTargetEntities(events, correlation) {
  // Collect targets from events + from correlation.targets column
  const fromEvents = events.map(e => e.target).filter(Boolean);
  const fromCorr   = Array.isArray(correlation.targets) ? correlation.targets : [];
  const targetList = [...new Set([...fromEvents, ...fromCorr])];
  if (targetList.length === 0) return [];
  const placeholders = targetList.map(() => '?').join(', ');
  const [rows] = await getPool().execute(
    `SELECT name, entity_type, criticality, description FROM entities WHERE name IN (${placeholders})`,
    targetList
  );
  return rows;
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

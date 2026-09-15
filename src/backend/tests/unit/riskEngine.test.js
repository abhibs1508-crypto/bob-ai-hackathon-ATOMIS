'use strict';

/**
 * Unit tests — Risk Engine (Phase 4)
 *
 * Tests the pure runRiskEngine() function with no database dependency.
 * All 10 required test scenarios plus factor-level tests.
 */

const { runRiskEngine } = require('../../src/services/risk/riskEngine');
const { calcSeverity, calcIocRisk, calcAssetCriticality,
        calcCorrelationStrength, calcRecency,
        calcAttackProgression, calcCrossSource } = require('../../src/services/risk/riskFactors');
const { classifyPriority } = require('../../src/services/risk/priorityClassifier');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides = {}) {
  return {
    id:              overrides.id         || 'uuid-x',
    event_id:        overrides.event_id   || 'EVT-x',
    source:          overrides.source     || 'siem',
    timestamp:       overrides.timestamp  || new Date().toISOString(),
    event_type:      overrides.event_type || 'port_scan',
    source_ip:       overrides.source_ip  !== undefined ? overrides.source_ip  : '10.0.0.1',
    target:          overrides.target     !== undefined ? overrides.target     : 'server-01',
    indicator_type:  overrides.indicator_type  || null,
    indicator_value: overrides.indicator_value || null,
    severity:        overrides.severity   || 'medium',
    confidence:      overrides.confidence !== undefined ? overrides.confidence : 70,
    location:        null,
    raw_data:        null,
  };
}

function makeCorrelation(overrides = {}) {
  return {
    id:                   overrides.id                   || 'corr-uuid-1',
    correlation_score:    overrides.correlation_score    !== undefined ? overrides.correlation_score    : 75,
    correlation_strength: overrides.correlation_strength || 'strong',
    attack_stages:        overrides.attack_stages        || ['RECONNAISSANCE', 'CREDENTIAL_ATTACK'],
    source_types:         overrides.source_types         || ['siem', 'sensor'],
    targets:              overrides.targets              || ['server-01'],
    source_ips:           overrides.source_ips           || ['10.0.0.1'],
    last_seen:            'last_seen' in overrides ? overrides.last_seen : new Date().toISOString(),
    title:                overrides.title                || 'Test correlation',
  };
}

function makeCtx(overrides = {}) {
  return {
    correlation:       overrides.correlation       || makeCorrelation(),
    events:            overrides.events            || [makeEvent()],
    matchedIndicators: overrides.matchedIndicators || [],
    targetEntities:    overrides.targetEntities    || [],
  };
}

// ---------------------------------------------------------------------------
// Priority classifier
// ---------------------------------------------------------------------------
describe('priorityClassifier', () => {
  test.each([
    [0,   'low'],
    [24,  'low'],
    [25,  'medium'],
    [49,  'medium'],
    [50,  'high'],
    [74,  'high'],
    [75,  'critical'],
    [100, 'critical'],
  ])('score %i → %s', (score, expected) => {
    expect(classifyPriority(score)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// Factor 1 — Severity
// ---------------------------------------------------------------------------
describe('calcSeverity', () => {
  test('critical event → score 100', () => {
    const ctx = makeCtx({ events: [makeEvent({ severity: 'critical', confidence: 90 })] });
    expect(calcSeverity(ctx).score).toBe(100);
  });
  test('high event → score 75', () => {
    const ctx = makeCtx({ events: [makeEvent({ severity: 'high' })] });
    expect(calcSeverity(ctx).score).toBeGreaterThanOrEqual(75);
  });
  test('low event → score 25', () => {
    const ctx = makeCtx({ events: [makeEvent({ severity: 'low' })] });
    expect(calcSeverity(ctx).score).toBe(25);
  });
  test('no events → score 0', () => {
    const ctx = makeCtx({ events: [] });
    expect(calcSeverity(ctx).score).toBe(0);
  });
  // Test 8: high severity but low confidence should not reach critical automatically
  test('Test 8: high severity + low confidence does not boost to 100', () => {
    const ctx = makeCtx({
      events: [makeEvent({ severity: 'high', confidence: 20 })],
    });
    const { score } = calcSeverity(ctx);
    // Base score for 'high' is 75; no boost because confidence < 80
    expect(score).toBe(75);
  });
});

// ---------------------------------------------------------------------------
// Factor 2 — IOC Risk
// ---------------------------------------------------------------------------
describe('calcIocRisk', () => {
  test('known malicious IOC (confidence 95) → 100', () => {
    const ctx = makeCtx({
      events: [makeEvent({ indicator_value: '1.2.3.4', indicator_type: 'ip' })],
      matchedIndicators: [{ indicator_type: 'ip', indicator_value: '1.2.3.4', threat_type: 'botnet', confidence: 95 }],
    });
    expect(calcIocRisk(ctx).score).toBe(100);
  });
  test('no indicator events → 0', () => {
    const ctx = makeCtx({
      events: [makeEvent({ indicator_value: null })],
      matchedIndicators: [],
    });
    expect(calcIocRisk(ctx).score).toBe(0);
  });
  test('IOC event with no DB match → UNKNOWN score (25)', () => {
    const ctx = makeCtx({
      events: [makeEvent({ indicator_value: '9.9.9.9', indicator_type: 'ip' })],
      matchedIndicators: [],
    });
    expect(calcIocRisk(ctx).score).toBe(25);
  });
  // Test 4: malicious IOC changes risk vs no IOC
  test('Test 4: malicious IOC produces higher score than no IOC', () => {
    const withIOC = calcIocRisk(makeCtx({
      events: [makeEvent({ indicator_value: '5.5.5.5' })],
      matchedIndicators: [{ indicator_type: 'ip', indicator_value: '5.5.5.5', confidence: 95 }],
    }));
    const withoutIOC = calcIocRisk(makeCtx({
      events: [makeEvent({ indicator_value: null })],
    }));
    expect(withIOC.score).toBeGreaterThan(withoutIOC.score);
  });
});

// ---------------------------------------------------------------------------
// Factor 3 — Asset Criticality
// ---------------------------------------------------------------------------
describe('calcAssetCriticality', () => {
  test('uses highest criticality entity (not average)', () => {
    const ctx = makeCtx({
      targetEntities: [
        { name: 'prod-db-01', criticality: 95, entity_type: 'server' },
        { name: 'dev-test-07', criticality: 10, entity_type: 'server' },
      ],
    });
    expect(calcAssetCriticality(ctx).score).toBe(95);
  });
  test('Test 3: critical target scores higher than dev target', () => {
    const prodCtx = makeCtx({ targetEntities: [{ name: 'prod', criticality: 95, entity_type: 'server' }] });
    const devCtx  = makeCtx({ targetEntities: [{ name: 'dev',  criticality: 10, entity_type: 'server' }] });
    expect(calcAssetCriticality(prodCtx).score).toBeGreaterThan(calcAssetCriticality(devCtx).score);
  });
  test('no entities → default score (25)', () => {
    const ctx = makeCtx({ targetEntities: [] });
    expect(calcAssetCriticality(ctx).score).toBe(25);
  });
});

// ---------------------------------------------------------------------------
// Factor 4 — Correlation Strength
// ---------------------------------------------------------------------------
describe('calcCorrelationStrength', () => {
  test('passes Phase 3 score directly', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ correlation_score: 77 }) });
    expect(calcCorrelationStrength(ctx).score).toBe(77);
  });
  test('clamps to 100 if over', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ correlation_score: 150 }) });
    expect(calcCorrelationStrength(ctx).score).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Factor 5 — Recency
// ---------------------------------------------------------------------------
describe('calcRecency', () => {
  test('Test 5: recent activity scores higher than old activity', () => {
    const nowCtx  = makeCtx({ correlation: makeCorrelation({ last_seen: new Date().toISOString() }) });
    const oldDate = new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(); // 8 hours ago
    const oldCtx  = makeCtx({ correlation: makeCorrelation({ last_seen: oldDate }) });
    expect(calcRecency(nowCtx).score).toBeGreaterThan(calcRecency(oldCtx).score);
  });
  test('score approaches 0 for very old events (100h ago)', () => {
    const ancient = new Date(Date.now() - 100 * 60 * 60 * 1000).toISOString();
    const ctx = makeCtx({ correlation: makeCorrelation({ last_seen: ancient }) });
    expect(calcRecency(ctx).score).toBeLessThan(5);
  });
  test('missing last_seen → score 0', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ last_seen: null }) });
    expect(calcRecency(ctx).score).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Factor 6 — Attack Progression
// ---------------------------------------------------------------------------
describe('calcAttackProgression', () => {
  test('Test 6: single stage → score 25', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: ['RECONNAISSANCE'] }) });
    expect(calcAttackProgression(ctx).score).toBe(25);
  });
  test('two stages → score 55', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: ['RECONNAISSANCE', 'CREDENTIAL_ATTACK'] }) });
    expect(calcAttackProgression(ctx).score).toBe(55);
  });
  test('three stages → score 75', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: ['RECONNAISSANCE', 'CREDENTIAL_ATTACK', 'EXPLOITATION'] }) });
    expect(calcAttackProgression(ctx).score).toBe(75);
  });
  test('four or more stages → score 100', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: ['RECONNAISSANCE', 'CREDENTIAL_ATTACK', 'EXPLOITATION', 'LATERAL_MOVEMENT'] }) });
    expect(calcAttackProgression(ctx).score).toBe(100);
  });
  test('THREAT_INTEL stage is excluded from meaningful count', () => {
    // Only THREAT_INTEL — not a meaningful attack stage
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: ['THREAT_INTEL'] }) });
    expect(calcAttackProgression(ctx).score).toBe(0);
  });
  test('THREAT_INTEL + RECONNAISSANCE → 1 meaningful stage → 25', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: ['THREAT_INTEL', 'RECONNAISSANCE'] }) });
    expect(calcAttackProgression(ctx).score).toBe(25);
  });
  test('no stages → score 0', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ attack_stages: [] }) });
    expect(calcAttackProgression(ctx).score).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Factor 7 — Cross-Source
// ---------------------------------------------------------------------------
describe('calcCrossSource', () => {
  test('Test 7: multiple sources → higher score than single source', () => {
    const multi  = makeCtx({ correlation: makeCorrelation({ source_types: ['siem','sensor','threat_intel'] }) });
    const single = makeCtx({ correlation: makeCorrelation({ source_types: ['siem'] }) });
    expect(calcCrossSource(multi).score).toBeGreaterThan(calcCrossSource(single).score);
  });
  test('1 source → 20', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ source_types: ['siem'] }) });
    expect(calcCrossSource(ctx).score).toBe(20);
  });
  test('2 sources → 50', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ source_types: ['siem', 'sensor'] }) });
    expect(calcCrossSource(ctx).score).toBe(50);
  });
  test('3 sources → 80', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ source_types: ['siem', 'sensor', 'threat_intel'] }) });
    expect(calcCrossSource(ctx).score).toBe(80);
  });
  test('4 sources → 100', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ source_types: ['siem', 'sensor', 'threat_intel', 'intelligence_report'] }) });
    expect(calcCrossSource(ctx).score).toBe(100);
  });
  test('duplicate source types count as one', () => {
    const ctx = makeCtx({ correlation: makeCorrelation({ source_types: ['siem', 'siem', 'siem'] }) });
    expect(calcCrossSource(ctx).score).toBe(20); // only 1 distinct
  });
});

// ---------------------------------------------------------------------------
// Test 1 — Critical coordinated attack
// ---------------------------------------------------------------------------
describe('Test 1: Critical coordinated attack', () => {
  test('produces critical or high priority', () => {
    const ctx = {
      correlation: makeCorrelation({
        correlation_score:    90,
        correlation_strength: 'very_strong',
        attack_stages:        ['RECONNAISSANCE', 'CREDENTIAL_ATTACK', 'THREAT_INTEL'],
        source_types:         ['siem', 'sensor', 'threat_intel'],
        last_seen:            new Date().toISOString(),
      }),
      events: [
        makeEvent({ severity: 'critical', confidence: 95, indicator_value: '185.220.101.47' }),
        makeEvent({ severity: 'high',     confidence: 90, indicator_value: '185.220.101.47' }),
      ],
      matchedIndicators: [{ indicator_type: 'ip', indicator_value: '185.220.101.47', threat_type: 'botnet_c2', confidence: 95 }],
      targetEntities:    [{ name: 'prod-db-01', criticality: 95, entity_type: 'server' }],
    };
    const result = runRiskEngine(ctx);
    expect(['high','critical']).toContain(result.priority);
    expect(result.score).toBeGreaterThanOrEqual(50);
  });
});

// ---------------------------------------------------------------------------
// Test 2 — Isolated dev probe
// ---------------------------------------------------------------------------
describe('Test 2: Isolated development probe', () => {
  test('produces low priority', () => {
    const ctx = {
      correlation: makeCorrelation({
        correlation_score:    15,
        correlation_strength: 'weak',
        attack_stages:        ['RECONNAISSANCE'],
        source_types:         ['siem'],
        last_seen:            new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(), // 6h ago
      }),
      events: [makeEvent({ severity: 'low', confidence: 40, indicator_value: null })],
      matchedIndicators: [],
      targetEntities:    [{ name: 'dev-test-07', criticality: 10, entity_type: 'server' }],
    };
    const result = runRiskEngine(ctx);
    expect(result.priority).toBe('low');
    expect(result.score).toBeLessThan(25);
  });
});

// ---------------------------------------------------------------------------
// Test 9 — Idempotency (score is deterministic for same input)
// ---------------------------------------------------------------------------
describe('Test 9: Deterministic / idempotency', () => {
  test('same context produces same score on repeated calls', () => {
    const ctx = makeCtx({
      events: [makeEvent({ severity: 'high', confidence: 85 })],
      matchedIndicators: [{ indicator_type: 'ip', indicator_value: '5.5.5.5', confidence: 90 }],
    });
    const r1 = runRiskEngine(ctx);
    const r2 = runRiskEngine(ctx);
    expect(r1.score).toBe(r2.score);
    expect(r1.priority).toBe(r2.priority);
  });
});

// ---------------------------------------------------------------------------
// Test 10 — Score boundaries
// ---------------------------------------------------------------------------
describe('Test 10: Score boundaries (0–100)', () => {
  test('score is never below 0', () => {
    const ctx = makeCtx({ events: [], matchedIndicators: [], targetEntities: [] });
    const { score } = runRiskEngine(ctx);
    expect(score).toBeGreaterThanOrEqual(0);
  });

  test('score is never above 100 even with all perfect inputs', () => {
    const ctx = {
      correlation: makeCorrelation({
        correlation_score: 100,
        attack_stages:     ['RECONNAISSANCE','CREDENTIAL_ATTACK','EXPLOITATION','LATERAL_MOVEMENT'],
        source_types:      ['siem','sensor','threat_intel','intelligence_report'],
        last_seen:         new Date().toISOString(),
      }),
      events: [makeEvent({ severity: 'critical', confidence: 100 })],
      matchedIndicators: [{ indicator_type: 'ip', indicator_value: 'x', confidence: 100 }],
      targetEntities:    [{ name: 'prod', criticality: 100, entity_type: 'server' }],
    };
    const { score } = runRiskEngine(ctx);
    expect(score).toBeLessThanOrEqual(100);
    expect(score).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Evidence structure
// ---------------------------------------------------------------------------
describe('Risk evidence structure', () => {
  test('riskEvidence contains version, factors, finalScore, priority', () => {
    const ctx = makeCtx();
    const result = runRiskEngine(ctx);
    expect(result.riskEvidence).toHaveProperty('version', '1.0');
    expect(result.riskEvidence).toHaveProperty('factors');
    expect(result.riskEvidence).toHaveProperty('finalScore');
    expect(result.riskEvidence).toHaveProperty('priority');
    expect(result.riskEvidence.factors).toBeInstanceOf(Array);
    expect(result.riskEvidence.factors).toHaveLength(7);
  });

  test('contributions are numerically consistent with weights', () => {
    const ctx = makeCtx();
    const result = runRiskEngine(ctx);
    const sumContributions = result.riskEvidence.factors.reduce((a, f) => a + f.contribution, 0);
    // Sum of contributions should ≈ finalScore (within 2 due to rounding)
    expect(Math.abs(sumContributions - result.riskEvidence.finalScore)).toBeLessThanOrEqual(2);
  });
});

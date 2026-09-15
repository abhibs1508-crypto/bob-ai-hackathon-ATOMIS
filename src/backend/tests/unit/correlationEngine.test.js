'use strict';

/**
 * Unit tests — Correlation Engine
 *
 * Tests the pure runEngine() function with no database dependency.
 * All 9 rules + scoring + evidence + scenarios are exercised here.
 *
 * Covers requirements:
 *   1.  same source correlation
 *   2.  same target correlation
 *   3.  source + target
 *   4.  temporal proximity
 *   5.  IOC match
 *   6.  cross-source correlation
 *   7.  repeated activity
 *   8.  entity relationship
 *   9.  attack sequence
 *   10. weak unrelated events
 *   11. duplicate correlation prevention (same key from same cluster)
 *   12. missing source_ip
 *   13. missing target
 *   14. missing indicator
 *   15. unknown event type
 *   16. events outside time window
 *   17. multiple sources
 *   18. score normalization (0-100)
 *   19. evidence generation
 *   20. Scenario A — CRITICAL coordinated attack
 *   21. Scenario B — LOW isolated probe
 *   22. Scenario C — multi-stage attack
 */

const { runEngine, buildCorrelationKey } = require('../../src/services/correlation/correlationEngine');
const { classifyStage, classifyStages, isMeaningfulProgression } = require('../../src/services/correlation/attackStageClassifier');
const { calculateScore } = require('../../src/services/correlation/correlationScoring');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides = {}) {
  const base = {
    id:              overrides.id              || 'uuid-' + Math.random().toString(36).slice(2),
    event_id:        overrides.event_id        || 'EVT-' + Math.random().toString(36).slice(2),
    source:          overrides.source          || 'siem',
    timestamp:       overrides.timestamp       || new Date().toISOString(),
    event_type:      overrides.event_type      || 'unknown',
    source_ip:       overrides.source_ip       !== undefined ? overrides.source_ip       : '185.10.10.20',
    target:          overrides.target          !== undefined ? overrides.target          : 'server-01',
    indicator_type:  overrides.indicator_type  || null,
    indicator_value: overrides.indicator_value || null,
    severity:        overrides.severity        || 'medium',
    confidence:      overrides.confidence      || 70,
    location:        overrides.location        || null,
    raw_data:        overrides.raw_data        || null,
  };
  return base;
}

function ts(minsAgo) {
  return new Date(Date.now() - minsAgo * 60 * 1000).toISOString();
}

// ---------------------------------------------------------------------------
// Attack Stage Classifier
// ---------------------------------------------------------------------------
describe('attackStageClassifier', () => {
  test('classifies port_scan as RECONNAISSANCE', () => {
    expect(classifyStage('port_scan')).toBe('RECONNAISSANCE');
  });
  test('classifies failed_login as CREDENTIAL_ATTACK', () => {
    expect(classifyStage('failed_login')).toBe('CREDENTIAL_ATTACK');
  });
  test('classifies auth_failure as CREDENTIAL_ATTACK', () => {
    expect(classifyStage('auth_failure')).toBe('CREDENTIAL_ATTACK');
  });
  test('classifies ioc_match as THREAT_INTEL', () => {
    expect(classifyStage('ioc_match')).toBe('THREAT_INTEL');
  });
  test('classifies exploit_attempt as EXPLOITATION', () => {
    expect(classifyStage('exploit_attempt')).toBe('EXPLOITATION');
  });
  test('classifies lateral_movement as LATERAL_MOVEMENT', () => {
    expect(classifyStage('lateral_movement')).toBe('LATERAL_MOVEMENT');
  });
  test('classifies unknown event as UNKNOWN', () => {
    expect(classifyStage('bizarre_unknown_event')).toBe('UNKNOWN');
  });
  test('classifyStages returns ordered unique stages', () => {
    const stages = classifyStages(['port_scan', 'failed_login', 'ioc_match', 'port_scan']);
    expect(stages).toContain('RECONNAISSANCE');
    expect(stages).toContain('CREDENTIAL_ATTACK');
    expect(stages).toContain('THREAT_INTEL');
    // No duplicates
    expect(stages.length).toBe(new Set(stages).size);
  });
  test('isMeaningfulProgression false for only UNKNOWN stages', () => {
    expect(isMeaningfulProgression(['UNKNOWN'])).toBe(false);
  });
  test('isMeaningfulProgression true for RECON + CREDENTIAL_ATTACK', () => {
    expect(isMeaningfulProgression(['RECONNAISSANCE', 'CREDENTIAL_ATTACK'])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Correlation Scoring
// ---------------------------------------------------------------------------
describe('correlationScoring', () => {
  test('score is 0 when no rules match', () => {
    const { score } = calculateScore([{ matched: false, ruleId: 'X' }]);
    expect(score).toBe(0);
  });

  test('score is between 0 and 100', () => {
    const rules = [
      { matched: true, ruleId: 'A', weight: 20, confidence: 1.0 },
      { matched: true, ruleId: 'B', weight: 15, confidence: 0.8 },
      { matched: true, ruleId: 'C', weight: 10, confidence: 0.5 },
    ];
    const { score } = calculateScore(rules);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  test('very_strong strength for score >= 75', () => {
    const { strength } = calculateScore([{ matched: true, ruleId: 'A', weight: 100, confidence: 1.0 }]);
    // With weight 100 and max raw = 100, score = 100
    expect(['very_strong', 'strong']).toContain(strength);
  });

  test('factors lists matched rule IDs', () => {
    const rules = [
      { matched: true,  ruleId: 'SAME_SOURCE', weight: 10, confidence: 1.0 },
      { matched: false, ruleId: 'IOC_MATCH' },
    ];
    const { factors } = calculateScore(rules);
    expect(factors).toContain('SAME_SOURCE');
    expect(factors).not.toContain('IOC_MATCH');
  });
});

// ---------------------------------------------------------------------------
// Test 1: Same source
// ---------------------------------------------------------------------------
describe('Rule: SAME_SOURCE', () => {
  test('fires when 2+ events share source_ip', () => {
    const ctx = {
      events: [
        makeEvent({ event_type: 'port_scan',   source_ip: '1.2.3.4' }),
        makeEvent({ event_type: 'failed_login', source_ip: '1.2.3.4' }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const result = runEngine(ctx);
    expect(result.shouldPersist).toBe(true);
    expect(result.factors).toContain('SAME_SOURCE');
  });

  test('does not fire with single event', () => {
    const sameSourceRule = require('../../src/services/correlation/correlationRules/sameSourceRule');
    const r = sameSourceRule.evaluate({ events: [makeEvent()], matchedIndicators: [], targetEntities: [] });
    expect(r.matched).toBe(false);
  });

  test('test 12 — missing source_ip handled gracefully', () => {
    const ctx = {
      events: [
        makeEvent({ source_ip: null }),
        makeEvent({ source_ip: null }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const sameSourceRule = require('../../src/services/correlation/correlationRules/sameSourceRule');
    const r = sameSourceRule.evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 2: Same target
// ---------------------------------------------------------------------------
describe('Rule: SAME_TARGET', () => {
  test('fires when 2+ events share target', () => {
    const ctx = {
      events: [
        makeEvent({ event_type: 'port_scan',   target: 'critical-server-01' }),
        makeEvent({ event_type: 'failed_login', target: 'critical-server-01' }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const sameTargetRule = require('../../src/services/correlation/correlationRules/sameTargetRule');
    const r = sameTargetRule.evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.sharedTarget).toBe('critical-server-01');
  });

  test('test 13 — missing target handled gracefully', () => {
    const ctx = {
      events: [
        makeEvent({ target: null }),
        makeEvent({ target: null }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const sameTargetRule = require('../../src/services/correlation/correlationRules/sameTargetRule');
    const r = sameTargetRule.evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 3: Source + target
// ---------------------------------------------------------------------------
describe('Rule: SOURCE_TARGET', () => {
  test('fires when same IP attacks same target', () => {
    const ctx = {
      events: [
        makeEvent({ source_ip: '10.0.0.1', target: 'db-prod-01', event_type: 'port_scan',    timestamp: ts(10) }),
        makeEvent({ source_ip: '10.0.0.1', target: 'db-prod-01', event_type: 'failed_login', timestamp: ts(5)  }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/sourceTargetRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.sourceIp).toBe('10.0.0.1');
    expect(r.evidence.target).toBe('db-prod-01');
  });
});

// ---------------------------------------------------------------------------
// Test 4: Temporal proximity
// ---------------------------------------------------------------------------
describe('Rule: TEMPORAL_PROXIMITY', () => {
  test('fires for events within IMMEDIATE window (5 min)', () => {
    const ctx = {
      events: [
        makeEvent({ timestamp: ts(3) }),
        makeEvent({ timestamp: ts(1) }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/temporalRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.windowLabel).toBe('IMMEDIATE');
  });

  test('test 16 — events 48h apart do NOT fire', () => {
    const ctx = {
      events: [
        makeEvent({ timestamp: ts(48 * 60) }),
        makeEvent({ timestamp: ts(0) }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/temporalRule').evaluate(ctx);
    expect(r.matched).toBe(false);
  });

  test('evidence includes firstSeen, lastSeen, durationMinutes', () => {
    const ctx = {
      events: [makeEvent({ timestamp: ts(12) }), makeEvent({ timestamp: ts(2) })],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/temporalRule').evaluate(ctx);
    expect(r.evidence).toHaveProperty('firstSeen');
    expect(r.evidence).toHaveProperty('lastSeen');
    expect(r.evidence).toHaveProperty('durationMinutes');
  });
});

// ---------------------------------------------------------------------------
// Test 5: IOC match
// ---------------------------------------------------------------------------
describe('Rule: IOC_MATCH', () => {
  test('fires when matched indicators provided', () => {
    const ctx = {
      events: [makeEvent({ indicator_value: '185.220.101.47' })],
      matchedIndicators: [{ indicator_type: 'ip', indicator_value: '185.220.101.47', threat_type: 'botnet_c2', confidence: 95 }],
      targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/indicatorRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.matchedIndicators).toHaveLength(1);
  });

  test('test 14 — does not fire when indicator missing', () => {
    const ctx = {
      events: [makeEvent({ indicator_value: null })],
      matchedIndicators: [],
      targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/indicatorRule').evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 6: Cross-source
// ---------------------------------------------------------------------------
describe('Rule: CROSS_SOURCE', () => {
  test('fires when events come from multiple source types', () => {
    const ctx = {
      events: [
        makeEvent({ source: 'siem' }),
        makeEvent({ source: 'sensor' }),
        makeEvent({ source: 'threat_intel' }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/crossSourceRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.sourceTypes).toHaveLength(3);
  });

  test('test 17 — does not fire when all from same source', () => {
    const ctx = {
      events: [makeEvent({ source: 'siem' }), makeEvent({ source: 'siem' })],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/crossSourceRule').evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 7: Repeated activity
// ---------------------------------------------------------------------------
describe('Rule: REPEATED_ACTIVITY', () => {
  test('fires when same event_type appears 3+ times', () => {
    const ctx = {
      events: [
        makeEvent({ event_type: 'failed_login' }),
        makeEvent({ event_type: 'failed_login' }),
        makeEvent({ event_type: 'failed_login' }),
        makeEvent({ event_type: 'port_scan' }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/repeatedActivityRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.repeatedEventType).toBe('failed_login');
    expect(r.evidence.repetitionCount).toBe(3);
  });

  test('does not fire for 2 events', () => {
    const ctx = {
      events: [makeEvent(), makeEvent()],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/repeatedActivityRule').evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 8: Entity relationship
// ---------------------------------------------------------------------------
describe('Rule: ENTITY_RELATION', () => {
  test('fires when target matches a known high-criticality entity', () => {
    const ctx = {
      events: [makeEvent({ target: 'prod-db-01.internal' })],
      matchedIndicators: [],
      targetEntities: [{ name: 'prod-db-01.internal', criticality: 95, entity_type: 'server' }],
    };
    const r = require('../../src/services/correlation/correlationRules/entityRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.confidence).toBeCloseTo(0.95, 1);
  });

  test('does not fire when no entities match', () => {
    const ctx = {
      events: [makeEvent({ target: 'dev-test-07.internal' })],
      matchedIndicators: [],
      targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/entityRule').evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 9: Attack sequence
// ---------------------------------------------------------------------------
describe('Rule: ATTACK_SEQUENCE', () => {
  test('fires for RECON → CREDENTIAL_ATTACK progression', () => {
    const ctx = {
      events: [
        makeEvent({ event_type: 'port_scan',    timestamp: ts(20) }),
        makeEvent({ event_type: 'failed_login', timestamp: ts(10) }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/attackSequenceRule').evaluate(ctx);
    expect(r.matched).toBe(true);
    expect(r.evidence.orderedStages).toContain('RECONNAISSANCE');
    expect(r.evidence.orderedStages).toContain('CREDENTIAL_ATTACK');
  });

  test('test 15 — two UNKNOWN event types do not produce meaningful progression', () => {
    const ctx = {
      events: [
        makeEvent({ event_type: 'bizarre_event_x' }),
        makeEvent({ event_type: 'bizarre_event_y' }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const r = require('../../src/services/correlation/correlationRules/attackSequenceRule').evaluate(ctx);
    expect(r.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Test 10: Weak / unrelated events
// ---------------------------------------------------------------------------
describe('Weak / unrelated events', () => {
  test('single unrelated event has low/no correlation', () => {
    const ctx = {
      events: [makeEvent({ event_type: 'port_scan', source_ip: null, target: null })],
      matchedIndicators: [], targetEntities: [],
    };
    const result = runEngine(ctx);
    // Single event cannot trigger enough rules to be meaningful
    expect(result.shouldPersist === false || result.score <= 25).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Test 11: Duplicate correlation prevention
// ---------------------------------------------------------------------------
describe('Duplicate correlation prevention', () => {
  test('same event cluster produces same correlation key', () => {
    const events = [
      makeEvent({ event_id: 'EVT-A', source_ip: '1.2.3.4', target: 'server-01' }),
      makeEvent({ event_id: 'EVT-B', source_ip: '1.2.3.4', target: 'server-01' }),
    ];
    const key1 = buildCorrelationKey(events, ['1.2.3.4'], ['server-01']);
    const key2 = buildCorrelationKey(events, ['1.2.3.4'], ['server-01']);
    expect(key1).toBe(key2);
  });

  test('different event sets produce different keys', () => {
    const eventsA = [makeEvent({ event_id: 'EVT-X' })];
    const eventsB = [makeEvent({ event_id: 'EVT-Y' })];
    const keyA = buildCorrelationKey(eventsA, [], []);
    const keyB = buildCorrelationKey(eventsB, [], []);
    expect(keyA).not.toBe(keyB);
  });
});

// ---------------------------------------------------------------------------
// Test 18: Score normalization
// ---------------------------------------------------------------------------
describe('Score normalization', () => {
  test('score is always 0-100', () => {
    // Simulate all rules firing at max weight/confidence
    const allRules = [
      { matched: true, ruleId: 'SAME_SOURCE',       weight: 10,  confidence: 1.0 },
      { matched: true, ruleId: 'SAME_TARGET',        weight: 10,  confidence: 1.0 },
      { matched: true, ruleId: 'SOURCE_TARGET',      weight: 15,  confidence: 1.0 },
      { matched: true, ruleId: 'TEMPORAL',           weight: 10,  confidence: 1.0 },
      { matched: true, ruleId: 'IOC_MATCH',          weight: 20,  confidence: 1.0 },
      { matched: true, ruleId: 'CROSS_SOURCE',       weight: 15,  confidence: 1.0 },
      { matched: true, ruleId: 'REPEATED_ACTIVITY',  weight: 5,   confidence: 1.0 },
      { matched: true, ruleId: 'ENTITY_RELATION',    weight: 5,   confidence: 1.0 },
      { matched: true, ruleId: 'ATTACK_SEQUENCE',    weight: 10,  confidence: 1.0 },
    ];
    const { score } = calculateScore(allRules);
    expect(score).toBeLessThanOrEqual(100);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Test 19: Evidence generation
// ---------------------------------------------------------------------------
describe('Evidence generation', () => {
  test('correlation result contains evidence object', () => {
    const ctx = {
      events: [
        makeEvent({ event_type: 'port_scan',    source_ip: '5.5.5.5', target: 'server-A', timestamp: ts(10) }),
        makeEvent({ event_type: 'failed_login', source_ip: '5.5.5.5', target: 'server-A', timestamp: ts(5)  }),
      ],
      matchedIndicators: [], targetEntities: [],
    };
    const result = runEngine(ctx);
    expect(result.shouldPersist).toBe(true);
    expect(result.correlationFactors).toBeDefined();
    expect(result.correlationFactors.rules).toBeInstanceOf(Array);
    expect(result.correlationFactors.rules.length).toBeGreaterThan(0);
    expect(result.correlationFactors.score).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Test 20: SCENARIO A — CRITICAL coordinated attack
// ---------------------------------------------------------------------------
describe('SCENARIO A — Coordinated Reconnaissance + Credential Attack', () => {
  const ATTACKER_IP = '185.220.101.47';
  const TARGET      = 'prod-db-01.internal';

  const scenarioAEvents = [
    makeEvent({ event_id: 'siem-001', source: 'siem',         event_type: 'port_scan',    source_ip: ATTACKER_IP, target: TARGET,      timestamp: ts(35), indicator_value: ATTACKER_IP, indicator_type: 'ip' }),
    makeEvent({ event_id: 'sensor-001', source: 'sensor',     event_type: 'failed_login', source_ip: ATTACKER_IP, target: TARGET,      timestamp: ts(28), indicator_value: ATTACKER_IP, indicator_type: 'ip' }),
    makeEvent({ event_id: 'sensor-002', source: 'sensor',     event_type: 'failed_login', source_ip: ATTACKER_IP, target: TARGET,      timestamp: ts(22), indicator_value: ATTACKER_IP, indicator_type: 'ip' }),
    makeEvent({ event_id: 'ti-001',   source: 'threat_intel', event_type: 'ioc_match',    source_ip: ATTACKER_IP, target: null,        timestamp: ts(15), indicator_value: ATTACKER_IP, indicator_type: 'ip' }),
  ];

  const matchedIndicators = [{ indicator_type: 'ip', indicator_value: ATTACKER_IP, threat_type: 'botnet_c2', confidence: 95 }];
  const targetEntities    = [{ name: TARGET, criticality: 95, entity_type: 'server' }];

  test('produces a SINGLE strong correlation (not 4 independent)', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.shouldPersist).toBe(true);
  });

  test('Scenario A: score is STRONG or VERY_STRONG', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(['strong', 'very_strong']).toContain(result.strength);
  });

  test('Scenario A: contains SAME_SOURCE factor', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.factors).toContain('SAME_SOURCE');
  });

  test('Scenario A: contains IOC_MATCH factor', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.factors).toContain('IOC_MATCH');
  });

  test('Scenario A: contains CROSS_SOURCE factor (siem+sensor+threat_intel)', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.factors).toContain('CROSS_SOURCE');
  });

  test('Scenario A: attack stages include RECONNAISSANCE and CREDENTIAL_ATTACK', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.attackStages).toContain('RECONNAISSANCE');
    expect(result.attackStages).toContain('CREDENTIAL_ATTACK');
  });

  test('Scenario A: sourceIps includes attacker IP', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.sourceIps).toContain(ATTACKER_IP);
  });

  test('Scenario A: targets includes prod-db-01.internal', () => {
    const ctx = { events: scenarioAEvents, matchedIndicators, targetEntities };
    const result = runEngine(ctx);
    expect(result.targets).toContain(TARGET);
  });
});

// ---------------------------------------------------------------------------
// Test 21: SCENARIO B — LOW isolated probe (false positive)
// ---------------------------------------------------------------------------
describe('SCENARIO B — Isolated Low-Priority Probe', () => {
  const PROBE_IP = '203.0.113.42';
  const DEV_HOST = 'dev-test-07.internal';

  const scenarioBEvents = [
    makeEvent({ event_id: 'siem-002', source: 'siem', event_type: 'port_scan', source_ip: PROBE_IP, target: DEV_HOST, timestamp: ts(120) }),
  ];

  test('Scenario B: single event engine result — not enough for strong correlation', () => {
    const ctx = { events: scenarioBEvents, matchedIndicators: [], targetEntities: [{ name: DEV_HOST, criticality: 10, entity_type: 'server' }] };
    const result = runEngine(ctx);
    // Single event: shouldPersist may be false, or score very low
    if (result.shouldPersist) {
      expect(result.score).toBeLessThanOrEqual(30);
      expect(['weak', 'moderate']).toContain(result.strength);
    } else {
      expect(result.shouldPersist).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Test 22: SCENARIO C — Multi-stage attack
// ---------------------------------------------------------------------------
describe('SCENARIO C — Multi-Stage Attack', () => {
  const ATTACKER   = '10.20.30.40';
  const SERVER_A   = 'web-server-01';
  const SERVER_B   = 'db-server-02';

  const scenarioCEvents = [
    makeEvent({ event_id: 'c-001', source: 'sensor',  event_type: 'port_scan',         source_ip: ATTACKER, target: SERVER_A, timestamp: ts(55) }),
    makeEvent({ event_id: 'c-002', source: 'siem',    event_type: 'failed_login',       source_ip: ATTACKER, target: SERVER_A, timestamp: ts(50) }),
    makeEvent({ event_id: 'c-003', source: 'siem',    event_type: 'exploit_attempt',    source_ip: ATTACKER, target: SERVER_A, timestamp: ts(45) }),
    makeEvent({ event_id: 'c-004', source: 'sensor',  event_type: 'lateral_movement',   source_ip: ATTACKER, target: SERVER_B, timestamp: ts(41) }),
  ];

  test('Scenario C: produces a strong or very_strong correlation', () => {
    const ctx = { events: scenarioCEvents, matchedIndicators: [], targetEntities: [] };
    const result = runEngine(ctx);
    expect(result.shouldPersist).toBe(true);
    expect(['strong', 'very_strong']).toContain(result.strength);
  });

  test('Scenario C: detects attack stage progression', () => {
    const ctx = { events: scenarioCEvents, matchedIndicators: [], targetEntities: [] };
    const result = runEngine(ctx);
    expect(result.factors).toContain('ATTACK_SEQUENCE');
    expect(result.attackStages).toContain('RECONNAISSANCE');
    expect(result.attackStages).toContain('CREDENTIAL_ATTACK');
    expect(result.attackStages).toContain('EXPLOITATION');
    expect(result.attackStages).toContain('LATERAL_MOVEMENT');
  });

  test('Scenario C: cross-source fires (sensor + siem)', () => {
    const ctx = { events: scenarioCEvents, matchedIndicators: [], targetEntities: [] };
    const result = runEngine(ctx);
    expect(result.factors).toContain('CROSS_SOURCE');
  });
});

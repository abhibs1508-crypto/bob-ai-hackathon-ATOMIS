'use strict';

const { buildIntelligenceContext } = require('../../src/services/ai/intelligenceContext');

describe('intelligence context builder', () => {
  const context = buildIntelligenceContext({
    correlation: { id: 'c-1', title: 'Campaign', description: 'Observed activity', event_count: 2, correlation_score: 140, correlation_strength: 'strong', source_ips: '["1.2.3.4","1.2.3.4"]', targets: '["db-01"]', source_types: '["siem","siem"]', attack_stages: 'not-json', password: 'hidden' },
    risk: { score: -5, priority: 'critical', severity_component: 120, risk_evidence: '{"attackProgression":{"score":70,"stagesObserved":["RECONNAISSANCE","RECONNAISSANCE"]}}' },
    events: [{ event_id: 'e-1', source: 'sensor', timestamp: '2026-01-01T00:00:00Z', event_type: 'port_scan', source_ip: '1.2.3.4', target: 'db-01', indicator_type: 'ip', indicator_value: '5.6.7.8', severity: 'high', confidence: 150, location: null, raw_data: { api_key: 'do-not-send' } }],
    indicators: [{ indicator_type: 'ip', indicator_value: '5.6.7.8', threat_type: 'malware', confidence: -1, token: 'hidden' }],
    entities: [{ name: 'db-01', entity_type: 'database', criticality: 180, description: 'not included' }],
  });

  test('selects approved fields without database or raw event data', () => {
    expect(context.campaign).not.toHaveProperty('password');
    expect(context.events[0]).not.toHaveProperty('raw_data');
    expect(JSON.stringify(context)).not.toContain('do-not-send');
  });

  test('normalizes duplicate metadata and malformed optional JSON safely', () => {
    expect(context.sourceIps).toEqual(['1.2.3.4']);
    expect(context.sources).toEqual(['siem', 'sensor']);
    expect(context.attackStages).toEqual(['RECONNAISSANCE']);
  });

  test('clamps scores and confidence to the presentation range', () => {
    expect(context.campaign.correlationScore).toBe(100);
    expect(context.risk.score).toBe(0);
    expect(context.risk.severityComponent).toBe(100);
    expect(context.events[0].confidence).toBe(100);
  });

  test('sanitizes indicators and entities', () => {
    expect(context.indicators).toEqual([{ type: 'ip', value: '5.6.7.8', threatType: 'malware', confidence: 0 }]);
    expect(context.entities).toEqual([{ name: 'db-01', entityType: 'database', criticality: 100 }]);
  });

  test('handles null and undefined inputs with safe values', () => {
    const empty = buildIntelligenceContext({ correlation: null, risk: null, events: null, indicators: null, entities: null });
    expect(empty.targets).toEqual([]);
    expect(empty.events).toEqual([]);
    expect(empty.risk.score).toBe(0);
  });
});

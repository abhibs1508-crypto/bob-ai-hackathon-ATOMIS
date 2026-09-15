'use strict';

/**
 * Unit tests — Normalization Service
 *
 * These tests run WITHOUT a database connection. The normalizer is a pure
 * transformation function that can be tested in complete isolation.
 */

const {
  normalise,
  normaliseSiem,
  normaliseSensor,
  normaliseThreatIntel,
  normaliseIntelligenceReport,
  normaliseSeverity,
  normaliseConfidence,
} = require('../../src/services/normalization/normalizer');

// ---------------------------------------------------------------------------
// normaliseSeverity
// ---------------------------------------------------------------------------
describe('normaliseSeverity', () => {
  test.each([
    ['LOW',      'low'],
    ['MEDIUM',   'medium'],
    ['HIGH',     'high'],
    ['CRITICAL', 'critical'],
    ['low',      'low'],
    ['medium',   'medium'],
    ['high',     'high'],
    ['critical', 'critical'],
    ['unknown',  'low'],
    [undefined,  'low'],
    [null,       'low'],
  ])('maps %s → %s', (input, expected) => {
    expect(normaliseSeverity(input)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// normaliseConfidence
// ---------------------------------------------------------------------------
describe('normaliseConfidence', () => {
  test('accepts valid integer', () => expect(normaliseConfidence(85)).toBe(85));
  test('clamps above 100 to 100', () => expect(normaliseConfidence(150)).toBe(100));
  test('clamps below 0 to 0', () => expect(normaliseConfidence(-5)).toBe(0));
  test('parses string integer', () => expect(normaliseConfidence('72')).toBe(72));
  test('returns 50 for NaN', () => expect(normaliseConfidence('abc')).toBe(50));
});

// ---------------------------------------------------------------------------
// SIEM normalisation
// ---------------------------------------------------------------------------
describe('normaliseSiem', () => {
  const payload = {
    event_type:  'AUTH_FAILURE',
    source_ip:   '185.10.10.20',
    target:      'critical-command-server',
    severity:    'HIGH',
    confidence:  88,
    timestamp:   '2025-01-01T10:00:00.000Z',
    raw_data:    { failed_attempts: 17, protocol: 'SSH' },
  };

  test('sets source to "siem"', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.source).toBe('siem');
  });

  test('normalises severity to lowercase', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.severity).toBe('high');
  });

  test('normalises event_type to lowercase', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.event_type).toBe('auth_failure');
  });

  test('preserves source_ip', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.source_ip).toBe('185.10.10.20');
  });

  test('preserves target', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.target).toBe('critical-command-server');
  });

  test('preserves raw_data', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.raw_data).toEqual({ failed_attempts: 17, protocol: 'SSH' });
  });

  test('maps src_ip alias to source_ip', () => {
    const result = normaliseSiem({ ...payload, src_ip: '10.0.0.1', source_ip: undefined }, 'EVT-X');
    expect(result.source_ip).toBe('10.0.0.1');
  });

  test('confidence is within 0-100', () => {
    const result = normaliseSiem(payload, 'EVT-001');
    expect(result.confidence).toBeGreaterThanOrEqual(0);
    expect(result.confidence).toBeLessThanOrEqual(100);
  });
});

// ---------------------------------------------------------------------------
// Sensor normalisation
// ---------------------------------------------------------------------------
describe('normaliseSensor', () => {
  const payload = {
    event_type: 'PORT_SCAN',
    source_ip:  '185.10.10.20',
    target:     'critical-command-server',
    severity:   'MEDIUM',
    confidence: 82,
    timestamp:  '2025-01-01T10:05:00.000Z',
    raw_data:   { ports_scanned: 42, protocol: 'TCP' },
  };

  test('sets source to "sensor"', () => {
    const result = normaliseSensor(payload, 'EVT-002');
    expect(result.source).toBe('sensor');
  });

  test('normalises event_type', () => {
    const result = normaliseSensor(payload, 'EVT-002');
    expect(result.event_type).toBe('port_scan');
  });

  test('maps attacker alias to source_ip', () => {
    const result = normaliseSensor({ ...payload, attacker: '10.1.1.1', source_ip: undefined }, 'EVT-X');
    expect(result.source_ip).toBe('10.1.1.1');
  });

  test('maps victim alias to target', () => {
    const result = normaliseSensor({ ...payload, victim: 'server-B', target: undefined }, 'EVT-X');
    expect(result.target).toBe('server-B');
  });
});

// ---------------------------------------------------------------------------
// Threat Intel normalisation
// ---------------------------------------------------------------------------
describe('normaliseThreatIntel', () => {
  const payload = {
    event_type:      'MALICIOUS_IOC',
    source_ip:       '185.10.10.20',
    indicator_type:  'IP',
    indicator_value: '185.10.10.20',
    severity:        'CRITICAL',
    confidence:      96,
    timestamp:       '2025-01-01T10:10:00.000Z',
    raw_data:        { ioc_status: 'malicious' },
  };

  test('sets source to "threat_intel"', () => {
    const result = normaliseThreatIntel(payload, 'EVT-003');
    expect(result.source).toBe('threat_intel');
  });

  test('normalises indicator_type to lowercase', () => {
    const result = normaliseThreatIntel(payload, 'EVT-003');
    expect(result.indicator_type).toBe('ip');
  });

  test('preserves indicator_value', () => {
    const result = normaliseThreatIntel(payload, 'EVT-003');
    expect(result.indicator_value).toBe('185.10.10.20');
  });

  test('maps ioc alias to indicator_value', () => {
    const result = normaliseThreatIntel(
      { ...payload, ioc: '10.2.3.4', indicator_value: undefined },
      'EVT-X'
    );
    expect(result.indicator_value).toBe('10.2.3.4');
  });

  test('maps type alias to indicator_type', () => {
    const result = normaliseThreatIntel(
      { ...payload, type: 'hash', indicator_type: undefined },
      'EVT-X'
    );
    expect(result.indicator_type).toBe('hash');
  });
});

// ---------------------------------------------------------------------------
// Intelligence Report normalisation
// ---------------------------------------------------------------------------
describe('normaliseIntelligenceReport', () => {
  const payload = {
    event_type: 'THREAT_REPORT',
    severity:   'HIGH',
    confidence: 75,
    timestamp:  '2025-01-01T10:15:00.000Z',
    raw_data:   {
      title:   'Suspicious coordinated activity',
      summary: 'Multiple indicators suggest coordinated intrusion activity.',
    },
  };

  test('sets source to "intelligence_report"', () => {
    const result = normaliseIntelligenceReport(payload, 'EVT-004');
    expect(result.source).toBe('intelligence_report');
  });

  test('normalises event_type to lowercase', () => {
    const result = normaliseIntelligenceReport(payload, 'EVT-004');
    expect(result.event_type).toBe('threat_report');
  });

  test('source_ip is null when not provided', () => {
    const result = normaliseIntelligenceReport(payload, 'EVT-004');
    expect(result.source_ip).toBeNull();
  });

  test('preserves raw_data title and summary', () => {
    const result = normaliseIntelligenceReport(payload, 'EVT-004');
    expect(result.raw_data.title).toBe('Suspicious coordinated activity');
    expect(result.raw_data.summary).toContain('coordinated intrusion');
  });

  test('lifts top-level title into raw_data', () => {
    const result = normaliseIntelligenceReport(
      { ...payload, title: 'Top level title', raw_data: {} },
      'EVT-X'
    );
    expect(result.raw_data.title).toBe('Top level title');
  });
});

// ---------------------------------------------------------------------------
// normalise() dispatcher
// ---------------------------------------------------------------------------
describe('normalise()', () => {
  test('dispatches SIEM payloads correctly', () => {
    const result = normalise({
      source: 'SIEM', event_type: 'login', severity: 'low',
      confidence: 50, timestamp: new Date().toISOString(),
    });
    expect(result.source).toBe('siem');
  });

  test('dispatches SENSOR payloads correctly', () => {
    const result = normalise({
      source: 'SENSOR', event_type: 'scan', severity: 'medium',
      confidence: 60, timestamp: new Date().toISOString(),
    });
    expect(result.source).toBe('sensor');
  });

  test('dispatches THREAT_INTEL payloads correctly', () => {
    const result = normalise({
      source: 'THREAT_INTEL', event_type: 'ioc_match', severity: 'high',
      confidence: 90, timestamp: new Date().toISOString(),
      indicator_type: 'ip', indicator_value: '1.2.3.4',
    });
    expect(result.source).toBe('threat_intel');
  });

  test('dispatches INTELLIGENCE_REPORT payloads correctly', () => {
    const result = normalise({
      source: 'INTELLIGENCE_REPORT', event_type: 'threat_report', severity: 'high',
      confidence: 70, timestamp: new Date().toISOString(),
    });
    expect(result.source).toBe('intelligence_report');
  });

  test('throws for unknown source', () => {
    expect(() => normalise({ source: 'UNKNOWN_SOURCE', event_type: 'x', severity: 'low', confidence: 50 }))
      .toThrow(/Unsupported source type/);
  });

  test('generates event_id when not provided', () => {
    const result = normalise({
      source: 'SIEM', event_type: 'login', severity: 'low',
      confidence: 50, timestamp: new Date().toISOString(),
    });
    expect(result.event_id).toBeTruthy();
    expect(result.event_id).toMatch(/^EVT-/);
  });

  test('uses provided event_id when given', () => {
    const result = normalise({
      event_id: 'MY-EVT-123',
      source: 'SIEM', event_type: 'login', severity: 'low',
      confidence: 50, timestamp: new Date().toISOString(),
    });
    expect(result.event_id).toBe('MY-EVT-123');
  });
});

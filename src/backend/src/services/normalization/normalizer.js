'use strict';

/**
 * CyberFusion — Normalization Service
 *
 * Converts heterogeneous threat-event payloads from four source types into a
 * single NormalizedThreatEvent structure. The correlation engine (Phase 3)
 * operates exclusively on normalized events and never needs to understand the
 * original source-specific formats.
 *
 * Supported source types:
 *   SIEM              — auth failures, suspicious logins, policy violations
 *   SENSOR            — port scans, traffic anomalies, network alerts
 *   THREAT_INTEL      — malicious IOCs, known-bad indicators
 *   INTELLIGENCE_REPORT — curated threat reports with narrative summaries
 *
 * All data is simulated for demonstration purposes.
 * No classified or real operational intelligence is represented.
 */

const { v4: uuidv4 } = require('uuid');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_SOURCES = ['SIEM', 'SENSOR', 'THREAT_INTEL', 'INTELLIGENCE_REPORT'];

// Aliases: allow lowercase / shorthand source names from seed data
const SOURCE_ALIAS_MAP = {
  siem:                 'SIEM',
  sensor:               'SENSOR',
  ti_feed:              'THREAT_INTEL',
  threat_intel:         'THREAT_INTEL',
  'threat-intel':       'THREAT_INTEL',
  intelligence_report:  'INTELLIGENCE_REPORT',
  intelligence:         'INTELLIGENCE_REPORT',
  report:               'INTELLIGENCE_REPORT',
};

const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];
const SEVERITY_NORMALISATION_MAP = {
  LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical',
  low: 'low', medium: 'medium', high: 'high', critical: 'critical',
  1: 'low', 2: 'medium', 3: 'high', 4: 'critical',
};

// ---------------------------------------------------------------------------
// @typedef NormalizedThreatEvent
// ---------------------------------------------------------------------------
/**
 * @typedef {Object} NormalizedThreatEvent
 * @property {string}      event_id        — unique identifier for this event
 * @property {string}      source          — normalised source label (lowercase)
 * @property {string}      timestamp       — ISO 8601 UTC timestamp
 * @property {string}      event_type      — normalised event type (lowercase)
 * @property {string|null} source_ip       — IPv4 or IPv6 of the originator
 * @property {string|null} target          — hostname, IP, or URL of the target
 * @property {string|null} indicator_type  — ip | domain | hash | url
 * @property {string|null} indicator_value — the IOC value
 * @property {string}      severity        — low | medium | high | critical
 * @property {number}      confidence      — 0–100 integer
 * @property {string|null} location        — country / region code
 * @property {Object|null} raw_data        — preserved original payload fields
 */

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Normalises a severity string to lowercase canonical form.
 * Returns 'low' for any unrecognised value.
 * @param {*} value
 * @returns {'low'|'medium'|'high'|'critical'}
 */
function normaliseSeverity(value) {
  const mapped = SEVERITY_NORMALISATION_MAP[value];
  if (mapped) return mapped;
  if (typeof value === 'string') {
    const lower = value.toLowerCase();
    if (VALID_SEVERITIES.includes(lower)) return lower;
  }
  return 'low';
}

/**
 * Returns a valid confidence integer (0–100).
 * Clamps and converts inputs rather than throwing — the validator handles
 * type/range errors before normalization runs.
 * @param {*} value
 * @returns {number}
 */
function normaliseConfidence(value) {
  const n = parseInt(value, 10);
  if (isNaN(n)) return 50;
  return Math.max(0, Math.min(100, n));
}

/**
 * Normalises an event_type to lowercase snake_case.
 * @param {string} value
 * @returns {string}
 */
function normaliseEventType(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9_]/g, '_');
}

/**
 * Normalises a source label to the canonical uppercase form.
 * @param {string} value
 * @returns {string}
 */
function normaliseSourceLabel(value) {
  return String(value).toUpperCase();
}

// ---------------------------------------------------------------------------
// Source-specific normalisers
// ---------------------------------------------------------------------------

/**
 * Normalises a SIEM event.
 *
 * SIEM-specific field aliases:
 *   src_ip → source_ip
 *   host / destination → target
 *   rule_name / event_name → event_type
 *
 * @param {Object} payload  — raw inbound payload
 * @param {string} eventId  — generated event_id
 * @returns {NormalizedThreatEvent}
 */
function normaliseSiem(payload, eventId) {
  return {
    event_id:        eventId,
    source:          'siem',
    timestamp:       payload.timestamp || new Date().toISOString(),
    event_type:      normaliseEventType(payload.event_type || payload.rule_name || payload.event_name || 'unknown'),
    source_ip:       payload.source_ip || payload.src_ip || null,
    target:          payload.target || payload.host || payload.destination || null,
    indicator_type:  payload.indicator_type || null,
    indicator_value: payload.indicator_value || null,
    severity:        normaliseSeverity(payload.severity),
    confidence:      normaliseConfidence(payload.confidence !== undefined ? payload.confidence : 75),
    location:        payload.location || null,
    raw_data:        payload.raw_data || null,
  };
}

/**
 * Normalises a SENSOR (network/cyber sensor) event.
 *
 * Sensor-specific field aliases:
 *   attacker / src → source_ip
 *   victim / dst → target
 *   alert_type → event_type
 *
 * @param {Object} payload
 * @param {string} eventId
 * @returns {NormalizedThreatEvent}
 */
function normaliseSensor(payload, eventId) {
  return {
    event_id:        eventId,
    source:          'sensor',
    timestamp:       payload.timestamp || new Date().toISOString(),
    event_type:      normaliseEventType(payload.event_type || payload.alert_type || 'unknown'),
    source_ip:       payload.source_ip || payload.attacker || payload.src || null,
    target:          payload.target || payload.victim || payload.dst || null,
    indicator_type:  payload.indicator_type || null,
    indicator_value: payload.indicator_value || null,
    severity:        normaliseSeverity(payload.severity),
    confidence:      normaliseConfidence(payload.confidence !== undefined ? payload.confidence : 70),
    location:        payload.location || null,
    raw_data:        payload.raw_data || null,
  };
}

/**
 * Normalises a THREAT_INTEL (threat intelligence feed) event.
 *
 * TI-specific field aliases:
 *   indicator / ioc → indicator_value
 *   type / ioc_type → indicator_type
 *
 * @param {Object} payload
 * @param {string} eventId
 * @returns {NormalizedThreatEvent}
 */
function normaliseThreatIntel(payload, eventId) {
  const indicatorValue = payload.indicator_value || payload.indicator || payload.ioc || null;
  const indicatorType  = payload.indicator_type  || payload.type       || payload.ioc_type || null;

  return {
    event_id:        eventId,
    source:          'threat_intel',
    timestamp:       payload.timestamp || new Date().toISOString(),
    event_type:      normaliseEventType(payload.event_type || 'ioc_match'),
    source_ip:       payload.source_ip || (indicatorType === 'IP' || indicatorType === 'ip' ? indicatorValue : null),
    target:          payload.target || null,
    indicator_type:  indicatorType ? indicatorType.toLowerCase() : null,
    indicator_value: indicatorValue,
    severity:        normaliseSeverity(payload.severity),
    confidence:      normaliseConfidence(payload.confidence !== undefined ? payload.confidence : 80),
    location:        payload.location || null,
    raw_data:        payload.raw_data || null,
  };
}

/**
 * Normalises an INTELLIGENCE_REPORT event.
 *
 * Report-specific field aliases:
 *   report_id → preserved in raw_data
 *   title / summary → preserved in raw_data
 *
 * @param {Object} payload
 * @param {string} eventId
 * @returns {NormalizedThreatEvent}
 */
function normaliseIntelligenceReport(payload, eventId) {
  // Preserve title and summary in raw_data for Phase 4 AI analysis
  const rawData = payload.raw_data || {};
  if (payload.title)   rawData.title   = payload.title;
  if (payload.summary) rawData.summary = payload.summary;

  return {
    event_id:        eventId,
    source:          'intelligence_report',
    timestamp:       payload.timestamp || new Date().toISOString(),
    event_type:      normaliseEventType(payload.event_type || 'threat_report'),
    source_ip:       payload.source_ip || null,
    target:          payload.target || null,
    indicator_type:  payload.indicator_type || null,
    indicator_value: payload.indicator_value || null,
    severity:        normaliseSeverity(payload.severity),
    confidence:      normaliseConfidence(payload.confidence !== undefined ? payload.confidence : 70),
    location:        payload.location || null,
    raw_data:        Object.keys(rawData).length > 0 ? rawData : null,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Normalises an inbound threat-event payload based on its source type.
 *
 * @param {Object} payload  — validated inbound request body
 * @returns {NormalizedThreatEvent}
 * @throws {Error} if the source type is unrecognised
 */
function normalise(payload) {
  // Resolve alias (e.g. 'ti_feed' → 'THREAT_INTEL', 'siem' → 'SIEM')
  const rawSource = (payload.source || '').toString().toLowerCase().replace(/-/g, '_');
  const source = SOURCE_ALIAS_MAP[rawSource] || (payload.source || '').toString().toUpperCase();
  const eventId = payload.event_id || `EVT-${uuidv4()}`;

  switch (source) {
    case 'SIEM':
      return normaliseSiem({ ...payload, source }, eventId);
    case 'SENSOR':
      return normaliseSensor({ ...payload, source }, eventId);
    case 'THREAT_INTEL':
      return normaliseThreatIntel({ ...payload, source }, eventId);
    case 'INTELLIGENCE_REPORT':
      return normaliseIntelligenceReport({ ...payload, source }, eventId);
    default:
      throw new Error(`Unsupported source type: "${payload.source}". Valid values: ${VALID_SOURCES.join(', ')}`);
  }
}

module.exports = {
  normalise,
  normaliseSiem,
  normaliseSensor,
  normaliseThreatIntel,
  normaliseIntelligenceReport,
  normaliseSeverity,
  normaliseConfidence,
  VALID_SOURCES,
  VALID_SEVERITIES,
};

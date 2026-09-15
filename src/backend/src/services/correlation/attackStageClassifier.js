'use strict';

/**
 * CyberFusion — Attack Stage Classifier
 *
 * Maps normalised event_type strings to broad attack stages.
 * Stages follow a loose MITRE ATT&CK-inspired progression.
 *
 * Deterministic, pure function — no AI or external calls.
 * Unknown event types are classified as UNKNOWN, not silently dropped.
 */

const STAGE_MAP = {
  // ── RECONNAISSANCE ────────────────────────────────────────────────────────
  port_scan:         'RECONNAISSANCE',
  network_scan:      'RECONNAISSANCE',
  host_discovery:    'RECONNAISSANCE',
  service_discovery: 'RECONNAISSANCE',
  ping_sweep:        'RECONNAISSANCE',
  dns_enumeration:   'RECONNAISSANCE',
  osint:             'RECONNAISSANCE',

  // ── INITIAL_ACCESS / CREDENTIAL_ATTACK ───────────────────────────────────
  failed_login:      'CREDENTIAL_ATTACK',
  auth_failure:      'CREDENTIAL_ATTACK',
  brute_force:       'CREDENTIAL_ATTACK',
  credential_attack: 'CREDENTIAL_ATTACK',
  password_spray:    'CREDENTIAL_ATTACK',
  phishing:          'INITIAL_ACCESS',
  spearphishing:     'INITIAL_ACCESS',

  // ── IOC / THREAT INTEL ────────────────────────────────────────────────────
  ioc_match:         'THREAT_INTEL',
  malicious_ioc:     'THREAT_INTEL',
  threat_report:     'THREAT_INTEL',
  indicator_match:   'THREAT_INTEL',

  // ── EXECUTION / EXPLOITATION ─────────────────────────────────────────────
  exploit_attempt:      'EXPLOITATION',
  command_execution:    'EXPLOITATION',
  suspicious_process:   'EXPLOITATION',
  malware_detection:    'EXPLOITATION',
  code_injection:       'EXPLOITATION',
  buffer_overflow:      'EXPLOITATION',

  // ── PERSISTENCE ───────────────────────────────────────────────────────────
  persistence_attempt: 'PERSISTENCE',
  scheduled_task:      'PERSISTENCE',
  registry_modification: 'PERSISTENCE',
  startup_modification: 'PERSISTENCE',

  // ── PRIVILEGE_ESCALATION ─────────────────────────────────────────────────
  privilege_escalation: 'PRIVILEGE_ESCALATION',
  sudo_misuse:          'PRIVILEGE_ESCALATION',
  token_manipulation:   'PRIVILEGE_ESCALATION',

  // ── LATERAL_MOVEMENT ─────────────────────────────────────────────────────
  lateral_movement: 'LATERAL_MOVEMENT',
  remote_service:   'LATERAL_MOVEMENT',
  pass_the_hash:    'LATERAL_MOVEMENT',
  remote_execution: 'LATERAL_MOVEMENT',

  // ── COMMAND_AND_CONTROL ───────────────────────────────────────────────────
  beacon:           'COMMAND_AND_CONTROL',
  c2_connection:    'COMMAND_AND_CONTROL',
  dns_tunneling:    'COMMAND_AND_CONTROL',
  covert_channel:   'COMMAND_AND_CONTROL',

  // ── EXFILTRATION ─────────────────────────────────────────────────────────
  data_exfiltration: 'EXFILTRATION',
  large_upload:      'EXFILTRATION',
  sensitive_file_access: 'EXFILTRATION',
};

/**
 * Attack stage ordering — used to detect meaningful progressions.
 * Lower index = earlier in the kill chain.
 */
const STAGE_ORDER = [
  'RECONNAISSANCE',
  'INITIAL_ACCESS',
  'CREDENTIAL_ATTACK',
  'THREAT_INTEL',
  'EXPLOITATION',
  'PERSISTENCE',
  'PRIVILEGE_ESCALATION',
  'LATERAL_MOVEMENT',
  'COMMAND_AND_CONTROL',
  'EXFILTRATION',
  'UNKNOWN',
];

/**
 * Returns the attack stage for a given event_type.
 * @param {string} eventType
 * @returns {string}
 */
function classifyStage(eventType) {
  if (!eventType) return 'UNKNOWN';
  const normalised = String(eventType).toLowerCase().replace(/[^a-z0-9_]/g, '_');
  return STAGE_MAP[normalised] || 'UNKNOWN';
}

/**
 * Classifies an array of event_types and returns unique ordered stages.
 * @param {string[]} eventTypes
 * @returns {string[]}
 */
function classifyStages(eventTypes) {
  const stages = new Set(eventTypes.map(classifyStage));
  // Return stages in kill-chain order (UNKNOWN last)
  return STAGE_ORDER.filter(s => stages.has(s));
}

/**
 * Returns true if the stages array contains a meaningful multi-step progression.
 * Meaningful = at least two distinct stages, and at least one is not UNKNOWN/THREAT_INTEL.
 * @param {string[]} orderedStages
 * @returns {boolean}
 */
function isMeaningfulProgression(orderedStages) {
  const meaningful = orderedStages.filter(s => s !== 'UNKNOWN' && s !== 'THREAT_INTEL');
  return meaningful.length >= 2;
}

module.exports = { classifyStage, classifyStages, isMeaningfulProgression, STAGE_ORDER, STAGE_MAP };

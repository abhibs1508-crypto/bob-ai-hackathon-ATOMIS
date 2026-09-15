'use strict';

/**
 * CyberFusion — Priority Classifier
 *
 * Converts a 0–100 risk score into a priority label.
 * Thresholds are read from riskConfig so they can be adjusted without code edits.
 */

const { PRIORITY_THRESHOLDS } = require('./riskConfig');

/**
 * Classifies a risk score into a priority label.
 * @param {number} score  — integer 0–100
 * @returns {'critical'|'high'|'medium'|'low'}
 */
function classifyPriority(score) {
  if (score >= PRIORITY_THRESHOLDS.CRITICAL) return 'critical';
  if (score >= PRIORITY_THRESHOLDS.HIGH)     return 'high';
  if (score >= PRIORITY_THRESHOLDS.MEDIUM)   return 'medium';
  return 'low';
}

module.exports = { classifyPriority };

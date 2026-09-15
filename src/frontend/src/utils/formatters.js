/**
 * CyberFusion — Formatting Utilities
 *
 * Pure functions for display formatting.
 * Never fabricates data — only formats what is passed in.
 */

/**
 * Map a priority string to a Tailwind colour class set.
 * @param {'critical'|'high'|'medium'|'low'} priority
 * @returns {{ text: string, bg: string, border: string, dot: string }}
 */
export function priorityColours(priority) {
  switch (priority?.toLowerCase()) {
    case 'critical': return { text: 'text-red-400',    bg: 'bg-red-900/30',    border: 'border-red-800/50',    dot: 'bg-red-500' };
    case 'high':     return { text: 'text-orange-400', bg: 'bg-orange-900/30', border: 'border-orange-800/50', dot: 'bg-orange-500' };
    case 'medium':   return { text: 'text-yellow-400', bg: 'bg-yellow-900/30', border: 'border-yellow-800/50', dot: 'bg-yellow-500' };
    default:         return { text: 'text-slate-400',  bg: 'bg-slate-800/40',  border: 'border-slate-700/50',  dot: 'bg-slate-500' };
  }
}

/**
 * Map correlation strength string to a display label and colour.
 * @param {string} strength
 */
export function strengthLabel(strength) {
  const map = {
    very_strong: { label: 'Very Strong', colour: 'text-red-400' },
    strong:      { label: 'Strong',      colour: 'text-orange-400' },
    moderate:    { label: 'Moderate',    colour: 'text-yellow-400' },
    weak:        { label: 'Weak',        colour: 'text-slate-400' },
  };
  return map[strength?.toLowerCase()] || { label: strength || '—', colour: 'text-slate-400' };
}

/**
 * Format a risk score (0-100) to a display string with colour class.
 * @param {number|null} score
 */
export function riskScoreDisplay(score) {
  if (score == null) return { label: '—', colour: 'text-slate-500' };
  if (score >= 80) return { label: String(score), colour: 'text-red-400' };
  if (score >= 60) return { label: String(score), colour: 'text-orange-400' };
  if (score >= 40) return { label: String(score), colour: 'text-yellow-400' };
  return { label: String(score), colour: 'text-slate-400' };
}

/**
 * Format an ISO 8601 timestamp to a compact local display.
 * @param {string} iso
 */
export function formatTimestamp(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-GB', {
      day:    '2-digit',
      month:  'short',
      year:   'numeric',
      hour:   '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/**
 * Truncate a string to maxLen characters with ellipsis.
 * @param {string} str
 * @param {number} maxLen
 */
export function truncate(str, maxLen = 60) {
  if (!str) return '—';
  return str.length > maxLen ? str.slice(0, maxLen) + '…' : str;
}

/**
 * Map an event_type slug to a human-readable label.
 * @param {string} eventType
 */
export function eventTypeLabel(eventType) {
  const map = {
    port_scan:     'Port Scan',
    failed_login:  'Failed Login',
    ioc_match:     'IOC Match',
    lateral_move:  'Lateral Movement',
    data_exfil:    'Data Exfiltration',
    malware_detect:'Malware Detected',
    anomaly:       'Anomaly',
  };
  return map[eventType] || eventType || '—';
}

import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, ChevronUp, ChevronDown, Filter } from 'lucide-react';
import { getAlerts } from '../../api/alertsApi.js';
import { priorityColours, riskScoreDisplay, formatTimestamp, truncate, strengthLabel } from '../../utils/formatters.js';
import LoadingState from '../common/LoadingState.jsx';
import ErrorState from '../common/ErrorState.jsx';
import EmptyState from '../common/EmptyState.jsx';

/**
 * ThreatQueue — priority-ordered analyst alert table.
 *
 * Renders live data from GET /api/alerts.
 * Never fabricates threat data.
 * Designed to be reusable in Phase 7B with onClick drill-down support.
 */
export default function ThreatQueue({ onSelectAlert, limit = 50 }) {
  const [alerts,  setAlerts]  = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [filter,  setFilter]  = useState('all'); // all | critical | high | medium | low

  const fetchAlerts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = { limit };
      if (filter !== 'all') params.priority = filter;
      const data = await getAlerts(params);
      setAlerts(data.alerts || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [filter, limit]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

  return (
    <div className="panel flex flex-col">
      {/* Header */}
      <div className="panel-header">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-slate-200">Analyst Priority Queue</h2>
          {!loading && !error && (
            <span className="tag bg-[#1b2130] text-slate-400 border border-[#263045]">
              {alerts.length} {alerts.length === 1 ? 'alert' : 'alerts'}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Priority filter */}
          <div className="flex items-center gap-1">
            <Filter className="w-3 h-3 text-slate-500" />
            <div className="flex gap-0.5">
              {FILTERS.map((f) => {
                const c = priorityColours(f);
                return (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors capitalize ${
                      filter === f
                        ? `${c.bg} ${c.text} ${c.border} border`
                        : 'text-slate-500 hover:text-slate-300'
                    }`}
                  >
                    {f}
                  </button>
                );
              })}
            </div>
          </div>

          <button
            onClick={fetchAlerts}
            disabled={loading}
            className="btn-ghost flex items-center gap-1.5"
            title="Refresh queue"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {loading && <LoadingState rows={4} label="Loading threat queue…" />}
        {!loading && error && (
          <ErrorState
            title="Failed to load alert queue."
            message={error}
            onRetry={fetchAlerts}
          />
        )}
        {!loading && !error && alerts.length === 0 && (
          <EmptyState
            title="No active threats detected."
            message="The analyst queue is currently clear."
          />
        )}
        {!loading && !error && alerts.length > 0 && (
          <AlertTable alerts={alerts} onSelectAlert={onSelectAlert} />
        )}
      </div>
    </div>
  );
}

/**
 * AlertTable — renders the actual rows.
 * Extracted to keep ThreatQueue manageable.
 */
function AlertTable({ alerts, onSelectAlert }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[#1e2a3b] text-[10px] text-slate-600 uppercase tracking-widest">
            <th className="px-4 py-2 text-left font-semibold">Priority</th>
            <th className="px-4 py-2 text-left font-semibold">Threat / Source</th>
            <th className="px-4 py-2 text-right font-semibold">Risk</th>
            <th className="px-4 py-2 text-right font-semibold">Corr.</th>
            <th className="px-4 py-2 text-left font-semibold hidden md:table-cell">Strength</th>
            <th className="px-4 py-2 text-left font-semibold hidden lg:table-cell">Target</th>
            <th className="px-4 py-2 text-left font-semibold hidden lg:table-cell">Status</th>
            <th className="px-4 py-2 text-left font-semibold hidden xl:table-cell">Detected</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[#1a2334]">
          {alerts.map((alert) => (
            <AlertRow key={alert.id} alert={alert} onSelectAlert={onSelectAlert} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertRow({ alert, onSelectAlert }) {
  const priority = alert.priority || 'low';
  const c = priorityColours(priority);
  const risk = riskScoreDisplay(alert.risk_score);
  const corr = riskScoreDisplay(alert.correlation_score);
  const strength = strengthLabel(alert.correlation_strength);

  const rowClass = `row-${priority}`;

  return (
    <tr
      className={`${rowClass} hover:bg-white/[0.02] transition-colors ${
        onSelectAlert ? 'cursor-pointer' : ''
      }`}
      onClick={onSelectAlert ? () => onSelectAlert(alert) : undefined}
    >
      {/* Priority */}
      <td className="px-4 py-3">
        <span className={`tag ${c.bg} ${c.text} ${c.border} border`}>
          <span className={`status-dot ${c.dot}`} />
          {priority.toUpperCase()}
        </span>
      </td>

      {/* Threat description / source */}
      <td className="px-4 py-3">
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-slate-200">
            {truncate(alert.title || alert.description || 'Correlation Alert', 45)}
          </span>
          {alert.source_ip && (
            <span className="text-[11px] text-slate-500 font-mono">
              {alert.source_ip}
            </span>
          )}
        </div>
      </td>

      {/* Risk score */}
      <td className="px-4 py-3 text-right">
        <span className={`font-bold text-sm ${risk.colour}`}>{risk.label}</span>
      </td>

      {/* Correlation score */}
      <td className="px-4 py-3 text-right">
        <span className={`font-medium ${corr.colour}`}>{corr.label}</span>
      </td>

      {/* Correlation strength */}
      <td className="px-4 py-3 hidden md:table-cell">
        <span className={`text-[11px] font-medium ${strength.colour}`}>
          {strength.label}
        </span>
      </td>

      {/* Target */}
      <td className="px-4 py-3 hidden lg:table-cell">
        <span className="font-mono text-[11px] text-slate-400">
          {alert.target || '—'}
        </span>
      </td>

      {/* Status */}
      <td className="px-4 py-3 hidden lg:table-cell">
        <StatusBadge status={alert.status} />
      </td>

      {/* Detected at */}
      <td className="px-4 py-3 hidden xl:table-cell">
        <span className="text-[11px] text-slate-500">
          {formatTimestamp(alert.created_at || alert.first_seen)}
        </span>
      </td>
    </tr>
  );
}

function StatusBadge({ status }) {
  const map = {
    open:         { label: 'OPEN',         cls: 'bg-blue-900/40 text-blue-400 border-blue-800/50' },
    acknowledged: { label: 'ACK\'D',       cls: 'bg-purple-900/40 text-purple-400 border-purple-800/50' },
    closed:       { label: 'CLOSED',       cls: 'bg-slate-800/60 text-slate-500 border-slate-700/50' },
  };
  const s = map[status] || { label: status || '—', cls: 'bg-slate-800/60 text-slate-500 border-slate-700/50' };
  return (
    <span className={`tag border ${s.cls}`}>{s.label}</span>
  );
}

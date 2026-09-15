import { useEffect, useState } from 'react';
import { Shield, Database, Cpu, Clock } from 'lucide-react';
import { getHealth } from '../../api/healthApi.js';
import { formatTimestamp } from '../../utils/formatters.js';

/**
 * SystemStatus — compact health status panel.
 * Fetches live data from /api/health.
 */
export default function SystemStatus() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function fetch() {
      try {
        const data = await getHealth();
        if (!cancelled) { setHealth(data); setError(false); }
      } catch {
        if (!cancelled) setError(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetch();
    const t = setInterval(fetch, 30_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  return (
    <div className="panel p-4">
      <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-3">
        System Status
      </p>

      {loading && <div className="skeleton h-20 w-full rounded" />}

      {!loading && error && (
        <p className="text-xs text-red-400">Backend unreachable</p>
      )}

      {!loading && !error && health && (
        <div className="space-y-2">
          <StatusRow
            icon={Shield}
            label="System"
            value={health.status === 'ok' ? 'ONLINE' : 'DEGRADED'}
            colour={health.status === 'ok' ? 'text-emerald-400' : 'text-yellow-400'}
          />
          <StatusRow
            icon={Database}
            label="Database"
            value={health.database === 'connected' ? 'CONNECTED' : 'UNAVAILABLE'}
            colour={health.database === 'connected' ? 'text-emerald-400' : 'text-red-400'}
          />
          <StatusRow
            icon={Cpu}
            label="AI Engine"
            value={health.ai_available ? health.ai_provider?.toUpperCase() : 'UNAVAILABLE'}
            colour={health.ai_available ? 'text-sky-400' : 'text-slate-500'}
          />
          {health.timestamp && (
            <div className="flex items-center gap-2 pt-1">
              <Clock className="w-3.5 h-3.5 text-slate-600" />
              <span className="text-[11px] text-slate-600">
                Last checked {formatTimestamp(health.timestamp)}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatusRow({ icon: Icon, label, value, colour }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Icon className="w-3.5 h-3.5" />
        {label}
      </div>
      <span className={`text-[11px] font-semibold tracking-wider ${colour}`}>{value}</span>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { Shield, Database, Cpu, CircleDot } from 'lucide-react';
import { getHealth } from '../../api/healthApi.js';

/**
 * TopBar — system status bar at the top of the analyst console.
 * Polls /api/health to show live system status.
 * Never hard-codes health status.
 */
export default function TopBar() {
  const [health, setHealth] = useState(null);
  const [error,  setError]  = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function fetchHealth() {
      try {
        const data = await getHealth();
        if (!cancelled) {
          setHealth(data);
          setError(false);
        }
      } catch {
        if (!cancelled) setError(true);
      }
    }

    fetchHealth();
    const interval = setInterval(fetchHealth, 30_000); // refresh every 30s
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const systemOnline  = health?.status === 'ok';
  const dbConnected   = health?.database === 'connected';
  const aiAvailable   = health?.ai_available === true;
  const aiProvider    = health?.ai_provider?.toUpperCase() || null;

  return (
    <header className="h-12 flex items-center justify-between px-4 bg-[#0e1117] border-b border-[#1e2a3b] flex-shrink-0">
      {/* Brand */}
      <div className="flex items-center gap-2">
        <Shield className="w-4 h-4 text-sky-400" />
        <span className="text-xs font-semibold text-sky-400 tracking-[0.15em] uppercase">
          Defence Intelligence Console
        </span>
      </div>

      {/* Status indicators */}
      <div className="flex items-center gap-4">
        {/* System status */}
        <StatusPill
          icon={<CircleDot className="w-3 h-3" />}
          label={error ? 'OFFLINE' : systemOnline ? 'SYSTEM ONLINE' : 'DEGRADED'}
          colour={error ? 'text-red-400' : systemOnline ? 'text-emerald-400' : 'text-yellow-400'}
          dotColour={error ? 'bg-red-500' : systemOnline ? 'bg-emerald-500 animate-pulse' : 'bg-yellow-500'}
        />

        {/* Database */}
        <StatusPill
          icon={<Database className="w-3 h-3" />}
          label={dbConnected ? 'DATABASE CONNECTED' : 'DATABASE UNAVAILABLE'}
          colour={dbConnected ? 'text-emerald-400' : 'text-red-400'}
          dotColour={dbConnected ? 'bg-emerald-500' : 'bg-red-500'}
        />

        {/* AI provider */}
        <StatusPill
          icon={<Cpu className="w-3 h-3" />}
          label={aiAvailable ? `AI: ${aiProvider}` : 'AI: UNAVAILABLE'}
          colour={aiAvailable ? 'text-sky-400' : 'text-slate-500'}
          dotColour={aiAvailable ? 'bg-sky-400' : 'bg-slate-600'}
        />
      </div>
    </header>
  );
}

function StatusPill({ icon, label, colour, dotColour }) {
  return (
    <div className={`flex items-center gap-1.5 text-[11px] font-medium tracking-wider ${colour}`}>
      <span className={`status-dot ${dotColour}`} />
      {icon}
      <span>{label}</span>
    </div>
  );
}

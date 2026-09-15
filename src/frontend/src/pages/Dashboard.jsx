import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Activity, GitMerge, RefreshCw } from 'lucide-react';
import StatCard from '../components/dashboard/StatCard.jsx';
import ThreatQueue from '../components/dashboard/ThreatQueue.jsx';
import SystemStatus from '../components/dashboard/SystemStatus.jsx';
import { getAlerts } from '../api/alertsApi.js';
import { getCorrelations } from '../api/correlationsApi.js';

/**
 * Dashboard — primary analyst overview page.
 *
 * Displays KPI summary cards and the priority threat queue.
 * All data sourced from the backend — no fabricated values.
 */
export default function Dashboard() {
  const [kpis,       setKpis]       = useState(null);
  const [kpiLoading, setKpiLoading] = useState(true);
  const [kpiError,   setKpiError]   = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadKpis() {
      setKpiLoading(true);
      setKpiError(false);
      try {
        // Fetch alerts and correlations concurrently for the KPI cards
        const [alertsData, correlationsData] = await Promise.all([
          getAlerts({ limit: 200 }),
          getCorrelations({ limit: 200 }),
        ]);

        if (!cancelled) {
          const alerts = alertsData.alerts || [];
          const correlations = correlationsData.correlations || [];

          setKpis({
            critical:     alerts.filter(a => a.priority === 'critical').length,
            high:         alerts.filter(a => a.priority === 'high').length,
            totalAlerts:  alerts.length,
            correlations: correlations.length,
          });
        }
      } catch {
        if (!cancelled) setKpiError(true);
      } finally {
        if (!cancelled) setKpiLoading(false);
      }
    }

    loadKpis();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="flex flex-col gap-0 h-full">
      {/* Page header */}
      <div className="px-6 py-4 border-b border-[#1e2a3b]">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-base font-bold text-slate-100 tracking-wide">
              Threat Intelligence Overview
            </h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Real-time correlation and prioritisation
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-slate-600">
              {new Date().toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' })}
            </span>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* KPI Cards */}
        <section aria-label="Key performance indicators">
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            <StatCard
              label="Critical Threats"
              value={kpis?.critical}
              icon={AlertTriangle}
              colour="text-red-400"
              bgColour="bg-red-950/20"
              borderColour="border-red-900/30"
              loading={kpiLoading}
              subLabel={kpiError ? 'Unavailable' : undefined}
            />
            <StatCard
              label="High Priority"
              value={kpis?.high}
              icon={Shield}
              colour="text-orange-400"
              bgColour="bg-orange-950/20"
              borderColour="border-orange-900/30"
              loading={kpiLoading}
              subLabel={kpiError ? 'Unavailable' : undefined}
            />
            <StatCard
              label="Active Alerts"
              value={kpis?.totalAlerts}
              icon={Activity}
              colour="text-sky-400"
              loading={kpiLoading}
              subLabel={kpiError ? 'Unavailable' : undefined}
            />
            <StatCard
              label="Correlations"
              value={kpis?.correlations}
              icon={GitMerge}
              colour="text-purple-400"
              loading={kpiLoading}
              subLabel={kpiError ? 'Unavailable' : undefined}
            />
          </div>
          {kpiError && (
            <p className="text-xs text-red-400/70 mt-2">
              KPI data unavailable — check backend connection.
            </p>
          )}
        </section>

        {/* Main content row */}
        <div className="flex gap-6">
          {/* Threat queue — takes most of the width */}
          <section className="flex-1 min-w-0" aria-label="Analyst priority queue">
            <ThreatQueue limit={50} />
          </section>

          {/* Right sidebar — system status */}
          <aside className="w-52 flex-shrink-0 space-y-4" aria-label="System status">
            <SystemStatus />

            {/* Intelligence console note */}
            <div className="panel p-4">
              <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500 mb-2">
                AI Intelligence
              </p>
              <p className="text-xs text-slate-400">
                Select a threat from the queue to view AI-generated intelligence reports.
              </p>
              <p className="text-[11px] text-slate-600 mt-2">Phase 7B</p>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}

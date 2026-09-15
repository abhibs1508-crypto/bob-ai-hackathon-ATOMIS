import { Suspense, lazy, useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Network, List, RefreshCw, Shield, AlertTriangle, Activity, GitMerge, Zap, Brain } from 'lucide-react';
import PriorityBadge from '../components/common/PriorityBadge.jsx';
import ThreatDetailPanel from '../components/dashboard/ThreatDetailPanel.jsx';
import { getCorrelations } from '../api/correlationsApi.js';
import { getRiskScores } from '../api/riskApi.js';
import { getHealthStatus } from '../api/healthApi.js';
import { getIntelligenceReport } from '../api/intelligenceApi.js';

// Lazy-load the heavy 3D graph
const CorrelationGraph3D = lazy(() => import('../components/dashboard/CorrelationGraph3D.jsx'));

const VIEW_LIST  = 'list';
const VIEW_GRAPH = 'graph';

function StatCard({ label, value, icon: Icon, colorClass, loading }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="panel-card p-4 flex items-center gap-4"
    >
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${colorClass} bg-opacity-10`}
           style={{ background: 'rgba(255,255,255,0.04)' }}>
        <Icon size={18} className={colorClass} />
      </div>
      <div>
        {loading
          ? <div className="skeleton w-8 h-6 mb-1" />
          : <p className="text-xl font-bold text-white">{value ?? '—'}</p>
        }
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
      </div>
    </motion.div>
  );
}

function ThreatRow({ item, onClick, isSelected }) {
  const priority = item.riskScore?.priority || item.priority || 'low';
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      whileHover={{ backgroundColor: 'var(--bg-hover)' }}
      onClick={() => onClick(item)}
      className={`flex items-center gap-3 px-4 py-3 cursor-pointer border-b transition-all ${
        isSelected ? 'bg-[var(--bg-hover)] border-l-2 border-l-[var(--accent)]' : 'border-[var(--border)]'
      }`}
      style={{ borderColor: 'var(--border)' }}
    >
      <PriorityBadge priority={priority} pulse />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white truncate">{item.title}</p>
        <p className="text-xs mt-0.5 truncate mono" style={{ color: 'var(--text-muted)' }}>
          {(item.sourceIps || item.source_ips || []).slice(0, 2).join(', ') || 'No source IP'}
          {' → '}
          {(item.targets || []).slice(0, 1).join(', ') || 'Unknown target'}
        </p>
      </div>
      <div className="text-right flex-shrink-0">
        <p className="text-lg font-bold" style={{ color: priority === 'critical' ? 'var(--critical)' : priority === 'high' ? 'var(--high)' : priority === 'medium' ? 'var(--medium)' : 'var(--low)' }}>
          {item.riskScore?.score ?? '?'}
        </p>
        <p className="text-[10px]" style={{ color: 'var(--text-dim)' }}>risk</p>
      </div>
    </motion.div>
  );
}

export default function Dashboard() {
  const [view, setView]               = useState(VIEW_LIST);
  const [correlations, setCorrelations] = useState([]);
  const [riskMap, setRiskMap]         = useState({});
  const [loading, setLoading]         = useState(true);
  const [selected, setSelected]       = useState(null);
  const [aiStatus, setAiStatus]       = useState(null);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [corrData, riskData, health] = await Promise.all([
        getCorrelations({ limit: 100 }),
        getRiskScores({ limit: 100 }),
        getHealthStatus(),
      ]);

      const corrs = corrData.correlations || corrData.data || corrData || [];
      const risks = riskData.riskScores || riskData.data || riskData || [];

      // Build risk lookup by correlation_id
      const map = {};
      for (const r of risks) map[r.correlation_id || r.correlationId] = r;
      setRiskMap(map);

      // Merge risk into correlations and sort by score desc
      const merged = corrs.map(c => ({ ...c, riskScore: map[c.id] }));
      merged.sort((a, b) => (b.riskScore?.score || 0) - (a.riskScore?.score || 0));
      setCorrelations(merged);
      setAiStatus(health?.ai_available);
      setLastRefresh(new Date());
    } catch (e) {
      console.error('[Dashboard] Load error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // KPI counts
  const kpis = {
    critical: correlations.filter(c => c.riskScore?.priority === 'critical').length,
    high:     correlations.filter(c => c.riskScore?.priority === 'high').length,
    total:    correlations.length,
    falsePoz: 0, // will come from intel reports
  };

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: 'var(--bg-primary)' }}>
      {/* ── Top Navigation Bar ── */}
      <header className="glass flex items-center justify-between px-6 py-3 z-20 border-b" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: 'var(--accent-glow)', border: '1px solid var(--accent)' }}>
            <Shield size={16} style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wide" style={{ color: 'var(--text-primary)' }}>CyberFusion</h1>
            <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>AI Threat Intelligence Platform</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* AI Status */}
          <div className="flex items-center gap-1.5">
            <Brain size={13} style={{ color: aiStatus ? 'var(--low)' : 'var(--text-dim)' }} />
            <span className="text-[11px]" style={{ color: aiStatus ? 'var(--low)' : 'var(--text-dim)' }}>
              {aiStatus === null ? 'Checking AI...' : aiStatus ? 'AI Online' : 'AI Offline'}
            </span>
          </div>

          {/* Last refresh */}
          <span className="text-[11px]" style={{ color: 'var(--text-dim)' }}>
            Updated {lastRefresh.toLocaleTimeString()}
          </span>

          {/* Refresh button */}
          <button onClick={load} disabled={loading} className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all"
            style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>

          {/* View toggle */}
          <div className="flex rounded-md overflow-hidden" style={{ border: '1px solid var(--border)' }}>
            {[
              { id: VIEW_LIST,  Icon: List,    label: 'List' },
              { id: VIEW_GRAPH, Icon: Network,  label: '3D Graph' },
            ].map(({ id, Icon, label }) => (
              <button key={id} onClick={() => setView(id)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-all"
                style={{
                  background: view === id ? 'var(--accent)' : 'var(--bg-card)',
                  color: view === id ? '#fff' : 'var(--text-muted)',
                }}>
                <Icon size={12} />
                {label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* ── KPI Bar ── */}
      <div className="grid grid-cols-4 gap-4 px-6 py-4 border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg-secondary)' }}>
        <StatCard label="Critical Threats"  value={kpis.critical} icon={AlertTriangle} colorClass="text-red-400"    loading={loading} />
        <StatCard label="High Priority"      value={kpis.high}     icon={Zap}           colorClass="text-orange-400" loading={loading} />
        <StatCard label="Total Correlations" value={kpis.total}    icon={GitMerge}      colorClass="text-sky-400"    loading={loading} />
        <StatCard label="Events Analysed"   value={correlations.reduce((s,c)=>s+(c.event_count||0),0)} icon={Activity} colorClass="text-purple-400" loading={loading} />
      </div>

      {/* ── Main Body ── */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: threat list */}
        <aside className="flex flex-col border-r" style={{ width: '340px', flexShrink: 0, borderColor: 'var(--border)', background: 'var(--bg-secondary)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border)' }}>
            <p className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
              Priority Queue · {correlations.length}
            </p>
          </div>
          <div className="flex-1 overflow-y-auto">
            {loading
              ? Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="px-4 py-3 border-b" style={{ borderColor: 'var(--border)' }}>
                    <div className="skeleton h-4 w-3/4 mb-2" />
                    <div className="skeleton h-3 w-1/2" />
                  </div>
                ))
              : correlations.length === 0
                ? <p className="text-center text-xs py-12" style={{ color: 'var(--text-dim)' }}>No correlations yet</p>
                : correlations.map(c => (
                    <ThreatRow key={c.id} item={c} onClick={setSelected} isSelected={selected?.id === c.id} />
                  ))
            }
          </div>
        </aside>

        {/* Right: main content area */}
        <main className="flex-1 overflow-hidden relative">
          <AnimatePresence mode="wait">
            {view === VIEW_LIST ? (
              <motion.div key="list" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="h-full flex overflow-hidden">
                {/* Detail panel or empty state */}
                {selected
                  ? <ThreatDetailPanel correlation={selected} riskScore={selected.riskScore} onClose={() => setSelected(null)} aiOnline={aiStatus} />
                  : (
                    <div className="flex-1 flex items-center justify-center">
                      <div className="text-center">
                        <Shield size={48} style={{ color: 'var(--text-dim)', margin: '0 auto 16px' }} />
                        <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Select a threat from the queue</p>
                        <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>AI analysis, risk breakdown, and event timeline will appear here</p>
                      </div>
                    </div>
                  )
                }
              </motion.div>
            ) : (
              <motion.div key="graph" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="h-full">
                <Suspense fallback={
                  <div className="h-full flex items-center justify-center">
                    <div className="text-center">
                      <div className="skeleton w-12 h-12 rounded-full mx-auto mb-4" />
                      <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Loading 3D Graph...</p>
                    </div>
                  </div>
                }>
                  <CorrelationGraph3D correlations={correlations} onNodeClick={c => { setSelected(c); setView(VIEW_LIST); }} />
                </Suspense>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

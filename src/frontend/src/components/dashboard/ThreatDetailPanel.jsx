import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Clock, Server, Globe, Brain, ChevronDown, ChevronUp, AlertCircle, CheckCircle, Activity } from 'lucide-react';
import PriorityBadge from '../common/PriorityBadge.jsx';
import { getIntelligenceReport, triggerAnalysis } from '../../api/intelligenceApi.js';
import { getCorrelationEvents } from '../../api/correlationsApi.js';

function RiskGauge({ score = 0 }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 75 ? 'var(--critical)' : pct >= 50 ? 'var(--high)' : pct >= 25 ? 'var(--medium)' : 'var(--low)';
  const r = 42, circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--bg-card)" strokeWidth="10" />
        <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
          style={{ transform: 'rotate(-90deg)', transformOrigin: '50% 50%', transition: 'stroke-dashoffset 0.8s ease' }} />
        <text x="50" y="46" textAnchor="middle" fill={color} fontSize="18" fontWeight="700" fontFamily="Inter">{score}</text>
        <text x="50" y="60" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter">RISK</text>
      </svg>
    </div>
  );
}

function RiskBar({ label, value, max = 30 }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px]">
        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span className="font-medium mono" style={{ color: 'var(--text-primary)' }}>{value}</span>
      </div>
      <div className="h-1.5 rounded-full" style={{ background: 'var(--bg-hover)' }}>
        <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, delay: 0.1 }} style={{ background: 'var(--accent)' }} />
      </div>
    </div>
  );
}

function EventTimeline({ events }) {
  if (!events?.length) return <p className="text-xs" style={{ color: 'var(--text-dim)' }}>No events found.</p>;
  return (
    <div className="space-y-2">
      {events.map((e, i) => (
        <motion.div key={e.id || i} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
          className="flex gap-3 items-start">
          <div className="flex flex-col items-center pt-1 flex-shrink-0">
            <div className={`dot dot-${e.severity || 'low'}`} />
            {i < events.length - 1 && <div className="w-px flex-1 mt-1" style={{ background: 'var(--border)', minHeight: 16 }} />}
          </div>
          <div className="pb-2 min-w-0">
            <p className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>{e.event_type}</p>
            <p className="text-[11px] mono mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {e.source_ip || '—'} → {e.target || '—'}
            </p>
            <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-dim)' }}>
              {new Date(e.timestamp).toLocaleString()}
            </p>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

function AiPanel({ correlationId, aiOnline }) {
  const [report, setReport]     = useState(null);
  const [loading, setLoading]   = useState(true);
  const [analysing, setAnalysing] = useState(false);
  const [open, setOpen]         = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    getIntelligenceReport(correlationId)
      .then(r => { if (alive) setReport(r?.report || r); })
      .catch(() => {})
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [correlationId]);

  async function handleAnalyse() {
    setAnalysing(true);
    try {
      const r = await triggerAnalysis(correlationId);
      setReport(r?.report || r);
    } catch { /* noop */ }
    finally { setAnalysing(false); }
  }

  const categorization = report?.categorization;
  const isFalsePos = report?.is_false_positive;

  return (
    <div className="panel-card overflow-hidden">
      <button className="w-full flex items-center justify-between px-4 py-3" onClick={() => setOpen(o => !o)}>
        <div className="flex items-center gap-2">
          <Brain size={14} style={{ color: 'var(--accent)' }} />
          <span className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--text-secondary)' }}>AI Intelligence</span>
          {categorization && (
            <span className={`badge badge-${categorization.toLowerCase()}`}>{categorization}</span>
          )}
          {isFalsePos && (
            <span className="badge" style={{ background: 'rgba(100,100,120,.15)', color: '#aab', borderColor: '#445' }}>
              <CheckCircle size={10} /> False Positive
            </span>
          )}
        </div>
        {open ? <ChevronUp size={14} style={{ color: 'var(--text-muted)' }} /> : <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div key="body" initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
            <div className="px-4 pb-4 space-y-3">
              {!aiOnline && (
                <div className="flex items-center gap-2 text-xs rounded-md px-3 py-2"
                  style={{ background: 'rgba(255,140,0,.08)', border: '1px solid rgba(255,140,0,.2)', color: 'var(--high)' }}>
                  <AlertCircle size={12} /> AI service offline — analysis unavailable
                </div>
              )}
              {loading
                ? <><div className="skeleton h-3 w-full mb-1" /><div className="skeleton h-3 w-4/5" /></>
                : report
                  ? (
                    <div className="space-y-3">
                      <div className="rounded-md px-3 py-2 text-xs" style={{ background: 'var(--bg-hover)', border: '1px solid var(--border)' }}>
                        <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: 'var(--text-muted)' }}>BLUF</p>
                        <p style={{ color: 'var(--text-primary)' }}>{report.bluf}</p>
                      </div>
                      {report.threat_assessment && (
                        <div>
                          <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: 'var(--text-muted)' }}>Assessment</p>
                          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{report.threat_assessment}</p>
                        </div>
                      )}
                      {report.recommended_actions?.length > 0 && (
                        <div>
                          <p className="text-[10px] uppercase tracking-widest mb-2" style={{ color: 'var(--text-muted)' }}>Actions</p>
                          <ul className="space-y-1">
                            {report.recommended_actions.map((a, i) => (
                              <li key={i} className="flex gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
                                <span style={{ color: 'var(--accent)' }}>›</span> {a}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )
                  : (
                    <div className="text-center py-2">
                      <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>No analysis yet for this correlation.</p>
                      {aiOnline && (
                        <button onClick={handleAnalyse} disabled={analysing}
                          className="px-4 py-2 rounded-md text-xs font-medium transition-all"
                          style={{ background: 'var(--accent)', color: '#fff', opacity: analysing ? 0.6 : 1 }}>
                          {analysing ? 'Analysing...' : '⚡ Run AI Analysis'}
                        </button>
                      )}
                    </div>
                  )
              }
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function ThreatDetailPanel({ correlation, riskScore, onClose, aiOnline }) {
  const [events, setEvents] = useState([]);
  const [evtLoading, setEvtLoading] = useState(true);

  useEffect(() => {
    if (!correlation?.id) return;
    setEvtLoading(true);
    getCorrelationEvents(correlation.id)
      .then(d => setEvents(d?.events || d || []))
      .catch(() => {})
      .finally(() => setEvtLoading(false));
  }, [correlation?.id]);

  const priority = riskScore?.priority || 'low';

  return (
    <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}
      className="flex-1 flex flex-col overflow-hidden" style={{ background: 'var(--bg-primary)' }}>
      {/* Header */}
      <div className="flex items-start justify-between px-6 py-4 border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg-secondary)' }}>
        <div className="flex-1 min-w-0 pr-4">
          <div className="flex items-center gap-3 mb-1">
            <PriorityBadge priority={priority} pulse />
          </div>
          <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>{correlation.title}</h2>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{correlation.description}</p>
        </div>
        <button onClick={onClose} className="p-1.5 rounded-md transition-all" style={{ color: 'var(--text-muted)' }}>
          <X size={16} />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-5">
        {/* Risk gauge + breakdown */}
        <div className="panel-card p-4">
          <div className="flex gap-6 items-start">
            <RiskGauge score={riskScore?.score || 0} />
            <div className="flex-1 space-y-3">
              <p className="text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>Risk Breakdown</p>
              <RiskBar label="Severity"            value={riskScore?.severity_component || riskScore?.severityComponent || 0} max={30} />
              <RiskBar label="IOC Match"           value={riskScore?.ioc_match_component || riskScore?.iocMatchComponent || 0} max={25} />
              <RiskBar label="Asset Criticality"   value={riskScore?.asset_criticality_component || riskScore?.assetCriticalityComponent || 0} max={20} />
              <RiskBar label="Correlation Strength" value={riskScore?.correlation_strength_component || riskScore?.correlationStrengthComponent || 0} max={15} />
              <RiskBar label="Recency"             value={riskScore?.recency_component || riskScore?.recencyComponent || 0} max={10} />
            </div>
          </div>
        </div>

        {/* Meta info */}
        <div className="grid grid-cols-2 gap-3">
          {[
            { icon: Activity,  label: 'Events',    value: correlation.event_count ?? '—' },
            { icon: Clock,     label: 'First Seen', value: correlation.first_seen ? new Date(correlation.first_seen).toLocaleDateString() : '—' },
            { icon: Globe,     label: 'Source IPs', value: (correlation.source_ips || correlation.sourceIps || []).join(', ') || '—' },
            { icon: Server,    label: 'Targets',   value: (correlation.targets || []).join(', ') || '—' },
          ].map(({ icon: Icon, label, value }) => (
            <div key={label} className="panel-card px-3 py-2.5 flex items-center gap-2">
              <Icon size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
              <div className="min-w-0">
                <p className="text-[10px] uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>{label}</p>
                <p className="text-xs font-medium truncate mono" style={{ color: 'var(--text-primary)' }}>{value}</p>
              </div>
            </div>
          ))}
        </div>

        {/* AI Panel */}
        <AiPanel correlationId={correlation.id} aiOnline={aiOnline} />

        {/* Event Timeline */}
        <div className="panel-card p-4">
          <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--text-muted)' }}>Event Timeline</p>
          {evtLoading
            ? <div className="skeleton h-20 w-full" />
            : <EventTimeline events={events} />
          }
        </div>
      </div>
    </motion.div>
  );
}

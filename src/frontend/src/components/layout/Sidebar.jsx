import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Shield,
  Bell,
  GitBranch,
  Brain,
  Settings,
  ChevronRight,
} from 'lucide-react';

/**
 * Sidebar — primary navigation for the analyst console.
 * Uses React Router NavLink for active state detection.
 */

const NAV_ITEMS = [
  { to: '/',             icon: LayoutDashboard, label: 'Dashboard',    end: true },
  { to: '/threats',      icon: Shield,          label: 'Threats' },
  { to: '/alerts',       icon: Bell,            label: 'Alerts' },
  { to: '/correlations', icon: GitBranch,       label: 'Correlations' },
  { to: '/intelligence', icon: Brain,           label: 'Intelligence' },
];

export default function Sidebar() {
  return (
    <nav
      className="w-52 flex-shrink-0 bg-[#0e1117] border-r border-[#1e2a3b] flex flex-col"
      aria-label="Primary navigation"
    >
      {/* Logo / brand */}
      <div className="h-12 flex items-center px-4 border-b border-[#1e2a3b]">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-sky-600/20 border border-sky-600/40 flex items-center justify-center">
            <Shield className="w-3.5 h-3.5 text-sky-400" />
          </div>
          <span className="text-sm font-bold text-slate-100 tracking-wide">
            Cyber<span className="text-sky-400">Fusion</span>
          </span>
        </div>
      </div>

      {/* Navigation items */}
      <div className="flex-1 py-3 space-y-0.5 px-2 overflow-y-auto">
        <p className="px-2 py-1 text-[10px] font-semibold text-slate-600 uppercase tracking-widest">
          Operations
        </p>
        {NAV_ITEMS.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center justify-between gap-2.5 px-2.5 py-2 rounded text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-sky-600/15 text-sky-300 border border-sky-600/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <div className="flex items-center gap-2.5">
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span>{label}</span>
                </div>
                {isActive && <ChevronRight className="w-3 h-3 text-sky-500" />}
              </>
            )}
          </NavLink>
        ))}
      </div>

      {/* Footer */}
      <div className="px-2 py-3 border-t border-[#1e2a3b]">
        <button className="flex items-center gap-2.5 px-2.5 py-2 w-full rounded text-xs font-medium text-slate-500 hover:text-slate-300 hover:bg-white/5 transition-colors">
          <Settings className="w-4 h-4" />
          Settings
        </button>
        <p className="px-2.5 pt-2 text-[10px] text-slate-700">v0.1.0 · ATOMIS Team</p>
      </div>
    </nav>
  );
}

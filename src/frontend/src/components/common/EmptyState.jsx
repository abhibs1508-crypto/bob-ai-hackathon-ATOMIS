import { ShieldOff } from 'lucide-react';

/**
 * EmptyState — professional empty data display.
 * Shown when a backend endpoint returns zero records.
 * Never displays fabricated threats or data.
 */
export default function EmptyState({
  title   = 'No active threats detected.',
  message = 'The analyst queue is currently clear.',
  icon: Icon = ShieldOff,
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 p-8 text-center">
      <div className="flex items-center justify-center w-12 h-12 rounded-full bg-slate-800/60 border border-slate-700/50">
        <Icon className="w-6 h-6 text-slate-500" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-slate-300">{title}</p>
        <p className="text-xs text-slate-500">{message}</p>
      </div>
    </div>
  );
}

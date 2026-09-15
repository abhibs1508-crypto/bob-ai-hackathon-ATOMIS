import { AlertTriangle, RefreshCw } from 'lucide-react';

/**
 * ErrorState — professional error display.
 * Never exposes stack traces, SQL, or internal paths.
 */
export default function ErrorState({
  title   = 'Unable to connect to intelligence services.',
  message = 'Check that the backend is running and try again.',
  onRetry,
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 p-8 text-center">
      <div className="flex items-center justify-center w-12 h-12 rounded-full bg-red-900/30 border border-red-800/50">
        <AlertTriangle className="w-6 h-6 text-red-400" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium text-slate-200">{title}</p>
        <p className="text-xs text-slate-500">{message}</p>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-2 btn-primary"
        >
          <RefreshCw className="w-3 h-3" />
          Retry
        </button>
      )}
    </div>
  );
}

/**
 * LoadingState — skeleton/spinner loading placeholder.
 * Used in every API-driven section to avoid blank screens.
 */
export default function LoadingState({ rows = 3, label = 'Loading intelligence data…' }) {
  return (
    <div className="space-y-2 p-4" role="status" aria-label={label}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton h-14 w-full rounded" />
      ))}
      <p className="text-center text-xs text-slate-600 pt-1">{label}</p>
    </div>
  );
}

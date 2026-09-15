/**
 * StatCard — reusable KPI summary card.
 * Displays a count, label, optional trend, and icon.
 * Only renders data provided — never fabricates values.
 */
export default function StatCard({
  label,
  value,
  icon: Icon,
  colour = 'text-slate-300',
  bgColour = 'bg-[#12161d]',
  borderColour = 'border-[#1e2a3b]',
  subLabel,
  loading = false,
}) {
  return (
    <div className={`panel flex flex-col gap-3 p-4 ${bgColour} ${borderColour}`}>
      <div className="flex items-start justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">
          {label}
        </p>
        {Icon && (
          <div className={`w-7 h-7 rounded flex items-center justify-center bg-white/5`}>
            <Icon className={`w-4 h-4 ${colour}`} />
          </div>
        )}
      </div>

      {loading ? (
        <div className="skeleton h-8 w-16 rounded" />
      ) : (
        <div className={`text-3xl font-bold tracking-tight ${colour}`}>
          {value ?? '—'}
        </div>
      )}

      {subLabel && (
        <p className="text-[11px] text-slate-600">{subLabel}</p>
      )}
    </div>
  );
}

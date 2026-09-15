import { Construction } from 'lucide-react';

/**
 * PlaceholderPage — coming-soon stub for navigation routes not yet implemented.
 * Clearly communicates to evaluators that the module is planned for Phase 7B.
 */
export default function PlaceholderPage({ title, description, icon }) {
  return (
    <div className="flex flex-col gap-0 h-full">
      <div className="px-6 py-4 border-b border-[#1e2a3b]">
        <h1 className="text-base font-bold text-slate-100">{title}</h1>
      </div>
      <div className="flex-1 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-center max-w-sm">
          <div className="w-14 h-14 rounded-full bg-[#1b2130] border border-[#263045] flex items-center justify-center">
            <Construction className="w-7 h-7 text-slate-500" />
          </div>
          <div>
            <p className="text-sm font-medium text-slate-300 mb-1">{title}</p>
            <p className="text-xs text-slate-500">{description}</p>
          </div>
          <span className="tag bg-[#1b2130] text-slate-500 border border-[#263045]">
            Coming in Phase 7B
          </span>
        </div>
      </div>
    </div>
  );
}

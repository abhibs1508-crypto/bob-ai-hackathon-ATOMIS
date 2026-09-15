import { Link } from 'react-router-dom';
import { Home } from 'lucide-react';

/**
 * NotFound — 404 page for unmatched routes.
 */
export default function NotFound() {
  return (
    <div className="flex flex-col gap-0 h-full">
      <div className="px-6 py-4 border-b border-[#1e2a3b]">
        <h1 className="text-base font-bold text-slate-100">Page Not Found</h1>
      </div>
      <div className="flex-1 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4 text-center">
          <p className="text-5xl font-bold text-slate-800">404</p>
          <div>
            <p className="text-sm font-medium text-slate-300">Route not recognised</p>
            <p className="text-xs text-slate-500 mt-1">
              The path you requested does not exist in this console.
            </p>
          </div>
          <Link
            to="/"
            className="flex items-center gap-2 btn-primary"
          >
            <Home className="w-3 h-3" />
            Return to Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}

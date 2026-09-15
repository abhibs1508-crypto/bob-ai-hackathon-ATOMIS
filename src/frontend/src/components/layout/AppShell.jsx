import { Outlet } from 'react-router-dom';
import TopBar from './TopBar.jsx';
import Sidebar from './Sidebar.jsx';

/**
 * AppShell — top-level layout wrapper.
 *
 * Structure:
 *   TopBar (full width, fixed height)
 *   ├── Sidebar (fixed width left column)
 *   └── Main content area (scrollable, fills remaining space)
 *
 * <Outlet /> renders the matched child route inside the main area.
 */
export default function AppShell() {
  return (
    <div className="flex flex-col h-full bg-[#0a0c0f]">
      <TopBar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-[#0e1117]">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './components/layout/AppShell.jsx';
import Dashboard from './pages/Dashboard.jsx';
import PlaceholderPage from './pages/PlaceholderPage.jsx';
import NotFound from './pages/NotFound.jsx';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="threats"      element={<PlaceholderPage title="Threat Browser"    description="Full threat event browser — coming in Phase 7B." icon="shield" />} />
          <Route path="alerts"       element={<PlaceholderPage title="Alert Queue"        description="Alert management and status tracking — coming in Phase 7B." icon="bell" />} />
          <Route path="correlations" element={<PlaceholderPage title="Correlation Graph"  description="Interactive event correlation graph — coming in Phase 7B." icon="git-branch" />} />
          <Route path="intelligence" element={<PlaceholderPage title="AI Intelligence"    description="Deep AI-generated intelligence reports — coming in Phase 7B." icon="brain" />} />
          <Route path="*"            element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

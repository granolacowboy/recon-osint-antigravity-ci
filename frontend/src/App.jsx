import { Navigate, Route, Routes } from 'react-router-dom';

import AppShell from './components/AppShell';
import CaseDetailPage from './pages/CaseDetailPage';
import CasesPage from './pages/CasesPage';
import ScanDetailPage from './pages/ScanDetailPage';
import './index.css';

export function AppRoutes() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Navigate replace to="/cases" />} />
        <Route path="/cases" element={<CasesPage />} />
        <Route path="/cases/:caseId" element={<CaseDetailPage />} />
        <Route path="/scans/:scanId" element={<ScanDetailPage />} />
        <Route path="*" element={<Navigate replace to="/cases" />} />
      </Routes>
    </AppShell>
  );
}

export default AppRoutes;

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Overview from './pages/Overview';
import URLAnalyzer from './pages/URLAnalyzer';
import Incidents from './pages/Incidents';
import IncidentDetails from './pages/IncidentDetails';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Settings from './pages/Settings';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
        {/* Left Sidebar */}
        <Sidebar />

        {/* Right Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto bg-grid-pattern">
          {/* Topbar */}
          <Topbar />

          {/* Main Route Content */}
          <main className="flex-1 p-6 md:p-8 max-w-7xl w-full mx-auto">
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/analyze" element={<URLAnalyzer />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/incidents/:id" element={<IncidentDetails />} />
              <Route path="/threat-intel" element={<ThreatIntelligence />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
};

export default App;

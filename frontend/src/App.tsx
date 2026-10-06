import React, { useState } from 'react';
import { Header } from './components/common/Header';
import { Sidebar } from './components/common/Sidebar';

// Pages
import { Dashboard } from './pages/Dashboard';
import { ThreatScanner } from './pages/ThreatScanner';
import { PhishingScanner } from './pages/PhishingScanner';
import { DeepfakeScanner } from './pages/DeepfakeScanner';
import { BehaviorAnalyzer } from './pages/BehaviorAnalyzer';
import { Incidents } from './pages/Incidents';
import { Analytics } from './pages/Analytics';
import { Settings } from './pages/Settings';

export function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');

  const renderContent = () => {
    switch (currentTab) {
      case 'dashboard':
        return <Dashboard onNavigate={(tab) => setCurrentTab(tab)} />;
      case 'scanner':
        return <ThreatScanner />;
      case 'phishing':
        return <PhishingScanner />;
      case 'deepfake':
        return <DeepfakeScanner />;
      case 'behavior':
        return <BehaviorAnalyzer />;
      case 'incidents':
        return <Incidents />;
      case 'analytics':
        return <Analytics />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard onNavigate={(tab) => setCurrentTab(tab)} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#080b11] text-slate-100 flex flex-col cyber-grid-bg">
      <Header activeIncidentsCount={3} />
      <div className="flex-1 flex overflow-hidden">
        <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 max-w-[1720px] mx-auto w-full">
          {renderContent()}
        </main>
      </div>
    </div>
  );
}

export default App;

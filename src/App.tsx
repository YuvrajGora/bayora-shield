import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext.tsx';
import { Header, NavTab } from './components/Header.tsx';
import { LoginModal } from './components/LoginModal.tsx';
import { RedTeamSandbox } from './components/RedTeamSandbox.tsx';
import { BlueTeamRules } from './components/BlueTeamRules.tsx';
import { PolicyGatewayPlayground } from './components/PolicyGatewayPlayground.tsx';
import { AuditLedger } from './components/AuditLedger.tsx';
import { AutomatedTestSuite } from './components/AutomatedTestSuite.tsx';
import { StorageArchitecture } from './components/StorageArchitecture.tsx';
import { api } from './services/api.ts';
import { ShieldX, AlertOctagon, Lock, RefreshCw, KeyRound, ShieldAlert, Cpu } from 'lucide-react';

function DashboardContent() {
  const { user, loading } = useAuth();
  const [currentTab, setCurrentTab] = useState<NavTab>('red_team');
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  const handleResetDatabase = async () => {
    setResetting(true);
    try {
      await api.resetDatabase();
      setIsResetModalOpen(false);
      window.location.reload();
    } catch (err: any) {
      alert(`Reset failed: ${err.message}`);
    } finally {
      setResetting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0f1d] flex items-center justify-center text-slate-400 text-xs">
        <div className="space-y-3 text-center">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="font-mono text-cyan-300">Initializing Bayora Shield Gateway...</p>
        </div>
      </div>
    );
  }

  // Handle Unauthorized tab views gracefully with security boundary notice
  const renderTabContent = () => {
    if (!user) {
      return (
        <div className="max-w-xl mx-auto py-16 px-4 text-center space-y-6">
          <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mx-auto shadow-lg shadow-cyan-950/50">
            <Lock className="w-8 h-8" />
          </div>
          <div className="space-y-2">
            <h2 className="text-2xl font-bold tracking-tight text-white">
              Authentication Required
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed max-w-md mx-auto">
              Bayora Shield enforces strict server-side role-based access control. Please authenticate with a verified persona to access the security testing environment.
            </p>
          </div>
          <div className="pt-2">
            <button
              onClick={() => setIsLoginModalOpen(true)}
              className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition-colors shadow-lg shadow-cyan-950/40 cursor-pointer"
            >
              Sign In with Security Persona
            </button>
          </div>
        </div>
      );
    }

    // Role boundary: Red Team trying to view Blue Team rules directly
    if (currentTab === 'blue_team' && user?.role === 'red_team') {
      return (
        <div className="max-w-2xl mx-auto py-12 px-4 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-rose-950/60 border border-rose-500/50 flex items-center justify-center text-rose-400 mx-auto">
            <Lock className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Security Isolation Barrier: Blue Team Rules Segregated
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed max-w-lg mx-auto">
            Bayora Shield enforces strict cryptographic and software role separation. Red Team operators are explicitly barred from viewing or downloading Blue Team defensive rules to ensure genuine adversarial testing integrity.
          </p>

          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded text-xs font-mono text-slate-300 max-w-md mx-auto text-left space-y-1">
            <div className="text-slate-500">Security Rule:</div>
            <div className="text-rose-400 font-semibold">GET /api/rules → HTTP 403 Forbidden</div>
            <div className="text-slate-400">Actor: {user.email} (red_team)</div>
          </div>

          <div className="pt-2 flex items-center justify-center gap-3">
            <button
              onClick={() => setIsLoginModalOpen(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold transition-colors cursor-pointer"
            >
              Authenticate as Blue Team Persona
            </button>
            <button
              onClick={() => setCurrentTab('red_team')}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors cursor-pointer"
            >
              Back to Red Team Sandbox
            </button>
          </div>
        </div>
      );
    }

    switch (currentTab) {
      case 'red_team':
        return <RedTeamSandbox />;
      case 'blue_team':
        return <BlueTeamRules />;
      case 'gateway':
        return <PolicyGatewayPlayground />;
      case 'audit':
        return <AuditLedger />;
      case 'tests':
        return <AutomatedTestSuite />;
      case 'architecture':
        return <StorageArchitecture />;
      default:
        return <RedTeamSandbox />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0f1d] text-slate-100 flex flex-col font-sans">
      <Header
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        onOpenResetModal={() => setIsResetModalOpen(true)}
        onOpenLoginModal={() => setIsLoginModalOpen(true)}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {renderTabContent()}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#070b14] py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">Bayora Shield</span>
            <span>·</span>
            <span>AI Testing Security & Policy Interception Gateway</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span>Deterministic Mock AI Sandbox</span>
            <span>·</span>
            <button
              onClick={() => setIsLoginModalOpen(true)}
              className="text-cyan-400 hover:underline cursor-pointer"
            >
              Switch Role
            </button>
          </div>
        </div>
      </footer>

      {/* Login / Persona Modal */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
      />

      {/* Reset Confirmation Modal */}
      {isResetModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-[#0b1120] border border-slate-800 rounded-lg max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-amber-400">
              <AlertOctagon className="w-6 h-6 shrink-0" />
              <h3 className="text-base font-bold text-white">Reset Database to Seed State?</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              This will restore all default rules, seed test runs, and initial audit logs. Useful for clearing test artifacts during a hackathon evaluation presentation.
            </p>
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsResetModalOpen(false)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleResetDatabase}
                disabled={resetting}
                className="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:bg-slate-800 text-white rounded text-xs font-semibold transition-colors"
              >
                {resetting ? 'Resetting...' : 'Confirm Factory Reset'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <DashboardContent />
    </AuthProvider>
  );
}

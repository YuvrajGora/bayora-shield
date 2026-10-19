import React from 'react';
import { useAuth } from '../context/AuthContext.tsx';
import { Shield, ShieldAlert, ShieldCheck, Database, RefreshCw, Terminal, LogOut } from 'lucide-react';
import { Role } from '../types/index.ts';

export type NavTab = 'red_team' | 'blue_team' | 'gateway' | 'audit' | 'tests' | 'architecture';

interface HeaderProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenResetModal: () => void;
  onOpenLoginModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({ currentTab, onSelectTab, onOpenResetModal, onOpenLoginModal }) => {
  const { user, logout } = useAuth();

  const getRoleDisplayName = (role: Role) => {
    switch (role) {
      case 'admin':
        return 'Admin (All Access)';
      case 'red_team':
        return 'Red Team (Attacker)';
      case 'blue_team':
        return 'Blue Team (Defender)';
    }
  };

  return (
    <header className="border-b border-slate-800/80 bg-[#070b14]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand title wordmark */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-9 h-9 rounded bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950/50">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <button
            onClick={() => onSelectTab(user?.role === 'red_team' ? 'red_team' : 'blue_team')}
            className="text-lg font-bold tracking-tight text-white hover:text-cyan-300 transition-colors whitespace-nowrap text-left"
          >
            Bayora Shield
          </button>
        </div>

        {/* Zone 2: Navigation Links (single-line, clean typography) */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium">
          <button
            onClick={() => onSelectTab('red_team')}
            className={`whitespace-nowrap transition-colors py-1 ${
              currentTab === 'red_team'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Red Team
          </button>

          <button
            onClick={() => onSelectTab('blue_team')}
            className={`whitespace-nowrap transition-colors py-1 ${
              currentTab === 'blue_team'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Blue Team
          </button>

          <button
            onClick={() => onSelectTab('gateway')}
            className={`whitespace-nowrap transition-colors py-1 ${
              currentTab === 'gateway'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Policy Gateway
          </button>

          <button
            onClick={() => onSelectTab('audit')}
            className={`whitespace-nowrap transition-colors py-1 ${
              currentTab === 'audit'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Audit Trail
          </button>

          <button
            onClick={() => onSelectTab('tests')}
            className={`whitespace-nowrap transition-colors py-1 ${
              currentTab === 'tests'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Automated Tests
          </button>

          <button
            onClick={() => onSelectTab('architecture')}
            className={`whitespace-nowrap transition-colors py-1 ${
              currentTab === 'architecture'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Storage & Architecture
          </button>
        </nav>

        {/* Zone 3: Active Profile, Role Switcher, Reset & Logout */}
        <div className="flex items-center gap-3 shrink-0">
          {user ? (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-300">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <span className="font-semibold text-white">{user.name}</span>
                <span className="text-slate-500">·</span>
                <span className={`font-mono font-medium ${
                  user.role === 'admin' ? 'text-cyan-400' : user.role === 'red_team' ? 'text-rose-400' : 'text-blue-400'
                }`}>
                  {user.role === 'admin' ? 'Admin' : user.role === 'red_team' ? 'Red Team' : 'Blue Team'}
                </span>
              </div>

              <button
                onClick={onOpenLoginModal}
                title="Switch Persona"
                className="px-2.5 py-1.5 text-xs text-slate-300 hover:text-cyan-300 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 rounded transition-colors whitespace-nowrap cursor-pointer"
              >
                Switch Persona
              </button>

              {user.role === 'admin' && (
                <button
                  onClick={onOpenResetModal}
                  title="Reset Demo Data"
                  className="p-1.5 text-slate-400 hover:text-cyan-400 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 rounded transition-colors"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              )}

              <button
                onClick={logout}
                title="Sign Out"
                className="p-1.5 text-slate-400 hover:text-rose-400 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 rounded transition-colors cursor-pointer"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenLoginModal}
              className="px-3.5 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors whitespace-nowrap cursor-pointer"
            >
              Sign In
            </button>
          )}
        </div>
      </div>

      {/* Mobile subnav */}
      <div className="md:hidden flex items-center justify-around overflow-x-auto py-2 px-3 border-t border-slate-800/60 bg-[#090e1a] text-xs">
        <button
          onClick={() => onSelectTab('red_team')}
          className={`px-2 py-1 whitespace-nowrap ${currentTab === 'red_team' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          Red Team
        </button>
        <button
          onClick={() => onSelectTab('blue_team')}
          className={`px-2 py-1 whitespace-nowrap ${currentTab === 'blue_team' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          Blue Team
        </button>
        <button
          onClick={() => onSelectTab('gateway')}
          className={`px-2 py-1 whitespace-nowrap ${currentTab === 'gateway' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          Gateway
        </button>
        <button
          onClick={() => onSelectTab('audit')}
          className={`px-2 py-1 whitespace-nowrap ${currentTab === 'audit' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          Audit
        </button>
        <button
          onClick={() => onSelectTab('tests')}
          className={`px-2 py-1 whitespace-nowrap ${currentTab === 'tests' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          Tests
        </button>
      </div>
    </header>
  );
};

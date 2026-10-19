import React from 'react';
import { useAuth } from '../context/AuthContext.tsx';
import { Role } from '../types/index.ts';
import { ShieldAlert, ShieldCheck, Shield, KeyRound, Lock, EyeOff } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const { switchRole, user } = useAuth();

  if (!isOpen) return null;

  const handleSelectRole = async (role: Role) => {
    await switchRole(role);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0b1120] border border-slate-800 rounded-lg max-w-2xl w-full p-6 shadow-2xl space-y-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            Switch Active Security Persona
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Bayora Shield enforces server-side role-based access control. Select a verified demo persona to test boundaries.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Admin */}
          <div
            onClick={() => handleSelectRole('admin')}
            className={`cursor-pointer p-4 rounded border transition-all text-left flex flex-col justify-between ${
              user?.role === 'admin'
                ? 'bg-cyan-950/30 border-cyan-500/80 shadow-sm shadow-cyan-950'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
            }`}
          >
            <div>
              <div className="w-8 h-8 rounded bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mb-3">
                <Shield className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-white">Administrator</h3>
              <p className="text-xs text-cyan-300 font-mono mt-0.5">admin@bayora.shield</p>
              <div className="text-xs text-slate-400 mt-3 space-y-1.5">
                <p>· Unrestricted audit oversight</p>
                <p>· Full gateway configuration</p>
                <p>· Run security test suites</p>
              </div>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleSelectRole('admin');
              }}
              className="mt-4 w-full py-1.5 px-3 bg-cyan-600/20 hover:bg-cyan-600/40 border border-cyan-500/40 text-cyan-300 rounded text-xs font-medium transition-colors"
            >
              {user?.role === 'admin' ? 'Active Persona' : 'Select Admin'}
            </button>
          </div>

          {/* Red Team */}
          <div
            onClick={() => handleSelectRole('red_team')}
            className={`cursor-pointer p-4 rounded border transition-all text-left flex flex-col justify-between ${
              user?.role === 'red_team'
                ? 'bg-rose-950/30 border-rose-500/80 shadow-sm shadow-rose-950'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
            }`}
          >
            <div>
              <div className="w-8 h-8 rounded bg-rose-950 border border-rose-500/40 flex items-center justify-center text-rose-400 mb-3">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-white">Red Team Operator</h3>
              <p className="text-xs text-rose-300 font-mono mt-0.5">redteam@bayora.shield</p>
              <div className="text-xs text-slate-400 mt-3 space-y-1.5">
                <p>· Submit harmless test probes</p>
                <p>· Query deterministic mock AI</p>
                <p className="text-rose-400">· Strictly barred from Blue rules</p>
              </div>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleSelectRole('red_team');
              }}
              className="mt-4 w-full py-1.5 px-3 bg-rose-600/20 hover:bg-rose-600/40 border border-rose-500/40 text-rose-300 rounded text-xs font-medium transition-colors"
            >
              {user?.role === 'red_team' ? 'Active Persona' : 'Select Red Team'}
            </button>
          </div>

          {/* Blue Team */}
          <div
            onClick={() => handleSelectRole('blue_team')}
            className={`cursor-pointer p-4 rounded border transition-all text-left flex flex-col justify-between ${
              user?.role === 'blue_team'
                ? 'bg-blue-950/30 border-blue-500/80 shadow-sm shadow-blue-950'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
            }`}
          >
            <div>
              <div className="w-8 h-8 rounded bg-blue-950 border border-blue-500/40 flex items-center justify-center text-blue-400 mb-3">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-white">Blue Team Defender</h3>
              <p className="text-xs text-blue-300 font-mono mt-0.5">blueteam@bayora.shield</p>
              <div className="text-xs text-slate-400 mt-3 space-y-1.5">
                <p>· Create & edit defensive rules</p>
                <p>· Monitor policy interception hits</p>
                <p className="text-blue-400">· Barred from running payloads</p>
              </div>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleSelectRole('blue_team');
              }}
              className="mt-4 w-full py-1.5 px-3 bg-blue-600/20 hover:bg-blue-600/40 border border-blue-500/40 text-blue-300 rounded text-xs font-medium transition-colors"
            >
              {user?.role === 'blue_team' ? 'Active Persona' : 'Select Blue Team'}
            </button>
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800 pt-4 text-xs text-slate-400">
          <span className="flex items-center gap-1.5">
            <EyeOff className="w-3.5 h-3.5 text-cyan-400" />
            Backend authorization validated on every request
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

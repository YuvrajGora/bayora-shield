import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext.tsx';
import { Role } from '../types/index.ts';
import { ShieldAlert, ShieldCheck, Shield, Lock, Eye, EyeOff, KeyRound, AlertTriangle } from 'lucide-react';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialRole?: Role;
}

const DEFAULT_DEMO_PASSWORDS: Record<Role, string> = {
  admin: 'bayora-admin-2026!',
  red_team: 'bayora-red-2026!',
  blue_team: 'bayora-blue-2026!',
};

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose, initialRole }) => {
  const { login, user } = useAuth();
  const [selectedRole, setSelectedRole] = useState<Role>(initialRole || user?.role || 'admin');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handlePersonaSelect = (role: Role) => {
    setSelectedRole(role);
    setError(null);
  };

  const handleFillDemoPassword = () => {
    setPassword(DEFAULT_DEMO_PASSWORDS[selectedRole]);
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) {
      setError('Please provide the account password.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await login({ role: selectedRole, password });
      setPassword('');
      onClose();
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-[#0b1120] border border-slate-800 rounded-lg max-w-2xl w-full p-6 shadow-2xl space-y-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            {user ? 'Switch Active Security Persona' : 'Sign In to Bayora Shield'}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Server-side role-based access control. Authenticate with verified persona credentials to acquire an authorized session.
          </p>
        </div>

        {error && (
          <div className="p-3 rounded bg-rose-950/60 border border-rose-500/50 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Persona Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Admin */}
          <div
            onClick={() => handlePersonaSelect('admin')}
            className={`cursor-pointer p-3.5 rounded border transition-all text-left flex flex-col justify-between ${
              selectedRole === 'admin'
                ? 'bg-cyan-950/40 border-cyan-500 shadow-sm shadow-cyan-950'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div>
              <div className="w-7 h-7 rounded bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mb-2">
                <Shield className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-bold text-white">Administrator</h3>
              <p className="text-[11px] text-cyan-300 font-mono">admin@bayora.shield</p>
              <div className="text-[11px] text-slate-400 mt-2 space-y-1">
                <p>· Full policy oversight</p>
                <p>· Run security test suite</p>
              </div>
            </div>
            <div className="mt-3 text-[11px] font-mono font-medium text-cyan-400">
              {selectedRole === 'admin' ? '✓ Selected' : 'Click to select'}
            </div>
          </div>

          {/* Red Team */}
          <div
            onClick={() => handlePersonaSelect('red_team')}
            className={`cursor-pointer p-3.5 rounded border transition-all text-left flex flex-col justify-between ${
              selectedRole === 'red_team'
                ? 'bg-rose-950/40 border-rose-500 shadow-sm shadow-rose-950'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div>
              <div className="w-7 h-7 rounded bg-rose-950 border border-rose-500/40 flex items-center justify-center text-rose-400 mb-2">
                <ShieldAlert className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-bold text-white">Red Team</h3>
              <p className="text-[11px] text-rose-300 font-mono">redteam@bayora.shield</p>
              <div className="text-[11px] text-slate-400 mt-2 space-y-1">
                <p>· Submit test probes</p>
                <p className="text-rose-400">· Barred from Blue rules</p>
              </div>
            </div>
            <div className="mt-3 text-[11px] font-mono font-medium text-rose-400">
              {selectedRole === 'red_team' ? '✓ Selected' : 'Click to select'}
            </div>
          </div>

          {/* Blue Team */}
          <div
            onClick={() => handlePersonaSelect('blue_team')}
            className={`cursor-pointer p-3.5 rounded border transition-all text-left flex flex-col justify-between ${
              selectedRole === 'blue_team'
                ? 'bg-blue-950/40 border-blue-500 shadow-sm shadow-blue-950'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div>
              <div className="w-7 h-7 rounded bg-blue-950 border border-blue-500/40 flex items-center justify-center text-blue-400 mb-2">
                <ShieldCheck className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-bold text-white">Blue Team</h3>
              <p className="text-[11px] text-blue-300 font-mono">blueteam@bayora.shield</p>
              <div className="text-[11px] text-slate-400 mt-2 space-y-1">
                <p>· Manage defense rules</p>
                <p className="text-blue-400">· Barred from running probes</p>
              </div>
            </div>
            <div className="mt-3 text-[11px] font-mono font-medium text-blue-400">
              {selectedRole === 'blue_team' ? '✓ Selected' : 'Click to select'}
            </div>
          </div>
        </div>

        {/* Authentication Form */}
        <form onSubmit={handleSubmit} className="space-y-4 pt-2 border-t border-slate-800">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
                Password for {selectedRole.toUpperCase().replace('_', ' ')}
              </label>
              <button
                type="button"
                onClick={handleFillDemoPassword}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 hover:underline cursor-pointer"
              >
                Use Local Demo Password ({DEFAULT_DEMO_PASSWORDS[selectedRole]})
              </button>
            </div>

            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={`Enter password for ${selectedRole}...`}
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 pr-10 font-mono"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-slate-500 font-mono">
              Unpredictable 256-bit server session
            </span>

            <div className="flex items-center gap-2">
              {user && (
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Cancel
                </button>
              )}
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white rounded text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {loading ? 'Authenticating...' : `Sign in as ${selectedRole.replace('_', ' ')}`}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};

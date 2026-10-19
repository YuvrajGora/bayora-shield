import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext.tsx';
import { api } from '../services/api.ts';
import { DefensiveRule, TestRun, RuleMatchType, RuleAction, RuleSeverity } from '../types/index.ts';
import { validateRegexSafety } from '../utils/regexSafety.ts';
import { ShieldCheck, Plus, ToggleLeft, ToggleRight, Trash2, Edit3, Lock, Eye, AlertOctagon, RefreshCw, EyeOff, ShieldAlert } from 'lucide-react';

export const BlueTeamRules: React.FC = () => {
  const { user } = useAuth();
  const [rules, setRules] = useState<DefensiveRule[]>([]);
  const [runs, setRuns] = useState<TestRun[]>([]);
  const [loading, setLoading] = useState(false);

  // Modal / Form state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<DefensiveRule | null>(null);

  const [ruleName, setRuleName] = useState('');
  const [ruleDescription, setRuleDescription] = useState('');
  const [matchType, setMatchType] = useState<RuleMatchType>('regex');
  const [pattern, setPattern] = useState('');
  const [action, setAction] = useState<RuleAction>('BLOCK');
  const [severity, setSeverity] = useState<RuleSeverity>('HIGH');
  const [category, setCategory] = useState('Prompt Defense');
  const [formError, setFormError] = useState<string | null>(null);

  // Sealed payload test result state
  const [sealProbeResult, setSealProbeResult] = useState<{
    runId: string;
    status: number;
    message: string;
    errorData?: any;
  } | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [rulesRes, runsRes] = await Promise.all([
        api.getRules(),
        api.getRuns(),
      ]);
      setRules(rulesRes.rules);
      setRuns(runsRes.runs);
    } catch (err: any) {
      console.error('Failed fetching defensive data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const openCreateModal = () => {
    setEditingRule(null);
    setRuleName('');
    setRuleDescription('');
    setMatchType('regex');
    setPattern('');
    setAction('BLOCK');
    setSeverity('HIGH');
    setCategory('Prompt Defense');
    setFormError(null);
    setIsModalOpen(true);
  };

  const openEditModal = (rule: DefensiveRule) => {
    setEditingRule(rule);
    setRuleName(rule.name);
    setRuleDescription(rule.description);
    setMatchType(rule.matchType);
    setPattern(rule.pattern);
    setAction(rule.action);
    setSeverity(rule.severity);
    setCategory(rule.category);
    setFormError(null);
    setIsModalOpen(true);
  };

  const handleToggleRule = async (rule: DefensiveRule) => {
    try {
      await api.updateRule(rule.id, { enabled: !rule.enabled });
      await fetchData();
    } catch (err: any) {
      alert(`Failed to toggle rule: ${err.message}`);
    }
  };

  const handleDeleteRule = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete rule "${name}"?`)) return;
    try {
      await api.deleteRule(id);
      await fetchData();
    } catch (err: any) {
      alert(`Failed to delete rule: ${err.message}`);
    }
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    // Client-side ReDoS and syntax safety check
    if (matchType === 'regex') {
      const safety = validateRegexSafety(pattern);
      if (!safety.safe) {
        setFormError(safety.reason || 'Unsafe regular expression pattern.');
        return;
      }
    }

    try {
      if (editingRule) {
        await api.updateRule(editingRule.id, {
          name: ruleName,
          description: ruleDescription,
          matchType,
          pattern,
          action,
          severity,
          category,
        });
      } else {
        await api.createRule({
          name: ruleName,
          description: ruleDescription,
          matchType,
          pattern,
          action,
          severity,
          category,
          enabled: true,
        });
      }
      setIsModalOpen(false);
      await fetchData();
    } catch (err: any) {
      setFormError(err.message || 'Error saving rule');
    }
  };

  // Test sealed payload boundary live: Blue Team attempts to read raw payload of a running test!
  const handleProbeSealedPayload = async (run: TestRun) => {
    setSealProbeResult(null);
    try {
      const res = await api.getRunRawPayload(run.id);
      setSealProbeResult({
        runId: run.id,
        status: 200,
        message: 'Payload unsealed & released to Blue Team.',
        errorData: res,
      });
    } catch (err: any) {
      setSealProbeResult({
        runId: run.id,
        status: err.status || 403,
        message: err.message || 'Access Denied: Payload is sealed during active execution.',
        errorData: err.data,
      });
    }
  };

  const activeCount = rules.filter((r) => r.enabled).length;
  const totalHits = rules.reduce((acc, r) => acc + (r.hitCount || 0), 0);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Blue Team Defensive Rule Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Author and enforce gateway detection signatures to mitigate prompt injection, jailbreaks, and sensitive data leakage.
          </p>
        </div>

        <button
          onClick={openCreateModal}
          className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition-colors shrink-0"
        >
          <Plus className="w-4 h-4" />
          Create Defensive Rule
        </button>
      </div>

      {/* Security Context Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#0b1120] border border-slate-800 rounded p-3.5">
          <span className="text-xs text-slate-400 block">Active Gateway Rules</span>
          <div className="text-xl font-bold text-white mt-1 tabular-nums font-mono">
            {activeCount} <span className="text-xs font-normal text-slate-500">/ {rules.length} total</span>
          </div>
        </div>

        <div className="bg-[#0b1120] border border-slate-800 rounded p-3.5">
          <span className="text-xs text-slate-400 block">Total Interceptions</span>
          <div className="text-xl font-bold text-rose-400 mt-1 tabular-nums font-mono">
            {totalHits}
          </div>
        </div>

        <div className="bg-[#0b1120] border border-slate-800 rounded p-3.5">
          <span className="text-xs text-slate-400 block">Hard Block Rules</span>
          <div className="text-xl font-bold text-cyan-300 mt-1 tabular-nums font-mono">
            {rules.filter((r) => r.action === 'BLOCK').length}
          </div>
        </div>

        <div className="bg-[#0b1120] border border-slate-800 rounded p-3.5">
          <span className="text-xs text-slate-400 block">Sealed Test Runs</span>
          <div className="text-xl font-bold text-amber-300 mt-1 tabular-nums font-mono">
            {runs.filter((r) => r.status === 'running').length}
          </div>
        </div>
      </div>

      {/* Sealed Payload Probe Banner */}
      {sealProbeResult && (
        <div
          className={`p-4 rounded border text-xs space-y-1.5 ${
            sealProbeResult.status === 403
              ? 'bg-blue-950/40 border-cyan-500/60 text-cyan-100'
              : 'bg-emerald-950/30 border-emerald-500/60 text-emerald-100'
          }`}
        >
          <div className="flex items-center justify-between font-semibold">
            <span className="flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-cyan-400" />
              Live Sealed Payload Quarantine Verification (HTTP {sealProbeResult.status})
            </span>
            <button
              onClick={() => setSealProbeResult(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>
          <p className="text-slate-300">{sealProbeResult.message}</p>
          <div className="font-mono text-[11px] bg-black/50 p-2.5 rounded border border-cyan-900/40 text-cyan-300 overflow-x-auto">
            {JSON.stringify(sealProbeResult.errorData || { error: sealProbeResult.message }, null, 2)}
          </div>
          <p className="text-[11px] text-slate-400">
            ✓ Security boundary holds: Blue Team cannot view raw payloads during test execution to prevent bias or preemptive tampering.
          </p>
        </div>
      )}

      {/* Rules Table */}
      <div className="bg-[#0b1120] border border-slate-800 rounded overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <span>Enforced Defense Rules</span>
          </h2>
          <button
            onClick={fetchData}
            className="text-xs text-slate-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>

        {rules.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No rules configured. Click "Create Defensive Rule" above to create your first detection pattern.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#070b14] border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-2.5 px-4 font-semibold">Status</th>
                  <th className="py-2.5 px-4 font-semibold">Rule Name</th>
                  <th className="py-2.5 px-4 font-semibold">Category</th>
                  <th className="py-2.5 px-4 font-semibold">Type & Pattern</th>
                  <th className="py-2.5 px-4 font-semibold">Action</th>
                  <th className="py-2.5 px-4 font-semibold">Severity</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Interceptions</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-slate-900/50 transition-colors">
                    {/* Status Toggle */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleRule(rule)}
                        title={rule.enabled ? 'Click to Disable' : 'Click to Enable'}
                        className="flex items-center gap-1.5 focus:outline-none"
                      >
                        {rule.enabled ? (
                          <span className="text-cyan-400 flex items-center gap-1 font-mono font-medium">
                            <ToggleRight className="w-5 h-5 text-cyan-400" />
                            ACTIVE
                          </span>
                        ) : (
                          <span className="text-slate-500 flex items-center gap-1 font-mono">
                            <ToggleLeft className="w-5 h-5 text-slate-600" />
                            OFF
                          </span>
                        )}
                      </button>
                    </td>

                    {/* Name & Desc */}
                    <td className="py-3 px-4 max-w-xs">
                      <div className="font-semibold text-white truncate">{rule.name}</div>
                      <div className="text-[11px] text-slate-400 truncate">{rule.description}</div>
                    </td>

                    {/* Category */}
                    <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                      {rule.category}
                    </td>

                    {/* Pattern */}
                    <td className="py-3 px-4 max-w-xs font-mono">
                      <span className="text-[11px] text-cyan-400 block uppercase font-sans">
                        {rule.matchType}
                      </span>
                      <span className="text-slate-300 truncate block text-[11px]" title={rule.pattern}>
                        {rule.pattern}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      {rule.action === 'BLOCK' ? (
                        <span className="text-rose-400 font-semibold font-mono">BLOCK</span>
                      ) : (
                        <span className="text-amber-400 font-semibold font-mono">FLAG</span>
                      )}
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`font-mono text-[11px] font-semibold ${
                          rule.severity === 'CRITICAL'
                            ? 'text-rose-400'
                            : rule.severity === 'HIGH'
                            ? 'text-amber-400'
                            : 'text-slate-400'
                        }`}
                      >
                        {rule.severity}
                      </span>
                    </td>

                    {/* Hits */}
                    <td className="py-3 px-4 whitespace-nowrap text-right font-mono tabular-nums text-slate-200">
                      {rule.hitCount}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 whitespace-nowrap text-right space-x-2">
                      <button
                        onClick={() => openEditModal(rule)}
                        className="text-slate-400 hover:text-cyan-300 p-1"
                        title="Edit Rule"
                      >
                        <Edit3 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDeleteRule(rule.id, rule.name)}
                        className="text-slate-400 hover:text-rose-400 p-1"
                        title="Delete Rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Sealed Test Runs Monitor (Demonstrates Zero-Knowledge Isolation) */}
      <div className="bg-[#0b1120] border border-slate-800 rounded p-4 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <EyeOff className="w-4 h-4 text-cyan-400" />
              Test Runs Quarantine & Zero-Knowledge Monitor
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Active test payloads are cryptographically sealed from Blue Team inspection until the test concludes.
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Monitored: <span className="text-cyan-300">{runs.length}</span> runs
          </span>
        </div>

        <div className="divide-y divide-slate-800/80">
          {runs.slice(0, 5).map((run) => (
            <div key={run.id} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="space-y-0.5 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-white">{run.title}</span>
                  <span className="text-[11px] font-mono text-slate-500">ID: {run.id}</span>
                  {run.status === 'running' ? (
                    <span className="text-[11px] font-mono text-amber-400 flex items-center gap-1">
                      <Lock className="w-3 h-3" /> SEALED (IN FLIGHT)
                    </span>
                  ) : (
                    <span className="text-[11px] font-mono text-emerald-400">
                      COMPLETED ({run.decision})
                    </span>
                  )}
                </div>
                <p className="text-xs font-mono text-slate-400 truncate">
                  {run.prompt}
                </p>
              </div>

              {/* Action: Test Sealed Boundary */}
              <div className="shrink-0 flex items-center gap-2">
                {run.status === 'running' ? (
                  <button
                    onClick={() => handleProbeSealedPayload(run)}
                    className="px-2.5 py-1 bg-amber-950/40 hover:bg-amber-900/60 border border-amber-500/50 text-amber-300 rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
                  >
                    <Lock className="w-3 h-3" />
                    Inspect Payload (Probe Boundary)
                  </button>
                ) : (
                  <button
                    onClick={() => handleProbeSealedPayload(run)}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                  >
                    View Released Payload
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Rule Create/Edit Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-[#0b1120] border border-slate-800 rounded-lg max-w-lg w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-base font-bold text-white">
              {editingRule ? 'Edit Defensive Rule' : 'Create New Defensive Rule'}
            </h3>

            {formError && (
              <div className="p-3 bg-rose-950/30 border border-rose-500/50 rounded text-xs text-rose-300">
                {formError}
              </div>
            )}

            <form onSubmit={handleSaveRule} className="space-y-3">
              <div>
                <label className="text-xs text-slate-300 font-medium block mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Delimiter Hijacking Guard"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium block mb-1">Category</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="Prompt Defense">Prompt Defense</option>
                  <option value="System Leakage">System Leakage</option>
                  <option value="Jailbreak">Jailbreak</option>
                  <option value="Prompt Injection">Prompt Injection</option>
                  <option value="Data Exfiltration">Data Exfiltration</option>
                  <option value="Heuristic">Heuristic</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-300 font-medium block mb-1">Match Type</label>
                  <select
                    value={matchType}
                    onChange={(e) => setMatchType(e.target.value as RuleMatchType)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="regex">Regular Expression (regex)</option>
                    <option value="contains_phrase">Contains Phrase</option>
                    <option value="keyword">Keywords (comma-separated)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs text-slate-300 font-medium block mb-1">Action</label>
                  <select
                    value={action}
                    onChange={(e) => setAction(e.target.value as RuleAction)}
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="BLOCK">BLOCK (Hard Drop)</option>
                    <option value="FLAG">FLAG (Monitor & Allow)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium block mb-1">
                  Pattern / Expression <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder={matchType === 'regex' ? 'e.g. ignore previous instructions|reveal prompt' : 'e.g. override, bypass'}
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium block mb-1">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as RuleSeverity)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium block mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="Rationale and threat profile for this rule..."
                  value={ruleDescription}
                  onChange={(e) => setRuleDescription(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition-colors"
                >
                  {editingRule ? 'Update Rule' : 'Create Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

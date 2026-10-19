import React, { useState } from 'react';
import { api } from '../services/api.ts';
import { AutomatedTestResult } from '../types/index.ts';
import { ShieldCheck, Play, CheckCircle2, XCircle, Clock, Terminal, ChevronDown, ChevronRight, ShieldAlert, Cpu } from 'lucide-react';

export const AutomatedTestSuite: React.FC = () => {
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<{
    total: number;
    passed: number;
    failed: number;
    durationMs: number;
    allPassed: boolean;
    executedAt: string;
  } | null>(null);
  const [results, setResults] = useState<AutomatedTestResult[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const handleRunTests = async () => {
    setRunning(true);
    try {
      const data = await api.runAutomatedTests();
      setSummary(data.summary);
      setResults(data.results);
    } catch (err: any) {
      alert(`Automated test execution failed: ${err.message}`);
    } finally {
      setRunning(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Automated Security Verification Suite
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Executes programmatic security checks against the live backend to verify server-side RBAC, zero-knowledge payload sealing, and gateway policy enforcement.
          </p>
        </div>

        <button
          onClick={handleRunTests}
          disabled={running}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-white rounded text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer disabled:cursor-not-allowed shrink-0"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          {running ? 'Executing Live Verification Suite...' : 'Run Security Verification Suite'}
        </button>
      </div>

      {/* Summary Banner */}
      {summary && (
        <div
          className={`p-4 rounded border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
            summary.allPassed
              ? 'bg-emerald-950/30 border-emerald-500/60 text-emerald-200'
              : 'bg-rose-950/30 border-rose-500/60 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {summary.allPassed ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
            )}
            <div>
              <span className="font-bold text-sm block">
                {summary.allPassed ? 'ALL SECURITY CONTROLS VERIFIED' : 'ONE OR MORE CHECKS FAILED'}
              </span>
              <span className="text-slate-300 text-xs">
                {summary.passed} of {summary.total} verification tests passed on server runtime in{' '}
                <strong className="font-mono text-cyan-300 tabular-nums">{summary.durationMs}ms</strong>.
              </span>
            </div>
          </div>

          <div className="font-mono text-[11px] text-slate-400">
            Executed: {new Date(summary.executedAt).toLocaleTimeString()}
          </div>
        </div>
      )}

      {/* Results List */}
      <div className="bg-[#0b1120] border border-slate-800 rounded overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-semibold text-white">Live Backend Assertions</span>
          <span className="text-slate-400">Status: {results.length > 0 ? `${results.filter(r => r.passed).length} passing` : 'Ready to execute'}</span>
        </div>

        {results.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500 space-y-2">
            <p>No tests executed in this session.</p>
            <p className="text-[11px] text-slate-600">
              Click "Run Security Verification Suite" above to run live HTTP assertions against the running server.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {results.map((test) => {
              const isExpanded = expandedId === test.id;
              return (
                <div key={test.id} className="p-4 hover:bg-slate-900/40 transition-colors">
                  <div
                    onClick={() => toggleExpand(test.id)}
                    className="flex items-start justify-between gap-4 cursor-pointer"
                  >
                    <div className="flex items-start gap-3 min-w-0">
                      <div className="mt-0.5 shrink-0">
                        {test.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400" />
                        )}
                      </div>

                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-white text-xs">{test.name}</span>
                          <span className="text-[11px] font-mono text-cyan-400/80">
                            [{test.category}]
                          </span>
                          <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                            {test.durationMs}ms
                          </span>
                        </div>
                        <p className="text-xs text-slate-400">{test.description}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                          test.passed
                            ? 'text-emerald-300 bg-emerald-950/40 border border-emerald-500/30'
                            : 'text-rose-300 bg-rose-950/40 border border-rose-500/30'
                        }`}
                      >
                        {test.passed ? 'PASSED' : 'FAILED'}
                      </span>
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-slate-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-slate-400" />
                      )}
                    </div>
                  </div>

                  {/* Expandable Evidence Drawer */}
                  {isExpanded && (
                    <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-3 text-xs pl-7">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div className="p-2.5 bg-slate-900 border border-slate-800 rounded">
                          <span className="text-slate-400 text-[11px] block">Expected Outcome</span>
                          <span className="font-mono text-emerald-300 mt-1 block">
                            {test.expected} (HTTP {test.httpStatusExpected})
                          </span>
                        </div>
                        <div className="p-2.5 bg-slate-900 border border-slate-800 rounded">
                          <span className="text-slate-400 text-[11px] block">Actual Server Response</span>
                          <span className="font-mono text-white mt-1 block">
                            {test.actual} (HTTP {test.httpStatusActual})
                          </span>
                        </div>
                      </div>

                      <div className="p-2.5 bg-black/40 border border-slate-800 rounded space-y-1">
                        <span className="text-slate-400 text-[11px] block font-mono">Assertion Evidence:</span>
                        <p className="font-mono text-[11px] text-cyan-300 break-words">{test.evidence}</p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Security Testing Rubric Details */}
      <div className="bg-[#0b1120] border border-slate-800 rounded p-4 text-xs space-y-3">
        <h3 className="font-semibold text-white flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          Hackathon Evaluation Protocol Coverage
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-slate-300">
          <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800/80 space-y-1">
            <span className="font-semibold text-cyan-300 block">1. Server-Side RBAC</span>
            <p className="text-[11px] text-slate-400">
              Validates authorization header on every request. Client button hiding is never treated as a security boundary.
            </p>
          </div>
          <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800/80 space-y-1">
            <span className="font-semibold text-cyan-300 block">2. Sealed Payload Isolation</span>
            <p className="text-[11px] text-slate-400">
              Payloads are masked with zero-knowledge tokens during in-flight tests to avoid defensive rule bias.
            </p>
          </div>
          <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800/80 space-y-1">
            <span className="font-semibold text-cyan-300 block">3. Synchronous Audit Trail</span>
            <p className="text-[11px] text-slate-400">
              Every rejected probe, access denial, and rule edit is logged into the audit ledger synchronously.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

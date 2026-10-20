import React, { useState, useEffect } from 'react';
import { api } from '../services/api.ts';
import { StorageInfo } from '../types/index.ts';
import { Database, HardDrive, CheckCircle2, AlertTriangle, ShieldCheck, RefreshCw } from 'lucide-react';

export const StorageArchitecture: React.FC = () => {
  const [info, setInfo] = useState<StorageInfo | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchStorageInfo = async () => {
    try {
      setLoading(true);
      const res = await api.getStorageInfo();
      setInfo(res);
    } catch (err) {
      console.error('Failed fetching storage info:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStorageInfo();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-4 border-b border-slate-800">
        <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          <Database className="w-5 h-5 text-cyan-400" />
          Storage Architecture & Security Boundaries
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Detailed transparency report on backend persistence, transactional guarantees, and documented system limitations.
        </p>
      </div>

      {/* Corruption Detection Alert */}
      {info?.isCorrupted && (
        <div className="p-3 bg-amber-950/40 border border-amber-800 text-amber-200 rounded text-xs flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
          <div>
            <strong>Storage Alert: Corrupted Database Detected.</strong> The damaged database was backed up to{' '}
            <code className="text-amber-300 font-mono">{info.corruptedBackupPath}</code> without overwriting existing data.
          </div>
        </div>
      )}

      {/* Persistence Architecture Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 space-y-4">
          <div className="bg-[#0b1120] border border-slate-800 rounded p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-sm font-semibold text-white flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-cyan-400" />
                Backend Storage Strategy: Server-Local Atomic JSON Store
              </span>
              <span className="text-xs font-mono text-cyan-300">Node.js Runtime</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Bayora Shield uses a synchronous server-side persistence layer backed by an atomic filesystem ledger (<code className="text-cyan-300 font-mono">data/bayora_shield_db.json</code>) and high-speed in-memory state caching. This architecture guarantees immediate consistency for policy gateway rule lookups without third-party external network latencies.
            </p>

            {/* Guarantees */}
            <div>
              <span className="text-xs font-semibold text-emerald-400 block mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                Persistence & Operational Guarantees
              </span>
              <ul className="space-y-1.5 text-xs text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="text-emerald-400 font-bold">·</span>
                  <span><strong>Zero External API Dependencies:</strong> Runs deterministically in hermetic environments without external Cloud SQL or Firestore credentials.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-emerald-400 font-bold">·</span>
                  <span><strong>Synchronous Gateway Evaluation:</strong> In-memory pattern cache evaluates regex and keyword rules in sub-millisecond durations.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-emerald-400 font-bold">·</span>
                  <span><strong>Atomic Disk Sync:</strong> Every rule update, test submission, and audit log entry is flushed synchronously to the server filesystem.</span>
                </li>
              </ul>
            </div>

            {/* Documented Limitations */}
            <div className="pt-3 border-t border-slate-800">
              <span className="text-xs font-semibold text-amber-400 block mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" />
                Documented Engineering Limitations
              </span>
              <ul className="space-y-1.5 text-xs text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="text-amber-400 font-bold">·</span>
                  <span><strong>Horizontal Distributed Scaling:</strong> Server-local storage is designed for single-node prototypes. Multi-region deployments require relational replication (e.g., PostgreSQL or Cloud SQL).</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-amber-400 font-bold">·</span>
                  <span><strong>Audit Integrity Boundary:</strong> Audit logs are tamper-evident at the application server boundary; hardware WORM (Write-Once-Read-Many) storage is not claimed.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-amber-400 font-bold">·</span>
                  <span><strong>Network Isolation:</strong> Security boundaries between Red Team and Blue Team are enforced via server-side software RBAC, not kernel-level network segmentation.</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Right Column: Active Telemetry */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-[#0b1120] border border-slate-800 rounded p-4 space-y-3">
            <span className="text-xs font-semibold text-white block pb-2 border-b border-slate-800">
              Current Database State
            </span>

            {info ? (
              <div className="space-y-3 text-xs">
                <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-400">Defensive Rules</span>
                  <span className="font-mono font-bold text-white tabular-nums">
                    {info.recordsCount.rules}
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-400">Executed Test Runs</span>
                  <span className="font-mono font-bold text-cyan-300 tabular-nums">
                    {info.recordsCount.testRuns}
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-400">Audit Ledger Entries</span>
                  <span className="font-mono font-bold text-rose-300 tabular-nums">
                    {info.recordsCount.auditLogs}
                  </span>
                </div>

                <div className="p-2.5 bg-black/40 border border-slate-800 rounded text-[11px] font-mono text-slate-400 space-y-1">
                  <span className="text-slate-500 block">Database Location:</span>
                  <span className="text-cyan-400 truncate block">{info.location}</span>
                </div>
              </div>
            ) : (
              <div className="py-6 text-center text-xs text-slate-500">Loading database state...</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

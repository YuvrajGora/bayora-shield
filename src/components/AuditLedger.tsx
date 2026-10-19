import React, { useState, useEffect } from 'react';
import { api } from '../services/api.ts';
import { AuditLogEntry, AuditEventType, AuditSeverity } from '../types/index.ts';
import { FileText, Search, Filter, Download, RefreshCw, AlertTriangle, ShieldX, CheckCircle, Info, Lock } from 'lucide-react';

export const AuditLedger: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  // Filters
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected entry for JSON inspector
  const [selectedEntry, setSelectedEntry] = useState<AuditLogEntry | null>(null);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const res = await api.getAuditLogs({
        eventType: eventTypeFilter,
        severity: severityFilter,
        search: searchQuery,
      });
      setLogs(res.logs);
      setTotal(res.total);
    } catch (err) {
      console.error('Failed fetching audit ledger:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [eventTypeFilter, severityFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchLogs();
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `bayora_shield_audit_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleExportCsv = () => {
    const headers = ['ID', 'Timestamp', 'EventType', 'Severity', 'ActorEmail', 'ActorRole', 'TargetResource', 'Decision', 'Details'];
    const rows = logs.map((l) => [
      `"${l.id}"`,
      `"${l.timestamp}"`,
      `"${l.eventType}"`,
      `"${l.severity}"`,
      `"${l.actorEmail}"`,
      `"${l.actorRole}"`,
      `"${l.targetResource}"`,
      `"${l.decision}"`,
      `"${(l.details || '').replace(/"/g, '""')}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `bayora_shield_audit_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getEventBadge = (type: AuditEventType) => {
    switch (type) {
      case 'ACCESS_DENIAL':
        return <span className="text-rose-400 font-mono font-bold">ACCESS_DENIAL</span>;
      case 'GATEWAY_BLOCKED':
        return <span className="text-rose-400 font-mono font-bold">GATEWAY_BLOCKED</span>;
      case 'GATEWAY_ALLOWED':
        return <span className="text-emerald-400 font-mono font-medium">GATEWAY_ALLOWED</span>;
      case 'TEST_SUBMISSION':
        return <span className="text-cyan-400 font-mono font-medium">TEST_SUBMIT</span>;
      case 'RULE_CREATED':
      case 'RULE_UPDATED':
      case 'RULE_DELETED':
        return <span className="text-blue-300 font-mono font-medium">{type}</span>;
      default:
        return <span className="text-slate-400 font-mono">{type}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            Security Audit Trail & Governance Ledger
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Tamper-evident system log capturing test submissions, policy gateway blocks, unauthorized access attempts, and rule modifications.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
          <button
            onClick={handleExportJson}
            className="px-3 py-1.5 bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/50 text-cyan-300 rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-[#0b1120] border border-slate-800 rounded p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Event Filter */}
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded px-2 py-1">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-900">All Event Types</option>
              <option value="ACCESS_DENIAL" className="bg-slate-900 text-rose-400">Access Denials</option>
              <option value="GATEWAY_BLOCKED" className="bg-slate-900 text-rose-400">Gateway Blocked</option>
              <option value="GATEWAY_ALLOWED" className="bg-slate-900 text-emerald-400">Gateway Allowed</option>
              <option value="TEST_SUBMISSION" className="bg-slate-900 text-cyan-400">Test Submissions</option>
              <option value="RULE_CREATED" className="bg-slate-900">Rule Created</option>
              <option value="RULE_UPDATED" className="bg-slate-900">Rule Updated</option>
              <option value="RULE_DELETED" className="bg-slate-900">Rule Deleted</option>
              <option value="SESSION_LOGIN" className="bg-slate-900">Session Logins</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded px-2 py-1">
            <span className="text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-slate-900">All Severities</option>
              <option value="CRITICAL" className="bg-slate-900 text-rose-400">Critical</option>
              <option value="WARNING" className="bg-slate-900 text-amber-400">Warning</option>
              <option value="INFO" className="bg-slate-900 text-slate-400">Info</option>
            </select>
          </div>

          <button
            onClick={fetchLogs}
            className="p-1 text-slate-400 hover:text-cyan-300 transition-colors"
            title="Refresh logs"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        {/* Free text search */}
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter details or actor..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-900 border border-slate-700/80 rounded pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48 sm:w-64"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors"
          >
            Search
          </button>
        </form>
      </div>

      {/* Audit Log Table */}
      <div className="bg-[#0b1120] border border-slate-800 rounded overflow-hidden">
        <div className="px-4 py-2.5 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>Showing <strong className="text-white font-mono">{logs.length}</strong> recorded entries</span>
          <span>Auto-refresh: <strong className="text-cyan-300 font-mono">5s</strong></span>
        </div>

        {logs.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-500">
            No audit log entries matching current criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#070b14] border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-2 px-3 font-semibold">Timestamp</th>
                  <th className="py-2 px-3 font-semibold">Event Type</th>
                  <th className="py-2 px-3 font-semibold">Severity</th>
                  <th className="py-2 px-3 font-semibold">Actor</th>
                  <th className="py-2 px-3 font-semibold">Resource</th>
                  <th className="py-2 px-3 font-semibold">Decision</th>
                  <th className="py-2 px-3 font-semibold">Details</th>
                  <th className="py-2 px-3 font-semibold text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 font-mono">
                {logs.map((entry) => (
                  <tr
                    key={entry.id}
                    onClick={() => setSelectedEntry(entry)}
                    className="hover:bg-slate-900/60 transition-colors cursor-pointer group"
                  >
                    {/* Timestamp */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-400 text-[11px] tabular-nums">
                      {new Date(entry.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>

                    {/* Event Type */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-xs">
                      {getEventBadge(entry.eventType)}
                    </td>

                    {/* Severity */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-[11px]">
                      <span
                        className={
                          entry.severity === 'CRITICAL'
                            ? 'text-rose-400 font-bold'
                            : entry.severity === 'WARNING'
                            ? 'text-amber-400 font-semibold'
                            : 'text-slate-400'
                        }
                      >
                        {entry.severity}
                      </span>
                    </td>

                    {/* Actor */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-300 text-[11px]">
                      <span className="font-sans font-medium text-white">{entry.actorEmail}</span>
                      <span className="text-[10px] text-slate-500 block">[{entry.actorRole}]</span>
                    </td>

                    {/* Resource */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-cyan-300 text-[11px]">
                      {entry.targetResource}
                    </td>

                    {/* Decision */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-[11px]">
                      <span
                        className={
                          entry.decision === 'DENIED' || entry.decision === 'BLOCKED'
                            ? 'text-rose-400 font-bold'
                            : 'text-emerald-400 font-medium'
                        }
                      >
                        {entry.decision}
                      </span>
                    </td>

                    {/* Details */}
                    <td className="py-2.5 px-3 font-sans text-slate-300 text-xs max-w-xs truncate" title={entry.details}>
                      {entry.details}
                    </td>

                    {/* Inspect */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-right font-sans text-xs text-slate-400 group-hover:text-cyan-300">
                      View →
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Audit Detail Modal */}
      {selectedEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="bg-[#0b1120] border border-slate-800 rounded-lg max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                Audit Record Evidence
              </h3>
              <button
                onClick={() => setSelectedEntry(null)}
                className="text-xs text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 bg-slate-900 border border-slate-800 rounded">
                  <span className="text-slate-400 block text-[11px]">Event Type</span>
                  <span className="font-mono font-bold text-white mt-0.5 block">{selectedEntry.eventType}</span>
                </div>
                <div className="p-2.5 bg-slate-900 border border-slate-800 rounded">
                  <span className="text-slate-400 block text-[11px]">Severity Level</span>
                  <span className="font-mono font-bold text-rose-400 mt-0.5 block">{selectedEntry.severity}</span>
                </div>
              </div>

              <div className="p-2.5 bg-slate-900 border border-slate-800 rounded">
                <span className="text-slate-400 block text-[11px]">Security Actor & Role</span>
                <span className="font-mono text-cyan-300 mt-0.5 block">
                  {selectedEntry.actorEmail} ({selectedEntry.actorRole})
                </span>
              </div>

              <div className="p-2.5 bg-slate-900 border border-slate-800 rounded">
                <span className="text-slate-400 block text-[11px]">Target Endpoint & Decision</span>
                <span className="font-mono text-slate-200 mt-0.5 block">
                  {selectedEntry.targetResource} → <strong className="text-white">{selectedEntry.decision}</strong>
                </span>
              </div>

              <div>
                <span className="text-slate-400 block mb-1 text-[11px]">Event Description</span>
                <div className="p-2.5 bg-slate-900 border border-slate-800 rounded text-slate-200 font-sans leading-relaxed">
                  {selectedEntry.details}
                </div>
              </div>

              <div>
                <span className="text-slate-400 block mb-1 text-[11px]">Raw JSON Payload</span>
                <pre className="p-2.5 bg-black/60 border border-slate-800 rounded text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedEntry, null, 2)}
                </pre>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEntry(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

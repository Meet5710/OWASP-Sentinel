import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Lock,
  RefreshCw,
} from 'lucide-react';
import type { ScopeGrant, AuditEvent } from '../types/api';
import { api } from '../services/api';
import { formatExactDateTime, formatRelativeTime } from '../utils/formatters';

interface SettingsAndAuditTabProps {
  scopes: ScopeGrant[];
  onRefreshData: () => Promise<void>;
}

export const SettingsAndAuditTab: React.FC<SettingsAndAuditTabProps> = ({
  scopes,
  onRefreshData,
}) => {
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [isLoadingAudit, setIsLoadingAudit] = useState<boolean>(true);

  const fetchAuditEvents = useCallback(async () => {
    setIsLoadingAudit(true);
    try {
      const data = await api.getAuditEvents(100);
      setAuditEvents(data);
    } catch (err: any) {
      console.error('Failed to load audit events:', err);
    } finally {
      setIsLoadingAudit(false);
    }
  }, []);

  useEffect(() => {
    fetchAuditEvents();
  }, [fetchAuditEvents]);

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 relative overflow-hidden">
        <div>
          <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1.5">
            <Lock className="w-4 h-4" />
            <span>Governance, Scopes & Audit Trail</span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Scope Grants & System Audit Trail</h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Enforces strict pre-scan clearance, authorized network boundaries, and immutable audit logs
            of all assessment activities.
          </p>
        </div>
      </div>

      {/* Safety Policy & Defense Controls Card */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl space-y-4 border border-slate-200/80 dark:border-white/10">
        <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center space-x-2.5 tracking-tight">
          <Shield className="w-5 h-5 text-emerald-500 dark:text-emerald-400" />
          <span>Active Safety & SSRF Defense Policies</span>
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="liquid-glass p-4.5 rounded-xl border border-slate-200/80 dark:border-white/10 space-y-2">
            <span className="font-semibold text-cyan-600 dark:text-cyan-300 block">Non-Destructive Testing</span>
            <p className="text-slate-600 dark:text-slate-300/80 leading-relaxed">
              Rules execute non-destructive inspections (headers, TLS configurations, cookies, banner disclosures)
              without firing exploit payloads or intrusive fuzzing.
            </p>
          </div>
          <div className="liquid-glass p-4.5 rounded-xl border border-slate-200/80 dark:border-white/10 space-y-2">
            <span className="font-semibold text-cyan-600 dark:text-cyan-300 block">SSRF & Metadata Protection</span>
            <p className="text-slate-600 dark:text-slate-300/80 leading-relaxed">
              Cloud metadata endpoints (<code className="text-cyan-600 dark:text-cyan-300 font-mono">169.254.169.254</code>), loopback interfaces,
              and private RFC 1918 subnets are rejected by default.
            </p>
          </div>
          <div className="liquid-glass p-4.5 rounded-xl border border-slate-200/80 dark:border-white/10 space-y-2">
            <span className="font-semibold text-cyan-600 dark:text-cyan-300 block">Subdomain Clearance</span>
            <p className="text-slate-600 dark:text-slate-300/80 leading-relaxed">
              Discovered subdomains are never automatically assessed without explicit scope grant clearance or
              administrator approval.
            </p>
          </div>
        </div>
      </div>

      {/* Active Scope Grants Table */}
      <div className="liquid-glass-card rounded-2xl shadow-2xl overflow-hidden border border-slate-200/80 dark:border-white/10">
        <div className="p-5 border-b border-slate-200/80 dark:border-white/10 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Configured Scope Grants</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">Formal assessment boundaries and authorization envelopes</p>
          </div>
          <button
            onClick={() => onRefreshData()}
            className="p-2 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white rounded-xl hover:bg-slate-500/10 dark:hover:bg-white/10 transition border border-slate-200/80 dark:border-white/5 cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-white/10 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Scope Code</th>
                <th className="py-3 px-4">Title</th>
                <th className="py-3 px-4">Authorized By</th>
                <th className="py-3 px-4">Permitted Ports</th>
                <th className="py-3 px-4">Subdomains Allowed</th>
                <th className="py-3 px-4 text-right">Validity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60 dark:divide-white/5">
              {scopes.map((s) => (
                <tr key={s.id} className="hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.03] transition-colors">
                  <td className="py-3.5 px-4 font-sans font-bold text-indigo-600 dark:text-indigo-300">{s.scope_code}</td>
                  <td className="py-3.5 px-4 text-slate-900 dark:text-white font-medium">{s.title}</td>
                  <td className="py-3.5 px-4 text-slate-700 dark:text-slate-300">{s.authorized_by}</td>
                  <td className="py-3.5 px-4 font-sans text-slate-700 dark:text-slate-300 font-medium">
                    {s.permitted_ports ? s.permitted_ports.join(', ') : '80, 443'}
                  </td>
                  <td className="py-3.5 px-4">
                    {s.allow_subdomains ? (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-400/30">
                        Allowed
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-400/30">
                        Approval Required
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-right text-slate-700 dark:text-slate-300 font-sans font-medium">
                    {new Date(s.valid_until).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* System Audit Events Trail */}
      <div className="liquid-glass-card rounded-2xl shadow-2xl overflow-hidden border border-slate-200/80 dark:border-white/10">
        <div className="p-5 border-b border-slate-200/80 dark:border-white/10 flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Immutable Security Audit Trail</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">Chronological log of assessment, authorization, and scan events</p>
          </div>
          <button
            onClick={fetchAuditEvents}
            className="p-2 text-slate-300 hover:text-white rounded-xl hover:bg-white/10 transition border border-white/5 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isLoadingAudit ? 'animate-spin' : ''}`} />
          </button>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-slate-400 font-semibold uppercase tracking-wider text-[11px] sticky top-0 bg-slate-950/80 backdrop-blur-md">
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {auditEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-white/[0.03] transition-colors">
                  <td className="py-3 px-4 font-sans font-semibold text-cyan-300">{evt.event_type}</td>
                  <td className="py-3 px-4 text-slate-300 font-sans">{evt.actor}</td>
                  <td className="py-3 px-4 text-slate-200">{evt.description}</td>
                  <td className="py-3 px-4 text-slate-400 font-sans text-right whitespace-nowrap">
                    <div className="text-slate-200">
                      {formatExactDateTime(evt.created_at || evt.timestamp)}
                    </div>
                    <div className="text-[10px] text-cyan-400/80">
                      {formatRelativeTime(evt.created_at || evt.timestamp)}
                    </div>
                  </td>
                </tr>
              ))}
              {auditEvents.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-10 text-center text-slate-400">
                    No audit records logged yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};


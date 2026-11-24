import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock,
  Play,
  Plus,
  RefreshCw,
} from 'lucide-react';
import type { ScheduledScan, AuthorizedAsset } from '../types/api';
import { api } from '../services/api';

interface SchedulesTabProps {
  assets: AuthorizedAsset[];
  onRefreshData: () => Promise<void>;
}

export const SchedulesTab: React.FC<SchedulesTabProps> = ({ assets, onRefreshData }) => {
  const [schedules, setSchedules] = useState<ScheduledScan[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRunningDue, setIsRunningDue] = useState<boolean>(false);
  const [dueResultMsg, setDueResultMsg] = useState<string | null>(null);

  // Form state
  const [selectedAssetId, setSelectedAssetId] = useState<string>(assets[0]?.id || '');
  const [frequency, setFrequency] = useState<string>('WEEKLY');
  const [cronExpr, setCronExpr] = useState<string>('0 2 * * 0');

  useEffect(() => {
    if (!selectedAssetId && assets.length > 0) {
      setSelectedAssetId(assets[0].id);
    }
  }, [assets, selectedAssetId]);

  const fetchSchedules = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await api.getSchedules();
      setSchedules(data);
    } catch (err: any) {
      console.error('Failed to load schedules:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSchedules();
  }, [fetchSchedules]);

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssetId) return;

    try {
      await api.createSchedule({
        target_id: selectedAssetId,
        frequency,
        cron_expression: frequency === 'CRON' ? cronExpr : undefined,
      });
      await fetchSchedules();
    } catch (err: any) {
      alert(`Failed to create schedule: ${err.message}`);
    }
  };

  const handleToggleSchedule = async (scheduleId: string, currentActive: boolean) => {
    try {
      await api.updateSchedule(scheduleId, !currentActive);
      await fetchSchedules();
    } catch (err: any) {
      alert(`Failed to update schedule: ${err.message}`);
    }
  };

  const handleRunDueScans = async () => {
    setIsRunningDue(true);
    setDueResultMsg(null);
    try {
      const res = await api.runDueSchedules();
      setDueResultMsg(`Executed ${res.count} due scan jobs successfully.`);
      await fetchSchedules();
      await onRefreshData();
    } catch (err: any) {
      setDueResultMsg(`Execution failed: ${err.message}`);
    } finally {
      setIsRunningDue(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 relative overflow-hidden">
        <div>
          <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1.5">
            <Clock className="w-4 h-4" />
            <span>Continuous Assessment Automation</span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Recurring Scan Scheduling</h2>
          <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Configure periodic security evaluations (Daily, Weekly, Monthly, or Cron) to automatically monitor target
            posture and detect configuration regressions.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={handleRunDueScans}
            disabled={isRunningDue}
            className="liquid-glass-btn-primary px-4 py-2 text-xs font-semibold flex items-center space-x-2 cursor-pointer disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${isRunningDue ? 'animate-spin text-cyan-300' : 'text-cyan-300'}`} />
            <span>{isRunningDue ? 'Running Due Scans...' : 'Execute Due Scans Now'}</span>
          </button>
        </div>
      </div>

      {dueResultMsg && (
        <div className="liquid-glass rounded-xl p-4 border border-cyan-500/30 bg-cyan-950/20 backdrop-blur-xl text-xs text-cyan-200 flex items-center justify-between">
          <span>{dueResultMsg}</span>
          <button onClick={() => setDueResultMsg(null)} className="text-slate-400 hover:text-white font-bold cursor-pointer">
            &times;
          </button>
        </div>
      )}

      {/* Create New Schedule Form */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl border border-slate-200/80 dark:border-white/10">
        <h3 className="text-base font-bold text-slate-900 dark:text-white mb-3.5 tracking-tight">Schedule Recurring Assessment</h3>
        <form onSubmit={handleCreateSchedule} className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
          <div>
            <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Target Asset</label>
            <select
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
              className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white font-sans bg-white dark:bg-slate-900/90 rounded-xl shadow-sm"
            >
              {assets.map((a) => (
                <option key={a.id} value={a.id} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                  {a.canonical_url}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Cadence / Frequency</label>
            <select
              value={frequency}
              onChange={(e) => setFrequency(e.target.value)}
              className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white bg-white dark:bg-slate-900/90 rounded-xl shadow-sm"
            >
              <option value="DAILY" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">DAILY (Every 24h)</option>
              <option value="WEEKLY" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">WEEKLY (Every 7 days)</option>
              <option value="MONTHLY" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">MONTHLY (Every 30 days)</option>
              <option value="CRON" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">CUSTOM CRON SYNTAX</option>
            </select>
          </div>

          {frequency === 'CRON' ? (
            <div>
              <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Cron Expression</label>
              <input
                type="text"
                value={cronExpr}
                onChange={(e) => setCronExpr(e.target.value)}
                placeholder="0 2 * * *"
                className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white font-sans rounded-xl border border-slate-200/80 dark:border-white/10"
                required
              />
            </div>
          ) : (
            <div className="flex items-end">
              <span className="text-slate-500 dark:text-slate-400 text-[11px] pb-2">Automatically sets next run time based on UTC interval</span>
            </div>
          )}

          <div className="flex items-end">
            <button
              type="submit"
              disabled={!selectedAssetId}
              className="liquid-glass-btn-primary w-full py-2.5 text-xs font-semibold flex items-center justify-center space-x-1.5 cursor-pointer disabled:opacity-40"
            >
              <Plus className="w-3.5 h-3.5 text-cyan-200" />
              <span>Create Schedule</span>
            </button>
          </div>
        </form>
      </div>

      {/* Schedules Table */}
      <div className="liquid-glass-card rounded-2xl shadow-2xl overflow-hidden border border-slate-200/80 dark:border-white/10">
        <div className="p-5 border-b border-slate-200/80 dark:border-white/10 flex items-center justify-between">
          <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Active Assessment Schedules</h3>
          <button
            onClick={fetchSchedules}
            className="p-2 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white rounded-xl hover:bg-slate-500/10 dark:hover:bg-white/10 transition border border-slate-200/80 dark:border-white/5 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-white/10 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4 font-medium">Target Asset</th>
                <th className="py-3 px-4 font-medium">Frequency</th>
                <th className="py-3 px-4 font-medium">Status</th>
                <th className="py-3 px-4 font-medium">Next Due Run</th>
                <th className="py-3 px-4 font-medium">Last Execution</th>
                <th className="py-3 px-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60 dark:divide-white/5">
              {schedules.map((s) => {
                const targetAsset = assets.find((a) => a.id === s.target_id);
                return (
                  <tr key={s.id} className="hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.03] transition-colors">
                    <td className="py-3.5 px-4 font-sans text-slate-900 dark:text-white font-semibold">
                      {targetAsset ? targetAsset.canonical_url : s.target_id}
                    </td>
                    <td className="py-3.5 px-4 font-semibold text-cyan-600 dark:text-cyan-300 font-sans">
                      {s.frequency} {s.cron_expression && `(${s.cron_expression})`}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                          s.is_active
                            ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-400/30'
                            : 'bg-slate-100 dark:bg-white/10 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-white/10'
                        }`}
                      >
                        {s.is_active ? 'ACTIVE' : 'PAUSED'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-700 dark:text-slate-300 font-sans">
                      {new Date(s.next_run_at).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>
                    <td className="py-3.5 px-4 text-slate-500 dark:text-slate-400 font-sans">
                      {s.last_run_at
                        ? new Date(s.last_run_at).toLocaleString([], {
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                          })
                        : 'Never'}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleToggleSchedule(s.id, s.is_active)}
                        className={`px-3 py-1 rounded-lg text-xs font-medium cursor-pointer transition border ${
                          s.is_active
                            ? 'bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border-amber-400/30'
                            : 'liquid-glass-btn-primary text-white'
                        }`}
                      >
                        {s.is_active ? 'Pause' : 'Resume'}
                      </button>
                    </td>
                  </tr>
                );
              })}
              {schedules.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-400">
                    No recurring schedules configured yet. Use the form above to register one.
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


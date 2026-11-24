import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  Search,
  CheckCircle,
  AlertTriangle,
  HelpCircle,
  XCircle,
  Eye,
  RefreshCw,
  Clock,
  Globe,
  Terminal,
  FileCode,
  Shield,
  ChevronUp,
  ChevronDown,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import type { Finding, AuthorizedAsset } from '../types/api';
import { api } from '../services/api';
import { FindingDetailModal } from './FindingDetailModal';
import { ScanTerminalModal } from './ScanTerminalModal';
import {
  formatExactDateTime,
  formatDateTimeShort,
  formatRelativeTime,
  cleanBugTitle,
  getVulnerableEndpointUrl,
} from '../utils/formatters';

interface FindingsTabProps {
  findings: Finding[];
  assets: AuthorizedAsset[];
  selectedTargetId?: string;
  onSelectTarget?: (targetId: string) => void;
  onRefreshData: () => Promise<void>;
  activeScanningTargetId?: string | null;
  scanStatusMessage?: string | null;
  latestScanRunInfo?: { scanId: string; targetId: string; time: string; count: number } | null;
  onTriggerScan?: (assetId: string) => Promise<void>;
}

export const FindingsTab: React.FC<FindingsTabProps> = ({
  findings,
  assets,
  selectedTargetId,
  onSelectTarget,
  onRefreshData,
  activeScanningTargetId,
  scanStatusMessage: externalScanStatusMsg,
  latestScanRunInfo: externalScanRunInfo,
  onTriggerScan,
}) => {
  // Filter States
  const [filterTarget, setFilterTarget] = useState<string>(selectedTargetId || '');
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [filterCategory, setFilterCategory] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Sorting and Pagination States
  type SortField = 'severity' | 'title' | 'target' | 'category' | 'status' | 'date';
  type SortOrder = 'asc' | 'desc';
  const [sortField, setSortField] = useState<SortField>('severity');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(20);

  // Selected Finding for Modal
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  // Terminal Modal State
  const [showTerminalModal, setShowTerminalModal] = useState(false);
  const [terminalScanId, setTerminalScanId] = useState<string | undefined>(undefined);

  // Local Live Scan Execution State for Scratch Scanning (Fallback)
  const [localIsScanning, setLocalIsScanning] = useState(false);
  const [localScanStatusMsg, setLocalScanStatusMsg] = useState<string | null>(null);
  const [localScanRunInfo, setLocalScanRunInfo] = useState<{ scanId: string; time: string; count: number } | null>(null);

  // Computed Scan State: True if either global App scan is active on this asset or local scan is active
  const isScanningTarget = (activeScanningTargetId !== undefined && activeScanningTargetId !== null)
    ? (activeScanningTargetId === filterTarget || (!filterTarget && Boolean(activeScanningTargetId)))
    : localIsScanning;

  const scanStatusMessage = externalScanStatusMsg || localScanStatusMsg;
  const latestScanRunInfo = (externalScanRunInfo && (!filterTarget || externalScanRunInfo.targetId === filterTarget))
    ? externalScanRunInfo
    : localScanRunInfo;

  // Synchronize when selectedTargetId changes from parent
  useEffect(() => {
    setFilterTarget(selectedTargetId || '');
  }, [selectedTargetId]);

  // Ensure scroll is at the top when FindingsTab is displayed
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0 });
    const scrollContainer = document.querySelector('.md\\:overflow-y-auto');
    if (scrollContainer) {
      scrollContainer.scrollTop = 0;
    }
  }, [selectedTargetId]);

  const activeTargetAsset = assets.find((a) => a.id === filterTarget);

  const handleTargetChange = (val: string) => {
    setFilterTarget(val);
    if (onSelectTarget) {
      onSelectTarget(val);
    }
  };

  const executeFreshTargetScan = async (assetId: string) => {
    if (!assetId || assetId === '__ALL__') return;
    if (onTriggerScan) {
      await onTriggerScan(assetId);
    } else {
      const targetAsset = assets.find((a) => a.id === assetId);
      setLocalIsScanning(true);
      setLocalScanStatusMsg(`Running natural live scan from scratch against ${targetAsset?.canonical_url || 'target'} across all 19 OWASP detection rules...`);
      try {
        const scanJob = await api.triggerScan(assetId);
        await onRefreshData();
        setLocalScanRunInfo({
          scanId: scanJob.id,
          time: new Date().toLocaleTimeString(),
          count: scanJob.failed_checks ?? 0,
        });
      } catch (err: any) {
        console.error('Scan execution error:', err);
      } finally {
        setLocalIsScanning(false);
        setLocalScanStatusMsg(null);
      }
    }
  };

  const handleSelectTarget = async (assetId: string, autoScan = false) => {
    handleTargetChange(assetId);
    if (autoScan && assetId && assetId !== '__ALL__' && activeScanningTargetId !== assetId) {
      await executeFreshTargetScan(assetId);
    }
  };

  // Group and merge duplicate findings on the same target sharing technical_issue_type
  const consolidatedFindings = useMemo(() => {
    const grouped = new Map<string, Finding>();

    for (const f of findings) {
      const key = `${f.target_id || ''}::${f.technical_issue_type || ''}`;
      const existing = grouped.get(key);

      if (!existing) {
        const ev = { ...(f.evidence || {}) };
        const scripts: string[] = Array.isArray(ev.contributing_scripts) && ev.contributing_scripts.length > 0
          ? [...ev.contributing_scripts]
          : ev.script_name ? [ev.script_name] : [];

        const r = String(f.rule_id || (f as any).detection_rule_id || '');
        if (scripts.length === 0 && r.startsWith('KALI:PRACTICE:')) {
          let clean = r.replace('KALI:PRACTICE:', '').toLowerCase().replace(/_mime$/, '');
          if (clean.endsWith('_py')) clean = clean.slice(0, -3) + '.py';
          scripts.push(clean.replace(/_/g, '-'));
        }

        grouped.set(key, {
          ...f,
          evidence: {
            ...ev,
            contributing_scripts: scripts,
            scripts_count: scripts.length,
          },
        });
      } else {
        const existingEv = existing.evidence || {};
        const newEv = f.evidence || {};

        const existingScripts: string[] = Array.isArray(existingEv.contributing_scripts) && existingEv.contributing_scripts.length > 0
          ? [...existingEv.contributing_scripts]
          : existingEv.script_name ? [existingEv.script_name] : [];

        const incomingScripts: string[] = Array.isArray(newEv.contributing_scripts) && newEv.contributing_scripts.length > 0
          ? [...newEv.contributing_scripts]
          : newEv.script_name ? [newEv.script_name] : [];

        const r = String(f.rule_id || (f as any).detection_rule_id || '');
        if (incomingScripts.length === 0 && r.startsWith('KALI:PRACTICE:')) {
          let clean = r.replace('KALI:PRACTICE:', '').toLowerCase().replace(/_mime$/, '');
          if (clean.endsWith('_py')) clean = clean.slice(0, -3) + '.py';
          incomingScripts.push(clean.replace(/_/g, '-'));
        }

        const mergedScripts = Array.from(new Set([...existingScripts, ...incomingScripts].filter(Boolean)));

        const existingExecs: any[] = Array.isArray(existingEv.all_executions) ? existingEv.all_executions : [];
        const incomingExecs: any[] = Array.isArray(newEv.all_executions) ? newEv.all_executions : [];
        const execMap = new Map<string, any>();
        for (const e of [...existingExecs, ...incomingExecs]) {
          if (e && e.script && !execMap.has(e.script)) {
            execMap.set(e.script, e);
          }
        }

        const existingMappings = existing.category_mappings || [];
        const newMappings = f.category_mappings || [];
        const mapKeys = new Set(existingMappings.map((m) => `${m.edition_identifier}-${m.category_identifier}`));
        const mergedMappings = [...existingMappings];
        for (const m of newMappings) {
          const k = `${m.edition_identifier}-${m.category_identifier}`;
          if (!mapKeys.has(k)) {
            mergedMappings.push(m);
            mapKeys.add(k);
          }
        }

        grouped.set(key, {
          ...existing,
          category_mappings: mergedMappings,
          evidence: {
            ...existingEv,
            contributing_scripts: mergedScripts,
            scripts_count: mergedScripts.length,
            all_executions: Array.from(execMap.values()),
          },
        });
      }
    }

    return Array.from(grouped.values());
  }, [findings]);

  // Filter Logic: Filter from consolidated findings
  const filteredFindings = consolidatedFindings.filter((f) => {
    if (filterTarget && filterTarget !== '__ALL__' && f.target_id !== filterTarget) return false;
    if (filterSeverity && f.severity !== filterSeverity) return false;
    if (filterStatus && f.validation_status !== filterStatus) return false;

    if (filterCategory) {
      const hasCategory = (f.category_mappings || []).some((m) =>
        m.category_identifier.toLowerCase().includes(filterCategory.toLowerCase())
      );
      if (!hasCategory) return false;
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = (f.title || '').toLowerCase().includes(q);
      const matchRule = (f.rule_id || '').toLowerCase().includes(q);
      const matchType = (f.technical_issue_type || '').toLowerCase().includes(q);
      const matchDesc = (f.description || '').toLowerCase().includes(q);
      const matchScripts = (f.evidence?.contributing_scripts || []).some((s: string) => s.toLowerCase().includes(q));
      if (!matchTitle && !matchRule && !matchType && !matchDesc && !matchScripts) return false;
    }

    return true;
  });

  const SEVERITY_WEIGHT: Record<string, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };

  const STATUS_WEIGHT: Record<string, number> = {
    CONFIRMED: 4,
    POTENTIAL: 3,
    MITIGATED: 2,
    FALSE_POSITIVE: 1,
  };

  // Sorting Logic: Sort filtered findings by selected column (default Severity descending)
  const sortedFindings = useMemo(() => {
    const list = [...filteredFindings];

    list.sort((a, b) => {
      let cmp = 0;

      switch (sortField) {
        case 'severity': {
          const weightA = SEVERITY_WEIGHT[a.severity?.toUpperCase()] || 0;
          const weightB = SEVERITY_WEIGHT[b.severity?.toUpperCase()] || 0;
          cmp = weightA - weightB;
          if (cmp === 0) {
            cmp = new Date(a.first_seen_at || 0).getTime() - new Date(b.first_seen_at || 0).getTime();
          }
          break;
        }
        case 'title': {
          const titleA = cleanBugTitle(a.title || '').toLowerCase();
          const titleB = cleanBugTitle(b.title || '').toLowerCase();
          cmp = titleA.localeCompare(titleB);
          break;
        }
        case 'target': {
          const targetA = assets.find((x) => x.id === a.target_id);
          const targetB = assets.find((x) => x.id === b.target_id);
          const urlA = getVulnerableEndpointUrl(a, targetA).toLowerCase();
          const urlB = getVulnerableEndpointUrl(b, targetB).toLowerCase();
          cmp = urlA.localeCompare(urlB);
          break;
        }
        case 'category': {
          const catA = (a.category_mappings?.[0]?.category_identifier || '').toLowerCase();
          const catB = (b.category_mappings?.[0]?.category_identifier || '').toLowerCase();
          cmp = catA.localeCompare(catB);
          break;
        }
        case 'status': {
          const sA = STATUS_WEIGHT[a.validation_status?.toUpperCase()] || 0;
          const sB = STATUS_WEIGHT[b.validation_status?.toUpperCase()] || 0;
          cmp = sA - sB;
          break;
        }
        case 'date': {
          const timeA = new Date(a.last_seen_at || a.first_seen_at || 0).getTime();
          const timeB = new Date(b.last_seen_at || b.first_seen_at || 0).getTime();
          cmp = timeA - timeB;
          break;
        }
      }

      return sortOrder === 'asc' ? cmp : -cmp;
    });

    return list;
  }, [filteredFindings, sortField, sortOrder, assets]);

  // Pagination Logic
  const totalItems = sortedFindings.length;
  const totalPages = pageSize === -1 ? 1 : Math.max(1, Math.ceil(totalItems / pageSize));

  // Reset page to 1 when filters or search change
  useEffect(() => {
    setCurrentPage(1);
  }, [filterTarget, filterSeverity, filterStatus, filterCategory, searchQuery]);

  // Ensure current page is valid when result set changes
  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(1);
    }
  }, [totalPages, currentPage]);

  const paginatedFindings = useMemo(() => {
    if (pageSize === -1) return sortedFindings;
    const start = (currentPage - 1) * pageSize;
    return sortedFindings.slice(start, start + pageSize);
  }, [sortedFindings, currentPage, pageSize]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder(field === 'severity' || field === 'date' ? 'desc' : 'asc');
    }
    setCurrentPage(1);
  };

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) {
      return <ArrowUpDown className="w-3 h-3 text-slate-400 opacity-60 inline-block ml-1" />;
    }
    return sortOrder === 'asc' ? (
      <ChevronUp className="w-3.5 h-3.5 text-indigo-500 dark:text-indigo-400 inline-block ml-1" />
    ) : (
      <ChevronDown className="w-3.5 h-3.5 text-indigo-500 dark:text-indigo-400 inline-block ml-1" />
    );
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30';
      case 'LOW':
        return 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30';
      default:
        return 'bg-slate-100 dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'CONFIRMED':
        return <AlertTriangle className="w-3.5 h-3.5 text-rose-600 dark:text-rose-400" />;
      case 'POTENTIAL':
        return <HelpCircle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />;
      case 'MITIGATED':
        return <CheckCircle className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />;
      case 'FALSE_POSITIVE':
        return <XCircle className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Filters Header Card */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center space-x-2.5">
              <div className="p-1.5 rounded-lg bg-indigo-500/20 border border-indigo-500/30 text-indigo-600 dark:text-indigo-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <span className="font-extrabold text-base tracking-wide bg-gradient-to-r from-slate-900 via-indigo-950 to-indigo-800 dark:from-white dark:via-slate-100 dark:to-indigo-200 bg-clip-text text-transparent">
                OWASP Finding Inventory & Taxonomy Mappings
              </span>
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
              Technical issues mapped to official OWASP Top 10 standards with evidence & remediation history.
            </p>
          </div>
          <button
            onClick={() => onRefreshData()}
            className="px-3.5 py-2 liquid-glass-btn-secondary text-slate-700 dark:text-slate-200 rounded-xl text-xs font-semibold flex items-center space-x-2 transition self-start md:self-auto cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Refresh Findings</span>
          </button>
        </div>

        {/* Target Filter Notification Banner if Filtered */}
        {activeTargetAsset && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4 py-3 rounded-2xl bg-indigo-500/10 dark:bg-indigo-950/40 border border-indigo-500/30 text-xs text-indigo-800 dark:text-indigo-200">
            <div className="flex items-center space-x-2.5">
              <Globe className="w-4 h-4 text-cyan-600 dark:text-cyan-400 shrink-0" />
              <span>
                Assessment target:{' '}
                <strong className="text-slate-900 dark:text-white font-sans">{activeTargetAsset.canonical_url}</strong>{' '}
                {latestScanRunInfo ? (
                  <span className="text-emerald-700 dark:text-emerald-300 ml-1.5 font-semibold">
                    &bull; Natural scan completed at {latestScanRunInfo.time} ({filteredFindings.length} issues found this run)
                  </span>
                ) : (
                  <span className="text-cyan-700 dark:text-cyan-300 ml-1 font-semibold">({filteredFindings.length} findings)</span>
                )}
              </span>
            </div>
            <div className="flex items-center space-x-2 self-start sm:self-auto">
              <button
                type="button"
                onClick={() => executeFreshTargetScan(activeTargetAsset.id)}
                disabled={isScanningTarget}
                className="liquid-glass-btn-primary px-3 py-1.5 text-white rounded-xl text-xs font-semibold flex items-center space-x-1.5 cursor-pointer shadow-md disabled:opacity-50"
                title="Execute natural live assessment scan from scratch"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-cyan-200 ${isScanningTarget ? 'animate-spin' : ''}`} />
                <span>{isScanningTarget ? 'Scanning...' : '⚡ Re-Scan from Scratch'}</span>
              </button>
              <button
                type="button"
                onClick={() => handleTargetChange('')}
                className="text-xs text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white px-2 py-1 transition cursor-pointer"
              >
                Clear
              </button>
            </div>
          </div>
        )}

        {/* Live Active Scanning Banner */}
        {isScanningTarget && (
          <div className="liquid-glass rounded-2xl p-4 border border-cyan-500/40 bg-cyan-500/10 dark:bg-cyan-950/30 flex items-center space-x-3.5 text-sm text-cyan-700 dark:text-cyan-200 shadow-xl">
            <RefreshCw className="w-5 h-5 text-cyan-500 dark:text-cyan-400 animate-spin shrink-0" />
            <div className="flex-1">
              <p className="font-semibold text-slate-900 dark:text-white tracking-tight">Running Natural Scan from Scratch</p>
              <p className="text-xs text-cyan-700 dark:text-cyan-200/90 mt-0.5">{scanStatusMessage}</p>
            </div>
          </div>
        )}

        {/* Filter Controls Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-3 border-t border-white/[0.08]">
          {/* Target Filter */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5 flex items-center justify-between">
              <span>Target Asset</span>
              {filterTarget && filterTarget !== '__ALL__' && (
                <span className="text-[10px] text-cyan-700 dark:text-cyan-400 font-semibold font-sans">
                  Filtered
                </span>
              )}
            </label>
            <select
              value={filterTarget}
              onChange={(e) => handleSelectTarget(e.target.value, false)}
              disabled={isScanningTarget}
              className="w-full liquid-glass-input rounded-xl p-2.5 text-xs text-slate-900 dark:text-white font-medium shadow-sm"
            >
              <option value="" className="bg-white dark:bg-slate-900 text-cyan-800 dark:text-cyan-300 font-semibold">
                -- All Authorized Targets ({consolidatedFindings.length} findings) --
              </option>
              {assets.map((a) => {
                const count = consolidatedFindings.filter((f) => f.target_id === a.id).length;
                return (
                  <option key={a.id} value={a.id} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                    {a.canonical_url} {count > 0 ? `(${count} findings)` : '(0 findings)'}
                  </option>
                );
              })}
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Severity</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="w-full liquid-glass-input rounded-xl p-2.5 text-xs text-slate-900 dark:text-white shadow-sm"
            >
              <option value="" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">All Severities</option>
              <option value="CRITICAL" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Critical</option>
              <option value="HIGH" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">High</option>
              <option value="MEDIUM" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Medium</option>
              <option value="LOW" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Low</option>
              <option value="INFO" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Info</option>
            </select>
          </div>

          {/* Validation Status Filter */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Status</label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="w-full liquid-glass-input rounded-xl p-2.5 text-xs text-slate-900 dark:text-white shadow-sm"
            >
              <option value="" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">All Statuses</option>
              <option value="CONFIRMED" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">CONFIRMED</option>
              <option value="POTENTIAL" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">POTENTIAL</option>
              <option value="MITIGATED" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">MITIGATED</option>
              <option value="FALSE_POSITIVE" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">FALSE_POSITIVE</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5">OWASP Category</label>
            <input
              type="text"
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              placeholder="e.g. A01 or A05"
              className="w-full liquid-glass-input rounded-xl p-2.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 font-sans border border-slate-200/80 dark:border-white/10"
            />
          </div>

          {/* Free Text Search */}
          <div>
            <label className="block text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5">Search Keywords</label>
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Title, rule, headers..."
                className="w-full liquid-glass-input rounded-xl pl-9 pr-3 py-2.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 border border-slate-200/80 dark:border-white/10"
              />
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-3" />
            </div>
          </div>
        </div>
      </div>

      {/* Findings Table Card */}
      <div className="liquid-glass-card rounded-2xl shadow-xl overflow-hidden border border-slate-200/80 dark:border-white/[0.08]">
        <div className="p-4 border-b border-slate-200/80 dark:border-white/[0.08] flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 backdrop-blur-md flex-wrap gap-2">
          <div className="flex items-center space-x-2 flex-wrap gap-y-1">
            <span>
              Showing <strong className="text-slate-900 dark:text-white">
                {totalItems === 0 ? 0 : pageSize === -1 ? 1 : (currentPage - 1) * pageSize + 1}
              </strong> to <strong className="text-slate-900 dark:text-white">
                {pageSize === -1 ? totalItems : Math.min(currentPage * pageSize, totalItems)}
              </strong> of{' '}
              <strong className="text-slate-900 dark:text-white">{totalItems}</strong> findings
              {activeTargetAsset && (
                <span className="ml-1 text-cyan-600 dark:text-cyan-300 font-sans font-semibold">
                  for {activeTargetAsset.canonical_url}
                </span>
              )}
            </span>
            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-500/30">
              Sorted by {sortField} ({sortOrder === 'desc' ? 'High-to-Low' : 'Low-to-High'})
            </span>
          </div>

          <div className="flex items-center space-x-3">
            {(filterTarget || filterSeverity || filterStatus || filterCategory || searchQuery) && (
              <button
                type="button"
                onClick={() => {
                  handleTargetChange('');
                  setFilterSeverity('');
                  setFilterStatus('');
                  setFilterCategory('');
                  setSearchQuery('');
                }}
                className="text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-200 font-medium cursor-pointer"
              >
                Reset Filters
              </button>
            )}
          </div>
        </div>

        <div className="overflow-x-auto w-full scrollbar-thin">
          <table className="w-full text-left text-xs table-auto">
            <thead>
              <tr className="bg-slate-50 dark:bg-white/[0.02] text-slate-500 dark:text-slate-400 border-b border-slate-200/80 dark:border-white/[0.06] select-none text-[10px] sm:text-[11px] uppercase tracking-wider font-semibold">
                <th
                  onClick={() => handleSort('severity')}
                  className="py-3 px-2.5 sm:px-3 w-[78px] cursor-pointer hover:text-indigo-600 dark:hover:text-indigo-400 transition"
                  title="Click to sort by severity (Critical to Low)"
                >
                  <div className="flex items-center space-x-1">
                    <span>Severity</span>
                    {renderSortIcon('severity')}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('title')}
                  className="py-3 px-2.5 sm:px-3 min-w-[150px] cursor-pointer hover:text-indigo-600 dark:hover:text-indigo-400 transition"
                  title="Click to sort by vulnerability title"
                >
                  <div className="flex items-center space-x-1">
                    <span>Vulnerability Title</span>
                    {renderSortIcon('title')}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('target')}
                  className="py-3 px-2.5 sm:px-3 min-w-[130px] max-w-[180px] cursor-pointer hover:text-indigo-600 dark:hover:text-indigo-400 transition"
                  title="Click to sort by target URL"
                >
                  <div className="flex items-center space-x-1">
                    <span>Target URL</span>
                    {renderSortIcon('target')}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('category')}
                  className="py-3 px-2.5 sm:px-3 w-[115px] cursor-pointer hover:text-indigo-600 dark:hover:text-indigo-400 transition"
                  title="Click to sort by OWASP Category"
                >
                  <div className="flex items-center space-x-1">
                    <span>OWASP Mappings</span>
                    {renderSortIcon('category')}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('status')}
                  className="py-3 px-2.5 sm:px-3 w-[95px] cursor-pointer hover:text-indigo-600 dark:hover:text-indigo-400 transition"
                  title="Click to sort by validation status"
                >
                  <div className="flex items-center space-x-1">
                    <span>Status</span>
                    {renderSortIcon('status')}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('date')}
                  className="py-3 px-2.5 sm:px-3 w-[105px] cursor-pointer hover:text-indigo-600 dark:hover:text-indigo-400 transition"
                  title="Click to sort by date observed"
                >
                  <div className="flex items-center space-x-1">
                    <span>First / Last Seen</span>
                    {renderSortIcon('date')}
                  </div>
                </th>
                <th className="py-3 px-2 sm:px-3 w-[85px] text-center font-semibold">
                  Action
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60 dark:divide-white/[0.04]">
              {paginatedFindings.map((finding) => {
                  const targetAsset = assets.find((a) => a.id === finding.target_id);
                  return (
                    <tr key={finding.id} className="findings-table-row hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.04] transition duration-100">
                      {/* Severity */}
                      <td className="py-3 px-2.5 sm:px-3 whitespace-nowrap">
                        <span
                          className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-bold ${getSeverityBadgeClass(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>
                      </td>

                      {/* Title & Contributing Scripts */}
                      <td className="py-3 px-2.5 sm:px-3">
                        <div className="font-semibold text-slate-900 dark:text-white leading-snug line-clamp-2">{cleanBugTitle(finding.title)}</div>
                        {(() => {
                          const ev = finding.evidence || {};
                          let scripts: string[] = [];
                          if (Array.isArray(ev.contributing_scripts) && ev.contributing_scripts.length > 0) {
                            scripts = ev.contributing_scripts;
                          } else if (ev.script_name) {
                            scripts = [ev.script_name];
                          } else {
                            const r = String(finding.rule_id || (finding as any).detection_rule_id || '');
                            if (r.startsWith('KALI:PRACTICE:')) {
                              let clean = r.replace('KALI:PRACTICE:', '').toLowerCase().replace(/_mime$/, '');
                              if (clean.endsWith('_py')) clean = clean.slice(0, -3) + '.py';
                              scripts = [clean.replace(/_/g, '-')];
                            }
                          }

                          return (
                            <div className="flex flex-wrap items-center gap-1 mt-1">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-sans font-bold bg-slate-100 dark:bg-slate-800/90 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700/70 shadow-sm">
                                {finding.technical_issue_type}
                              </span>

                              {scripts.length > 0 ? (
                                <div className="flex flex-wrap items-center gap-1">
                                  <span className="text-[9px] text-cyan-700 dark:text-cyan-400 font-sans font-semibold flex items-center gap-0.5 mr-0.5">
                                    <Terminal className="w-2.5 h-2.5 text-cyan-600 dark:text-cyan-400 shrink-0" />
                                    <span>Detected by:</span>
                                  </span>
                                  {scripts.slice(0, 2).map((scriptName) => (
                                    <span
                                      key={scriptName}
                                      className="inline-flex items-center px-1.5 py-0.5 rounded font-sans text-[9px] font-semibold bg-emerald-500/10 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-300 border border-emerald-500/30 dark:border-emerald-500/35 shadow-sm"
                                      title={`Vulnerability confirmed by Kali script: Practice_Scripts/${scriptName}`}
                                    >
                                      <FileCode className="w-2.5 h-2.5 mr-1 text-emerald-400 shrink-0" />
                                      {scriptName}
                                    </span>
                                  ))}
                                  {scripts.length > 2 && (
                                    <span
                                      className="text-[9px] text-slate-500 dark:text-slate-400 font-sans font-medium px-1 cursor-default"
                                      title={scripts.slice(2).join(', ')}
                                    >
                                      +{scripts.length - 2} more
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded font-sans text-[9px] font-semibold text-cyan-800 dark:text-cyan-300 bg-cyan-500/10 border border-cyan-500/30">
                                  <Shield className="w-2.5 h-2.5 mr-1 text-cyan-400 shrink-0" />
                                  {finding.rule_id}
                                </span>
                              )}
                            </div>
                          );
                        })()}
                      </td>

                      {/* Target */}
                      <td className="py-3 px-2.5 sm:px-3 font-sans text-slate-700 dark:text-slate-300 max-w-[180px]">
                        {(() => {
                          const vulnUrl = getVulnerableEndpointUrl(finding, targetAsset);
                          let specificPath = '';
                          try {
                            const u = new URL(vulnUrl);
                            if (u.pathname && u.pathname !== '/') {
                              specificPath = u.pathname + (u.search || '');
                            }
                          } catch {}

                          return (
                            <div>
                              <div
                                className="truncate text-slate-900 dark:text-slate-100 text-xs font-semibold max-w-[170px]"
                                title={vulnUrl}
                              >
                                {vulnUrl}
                              </div>
                              {specificPath && (
                                <span
                                  className="inline-flex items-center space-x-1 mt-1 px-1.5 py-0.5 rounded text-[9px] bg-rose-500/10 dark:bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30 dark:border-rose-500/40 font-mono font-bold"
                                  title={`Specific Vulnerable Path: ${specificPath}`}
                                >
                                  <Globe className="w-2.5 h-2.5 text-rose-500 shrink-0" />
                                  <span className="truncate max-w-[140px]">{specificPath}</span>
                                </span>
                              )}
                            </div>
                          );
                        })()}
                      </td>

                      {/* OWASP Category Mappings */}
                      <td className="py-3 px-2.5 sm:px-3">
                        <div className="flex flex-wrap gap-1 max-w-[125px]">
                          {[...(finding.category_mappings || [])]
                            .sort((a, b) => (b.edition_identifier === '2025' ? 1 : 0) - (a.edition_identifier === '2025' ? 1 : 0))
                            .slice(0, 2)
                            .map((m) => {
                              const is2025 = m.edition_identifier === '2025';
                              const rawCode = m.category_identifier || '';
                              const match = rawCode.match(/^([A-Z0-9]+:\d{4})\s*(.*)$/);
                              const displayCode = match ? match[1] : rawCode;
                              const codeTitle = match && match[2] ? match[2] : (m.justification || '');
                              return (
                                <span
                                  key={m.id}
                                  className={`inline-flex items-center px-1.5 py-0.5 rounded font-sans font-semibold text-[9px] border ${
                                    is2025
                                      ? 'bg-cyan-500/15 dark:bg-cyan-500/20 text-cyan-800 dark:text-cyan-200 border-cyan-400/40 dark:border-cyan-500/40 font-bold shadow-sm'
                                      : 'bg-indigo-500/10 dark:bg-indigo-500/15 text-indigo-800 dark:text-indigo-300 border-indigo-400/30 dark:border-indigo-500/30'
                                  }`}
                                  title={`OWASP ${m.edition_identifier}: ${codeTitle || m.justification}`}
                                >
                                  {displayCode}
                                </span>
                              );
                            })}
                          {(finding.category_mappings || []).length > 2 && (
                            <span
                              className="text-[9px] text-slate-500 dark:text-slate-400 font-sans self-center font-medium cursor-default"
                              title={(finding.category_mappings || []).slice(2).map(m => m.category_identifier).join(', ')}
                            >
                              +{(finding.category_mappings || []).length - 2} more
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3 px-2.5 sm:px-3 whitespace-nowrap">
                        <div className="flex items-center space-x-1.5 font-medium">
                          {getStatusIcon(finding.validation_status)}
                          <span className="text-slate-700 dark:text-slate-300 text-[10px] sm:text-[11px] font-semibold">{finding.validation_status}</span>
                        </div>
                      </td>

                      {/* First/Last Seen with Accurate Time & Precision */}
                      <td className="py-3 px-2.5 sm:px-3 whitespace-nowrap text-[10px] sm:text-[11px]">
                        <div
                          className="font-medium text-slate-800 dark:text-slate-200"
                          title={`First Seen: ${formatExactDateTime(finding.first_seen_at)}`}
                        >
                          {formatDateTimeShort(finding.first_seen_at)}
                        </div>
                        <div
                          className="text-[9px] text-cyan-700 dark:text-cyan-400 font-sans font-semibold flex items-center space-x-1 mt-0.5"
                          title={`Last Verified: ${formatExactDateTime(finding.last_seen_at)}`}
                        >
                          <Clock className="w-2.5 h-2.5 shrink-0" />
                          <span>verified {formatRelativeTime(finding.last_seen_at)}</span>
                        </div>
                      </td>

                      {/* Action */}
                      <td className="py-3 px-2 sm:px-3 w-[85px] text-center whitespace-nowrap">
                        <div className="flex items-center justify-center">
                          <button
                            type="button"
                            onClick={() => setActiveFinding(finding)}
                            className="inline-flex items-center justify-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-50 dark:bg-indigo-950/40 hover:bg-indigo-100 dark:hover:bg-indigo-900/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-500/30 transition shadow-sm cursor-pointer hover:scale-[1.02] shrink-0"
                            title="Inspect complete evidence, payloads, scripts & trace"
                          >
                            <Eye className="w-3.5 h-3.5 shrink-0" />
                            <span>Evidence</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}

                {filteredFindings.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-14 text-center text-slate-500">
                      <ShieldAlert className="w-12 h-12 mx-auto mb-2.5 opacity-30 text-slate-400" />
                      <p className="text-sm font-semibold text-slate-400">
                        {activeTargetAsset
                          ? `No findings identified for ${activeTargetAsset.canonical_url}`
                          : 'No findings match the current criteria.'}
                      </p>
                      <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                        {activeTargetAsset
                          ? 'Assessment checks ran cleanly or no vulnerabilities were flagged on this specific target.'
                          : 'Try adjusting the severity or status filters, or launch an assessment against an asset.'}
                      </p>
                      <button
                        onClick={() => {
                          handleTargetChange('');
                          setFilterSeverity('');
                          setFilterStatus('');
                          setFilterCategory('');
                          setSearchQuery('');
                        }}
                        className="mt-3 px-3.5 py-1.5 liquid-glass-btn-secondary text-cyan-300 rounded-lg text-xs font-medium cursor-pointer"
                      >
                        Reset All Filters
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls Bar */}
          {totalItems > 0 && (
            <div className="p-4 border-t border-slate-200/80 dark:border-white/[0.08] flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-600 dark:text-slate-400 bg-slate-50/50 dark:bg-white/[0.01]">
              <div className="flex items-center space-x-3">
                <span>
                  Showing{' '}
                  <strong className="text-slate-900 dark:text-white">
                    {pageSize === -1 ? 1 : Math.min((currentPage - 1) * pageSize + 1, totalItems)}
                  </strong>{' '}
                  to{' '}
                  <strong className="text-slate-900 dark:text-white">
                    {pageSize === -1 ? totalItems : Math.min(currentPage * pageSize, totalItems)}
                  </strong>{' '}
                  of <strong className="text-slate-900 dark:text-white">{totalItems}</strong> findings
                </span>
                <div className="flex items-center space-x-1.5 pl-2 border-l border-slate-300 dark:border-white/10">
                  <span className="text-[11px]">Rows per page:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      setPageSize(Number(e.target.value));
                      setCurrentPage(1);
                    }}
                    className="liquid-glass-input rounded-lg px-2 py-1 text-xs text-slate-900 dark:text-white bg-white dark:bg-slate-900 border border-slate-300 dark:border-white/10 cursor-pointer"
                  >
                    <option value={10}>10</option>
                    <option value={20}>20</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
                    <option value={-1}>All ({totalItems})</option>
                  </select>
                </div>
              </div>

              {pageSize !== -1 && totalPages > 1 && (
                <div className="flex items-center space-x-1.5">
                  <button
                    type="button"
                    onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                    disabled={currentPage === 1}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-white/5 hover:bg-slate-100 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed transition text-slate-800 dark:text-slate-200 flex items-center space-x-1 cursor-pointer font-medium"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                    <span>Prev</span>
                  </button>

                  <div className="flex items-center space-x-1 px-1">
                    {Array.from({ length: totalPages }, (_, i) => i + 1)
                      .filter((p) => p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1)
                      .reduce((acc: (number | string)[], p, idx, arr) => {
                        if (idx > 0 && p - (arr[idx - 1] as number) > 1) {
                          acc.push('...');
                        }
                        acc.push(p);
                        return acc;
                      }, [])
                      .map((item, idx) =>
                        item === '...' ? (
                          <span key={`dots-${idx}`} className="px-1 text-slate-400">...</span>
                        ) : (
                          <button
                            key={item}
                            type="button"
                            onClick={() => setCurrentPage(item as number)}
                            className={`w-7 h-7 rounded-lg text-xs font-semibold flex items-center justify-center transition cursor-pointer ${
                              currentPage === item
                                ? 'bg-indigo-600 text-white shadow-sm'
                                : 'border border-slate-200 dark:border-white/10 bg-white dark:bg-white/5 hover:bg-slate-100 dark:hover:bg-white/10 text-slate-800 dark:text-slate-200'
                            }`}
                          >
                            {item}
                          </button>
                        )
                      )}
                  </div>

                  <button
                    type="button"
                    onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
                    disabled={currentPage === totalPages}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-white/5 hover:bg-slate-100 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed transition text-slate-800 dark:text-slate-200 flex items-center space-x-1 cursor-pointer font-medium"
                  >
                    <span>Next</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

      {/* Finding Detail Modal with Fluid Spring Animation */}
      <AnimatePresence>
        {activeFinding && (
          <FindingDetailModal
            finding={activeFinding}
            asset={assets.find((a) => a.id === activeFinding.target_id) || (filterTarget ? assets.find((a) => a.id === filterTarget) : null) || assets[0] || null}
            onClose={() => setActiveFinding(null)}
            onStatusUpdated={(updated) => {
              setActiveFinding(updated);
              onRefreshData();
            }}
            onOpenTerminal={(scanId) => {
              setTerminalScanId(
                scanId ||
                  activeFinding?.scan_id ||
                  activeFinding?.last_scan_id ||
                  activeFinding?.initial_scan_id ||
                  filteredFindings[0]?.scan_id ||
                  filteredFindings[0]?.last_scan_id ||
                  filteredFindings[0]?.initial_scan_id
              );
              setShowTerminalModal(true);
            }}
          />
        )}
      </AnimatePresence>

      {/* Deep Scan Live Terminal Console Modal */}
      <AnimatePresence>
        {showTerminalModal && (
          <ScanTerminalModal
            scanId={
              terminalScanId ||
              activeFinding?.scan_id ||
              activeFinding?.last_scan_id ||
              activeFinding?.initial_scan_id ||
              filteredFindings[0]?.scan_id ||
              filteredFindings[0]?.last_scan_id ||
              filteredFindings[0]?.initial_scan_id
            }
            targetAsset={
              activeTargetAsset ||
              assets.find((a) => a.id === (activeFinding?.target_id || filteredFindings[0]?.target_id)) ||
              null
            }
            onClose={() => setShowTerminalModal(false)}
          />
        )}
      </AnimatePresence>
    </div>
  );
};


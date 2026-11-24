import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe,
  Shield,
  CheckCircle,
  AlertTriangle,
  Play,
  Clock,
  Plus,
  RefreshCw,
  Radar,
  Search,
  ExternalLink,
  Zap,
  Check,
  ChevronDown,
  ChevronUp,
  Layers,
  Server,
  Activity,
  X,
  Trash2,
  Terminal,
} from 'lucide-react';
import type { AuthorizedAsset, ScopeGrant, ScanJob } from '../types/api';
import { api } from '../services/api';
import { formatDateTimeShort, formatRelativeTime } from '../utils/formatters';
import { ScanTerminalModal } from './ScanTerminalModal';
import { LiveScanTerminal } from './LiveScanTerminal';
import { KaliTerminal } from './KaliTerminal';
import type { TerminalLogEntry } from '../types/api';
import { getAssessmentTerminalState, setAssessmentTerminalState } from '../utils/assessmentTerminalStore';

interface TargetAssessmentTabProps {
  assets: AuthorizedAsset[];
  scopes: ScopeGrant[];
  onRefreshData: () => Promise<void>;
  onScanCompleted: (scan: ScanJob, asset?: AuthorizedAsset) => void;
  onNavigateToTab: (tab: any) => void;
  onSelectTarget?: (targetId: string) => void;
}

export const TargetAssessmentTab: React.FC<TargetAssessmentTabProps> = ({
  assets,
  scopes,
  onRefreshData,
  onScanCompleted,
  onNavigateToTab,
  onSelectTarget,
}) => {
  // Input Form State
  const [targetInput, setTargetInput] = useState('');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [selectedScopeCode, setSelectedScopeCode] = useState(scopes[0]?.scope_code || '');
  const [skipDns, setSkipDns] = useState(true); // default true for mock/testing
  const approvalNotes = 'Authorized by Security Assessment Plan';

  // Ensure the page always starts cleanly at the top when mounted
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0 });
    const scrollContainers = document.querySelectorAll('.overflow-y-auto, [class*="overflow-y-auto"]');
    scrollContainers.forEach((container) => {
      // Only reset top-level layout scroll containers, not internal terminal viewports
      if (!container.className.includes('bg-[#0b0f19]')) {
        container.scrollTop = 0;
      }
    });
  }, []);

  // Synchronize scope selection when scopes load
  useEffect(() => {
    if (!selectedScopeCode && scopes.length > 0) {
      setSelectedScopeCode(scopes[0].scope_code);
    }
  }, [scopes, selectedScopeCode]);

  // Validation State
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<{
    valid: boolean;
    message: string;
    details?: any;
  } | null>(null);

  // Scanning State
  const [scanningAssetId, setScanningAssetId] = useState<string | null>(null);
  const [deletingAssetId, setDeletingAssetId] = useState<string | null>(null);
  const [scanStatusMessage, setScanStatusMessage] = useState<string | null>(null);
  const [scanErrorMessage, setScanErrorMessage] = useState<string | null>(null);

  // Automated Practice Scripts Scanning State (Phase 1 Kali Terminal -> Phase 2 Red Team Terminal)
  const [isAutomatedPracticeScanning, setIsAutomatedPracticeScanning] = useState(false);
  const [practiceScanTarget, setPracticeScanTarget] = useState<AuthorizedAsset | null>(null);

  // Scan Terminal State
  const [showTerminalModal, setShowTerminalModal] = useState(false);
  const [terminalAsset, setTerminalAsset] = useState<AuthorizedAsset | null>(null);
  const [terminalScanId, setTerminalScanId] = useState<string | undefined>(undefined);
  const [terminalScanJob, setTerminalScanJob] = useState<ScanJob | null>(null);

  // Persistent Inline Live Terminal State (Preserved across tab switches and visits)
  const storedTerminalState = getAssessmentTerminalState();
  const [showLiveTerminal, setShowLiveTerminal] = useState(storedTerminalState.showLiveTerminal);
  const [selectedTerminalAsset, setSelectedTerminalAsset] = useState<AuthorizedAsset | null>(() => {
    if (storedTerminalState.selectedTerminalAsset) {
      return (
        assets.find((a) => a.id === storedTerminalState.selectedTerminalAsset?.id) ||
        storedTerminalState.selectedTerminalAsset
      );
    }
    return null;
  });
  const [terminalTargetScope, setTerminalTargetScope] = useState<string>(
    storedTerminalState.kaliActiveAssetId && storedTerminalState.kaliActiveAssetId !== 'all'
      ? storedTerminalState.kaliActiveAssetId
      : 'personal'
  );
  const [inlineTerminalLogs, setInlineTerminalLogs] = useState<TerminalLogEntry[]>(
    storedTerminalState.inlineTerminalLogs
  );
  const [latestScanJob, setLatestScanJob] = useState<ScanJob | null>(
    storedTerminalState.latestScanJob
  );
  const terminalContainerRef = useRef<HTMLDivElement>(null);

  // Ensure the page starts cleanly at the top when navigating to Target Assessment
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    const mainContainer = document.querySelector('main')?.parentElement;
    if (mainContainer) {
      mainContainer.scrollTop = 0;
    }
  }, []);

  // New Scope Modal
  const [showScopeModal, setShowScopeModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [newScopeTitle, setNewScopeTitle] = useState('');
  const [newScopeCode, setNewScopeCode] = useState('');
  const [newAuthorizedBy, setNewAuthorizedBy] = useState('secops@sentinel.internal');

  // 1. Live Target Validation
  const handleValidateTarget = async () => {
    if (!targetInput.trim()) return;
    setValidating(true);
    setValidationResult(null);

    try {
      const res = await api.validateTarget(targetInput.trim(), isAuthorized);
      setValidationResult({
        valid: res.is_valid,
        message: `Target validated successfully! Canonical URL: ${res.canonical_url} (Port: ${res.port})`,
        details: res,
      });
    } catch (err: any) {
      setValidationResult({
        valid: false,
        message: err.message || 'Validation failed. Check authorization and target URL format.',
      });
    } finally {
      setValidating(false);
    }
  };

  // 2. Register Target Asset
  const handleRegisterTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    if (!isAuthorized) {
      alert('Explicit authorization is required before adding targets to the assessment inventory.');
      return;
    }

    try {
      // If no scope exists, generate one automatically
      let scopeCodeToUse = selectedScopeCode;
      if (!scopeCodeToUse) {
        const autoScopeCode = `SCOPE-DEFAULT-${Date.now().toString().slice(-6)}`;
        await api.createScope({
          organization_name: 'Internal Assessment Group',
          scope_code: autoScopeCode,
          title: 'Default Assessment Scope',
          authorized_by: 'secops@sentinel.internal',
          valid_from: new Date().toISOString(),
          valid_until: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
          permitted_ports: [80, 443, 8080, 8443, 5000, 3000],
          permitted_schemes: ['http', 'https'],
          allow_subdomains: true,
        });
        scopeCodeToUse = autoScopeCode;
      }

      await api.registerAsset({
        target: targetInput.trim(),
        scope_code: scopeCodeToUse,
        is_authorized: isAuthorized,
        skip_dns_resolution: skipDns,
        approval_notes: approvalNotes,
      });

      setTargetInput('');
      setValidationResult(null);
      await onRefreshData();
    } catch (err: any) {
      alert(`Registration failed: ${err.message}`);
    }
  };

  // 3. Trigger Scan: Phase 1 Kali Practice Scripts Scanning -> Phase 2 Red Team Scanner Terminal
  const handleExecuteScan = async (asset: AuthorizedAsset) => {
    if (asset.approval_status !== 'APPROVED') {
      setScanErrorMessage(`Asset cannot be scanned: Status is '${asset.approval_status}'. Approval is required.`);
      return;
    }

    setScanErrorMessage(null);
    setScanStatusMessage(`Phase 1: Dispatching Kali Linux Practice Scripts suite (407 scripts) against ${asset.canonical_url}...`);
    setSelectedTerminalAsset(asset);
    setTerminalTargetScope(asset.id);
    setShowLiveTerminal(false);
    setInlineTerminalLogs([]);
    setLatestScanJob(null);
    setScanningAssetId(asset.id);
    setPracticeScanTarget(asset);
    setIsAutomatedPracticeScanning(true);

    setAssessmentTerminalState({
      selectedTerminalAsset: asset,
      inlineTerminalLogs: [],
      latestScanJob: null,
      showLiveTerminal: false,
      lastScannedAssetId: asset.id,
    });

    // Smoothly scroll down so user visibly watches Phase 1 Kali Terminal execute Practice Scripts
    setTimeout(() => {
      const el = document.getElementById('kali-terminal-section');
      if (el && typeof el.scrollIntoView === 'function') {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 60);
  };

  // Called when Kali Practice Scripts finishes -> automatically redirects to OWASP Findings tab
  const handlePracticeScanComplete = async (bugsFound: number) => {
    setIsAutomatedPracticeScanning(false);
    setScanningAssetId(null);
    setScanStatusMessage(null);

    const asset = practiceScanTarget || selectedTerminalAsset;
    if (!asset) {
      if (onNavigateToTab) onNavigateToTab('findings');
      return;
    }

    try {
      // Refresh findings data immediately from DB (scan_practice_scripts already stored all findings in DB)
      await onRefreshData();
    } catch {}

    // Select scanned target in findings filter
    if (onSelectTarget) {
      onSelectTarget(asset.id);
    }

    // Redirect directly to OWASP Findings tab immediately as requested
    if (onNavigateToTab) {
      onNavigateToTab('findings');
    }
  };

  // Called after live terminal scan output finishes streaming
  const handlePerformRedirectToFindings = () => {
    // Keep showLiveTerminal = true so scanning results remain visible on the terminal when returning!
    if (selectedTerminalAsset) {
      if (onSelectTarget) {
        onSelectTarget(selectedTerminalAsset.id);
      }
    }
    if (onNavigateToTab) {
      onNavigateToTab('findings');
    }
    if (latestScanJob && onScanCompleted) {
      onScanCompleted(latestScanJob, selectedTerminalAsset || undefined);
    }
  };

  // Delete Asset
  const handleDeleteAsset = async (asset: AuthorizedAsset) => {
    const confirmDelete = window.confirm(
      `Are you sure you want to delete "${asset.canonical_url}" from your inventory?\n\nThis will permanently remove the asset, its associated scan jobs, and findings.`
    );
    if (!confirmDelete) return;

    setDeletingAssetId(asset.id);
    setScanErrorMessage(null);
    try {
      await api.deleteAsset(asset.id);
      await onRefreshData();
    } catch (err: any) {
      setScanErrorMessage(`Failed to delete asset: ${err.message || 'Unknown error'}`);
    } finally {
      setDeletingAssetId(null);
    }
  };

  // 4. Create New Scope
  const handleCreateScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName || !newScopeCode || !newScopeTitle) return;

    try {
      const created = await api.createScope({
        organization_name: newOrgName,
        scope_code: newScopeCode.toUpperCase(),
        title: newScopeTitle,
        authorized_by: newAuthorizedBy,
        valid_from: new Date().toISOString(),
        valid_until: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        permitted_ports: [80, 443, 8080, 8443],
        permitted_schemes: ['http', 'https'],
        allow_subdomains: true,
      });

      setShowScopeModal(false);
      setSelectedScopeCode(created.scope_code);
      await onRefreshData();
    } catch (err: any) {
      alert(`Failed to create scope: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target Registration & Clearance Panel */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center space-x-2.5">
              <span className="p-2 rounded-xl bg-indigo-500/20 border border-indigo-400/30 text-indigo-700 dark:text-indigo-300">
                <Globe className="w-5 h-5" />
              </span>
              <span className="tracking-tight">Target Assessment & Scope Authorization</span>
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
              Strict input validation, SSRF boundary protection, and mandatory cryptographic authorization verification.
            </p>
          </div>
          <div className="flex items-center space-x-2.5">
            <button
              type="button"
              onClick={() => setShowScopeModal(true)}
              className="liquid-glass-btn-secondary text-xs px-3.5 py-2 font-medium flex items-center space-x-1.5 cursor-pointer shadow-sm rounded-xl"
            >
              <Plus className="w-3.5 h-3.5 text-cyan-400" />
              <span>Create Scope Grant</span>
            </button>
          </div>
        </div>

        <form onSubmit={handleRegisterTarget} className="space-y-5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Target Input */}
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5 font-sans">
                Target URL, Domain, or IP
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="https://example.com or 93.184.216.34:8443"
                  className="liquid-glass-input w-full px-3.5 py-2.5 text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 font-sans font-medium border border-slate-200/80 dark:border-white/10"
                  required
                />
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1.5 flex items-center space-x-1">
                <span>Supported schemes: <code className="text-cyan-600 dark:text-cyan-300 font-sans font-semibold">http://</code>, <code className="text-cyan-600 dark:text-cyan-300 font-sans font-semibold">https://</code>. Ports: 1–65535. Excluded: Cloud metadata, RFC1918 loopback.</span>
              </p>
            </div>

            {/* Scope Grant Selection */}
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5 font-sans">
                Scope Grant
              </label>
              <select
                value={selectedScopeCode}
                onChange={(e) => setSelectedScopeCode(e.target.value)}
                className="liquid-glass-input w-full px-3 py-2.5 text-sm text-slate-900 dark:text-white font-sans bg-white dark:bg-slate-900/90 shadow-sm"
              >
                {scopes.map((s) => (
                  <option key={s.id} value={s.scope_code} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                    {s.scope_code} ({s.title})
                  </option>
                ))}
                {scopes.length === 0 && <option value="" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">No Scope (Will auto-generate)</option>}
              </select>
              <p className="text-[11px] text-slate-500 dark:text-slate-400/90 mt-1.5">
                Enforces permitted ports, protocols, and subdomain boundary rules.
              </p>
            </div>
          </div>

          {/* Authorization Checkbox & Lab Options */}
          <div className="liquid-glass rounded-xl p-4.5 space-y-3 border border-slate-200/80 dark:border-white/10">
            <div className="flex items-start space-x-3">
              <input
                id="auth-checkbox"
                type="checkbox"
                checked={isAuthorized}
                onChange={(e) => setIsAuthorized(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-slate-300 dark:border-white/20 bg-slate-100 dark:bg-slate-900/80 text-indigo-500 focus:ring-indigo-400 cursor-pointer accent-indigo-500"
              />
              <label htmlFor="auth-checkbox" className="text-xs text-slate-700 dark:text-slate-200 leading-relaxed cursor-pointer select-none">
                <span className="font-semibold text-slate-900 dark:text-white">Explicit Authorization Acknowledgment:</span> I confirm that
                I own or possess explicit written authorization to perform security testing against this target.
                Assessments are strictly non-destructive.
              </label>
            </div>

            <div className="flex items-center space-x-4 pt-2.5 border-t border-slate-200/80 dark:border-white/10 text-xs">
              <label className="flex items-center space-x-2 text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={skipDns}
                  onChange={(e) => setSkipDns(e.target.checked)}
                  className="rounded border-slate-300 dark:border-white/20 bg-slate-100 dark:bg-slate-900 text-indigo-500 accent-indigo-500 cursor-pointer"
                />
                <span>Skip DNS resolution (Safe offline/lab mode)</span>
              </label>
            </div>
          </div>

          {/* Validation Status Feedback */}
          {validationResult && (
            <div
              className={`p-3.5 rounded-xl text-xs flex items-start space-x-2.5 border backdrop-blur-md ${
                validationResult.valid
                  ? 'bg-emerald-500/15 border-emerald-400/30 text-emerald-200'
                  : 'bg-rose-500/15 border-rose-400/30 text-rose-200'
              }`}
            >
              {validationResult.valid ? (
                <CheckCircle className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
              )}
              <div>
                <p className="font-medium">{validationResult.message}</p>
              </div>
            </div>
          )}

          {/* Form Actions */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-200/80 dark:border-white/10">
            <button
              type="button"
              onClick={() => onNavigateToTab('subdomains')}
              className="liquid-glass-btn-secondary px-3.5 py-2 text-xs font-semibold flex items-center justify-center space-x-2 cursor-pointer text-cyan-600 dark:text-cyan-300 hover:text-cyan-700 dark:hover:text-white rounded-xl shadow-sm"
              title="Launch Subdomain Finder & Reconnaissance Engine"
            >
              <Radar className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>Subdomain Finder &rarr;</span>
            </button>

            <div className="flex items-center space-x-3">
              <button
                type="button"
                onClick={handleValidateTarget}
                disabled={validating || !targetInput.trim()}
                className="liquid-glass-btn-secondary px-4 py-2 text-xs font-medium flex items-center space-x-1.5 cursor-pointer disabled:opacity-40"
              >
                {validating ? <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" /> : <Shield className="w-3.5 h-3.5 text-cyan-400" />}
                <span>Validate Input</span>
              </button>
              <button
                type="submit"
                disabled={!targetInput.trim() || !isAuthorized}
                className="liquid-glass-btn-primary px-5 py-2 text-xs font-semibold flex items-center space-x-1.5 cursor-pointer disabled:opacity-40"
              >
                <Plus className="w-3.5 h-3.5 text-white" />
                <span>Register Authorized Target</span>
              </button>
            </div>
          </div>
        </form>
      </div>

{/* Authorized Targets Table */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Authorized Target Inventory</h2>
            <p className="text-xs text-slate-600 dark:text-slate-400">Approved assets available for non-destructive security evaluation</p>
          </div>
          <button
            onClick={() => onRefreshData()}
            className="p-2 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white rounded-xl hover:bg-slate-500/10 dark:hover:bg-white/10 transition border border-slate-200/80 dark:border-white/5 cursor-pointer"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-white/10 text-slate-500 dark:text-slate-400 font-semibold text-xs font-sans">
                <th className="pb-3">Canonical Target</th>
                <th className="pb-3">Scope Grant</th>
                <th className="pb-3">Approval Status</th>
                <th className="pb-3">Subdomain</th>
                <th className="pb-3">First Registered</th>
                <th className="pb-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60 dark:divide-white/5">
              {assets.map((asset) => {
                const isScanning = scanningAssetId === asset.id;
                return (
                  <tr key={asset.id} className="hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.04] transition-colors">
                    <td className="py-3.5 font-sans text-xs text-slate-900 dark:text-white font-semibold">
                      <div className="flex items-center space-x-2">
                        <Globe className="w-3.5 h-3.5 text-indigo-500 dark:text-indigo-400 shrink-0" />
                        <span className="truncate max-w-sm">{asset.canonical_url}</span>
                      </div>
                    </td>
                    <td className="py-3.5 font-sans text-xs text-slate-600 dark:text-slate-300 font-medium">{asset.scope_grant_id?.slice(0, 8)}...</td>
                    <td className="py-3.5">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold tracking-wide border ${
                          asset.approval_status === 'APPROVED'
                            ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-400/30'
                            : asset.approval_status === 'PENDING'
                            ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-400/30'
                            : 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-400/30'
                        }`}
                      >
                        {asset.approval_status}
                      </span>
                    </td>
                    <td className="py-3.5 text-slate-700 dark:text-slate-300">
                      {asset.is_subdomain ? (
                        <span className="text-amber-600 dark:text-amber-300 font-medium">Yes (Subdomain)</span>
                      ) : (
                        <span>Apex Target</span>
                      )}
                    </td>
                    <td className="py-3.5 text-slate-700 dark:text-slate-300">
                      <div className="flex flex-col">
                        <span className="font-sans text-xs text-slate-800 dark:text-slate-200 font-medium">
                          {formatDateTimeShort(asset.created_at || asset.first_discovered_at)}
                        </span>
                        {(asset.created_at || asset.first_discovered_at) && (
                          <span className="text-[10px] text-slate-500 dark:text-slate-400">
                            {formatRelativeTime(asset.created_at || asset.first_discovered_at)}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 text-right">
                      <div className="flex items-center justify-end space-x-1.5">
                        <button
                          onClick={() => handleExecuteScan(asset)}
                          disabled={isScanning || asset.approval_status !== 'APPROVED'}
                          className="liquid-glass-btn-primary px-3 py-1.5 disabled:opacity-40 text-white rounded-lg text-xs font-medium flex items-center space-x-1.5 cursor-pointer shadow-md"
                          title="Scan this target"
                        >
                          {isScanning ? (
                            <RefreshCw className="w-3 h-3 animate-spin text-cyan-200" />
                          ) : (
                            <Play className="w-3 h-3 fill-current text-cyan-200" />
                          )}
                          <span>{isScanning ? 'Scanning...' : 'Scan'}</span>
                        </button>
                        <button
                          onClick={() => onNavigateToTab('schedules')}
                          className="p-1.5 text-slate-300 hover:text-white hover:bg-white/10 rounded-lg transition border border-white/5 cursor-pointer"
                          title="Schedule Recurring Assessment"
                        >
                          <Clock className="w-4 h-4 text-slate-300" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteAsset(asset)}
                          disabled={deletingAssetId === asset.id || isScanning}
                          className="p-1.5 text-rose-400 hover:text-rose-200 hover:bg-rose-500/20 rounded-lg transition border border-rose-500/20 cursor-pointer disabled:opacity-50"
                          title={`Delete asset ${asset.canonical_url}`}
                        >
                          {deletingAssetId === asset.id ? (
                            <RefreshCw className="w-4 h-4 animate-spin text-rose-300" />
                          ) : (
                            <Trash2 className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {assets.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-slate-400">
                    No authorized targets registered. Use the form above to add an authorized domain or IP.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Kali Linux Interactive Assessment Terminal */}
      <div id="kali-terminal-section" className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight flex items-center space-x-2">
              <span className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30">
                <Terminal className="w-4 h-4" />
              </span>
              <span>Kali Linux Target Assessment Terminal</span>
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Execute manual assessment scripts (.py, .sh), cURL probes, and custom exploit tests directly against your authorized targets.
            </p>
          </div>
        </div>

        <KaliTerminal
          assets={assets}
          selectedTargetId={terminalTargetScope}
          isAutomatedPracticeScanning={isAutomatedPracticeScanning}
          practiceScanTarget={practiceScanTarget}
          onPracticeScanComplete={handlePracticeScanComplete}
          onSelectTarget={(targetId) => {
            setTerminalTargetScope(targetId);
            if (targetId === 'all' || targetId === 'personal') {
              setSelectedTerminalAsset(null);
            } else {
              const found = assets.find((a) => a.id === targetId);
              if (found) setSelectedTerminalAsset(found);
            }
            if (onSelectTarget) onSelectTarget(targetId);
          }}
        />
      </div>

      {/* Live Red-Team Scan Execution Terminal Console (Visible ONLY when user taps Scan on a target in asset inventory) */}
      <AnimatePresence>
        {showLiveTerminal && selectedTerminalAsset && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 15 }}
            transition={{ duration: 0.25 }}
            ref={terminalContainerRef}
            className="space-y-2 pt-1"
          >
            <LiveScanTerminal
              activeAsset={selectedTerminalAsset}
              isScanning={scanningAssetId !== null}
              scanJob={latestScanJob}
              terminalLogs={inlineTerminalLogs}
              onRedirectToFindings={handlePerformRedirectToFindings}
              onClose={() => {
                setShowLiveTerminal(false);
                setAssessmentTerminalState({ showLiveTerminal: false });
              }}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Active Scan Error Notification */}
      {scanErrorMessage && (
        <div className="liquid-glass rounded-2xl p-4.5 border border-rose-500/30 bg-rose-500/10 dark:bg-rose-950/25 backdrop-blur-xl flex items-center justify-between text-sm text-rose-700 dark:text-rose-200 shadow-xl">
          <div className="flex items-center space-x-3.5">
            <AlertTriangle className="w-5 h-5 text-rose-500 dark:text-rose-400 shrink-0" />
            <div>
              <p className="font-semibold text-slate-900 dark:text-white tracking-tight">Assessment Error</p>
              <p className="text-xs text-rose-600 dark:text-rose-200/90 mt-0.5">{scanErrorMessage}</p>
            </div>
          </div>
          <button
            onClick={() => setScanErrorMessage(null)}
            className="p-1.5 text-slate-400 hover:text-slate-900 dark:hover:text-white rounded-lg hover:bg-slate-500/10 dark:hover:bg-white/10 transition cursor-pointer"
          >
            &times;
          </button>
        </div>
      )}

      {/* Active Scan Progress Notification */}
      {scanStatusMessage && (
        <div className="liquid-glass rounded-2xl p-4.5 border border-cyan-500/30 bg-cyan-500/10 dark:bg-cyan-950/20 backdrop-blur-xl flex items-center space-x-3.5 text-sm text-cyan-700 dark:text-cyan-200 shadow-xl">
          <RefreshCw className="w-5 h-5 text-cyan-500 dark:text-cyan-400 animate-spin shrink-0" />
          <div className="flex-1">
            <p className="font-semibold text-slate-900 dark:text-white tracking-tight">Security Assessment in Progress</p>
            <p className="text-xs text-cyan-700 dark:text-cyan-200/80 mt-0.5">{scanStatusMessage}</p>
          </div>
          <button
            onClick={() => onNavigateToTab('findings')}
            className="liquid-glass-btn-primary px-3.5 py-1.5 text-white rounded-lg text-xs font-medium cursor-pointer"
          >
            Go to Findings
          </button>
        </div>
      )}

      {/* Scope Grant Creation Modal */}
      {showScopeModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto modal-dimmed-backdrop">
          <div className="min-h-full flex items-start justify-center p-4">
            <div className="liquid-glass-card rounded-3xl max-w-lg w-full p-6 shadow-2xl space-y-4 border border-slate-200/80 dark:border-white/20 my-8 text-left">
            <div className="flex items-center justify-between border-b border-slate-200/80 dark:border-white/10 pb-3">
              <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Create New Scope Grant</h3>
              <button
                onClick={() => setShowScopeModal(false)}
                className="text-slate-400 hover:text-slate-900 dark:hover:text-white text-xl font-bold p-1 cursor-pointer"
              >
                &times;
              </button>
            </div>
            <form onSubmit={handleCreateScope} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Organization Name</label>
                <input
                  type="text"
                  value={newOrgName}
                  onChange={(e) => setNewOrgName(e.target.value)}
                  placeholder="e.g. Acme Corp"
                  className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white border border-slate-200/80 dark:border-white/10"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Scope Code</label>
                  <input
                    type="text"
                    value={newScopeCode}
                    onChange={(e) => setNewScopeCode(e.target.value)}
                    placeholder="SCOPE-ACME-01"
                    className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white font-sans border border-slate-200/80 dark:border-white/10"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Authorized By</label>
                  <input
                    type="email"
                    value={newAuthorizedBy}
                    onChange={(e) => setNewAuthorizedBy(e.target.value)}
                    className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white border border-slate-200/80 dark:border-white/10"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1.5">Scope Title</label>
                <input
                  type="text"
                  value={newScopeTitle}
                  onChange={(e) => setNewScopeTitle(e.target.value)}
                  placeholder="Production Web Apps & APIs"
                  className="liquid-glass-input w-full px-3 py-2 text-slate-900 dark:text-white border border-slate-200/80 dark:border-white/10"
                  required
                />
              </div>
              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-200/80 dark:border-white/10">
                <button
                  type="button"
                  onClick={() => setShowScopeModal(false)}
                  className="liquid-glass-btn-secondary px-3.5 py-1.5 text-slate-700 dark:text-slate-300 text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="liquid-glass-btn-primary px-4 py-1.5 text-white text-xs font-medium cursor-pointer"
                >
                  Save Scope Grant
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    )}
      {/* Deep Scan Live Terminal Console Modal */}
      <AnimatePresence>
        {showTerminalModal && (
          <ScanTerminalModal
            scanId={terminalScanId}
            initialScanJob={terminalScanJob}
            targetAsset={terminalAsset}
            onClose={() => setShowTerminalModal(false)}
          />
        )}
      </AnimatePresence>
    </div>
  );
};


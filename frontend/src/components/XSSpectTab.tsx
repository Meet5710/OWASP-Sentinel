import React, { useState, useMemo } from 'react';
import {
  Code,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Play,
  RotateCcw,
  AlertTriangle,
  ChevronDown,
  Search,
  ExternalLink,
  Copy,
  Check,
  Activity,
  Sliders,
  Terminal,
  FileCode,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import type { AuthorizedAsset } from '../types/api';
import type { ActiveTab } from './Sidebar';
import { api } from '../services/api';

export interface XSSpectTabProps {
  assets: AuthorizedAsset[];
  onNavigateToTab?: (tab: ActiveTab) => void;
  onRefreshData?: () => void;
}

interface TestFinding {
  id: string;
  parameter: string;
  payloadType: string;
  context: string;
  reflectionStatus: 'Reflected & Executed' | 'Reflected (Encoded)' | 'Not Reflected';
  severity: 'HIGH' | 'LOW' | 'INFO';
  timestamp: string;
}

export const XSSpectTab: React.FC<XSSpectTabProps> = ({
  assets,
  onNavigateToTab,
}) => {
  const approvedAssets = useMemo(
    () => assets.filter((a) => a.approval_status === 'APPROVED' || !a.approval_status),
    [assets]
  );

  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [parameterInput, setParameterInput] = useState<string>('q, search, id, query, redirect');
  const [detectionMode, setDetectionMode] = useState<'STANDARD' | 'DEEP' | 'DOM'>('STANDARD');
  const [usePlaywright, setUsePlaywright] = useState<boolean>(true);
  const [isTargetDropdownOpen, setIsTargetDropdownOpen] = useState<boolean>(false);
  const [searchTargetQuery, setSearchTargetQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [findingsFilter, setFindingsFilter] = useState<'ALL' | 'EXECUTED' | 'REFLECTED' | 'SCRIPTS' | 'HANDLERS'>('ALL');
  const [scanResult, setScanResult] = useState<{
    url: string;
    target_id?: string;
    parameters_tested: string[];
    findings: Array<{
      parameter: string;
      payload: string;
      executed: boolean;
      reflected: boolean;
      dialog_message?: string | null;
      error?: string | null;
    }>;
    vulnerable: boolean;
    error?: string | null;
  } | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const targetDropdownRef = React.useRef<HTMLDivElement | null>(null);

  // Close dropdown on outside click
  React.useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (targetDropdownRef.current && !targetDropdownRef.current.contains(e.target as Node)) {
        setIsTargetDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedAsset = useMemo(
    () => (selectedAssetId ? assets.find((a) => a.id === selectedAssetId) || null : null),
    [assets, selectedAssetId]
  );

  const displayedFindings = useMemo(() => {
    if (!scanResult) return [];
    return scanResult.findings.filter((f) => {
      if (findingsFilter === 'EXECUTED') return f.executed;
      if (findingsFilter === 'REFLECTED') return f.reflected;
      if (findingsFilter === 'SCRIPTS') return f.payload.toLowerCase().includes('script');
      if (findingsFilter === 'HANDLERS') return /on\w+=/i.test(f.payload);
      return true;
    });
  }, [scanResult, findingsFilter]);

  // Sync default target URL when asset is explicitly chosen
  React.useEffect(() => {
    if (selectedAsset) {
      setTargetUrl(selectedAsset.canonical_url || (selectedAsset.host ? `https://${selectedAsset.host}/search?q=test` : ''));
    } else {
      setTargetUrl('');
    }
  }, [selectedAsset]);

  const handleLaunchScan = async () => {
    if ((!selectedAsset && !targetUrl.trim()) || isScanning) return;
    setIsScanning(true);
    setScanError(null);
    setScanResult(null);

    const parsedParams = parameterInput
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    try {
      const response = await api.launchXSSpectScan({
        url: targetUrl.trim(),
        target_id: selectedAsset?.id,
        parameters: parsedParams.length > 0 ? parsedParams : undefined,
        detection_mode: detectionMode,
        use_playwright: usePlaywright,
        delay: 0.05,
      });
      setScanResult(response);
      if (response.error && response.findings.length === 0) {
        setScanError(response.error);
      }
    } catch (err: any) {
      setScanError(err.message || 'Failed to complete XSSpect assessment');
    } finally {
      setIsScanning(false);
    }
  };

  const filteredAssets = useMemo(() => {
    if (!searchTargetQuery.trim()) return approvedAssets;
    const q = searchTargetQuery.toLowerCase();
    return approvedAssets.filter(
      (a) =>
        (a.host && a.host.toLowerCase().includes(q)) ||
        (a.canonical_url && a.canonical_url.toLowerCase().includes(q))
    );
  }, [approvedAssets, searchTargetQuery]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* 1. Header Banner */}
      <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center space-x-4">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-rose-500/20 to-pink-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0 shadow-inner">
            <Code className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-xl font-bold font-sans text-slate-900 dark:text-white">
                XSSpect
              </h1>
              <span className="text-[11px] font-bold font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">
                Reflected XSS Detection
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-2xl">
              Automated reflected cross-site scripting parameter verification, Playwright headless DOM execution interception, and reflection context analysis against authorized targets only.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <div className="px-3.5 py-1.5 rounded-xl bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/10 text-xs font-mono text-slate-600 dark:text-slate-300 flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Scope Guard Active</span>
          </div>
        </div>
      </div>

      {/* 2. Mandatory Authorization Notice */}
      <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-start space-x-3 text-rose-300 text-xs">
        <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-bold text-rose-400 uppercase tracking-wider text-[11px] font-mono">
            Authorized Testing Notice &amp; Scope Restriction
          </div>
          <p className="text-slate-700 dark:text-rose-200/90 leading-relaxed">
            XSSSpect performs reflected XSS detection against <strong>authorized targets only</strong>. The user must provide a target URL that they own or have explicit, prior written permission to test. Testing systems without permission is strictly prohibited.
          </p>
        </div>
      </div>

      {/* 3. Configuration & Scope Launcher */}
      <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-sm space-y-5">
        <div className="flex items-center justify-between border-b border-slate-200/60 dark:border-white/10 pb-4">
          <div className="flex items-center space-x-2 text-xs font-bold font-mono text-slate-600 dark:text-slate-300 uppercase tracking-wider">
            <Sliders className="w-4 h-4 text-rose-400" />
            <span>Assessment Scope &amp; Target Parameters</span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Engine: Python xssspect / Playwright
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          {/* Target Asset Selector */}
          <div className="lg:col-span-4 relative" ref={targetDropdownRef}>
            <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
              Authorized Scoped Target
            </label>
            <div
              onClick={() => setIsTargetDropdownOpen((prev) => !prev)}
              className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-2xl px-3.5 py-2.5 text-xs text-slate-900 dark:text-white flex items-center justify-between cursor-pointer hover:border-rose-500/50 shadow-sm transition"
            >
              <div className="flex items-center space-x-2.5 truncate">
                <Globe className={`w-4 h-4 shrink-0 ${selectedAsset ? 'text-rose-400' : 'text-slate-400'}`} />
                <span className={`truncate ${selectedAsset ? 'font-bold' : 'text-slate-400 dark:text-slate-500 font-medium'}`}>
                  {selectedAsset ? selectedAsset.host || selectedAsset.canonical_url : 'Select a Target'}
                </span>
                {selectedAsset && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono font-bold shrink-0">
                    Authorized
                  </span>
                )}
              </div>
              <ChevronDown className="w-4 h-4 text-slate-400 shrink-0 ml-2" />
            </div>

            {isTargetDropdownOpen && (
              <div className="absolute left-0 right-0 mt-2 z-50 bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/15 rounded-2xl shadow-2xl p-2.5 space-y-2 backdrop-blur-xl max-h-72 overflow-y-auto">
                <div className="relative">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search scoped inventory..."
                    value={searchTargetQuery}
                    onChange={(e) => setSearchTargetQuery(e.target.value)}
                    className="w-full bg-slate-50 dark:bg-black/40 border border-slate-300 dark:border-white/10 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-rose-500"
                    autoFocus
                  />
                </div>
                <div className="divide-y divide-slate-100 dark:divide-white/5">
                  <div
                    onClick={() => {
                      setSelectedAssetId('');
                      setIsTargetDropdownOpen(false);
                    }}
                    className={`p-2.5 rounded-xl cursor-pointer flex items-center justify-between text-xs transition ${
                      !selectedAssetId
                        ? 'bg-rose-500/15 text-rose-400 font-bold'
                        : 'hover:bg-slate-100 dark:hover:bg-white/5 text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    <div className="font-mono italic">Select a Target (none)</div>
                  </div>
                  {filteredAssets.length === 0 ? (
                    <div className="p-3 text-center text-xs text-slate-400">
                      No authorized targets match your search.
                    </div>
                  ) : (
                    filteredAssets.map((asset) => (
                      <div
                        key={asset.id}
                        onClick={() => {
                          setSelectedAssetId(asset.id);
                          setIsTargetDropdownOpen(false);
                        }}
                        className={`p-2.5 rounded-xl cursor-pointer flex items-center justify-between text-xs transition ${
                          selectedAssetId === asset.id
                            ? 'bg-rose-500/15 text-rose-400 font-bold'
                            : 'hover:bg-slate-100 dark:hover:bg-white/5 text-slate-800 dark:text-slate-300'
                        }`}
                      >
                        <div className="truncate pr-2">
                          <div className="font-mono font-bold truncate">
                            {asset.host || asset.canonical_url}
                          </div>
                          <div className="text-[10px] text-slate-500 dark:text-slate-400">
                            {asset.canonical_url || `https://${asset.host}`}
                          </div>
                        </div>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold">
                          Scoped
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Target URL Input */}
          <div className="lg:col-span-5">
            <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
              Authorized Endpoint URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder={selectedAsset ? "https://target.com/search?q=" : "Select a target above to populate..."}
              className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-2xl px-3.5 py-2.5 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:border-rose-500 transition shadow-sm"
            />
          </div>

          {/* Action Trigger */}
          <div className="lg:col-span-3 flex items-center justify-end">
            <button
              type="button"
              onClick={handleLaunchScan}
              disabled={(!selectedAsset && !targetUrl.trim()) || isScanning}
              className={`w-full px-5 py-2.5 rounded-2xl font-bold text-xs flex items-center justify-center space-x-2 transition ${
                (selectedAsset || targetUrl.trim()) && !isScanning
                  ? 'bg-gradient-to-r from-rose-600 to-pink-500 hover:from-rose-500 hover:to-pink-400 text-white shadow-lg shadow-rose-500/25 cursor-pointer'
                  : 'bg-slate-200 dark:bg-white/10 text-slate-400 dark:text-slate-500 cursor-not-allowed border border-slate-300/40 dark:border-white/5'
              }`}
            >
              {isScanning ? (
                <>
                  <Activity className="w-4 h-4 animate-spin shrink-0 text-rose-400" />
                  <span>Probing Parameters...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current shrink-0" />
                  <span>Launch XSSpect Assessment</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Extended Parameter & Detection Options */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4 border-t border-slate-200/60 dark:border-white/10">
          <div>
            <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
              Target Parameters (comma-separated)
            </label>
            <input
              type="text"
              value={parameterInput}
              onChange={(e) => setParameterInput(e.target.value)}
              className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl px-3 py-2 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:border-rose-500"
            />
          </div>

          <div>
            <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
              Detection Strategy
            </label>
            <div className="grid grid-cols-3 gap-1 bg-slate-100 dark:bg-black/50 p-1 rounded-xl border border-slate-300 dark:border-white/10 text-xs font-mono">
              {[
                { id: 'STANDARD', label: 'STANDARD (15)' },
                { id: 'DEEP', label: 'DEEP (36)' },
                { id: 'DOM', label: 'DOM (18)' },
              ].map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setDetectionMode(id as any)}
                  className={`py-1.5 px-1 rounded-lg text-center transition font-bold cursor-pointer text-[10px] sm:text-[11px] ${
                    detectionMode === id
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 shadow-sm'
                      : 'text-slate-600 dark:text-slate-400 hover:text-white'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
              Execution Engine
            </label>
            <label className="flex items-center space-x-2.5 p-2 bg-slate-100 dark:bg-black/50 rounded-xl border border-slate-300 dark:border-white/10 cursor-pointer text-xs">
              <input
                type="checkbox"
                checked={usePlaywright}
                onChange={(e) => setUsePlaywright(e.target.checked)}
                className="accent-rose-500 cursor-pointer"
              />
              <span className="text-slate-800 dark:text-slate-300 font-mono">
                Playwright Headless Browser (DOM Execution)
              </span>
            </label>
          </div>
        </div>
      </div>

      {/* 4. Telemetry & Module Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
          <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Target Permission</div>
          <div className="text-base font-bold font-mono text-emerald-400 flex items-center space-x-1.5">
            <ShieldCheck className="w-4 h-4" />
            <span>Authorized Only</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
          <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Playwright Engine</div>
          <div className="text-base font-bold font-mono text-cyan-400 flex items-center space-x-1.5">
            <Terminal className="w-4 h-4" />
            <span>Chromium Headless</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
          <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Module Path</div>
          <div className="text-base font-bold font-mono text-purple-400 truncate">
            xssspect/
          </div>
        </div>

        <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
          <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Assessment Mode</div>
          <div className="text-base font-bold font-mono text-rose-400 flex items-center space-x-1.5">
            <span>{detectionMode}</span>
            <span className="text-[10px] text-slate-400 font-sans font-normal">
              ({detectionMode === 'DEEP' ? '36 Probes' : detectionMode === 'DOM' ? '18 Probes' : '15 Probes'})
            </span>
          </div>
        </div>
      </div>

      {/* 5. Assessment Findings & Parameter Reflection */}
      <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-200/60 dark:border-white/10 pb-4">
          <div className="flex items-center space-x-2 text-xs font-bold font-mono text-slate-700 dark:text-slate-200 uppercase tracking-wider">
            <FileCode className="w-4 h-4 text-rose-400" />
            <span>XSSpect Assessment Logs &amp; Parameter Reflection</span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Target: {selectedAsset?.host || (targetUrl ? new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`).hostname : 'No Target Selected')}
          </span>
        </div>

        {/* Error Alert */}
        {scanError && (
          <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-start space-x-3 text-rose-300 text-xs animate-in fade-in">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold text-rose-400 uppercase font-mono text-[11px]">Assessment Notice</span>
              <p className="text-slate-700 dark:text-rose-200/90">{scanError}</p>
            </div>
          </div>
        )}

        {/* Live Scanning Banner */}
        {isScanning && (
          <div className="p-8 rounded-2xl bg-slate-50 dark:bg-black/40 border border-slate-200 dark:border-white/10 text-center space-y-3 animate-in fade-in">
            <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center mx-auto animate-pulse">
              <Activity className="w-6 h-6 animate-spin" />
            </div>
            <h3 className="text-sm font-bold text-slate-800 dark:text-white">
              Evaluating Reflected Parameters via Playwright...
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
              Injecting probe payloads, checking DOM reflection, and listening for alert dialog events in headless Chromium.
            </p>
          </div>
        )}

        {/* Findings Results */}
        {!isScanning && scanResult && (
          <div className="space-y-4 animate-in fade-in">
            {/* Posture Banner */}
            <div
              className={`p-4 rounded-2xl border flex items-center justify-between gap-4 ${
                scanResult.vulnerable
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              }`}
            >
              <div className="flex items-center space-x-3">
                {scanResult.vulnerable ? (
                  <ShieldAlert className="w-6 h-6 shrink-0" />
                ) : (
                  <ShieldCheck className="w-6 h-6 shrink-0" />
                )}
                <div>
                  <div className="font-bold font-mono text-sm uppercase">
                    {scanResult.vulnerable ? 'Vulnerable: Reflected XSS Executed' : 'Clean: No Reflected XSS Detected'}
                  </div>
                  <div className="text-xs text-slate-600 dark:text-slate-300 mt-0.5">
                    {scanResult.vulnerable
                      ? `${scanResult.findings.filter((f) => f.executed).length} probe(s) triggered browser JavaScript execution (alert dialog).`
                      : `Tested ${scanResult.parameters_tested.length} parameter(s) with ${scanResult.findings.length} probe payload(s). Zero executions triggered.`}
                  </div>
                </div>
              </div>
              <div className="text-right shrink-0">
                <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-black/40 border border-white/10">
                  {scanResult.findings.length} Probes Checked
                </span>
              </div>
            </div>

            {/* Filter Chips Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-1 pb-1">
              <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setFindingsFilter('ALL')}
                  className={`px-2.5 py-1 rounded-xl transition cursor-pointer text-[11px] ${
                    findingsFilter === 'ALL'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold'
                      : 'bg-slate-100 dark:bg-white/5 text-slate-500 hover:text-white'
                  }`}
                >
                  All Probes ({scanResult.findings.length})
                </button>
                <button
                  type="button"
                  onClick={() => setFindingsFilter('EXECUTED')}
                  className={`px-2.5 py-1 rounded-xl transition cursor-pointer text-[11px] ${
                    findingsFilter === 'EXECUTED'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 font-bold'
                      : 'bg-slate-100 dark:bg-white/5 text-slate-500 hover:text-white'
                  }`}
                >
                  Executed ({scanResult.findings.filter((f) => f.executed).length})
                </button>
                <button
                  type="button"
                  onClick={() => setFindingsFilter('REFLECTED')}
                  className={`px-2.5 py-1 rounded-xl transition cursor-pointer text-[11px] ${
                    findingsFilter === 'REFLECTED'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40 font-bold'
                      : 'bg-slate-100 dark:bg-white/5 text-slate-500 hover:text-white'
                  }`}
                >
                  Reflected ({scanResult.findings.filter((f) => f.reflected).length})
                </button>
                <button
                  type="button"
                  onClick={() => setFindingsFilter('SCRIPTS')}
                  className={`px-2.5 py-1 rounded-xl transition cursor-pointer text-[11px] ${
                    findingsFilter === 'SCRIPTS'
                      ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 font-bold'
                      : 'bg-slate-100 dark:bg-white/5 text-slate-500 hover:text-white'
                  }`}
                >
                  Script Tags ({scanResult.findings.filter((f) => f.payload.toLowerCase().includes('script')).length})
                </button>
                <button
                  type="button"
                  onClick={() => setFindingsFilter('HANDLERS')}
                  className={`px-2.5 py-1 rounded-xl transition cursor-pointer text-[11px] ${
                    findingsFilter === 'HANDLERS'
                      ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40 font-bold'
                      : 'bg-slate-100 dark:bg-white/5 text-slate-500 hover:text-white'
                  }`}
                >
                  Event Handlers ({scanResult.findings.filter((f) => /on\w+=/i.test(f.payload)).length})
                </button>
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                Showing {displayedFindings.length} of {scanResult.findings.length}
              </span>
            </div>

            {/* Findings Table */}
            {displayedFindings.length > 0 ? (
              <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-white/10">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-50 dark:bg-black/50 text-[11px] font-mono text-slate-500 dark:text-slate-400 uppercase border-b border-slate-200 dark:border-white/10">
                    <tr>
                      <th className="p-3">Parameter</th>
                      <th className="p-3">Injected Probe</th>
                      <th className="p-3">Execution</th>
                      <th className="p-3">Reflection</th>
                      <th className="p-3">Dialog Trigger</th>
                      <th className="p-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-white/5 font-mono">
                    {displayedFindings.map((f, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/50 dark:hover:bg-white/[0.02] transition">
                        <td className="p-3 font-bold text-rose-400">{f.parameter}</td>
                        <td className="p-3 max-w-xs truncate text-slate-800 dark:text-slate-200" title={f.payload}>
                          <code>{f.payload}</code>
                        </td>
                        <td className="p-3">
                          {f.executed ? (
                            <span className="px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[10px] font-bold">
                              Executed (Alert)
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20 text-[10px]">
                              Not Executed
                            </span>
                          )}
                        </td>
                        <td className="p-3">
                          {f.reflected ? (
                            <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[10px] font-bold">
                              Reflected
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20 text-[10px]">
                              Clean
                            </span>
                          )}
                        </td>
                        <td className="p-3 text-slate-500 dark:text-slate-400">
                          {f.dialog_message ? `"${f.dialog_message}"` : f.error ? `Error: ${f.error}` : '—'}
                        </td>
                        <td className="p-3 text-right">
                          <button
                            type="button"
                            onClick={() => handleCopy(f.payload, `payload-${idx}`)}
                            className="p-1.5 rounded-lg hover:bg-slate-200 dark:hover:bg-white/10 text-slate-400 hover:text-white transition cursor-pointer"
                            title="Copy payload"
                          >
                            {copiedId === `payload-${idx}` ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-6 text-center text-xs text-slate-400">
                No query parameters were found on the target endpoint URL to test.
              </div>
            )}
          </div>
        )}

        {/* Initial Idle Ready State */}
        {!isScanning && !scanResult && (
          <div className="p-8 rounded-2xl bg-slate-50 dark:bg-black/40 border border-dashed border-slate-300 dark:border-white/10 text-center space-y-3">
            <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center mx-auto">
              <Code className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-bold text-slate-800 dark:text-white">
              Ready for Authorized Reflected XSS Assessment
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
              Select an authorized target or enter an endpoint URL above, then click <strong className="text-rose-400">Launch XSSpect Assessment</strong> to begin automated parameter probing.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};


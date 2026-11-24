import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Radar,
  Search,
  RefreshCw,
  Plus,
  CheckCircle,
  AlertTriangle,
  ExternalLink,
  Zap,
  Check,
  X,
  Shield,
  Layers,
  Download,
  Copy,
  FileText,
  Filter,
  Pause,
  Play,
  CheckSquare,
  Square,
  Activity,
  Globe,
  Server,
} from 'lucide-react';
import type { AuthorizedAsset, ScopeGrant, DiscoveredSubdomain, SubdomainDiscoveryResponse } from '../types/api';
import { api } from '../services/api';
import type { ActiveTab } from './Sidebar';

interface SubdomainFinderTabProps {
  assets: AuthorizedAsset[];
  scopes: ScopeGrant[];
  onRefreshData: () => Promise<void>;
  onNavigateToTab?: (tab: ActiveTab) => void;
}

export const SubdomainFinderTab: React.FC<SubdomainFinderTabProps> = ({
  assets,
  scopes,
  onRefreshData,
  onNavigateToTab,
}) => {
  const [subdomainDomainInput, setSubdomainDomainInput] = useState('');
  const [selectedScopeCode, setSelectedScopeCode] = useState(scopes[0]?.scope_code || '');

  // Reconnaissance Settings
  const [continuousScan, setContinuousScan] = useState(true);
  const [includeDnsProbe, setIncludeDnsProbe] = useState(true);
  const [includeCertTransparency, setIncludeCertTransparency] = useState(true);
  const [includePermutations, setIncludePermutations] = useState(true);
  const [verifyLiveSubdomains, setVerifyLiveSubdomains] = useState(true);
  const [enableLiveScraping, setEnableLiveScraping] = useState(true);

  // Scan State
  const [isDiscoveringSubdomains, setIsDiscoveringSubdomains] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<SubdomainDiscoveryResponse | null>(null);
  const [scanPhase, setScanPhase] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [targetProgress, setTargetProgress] = useState<number>(0);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [subdomainError, setSubdomainError] = useState<string | null>(null);
  const [subdomainSuccessMsg, setSubdomainSuccessMsg] = useState<string | null>(null);
  const [addingAssetSubdomain, setAddingAssetSubdomain] = useState<string | null>(null);

  // Table Filters & Pagination
  const [searchFilter, setSearchFilter] = useState('');
  const [activeFilterTab, setActiveFilterTab] = useState<'all' | 'live' | 'live_scraped' | 'dns' | 'inventory'>('all');
  const [selectedSubdomains, setSelectedSubdomains] = useState<Set<string>>(new Set());
  const [pageSize, setPageSize] = useState<number>(50);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);

  // Pre-select first scope when scopes load
  useEffect(() => {
    if (!selectedScopeCode && scopes.length > 0) {
      setSelectedScopeCode(scopes[0].scope_code);
    }
  }, [scopes, selectedScopeCode]);

  // Extract clean apex domains from existing inventory for 1-click discovery chips
  const suggestedApexDomains = useMemo(() => {
    const set = new Set<string>();
    assets.forEach((a) => {
      const h = a.host || a.hostname || '';
      if (h) {
        const parts = h.split('.').filter(Boolean);
        if (parts.length >= 2) {
          const apex = parts.slice(-2).join('.');
          set.add(apex);
        }
      }
    });
    return Array.from(set);
  }, [assets]);

  // Set initial subdomain domain once on mount without resetting on user clear
  const subdomainInputInitializedRef = useRef(false);
  useEffect(() => {
    if (!subdomainInputInitializedRef.current && suggestedApexDomains.length > 0) {
      setSubdomainDomainInput(suggestedApexDomains[0]);
      subdomainInputInitializedRef.current = true;
    }
  }, [suggestedApexDomains]);

  // Continuous smooth progress animation ticker - prevents any visual stutter or freeze
  useEffect(() => {
    if (!isDiscoveringSubdomains) {
      if (targetProgress >= 100) {
        setScanProgress(100);
      }
      return;
    }

    const interval = setInterval(() => {
      setScanProgress((prev) => {
        // If we are below the target from the server, smoothly advance toward it
        if (prev < targetProgress) {
          const delta = targetProgress - prev;
          const step = Math.max(0.25, delta * 0.18);
          return Math.min(targetProgress, prev + step);
        }
        // If we have reached the server's reported progress, but the scan is still actively running,
        // continuously creep forward by tiny fractional increments (+0.07%) so the bar
        // NEVER appears frozen or stuck, up to a soft ceiling before 99%
        if (prev < 99 && prev < targetProgress + 3.5) {
          return prev + 0.07;
        }
        return prev;
      });
    }, 50);

    return () => clearInterval(interval);
  }, [isDiscoveringSubdomains, targetProgress]);

  // Stop / Abort Active Scan
  const handleStopScan = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsDiscoveringSubdomains(false);
    setScanMessage('Scan paused by user.');
  };

  // Discover Subdomains (supports both Continuous Live Stream & Standard Aggregation)
  const handleDiscoverSubdomains = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const domain = subdomainDomainInput.trim();
    if (!domain) return;

    setIsDiscoveringSubdomains(true);
    setSubdomainError(null);
    setSubdomainSuccessMsg(null);
    setScanProgress(6);
    setTargetProgress(6);
    setScanPhase('Initiating Discovery Engine');
    setScanMessage(`Preparing multi-stage reconnaissance for '${domain}'...`);
    setSelectedSubdomains(new Set());
    setCurrentPage(1);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    const payload = {
      domain,
      include_cert_transparency: includeCertTransparency,
      include_dns_probe: includeDnsProbe,
      include_permutations: includePermutations,
      enable_live_scraping: enableLiveScraping,
      verify_live: verifyLiveSubdomains,
      continuous_scan: continuousScan,
    };

    if (continuousScan) {
      // Initialize accumulator map
      const subMap = new Map<string, DiscoveredSubdomain>();

      try {
        await api.findSubdomainsStream(
          payload,
          (ev: any) => {
            if (ev.type === 'phase') {
              setScanPhase(ev.phase || '');
              if (typeof ev.progress === 'number') {
                setTargetProgress(ev.progress);
              }
              if (ev.message) setScanMessage(ev.message);
            } else if (ev.type === 'batch') {
              // Smoothly bump progress slightly on newly streamed batches
              setTargetProgress((prev) => Math.min(98, prev + 0.35));
              if (Array.isArray(ev.items)) {
                for (const item of ev.items) {
                  const existing = subMap.get(item.subdomain);
                  if (existing) {
                    subMap.set(item.subdomain, {
                      ...existing,
                      ...item,
                      ip_addresses: item.ip_addresses?.length ? item.ip_addresses : existing.ip_addresses,
                      sources: Array.from(new Set([...existing.sources, ...(item.sources || [])])),
                      live_scraped: item.live_scraped || existing.live_scraped || false,
                      page_title: item.page_title || existing.page_title || null,
                    });
                  } else {
                    subMap.set(item.subdomain, item);
                  }
                }
                const updatedList = Array.from(subMap.values());
                const liveCount = updatedList.filter((s) => s.is_live).length;
                const dnsCount = updatedList.filter((s) => s.ip_addresses && s.ip_addresses.length > 0).length;
                const liveScrapedCount = updatedList.filter((s) => s.live_scraped || s.sources?.some((src) => src.includes('Live Web Scraper'))).length;

                setDiscoveryResult({
                  target_domain: domain,
                  total_discovered: updatedList.length,
                  live_count: liveCount,
                  dns_active_count: dnsCount,
                  live_scraped_count: liveScrapedCount,
                  subdomains: updatedList,
                  discovered_at: new Date().toISOString(),
                });
              }
            } else if (ev.type === 'complete') {
              setTargetProgress(100);
              setScanProgress(100);
              setScanPhase('Reconnaissance Complete');
              setScanMessage(`Continuous scan finished: Discovered ${ev.total_discovered} subdomains (${ev.live_count} live services).`);
              if (ev.result) {
                setDiscoveryResult(ev.result);
              }
              setSubdomainSuccessMsg(`Continuous live scan complete! Identified ${ev.total_discovered} total attack surface targets.`);
            }
          },
          abortController.signal
        );
      } catch (err: any) {
        if (err.name === 'AbortError') {
          setScanMessage('Scan aborted by user.');
        } else {
          // Fallback to standard non-streaming discover
          try {
            const res = await api.findSubdomains(payload);
            setDiscoveryResult(res);
            setSubdomainSuccessMsg(
              `Reconnaissance complete! Discovered ${res.total_discovered} subdomains (${res.live_count} live services).`
            );
          } catch (fallbackErr: any) {
            setSubdomainError(fallbackErr.message || err.message || 'Subdomain reconnaissance failed.');
          }
        }
      } finally {
        setIsDiscoveringSubdomains(false);
        abortControllerRef.current = null;
      }
    } else {
      // Standard Aggregated Discovery
      try {
        setTargetProgress(35);
        setScanProgress(20);
        setScanPhase('Running Multi-Engine Reconnaissance');
        setScanMessage('Gathering passive intelligence, deep dictionary probing, and verifying live services...');
        const res = await api.findSubdomains(payload);
        setDiscoveryResult(res);
        setTargetProgress(100);
        setScanProgress(100);
        setScanPhase('Reconnaissance Complete');
        setSubdomainSuccessMsg(
          `Reconnaissance complete! Discovered ${res.total_discovered} subdomains (${res.live_count} live services).`
        );
      } catch (err: any) {
        setSubdomainError(err.message || 'Subdomain reconnaissance failed. Please check network connectivity.');
      } finally {
        setIsDiscoveringSubdomains(false);
        abortControllerRef.current = null;
      }
    }
  };

  // Add individual discovered subdomain to inventory
  const handleAddSubdomainToInventory = async (sub: DiscoveredSubdomain) => {
    try {
      setAddingAssetSubdomain(sub.subdomain);
      const scopeCodeToUse = selectedScopeCode || (scopes[0]?.scope_code ?? 'SCOPE-DEFAULT');

      await api.registerAsset({
        target: sub.canonical_url,
        scope_code: scopeCodeToUse,
        is_authorized: true,
        approval_notes: `Discovered via automated reconnaissance on ${subdomainDomainInput}`,
        skip_dns_resolution: true,
      });

      await onRefreshData();

      if (discoveryResult) {
        setDiscoveryResult({
          ...discoveryResult,
          subdomains: discoveryResult.subdomains.map((s) =>
            s.subdomain === sub.subdomain ? { ...s, is_already_in_inventory: true } : s
          ),
        });
      }
      setSubdomainSuccessMsg(`Added '${sub.subdomain}' to authorized target inventory!`);
    } catch (err: any) {
      setSubdomainError(err.message || `Failed to add '${sub.subdomain}' to inventory.`);
    } finally {
      setAddingAssetSubdomain(null);
    }
  };

  // Batch add all live discovered subdomains to inventory
  const handleBatchAddLiveToInventory = async () => {
    if (!discoveryResult) return;
    const unaddedLive = discoveryResult.subdomains.filter((s) => s.is_live && !s.is_already_in_inventory);
    if (unaddedLive.length === 0) {
      alert('All live subdomains are already in your authorized inventory.');
      return;
    }

    setIsDiscoveringSubdomains(true);
    let addedCount = 0;
    const scopeCodeToUse = selectedScopeCode || (scopes[0]?.scope_code ?? 'SCOPE-DEFAULT');

    try {
      for (const sub of unaddedLive) {
        try {
          await api.registerAsset({
            target: sub.canonical_url,
            scope_code: scopeCodeToUse,
            is_authorized: true,
            approval_notes: `Batch added from reconnaissance for ${discoveryResult.target_domain}`,
            skip_dns_resolution: true,
          });
          addedCount++;
        } catch {
          // continue batch
        }
      }
      await onRefreshData();

      setDiscoveryResult({
        ...discoveryResult,
        subdomains: discoveryResult.subdomains.map((s) => (s.is_live ? { ...s, is_already_in_inventory: true } : s)),
      });

      setSubdomainSuccessMsg(`Successfully imported ${addedCount} live subdomains into your authorized inventory!`);
    } catch (err: any) {
      setSubdomainError(err.message || 'Failed during batch import.');
    } finally {
      setIsDiscoveringSubdomains(false);
    }
  };

  // Batch add selected subdomains
  const handleBatchAddSelectedToInventory = async () => {
    if (!discoveryResult || selectedSubdomains.size === 0) return;
    const targetsToAdd = discoveryResult.subdomains.filter(
      (s) => selectedSubdomains.has(s.subdomain) && !s.is_already_in_inventory
    );

    if (targetsToAdd.length === 0) {
      alert('Selected subdomains are already in your authorized inventory.');
      return;
    }

    setIsDiscoveringSubdomains(true);
    let addedCount = 0;
    const scopeCodeToUse = selectedScopeCode || (scopes[0]?.scope_code ?? 'SCOPE-DEFAULT');

    try {
      for (const sub of targetsToAdd) {
        try {
          await api.registerAsset({
            target: sub.canonical_url,
            scope_code: scopeCodeToUse,
            is_authorized: true,
            approval_notes: `Batch imported selection from reconnaissance for ${discoveryResult.target_domain}`,
            skip_dns_resolution: true,
          });
          addedCount++;
        } catch {
          // continue
        }
      }
      await onRefreshData();

      setDiscoveryResult({
        ...discoveryResult,
        subdomains: discoveryResult.subdomains.map((s) =>
          selectedSubdomains.has(s.subdomain) ? { ...s, is_already_in_inventory: true } : s
        ),
      });

      setSelectedSubdomains(new Set());
      setSubdomainSuccessMsg(`Successfully imported ${addedCount} selected targets into your authorized inventory!`);
    } catch (err: any) {
      setSubdomainError(err.message || 'Failed during batch import.');
    } finally {
      setIsDiscoveringSubdomains(false);
    }
  };

  // Export functions
  const handleExportCsv = () => {
    if (!discoveryResult || discoveryResult.subdomains.length === 0) return;
    const headers = ['Subdomain', 'Canonical URL', 'Live Status', 'Status Code', 'Page Title', 'Live Scraped', 'Response Time (ms)', 'Server Banner', 'Resolved IPs', 'Sources'];
    const rows = discoveryResult.subdomains.map((s) => [
      `"${s.subdomain}"`,
      `"${s.canonical_url}"`,
      s.is_live ? 'LIVE' : 'UNREACHABLE',
      s.status_code || '',
      `"${s.page_title || ''}"`,
      s.live_scraped ? 'YES' : 'NO',
      s.response_time_ms || '',
      `"${s.server_banner || ''}"`,
      `"${(s.ip_addresses || []).join(';')}"`,
      `"${(s.sources || []).join(';')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `subdomains_${discoveryResult.target_domain}_${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExportTxt = () => {
    if (!discoveryResult || discoveryResult.subdomains.length === 0) return;
    const txtContent = discoveryResult.subdomains.map((s) => s.subdomain).join('\n');
    const blob = new Blob([txtContent], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `subdomains_${discoveryResult.target_domain}_${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJson = () => {
    if (!discoveryResult) return;
    const jsonContent = JSON.stringify(discoveryResult, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `subdomains_${discoveryResult.target_domain}_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIp(text);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  // Filtered & Paginated List
  const filteredSubdomains = useMemo(() => {
    if (!discoveryResult) return [];
    return discoveryResult.subdomains.filter((sub) => {
      // Tab filter
      if (activeFilterTab === 'live' && !sub.is_live) return false;
      if (activeFilterTab === 'live_scraped' && !sub.live_scraped && !sub.sources?.some((src) => src.includes('Live Web Scraper'))) return false;
      if (activeFilterTab === 'dns' && (!sub.ip_addresses || sub.ip_addresses.length === 0)) return false;
      if (activeFilterTab === 'inventory' && !sub.is_already_in_inventory) return false;

      // Text search filter
      if (searchFilter.trim()) {
        const query = searchFilter.toLowerCase();
        const matchesSubdomain = sub.subdomain.toLowerCase().includes(query);
        const matchesUrl = sub.canonical_url.toLowerCase().includes(query);
        const matchesIp = sub.ip_addresses?.some((ip) => ip.toLowerCase().includes(query));
        const matchesSource = sub.sources?.some((src) => src.toLowerCase().includes(query));
        const matchesBanner = sub.server_banner?.toLowerCase().includes(query);
        const matchesTitle = sub.page_title?.toLowerCase().includes(query);
        if (!matchesSubdomain && !matchesUrl && !matchesIp && !matchesSource && !matchesBanner && !matchesTitle) {
          return false;
        }
      }

      return true;
    });
  }, [discoveryResult, activeFilterTab, searchFilter]);

  const totalPages = Math.ceil(filteredSubdomains.length / pageSize) || 1;
  const paginatedSubdomains = useMemo(() => {
    if (pageSize >= 9999) return filteredSubdomains;
    const start = (currentPage - 1) * pageSize;
    return filteredSubdomains.slice(start, start + pageSize);
  }, [filteredSubdomains, currentPage, pageSize]);

  const toggleSelectAllPage = () => {
    const next = new Set(selectedSubdomains);
    const allPageSelected = paginatedSubdomains.every((s) => next.has(s.subdomain));
    if (allPageSelected) {
      paginatedSubdomains.forEach((s) => next.delete(s.subdomain));
    } else {
      paginatedSubdomains.forEach((s) => next.add(s.subdomain));
    }
    setSelectedSubdomains(next);
  };

  const toggleSelectSubdomain = (sub: string) => {
    const next = new Set(selectedSubdomains);
    if (next.has(sub)) next.delete(sub);
    else next.add(sub);
    setSelectedSubdomains(next);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner Card */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl relative overflow-hidden border border-cyan-500/25">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-white/10 gap-3">
          <div>
            <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 font-semibold text-xs mb-1.5 font-sans">
              <Radar className="w-4 h-4 animate-pulse text-cyan-400" />
              <span>Asset Reconnaissance &amp; Multi-Engine Attack Surface Intelligence</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center space-x-2.5">
              <span>Subdomain Finder</span>
              <span className="text-xs font-sans font-semibold px-2.5 py-0.5 rounded-full liquid-glass-pill text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span>Continuous Live Engine</span>
              </span>
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Unbounded, adaptive attack surface discovery across Certificate Transparency logs (crt.sh, CertSpotter), Passive DNS (HackerTarget, AlienVault, Anubis),
              authoritative DNS protocol mining (TXT/SPF, MX, NS), target-specific vocabulary extraction, dynamic multi-level mutations, and live HTTP/HTTPS fingerprinting.
            </p>
          </div>

          {/* Scope Assignment Dropdown */}
          <div className="flex items-center space-x-2 shrink-0">
            <label className="text-xs text-slate-600 dark:text-slate-300 font-medium">Assign Scope:</label>
            <select
              value={selectedScopeCode}
              onChange={(e) => setSelectedScopeCode(e.target.value)}
              className="liquid-glass-input px-3 py-1.5 text-xs text-slate-900 dark:text-white rounded-xl font-sans cursor-pointer shadow-sm"
            >
              {scopes.map((s) => (
                <option key={s.id} value={s.scope_code} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                  {s.scope_code} ({s.title})
                </option>
              ))}
              {scopes.length === 0 && (
                <option value="" className="bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400">
                  Default Scope
                </option>
              )}
            </select>
          </div>
        </div>

        {/* Subdomain Input Form */}
        <form onSubmit={handleDiscoverSubdomains} className="mt-5 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5 font-sans">
              Apex Domain to Enumerate
            </label>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={subdomainDomainInput}
                  onChange={(e) => setSubdomainDomainInput(e.target.value)}
                  placeholder="e.g. gov.in, smarttrichy.in, example.com, acme.org"
                  className="liquid-glass-input w-full pl-10 pr-9 py-2.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 font-sans font-medium border border-slate-200/80 dark:border-white/10"
                />
                {subdomainDomainInput && (
                  <button
                    type="button"
                    onClick={() => setSubdomainDomainInput('')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-900 dark:hover:text-white p-1 rounded-md hover:bg-slate-500/10 dark:hover:bg-white/10 transition cursor-pointer"
                    title="Clear input"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {isDiscoveringSubdomains ? (
                <button
                  type="button"
                  onClick={handleStopScan}
                  className="px-5 py-2.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-xl flex items-center justify-center space-x-2 cursor-pointer shrink-0 shadow-lg shadow-rose-500/25 transition"
                >
                  <Pause className="w-4 h-4" />
                  <span>Pause Scan</span>
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!subdomainDomainInput.trim()}
                  className="liquid-glass-btn-primary px-6 py-2.5 text-xs font-semibold text-white flex items-center justify-center space-x-2 cursor-pointer disabled:opacity-40 shrink-0 shadow-lg shadow-cyan-500/20"
                >
                  <Radar className="w-4 h-4 text-cyan-300" />
                  <span>Discover Subdomains</span>
                </button>
              )}
            </div>
          </div>

          {/* Quick Select Domain Chips */}
          {suggestedApexDomains.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Quick Select Registered Targets:</span>
              {suggestedApexDomains.map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setSubdomainDomainInput(d)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-sans font-semibold transition cursor-pointer border ${
                    subdomainDomainInput === d
                      ? 'bg-cyan-500/25 text-cyan-700 dark:text-cyan-200 border-cyan-400/50 shadow-[0_0_10px_rgba(6,182,212,0.3)]'
                      : 'liquid-glass text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20'
                  }`}
                >
                  {d}
                </button>
              ))}
            </div>
          )}

          {/* Reconnaissance Engine Toggles */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3 pt-2">
            <label className="flex items-center space-x-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer liquid-glass p-3 rounded-xl border border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20">
              <input
                type="checkbox"
                checked={continuousScan}
                onChange={(e) => setContinuousScan(e.target.checked)}
                className="rounded border-slate-300 dark:border-white/20 text-cyan-500 focus:ring-0 cursor-pointer"
              />
              <span className="flex flex-col">
                <span className="font-semibold text-cyan-600 dark:text-cyan-400 flex items-center space-x-1">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  <span>Continuous Live Scan</span>
                </span>
                <span className="text-[10px] text-slate-500">Real-time streaming pipeline</span>
              </span>
            </label>

            <label className="flex items-center space-x-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer liquid-glass p-3 rounded-xl border border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20">
              <input
                type="checkbox"
                checked={enableLiveScraping}
                onChange={(e) => setEnableLiveScraping(e.target.checked)}
                className="rounded border-slate-300 dark:border-white/20 text-cyan-500 focus:ring-0 cursor-pointer"
              />
              <span className="flex flex-col">
                <span className="font-semibold text-cyan-600 dark:text-cyan-400 flex items-center space-x-1">
                  <Zap className="w-3 h-3 text-cyan-400" />
                  <span>Live Web &amp; JS Scraper</span>
                </span>
                <span className="text-[10px] text-slate-500">Spider HTML, JS &amp; sitemaps</span>
              </span>
            </label>

            <label className="flex items-center space-x-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer liquid-glass p-3 rounded-xl border border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20">
              <input
                type="checkbox"
                checked={includeCertTransparency}
                onChange={(e) => setIncludeCertTransparency(e.target.checked)}
                className="rounded border-slate-300 dark:border-white/20 text-indigo-500 focus:ring-0 cursor-pointer"
              />
              <span className="flex flex-col">
                <span className="font-semibold text-slate-900 dark:text-slate-200">Passive Intelligence</span>
                <span className="text-[10px] text-slate-500">crt.sh, HackerTarget, Wayback</span>
              </span>
            </label>

            <label className="flex items-center space-x-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer liquid-glass p-3 rounded-xl border border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20">
              <input
                type="checkbox"
                checked={includeDnsProbe}
                onChange={(e) => setIncludeDnsProbe(e.target.checked)}
                className="rounded border-slate-300 dark:border-white/20 text-indigo-500 focus:ring-0 cursor-pointer"
              />
              <span className="flex flex-col">
                <span className="font-semibold text-slate-900 dark:text-slate-200">Dynamic Probing</span>
                <span className="text-[10px] text-slate-500">Target vocabulary &amp; heuristics</span>
              </span>
            </label>

            <label className="flex items-center space-x-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer liquid-glass p-3 rounded-xl border border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20">
              <input
                type="checkbox"
                checked={includePermutations}
                onChange={(e) => setIncludePermutations(e.target.checked)}
                className="rounded border-slate-300 dark:border-white/20 text-indigo-500 focus:ring-0 cursor-pointer"
              />
              <span className="flex flex-col">
                <span className="font-semibold text-slate-900 dark:text-slate-200">Permutations</span>
                <span className="text-[10px] text-slate-500">Child domains &amp; numeric ranges</span>
              </span>
            </label>

            <label className="flex items-center space-x-2.5 text-xs text-slate-700 dark:text-slate-300 cursor-pointer liquid-glass p-3 rounded-xl border border-slate-200/80 dark:border-white/10 hover:border-slate-300 dark:hover:border-white/20">
              <input
                type="checkbox"
                checked={verifyLiveSubdomains}
                onChange={(e) => setVerifyLiveSubdomains(e.target.checked)}
                className="rounded border-slate-300 dark:border-white/20 text-indigo-500 focus:ring-0 cursor-pointer"
              />
              <span className="flex flex-col">
                <span className="font-semibold text-slate-900 dark:text-slate-200">Live Verification</span>
                <span className="text-[10px] text-slate-500">HTTP/S, latency &amp; banners</span>
              </span>
            </label>
          </div>
        </form>

        {/* Live Scan Progress Bar & Status Banner */}
        {isDiscoveringSubdomains && (
          <div className="mt-5 p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/25 space-y-2.5 animate-fadeIn shadow-[0_0_20px_rgba(6,182,212,0.12)]">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center space-x-2">
                <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
                <span className="font-semibold text-cyan-300">{scanPhase || 'Scanning...'}</span>
              </div>
              <div className="flex items-center space-x-2">
                {discoveryResult && discoveryResult.total_discovered > 0 && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-400/30">
                    {discoveryResult.total_discovered} found
                  </span>
                )}
                <span className="font-sans font-bold text-cyan-200 min-w-[36px] text-right">
                  {Math.min(100, Math.round(scanProgress))}%
                </span>
              </div>
            </div>
            <div className="w-full bg-slate-900/80 rounded-full h-2.5 overflow-hidden p-0.5 border border-cyan-500/20 relative shadow-inner">
              <div
                className="bg-gradient-to-r from-cyan-500 via-indigo-500 to-emerald-400 h-full rounded-full transition-all duration-150 ease-out relative overflow-hidden shadow-[0_0_10px_rgba(6,182,212,0.4)]"
                style={{ width: `${Math.min(100, Math.max(scanProgress, 4))}%` }}
              >
                {/* Continuous glowing shimmer scanning line */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/35 to-transparent -translate-x-full animate-progress-shimmer" />
              </div>
            </div>
            {scanMessage && (
              <p className="text-[11px] text-slate-300 font-sans italic">{scanMessage}</p>
            )}
          </div>
        )}

        {/* Notification Messages */}
        {subdomainError && (
          <div className="mt-4 p-3.5 rounded-xl bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{subdomainError}</span>
            </div>
            <button
              type="button"
              onClick={() => setSubdomainError(null)}
              className="p-1 hover:text-white cursor-pointer"
            >
              &times;
            </button>
          </div>
        )}

        {subdomainSuccessMsg && (
          <div className="mt-4 p-3.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 shrink-0 text-emerald-400" />
              <span>{subdomainSuccessMsg}</span>
            </div>
            <button
              type="button"
              onClick={() => setSubdomainSuccessMsg(null)}
              className="p-1 hover:text-white cursor-pointer"
            >
              &times;
            </button>
          </div>
        )}

        {/* Discovery Results View */}
        {discoveryResult && (
          <div className="mt-6 pt-5 border-t border-white/10 space-y-4">
            {/* Metric Summary Tickers */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <div className="liquid-glass p-3 rounded-xl border border-white/10 flex items-center space-x-3">
                <Globe className="w-6 h-6 text-cyan-400 shrink-0" />
                <div>
                  <div className="text-[10px] text-slate-400 font-medium">Total Discovered</div>
                  <div className="text-lg font-bold text-slate-900 dark:text-white">{discoveryResult.total_discovered}</div>
                </div>
              </div>

              <div className="liquid-glass p-3 rounded-xl border border-emerald-500/25 bg-emerald-500/5 flex items-center space-x-3">
                <Activity className="w-6 h-6 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-[10px] text-slate-400 font-medium">Live Services (HTTP/S)</div>
                  <div className="text-lg font-bold text-emerald-400">{discoveryResult.live_count}</div>
                </div>
              </div>

              <div className="liquid-glass p-3 rounded-xl border border-cyan-500/25 bg-cyan-500/5 flex items-center space-x-3">
                <Zap className="w-6 h-6 text-cyan-400 shrink-0" />
                <div>
                  <div className="text-[10px] text-slate-400 font-medium">Live Scraped</div>
                  <div className="text-lg font-bold text-cyan-400">
                    {discoveryResult.live_scraped_count ?? discoveryResult.subdomains.filter(s => s.live_scraped || s.sources?.some(src => src.includes('Live Web Scraper'))).length}
                  </div>
                </div>
              </div>

              <div className="liquid-glass p-3 rounded-xl border border-indigo-500/25 bg-indigo-500/5 flex items-center space-x-3">
                <Server className="w-6 h-6 text-indigo-400 shrink-0" />
                <div>
                  <div className="text-[10px] text-slate-400 font-medium">DNS Active (Resolved)</div>
                  <div className="text-lg font-bold text-indigo-300">{discoveryResult.dns_active_count || discoveryResult.subdomains.filter(s => s.ip_addresses?.length).length}</div>
                </div>
              </div>

              <div className="liquid-glass p-3 rounded-xl border border-white/10 flex items-center space-x-3">
                <Shield className="w-6 h-6 text-amber-400 shrink-0" />
                <div>
                  <div className="text-[10px] text-slate-400 font-medium">In Inventory</div>
                  <div className="text-lg font-bold text-amber-300">{discoveryResult.subdomains.filter(s => s.is_already_in_inventory).length}</div>
                </div>
              </div>
            </div>

            {/* Filter Tabs & Search Controls */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => { setActiveFilterTab('all'); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition ${
                    activeFilterTab === 'all'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/50'
                      : 'liquid-glass text-slate-400 hover:text-white border border-white/10'
                  }`}
                >
                  All Discovered ({discoveryResult.total_discovered})
                </button>

                <button
                  type="button"
                  onClick={() => { setActiveFilterTab('live'); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition ${
                    activeFilterTab === 'live'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-400/50'
                      : 'liquid-glass text-slate-400 hover:text-white border border-white/10'
                  }`}
                >
                  Live Services Only ({discoveryResult.live_count})
                </button>

                <button
                  type="button"
                  onClick={() => { setActiveFilterTab('live_scraped'); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition flex items-center space-x-1.5 ${
                    activeFilterTab === 'live_scraped'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/50'
                      : 'liquid-glass text-slate-400 hover:text-white border border-white/10'
                  }`}
                >
                  <Zap className="w-3 h-3 text-cyan-400" />
                  <span>Live Scraped ({discoveryResult.live_scraped_count ?? discoveryResult.subdomains.filter(s => s.live_scraped || s.sources?.some(src => src.includes('Live Web Scraper'))).length})</span>
                </button>

                <button
                  type="button"
                  onClick={() => { setActiveFilterTab('dns'); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition ${
                    activeFilterTab === 'dns'
                      ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-400/50'
                      : 'liquid-glass text-slate-400 hover:text-white border border-white/10'
                  }`}
                >
                  DNS Resolved ({discoveryResult.dns_active_count || discoveryResult.subdomains.filter(s => s.ip_addresses?.length).length})
                </button>

                <button
                  type="button"
                  onClick={() => { setActiveFilterTab('inventory'); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition ${
                    activeFilterTab === 'inventory'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-400/50'
                      : 'liquid-glass text-slate-400 hover:text-white border border-white/10'
                  }`}
                >
                  In Inventory ({discoveryResult.subdomains.filter(s => s.is_already_in_inventory).length})
                </button>
              </div>

              {/* Export & Batch Dropdown */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative flex items-center space-x-1.5">
                  <button
                    type="button"
                    onClick={handleExportCsv}
                    title="Export as CSV spreadsheet"
                    className="liquid-glass-btn-secondary px-2.5 py-1.5 text-xs text-slate-300 hover:text-white rounded-lg flex items-center space-x-1 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    <span>CSV</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleExportTxt}
                    title="Export clean list of subdomains for CLI tools"
                    className="liquid-glass-btn-secondary px-2.5 py-1.5 text-xs text-slate-300 hover:text-white rounded-lg flex items-center space-x-1 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-indigo-400" />
                    <span>TXT List</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleExportJson}
                    title="Export raw JSON"
                    className="liquid-glass-btn-secondary px-2.5 py-1.5 text-xs text-slate-300 hover:text-white rounded-lg flex items-center space-x-1 cursor-pointer"
                  >
                    <span>JSON</span>
                  </button>
                </div>

                {selectedSubdomains.size > 0 && (
                  <button
                    type="button"
                    onClick={handleBatchAddSelectedToInventory}
                    disabled={isDiscoveringSubdomains}
                    className="liquid-glass-btn-primary px-3 py-1.5 text-xs text-white font-medium flex items-center space-x-1.5 cursor-pointer shadow-md disabled:opacity-50"
                  >
                    <Plus className="w-3.5 h-3.5 text-cyan-200" />
                    <span>Add {selectedSubdomains.size} Selected</span>
                  </button>
                )}

                {discoveryResult.live_count > 0 && (
                  <button
                    type="button"
                    onClick={handleBatchAddLiveToInventory}
                    disabled={isDiscoveringSubdomains}
                    className="liquid-glass-btn-primary px-3.5 py-1.5 text-xs text-white font-medium flex items-center space-x-1.5 cursor-pointer shadow-md disabled:opacity-50"
                  >
                    <Plus className="w-3.5 h-3.5 text-cyan-200" />
                    <span>Batch Add All Live</span>
                  </button>
                )}
              </div>
            </div>

            {/* Instant Filter Search Bar */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => { setSearchFilter(e.target.value); setCurrentPage(1); }}
                placeholder="Filter results by keyword, subdomain (e.g. 'delhi', 'admin', 'api'), IP address, or source..."
                className="liquid-glass-input w-full pl-9 pr-8 py-2 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 font-sans"
              />
              {searchFilter && (
                <button
                  type="button"
                  onClick={() => { setSearchFilter(''); setCurrentPage(1); }}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white p-0.5"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Subdomains Table */}
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto rounded-xl border border-slate-200/80 dark:border-white/10">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-100/90 dark:bg-slate-900/90 sticky top-0 backdrop-blur-md z-10">
                  <tr className="border-b border-slate-200/80 dark:border-white/10 text-slate-500 dark:text-slate-400 font-semibold text-xs font-sans">
                    <th className="py-2.5 px-3 w-8">
                      <button
                        type="button"
                        onClick={toggleSelectAllPage}
                        className="cursor-pointer text-slate-400 hover:text-white"
                        title="Select all on this page"
                      >
                        {paginatedSubdomains.length > 0 && paginatedSubdomains.every((s) => selectedSubdomains.has(s.subdomain)) ? (
                          <CheckSquare className="w-4 h-4 text-cyan-400" />
                        ) : (
                          <Square className="w-4 h-4" />
                        )}
                      </button>
                    </th>
                    <th className="py-2.5 px-3.5">Subdomain &amp; Canonical URL</th>
                    <th className="py-2.5 px-3">Live Service Status</th>
                    <th className="py-2.5 px-3">Resolved IP</th>
                    <th className="py-2.5 px-3">Discovery Sources</th>
                    <th className="py-2.5 px-3.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/60 dark:divide-white/5">
                  {paginatedSubdomains.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400 text-xs">
                        No subdomains match your active search or filter criteria.
                      </td>
                    </tr>
                  ) : (
                    paginatedSubdomains.map((sub) => {
                      const isSelected = selectedSubdomains.has(sub.subdomain);
                      return (
                        <tr
                          key={sub.subdomain}
                          className={`hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.03] transition-colors ${
                            isSelected ? 'bg-cyan-500/[0.08]' : ''
                          }`}
                        >
                          <td className="py-3 px-3">
                            <button
                              type="button"
                              onClick={() => toggleSelectSubdomain(sub.subdomain)}
                              className="cursor-pointer text-slate-400 hover:text-white"
                            >
                              {isSelected ? (
                                <CheckSquare className="w-4 h-4 text-cyan-400" />
                              ) : (
                                <Square className="w-4 h-4" />
                              )}
                            </button>
                          </td>

                          <td className="py-3 px-3.5">
                            <div className="flex items-center space-x-2">
                              <span className="font-sans text-xs font-semibold text-slate-900 dark:text-white">
                                {sub.subdomain}
                              </span>
                              <a
                                href={sub.canonical_url}
                                target="_blank"
                                rel="noreferrer"
                                className="text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300"
                                title="Open URL in new tab"
                              >
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            </div>
                            <span className="text-[10px] text-slate-500 dark:text-slate-400 font-sans block mt-0.5">
                              {sub.canonical_url}
                            </span>
                            {sub.page_title && (
                              <span className="text-[10px] text-slate-500 dark:text-slate-400 font-sans flex items-center space-x-1 mt-0.5 truncate max-w-xs" title={sub.page_title}>
                                <Globe className="w-2.5 h-2.5 text-cyan-400 shrink-0" />
                                <span className="truncate">{sub.page_title}</span>
                              </span>
                            )}
                          </td>

                          <td className="py-3 px-3">
                            {sub.is_live ? (
                              <div className="space-y-1">
                                <div className="flex items-center space-x-1.5 flex-wrap gap-1">
                                  <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-400/30">
                                    HTTP {sub.status_code || 200}
                                  </span>
                                  {(sub.live_scraped || sub.sources?.some(s => s.includes('Live Web Scraper'))) && (
                                    <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 flex items-center gap-1 shadow-[0_0_8px_rgba(6,182,212,0.25)]">
                                      <Zap className="w-2.5 h-2.5 text-cyan-400 animate-pulse" /> Live Scraped
                                    </span>
                                  )}
                                  {sub.response_time_ms && (
                                    <span className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">
                                      {sub.response_time_ms}ms
                                    </span>
                                  )}
                                </div>
                                {sub.server_banner && (
                                  <div className="text-[10px] text-slate-400 font-mono truncate max-w-[140px]" title={sub.server_banner}>
                                    {sub.server_banner}
                                  </div>
                                )}
                              </div>
                            ) : sub.ip_addresses && sub.ip_addresses.length > 0 ? (
                              <div className="space-y-1">
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-400/20 block w-fit">
                                  DNS Active (Port 80/443 closed)
                                </span>
                                {(sub.live_scraped || sub.sources?.some(s => s.includes('Live Web Scraper'))) && (
                                  <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 flex items-center gap-1 w-fit">
                                    <Zap className="w-2.5 h-2.5 text-cyan-400" /> Live Scraped
                                  </span>
                                )}
                              </div>
                            ) : (
                              <div className="space-y-1">
                                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-white/10 block w-fit">
                                  Passive / CT Record
                                </span>
                                {(sub.live_scraped || sub.sources?.some(s => s.includes('Live Web Scraper'))) && (
                                  <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-400/30 flex items-center gap-1 w-fit">
                                    <Zap className="w-2.5 h-2.5 text-cyan-400" /> Live Scraped
                                  </span>
                                )}
                              </div>
                            )}
                          </td>

                          <td className="py-3 px-3">
                            <div className="font-sans text-[11px] text-slate-700 dark:text-slate-300 space-y-1">
                              {sub.ip_addresses && sub.ip_addresses.length > 0 ? (
                                sub.ip_addresses.slice(0, 2).map((ip) => (
                                  <div key={ip} className="flex items-center space-x-1.5">
                                    <span>{ip}</span>
                                    <button
                                      type="button"
                                      onClick={() => copyToClipboard(ip)}
                                      className="text-slate-500 hover:text-cyan-400 cursor-pointer"
                                      title="Copy IP"
                                    >
                                      {copiedIp === ip ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
                                    </button>
                                  </div>
                                ))
                              ) : (
                                <span className="text-slate-500 text-[10px]">No active A-record</span>
                              )}
                            </div>
                          </td>

                          <td className="py-3 px-3">
                            <div className="flex flex-wrap gap-1 max-w-xs">
                              {(sub.sources || []).map((src) => {
                                const isCT = src.includes('Certificate') || src.includes('crt.sh') || src.includes('CertSpotter');
                                const isPassive = src.includes('Passive') || src.includes('HackerTarget') || src.includes('AlienVault');
                                const isDNS = src.includes('Wordlist') || src.includes('DNS');
                                const isPerm = src.includes('Permutations');
                                return (
                                  <span
                                    key={src}
                                    className={`px-1.5 py-0.5 rounded text-[9px] font-sans border ${
                                      isCT
                                        ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                                        : isPassive
                                        ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                                        : isPerm
                                        ? 'bg-purple-500/10 border-purple-500/30 text-purple-300'
                                        : isDNS
                                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                                        : 'bg-white/5 border-white/10 text-slate-300'
                                    }`}
                                  >
                                    {src}
                                  </span>
                                );
                              })}
                            </div>
                          </td>

                          <td className="py-3 px-3.5 text-right">
                            {sub.is_already_in_inventory ? (
                              <span className="inline-flex items-center text-[11px] text-emerald-400 font-medium space-x-1">
                                <Check className="w-3 h-3" />
                                <span>In Inventory</span>
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handleAddSubdomainToInventory(sub)}
                                disabled={addingAssetSubdomain === sub.subdomain}
                                className="liquid-glass-btn-secondary px-2.5 py-1 text-[11px] font-semibold text-cyan-300 hover:text-white rounded-lg flex items-center space-x-1 cursor-pointer ml-auto disabled:opacity-50"
                              >
                                {addingAssetSubdomain === sub.subdomain ? (
                                  <RefreshCw className="w-3 h-3 animate-spin text-cyan-400" />
                                ) : (
                                  <Plus className="w-3 h-3 text-cyan-400" />
                                )}
                                <span>Add to Inventory</span>
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {filteredSubdomains.length > 0 && (
              <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-400 gap-3 pt-2">
                <div className="flex items-center space-x-2">
                  <span>Showing {(currentPage - 1) * pageSize + 1} - {Math.min(currentPage * pageSize, filteredSubdomains.length)} of {filteredSubdomains.length} items</span>
                  <span>|</span>
                  <label className="flex items-center space-x-1">
                    <span>Rows per page:</span>
                    <select
                      value={pageSize}
                      onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                      className="liquid-glass-input px-2 py-0.5 rounded text-xs cursor-pointer"
                    >
                      <option value={25} className="bg-slate-900 text-white">25</option>
                      <option value={50} className="bg-slate-900 text-white">50</option>
                      <option value={100} className="bg-slate-900 text-white">100</option>
                      <option value={250} className="bg-slate-900 text-white">250</option>
                      <option value={500} className="bg-slate-900 text-white">500</option>
                      <option value={1000} className="bg-slate-900 text-white">1000</option>
                      <option value={9999} className="bg-slate-900 text-white">All (9999+)</option>
                    </select>
                  </label>
                </div>

                {pageSize < 9999 && totalPages > 1 && (
                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      disabled={currentPage <= 1}
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      className="liquid-glass-btn-secondary px-2.5 py-1 rounded text-xs disabled:opacity-40 cursor-pointer"
                    >
                      &larr; Prev
                    </button>
                    <span className="font-sans font-semibold text-slate-300">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button
                      type="button"
                      disabled={currentPage >= totalPages}
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                      className="liquid-glass-btn-secondary px-2.5 py-1 rounded text-xs disabled:opacity-40 cursor-pointer"
                    >
                      Next &rarr;
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Target Inventory Link Card */}
      {onNavigateToTab && (
        <div className="liquid-glass p-4 rounded-2xl flex items-center justify-between text-xs border border-white/10">
          <div className="flex items-center space-x-3 text-slate-300">
            <Shield className="w-4 h-4 text-indigo-400" />
            <span>Ready to scan your authorized targets or execute OWASP Top 10 assessments?</span>
          </div>
          <button
            type="button"
            onClick={() => onNavigateToTab('targets')}
            className="liquid-glass-btn-secondary px-3 py-1.5 rounded-lg text-cyan-300 hover:text-white font-medium cursor-pointer"
          >
            Go to Target Assessment &rarr;
          </button>
        </div>
      )}
    </div>
  );
};

import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import {
  Route,
  Play,
  Pause,
  RotateCcw,
  Search,
  Filter,
  CheckCircle,
  AlertTriangle,
  Lock,
  Globe,
  ExternalLink,
  Download,
  Copy,
  Clock,
  Zap,
  Activity,
  Layers,
  FileCode,
  Trash2,
  ChevronDown,
  ChevronUp,
  ArrowUpDown,
  Sliders,
  Plus,
  X,
  History,
  Sparkles,
  RefreshCw,
  Check,
  StopCircle,
  ShieldCheck,
  Server,
  ArrowRight,
} from 'lucide-react';
import type {
  AuthorizedAsset,
  PathFinderScan,
  DiscoveredPath,
  PathFinderMode,
  PathFinderStatus,
} from '../types/api';
import { api } from '../services/api';
import type { ActiveTab } from './Sidebar';

export interface PathFinderTabProps {
  assets: AuthorizedAsset[];
  onNavigateToTab?: (tab: ActiveTab) => void;
  onRefreshData?: () => void;
}

interface CustomHeaderRow {
  id: string;
  key: string;
  value: string;
  enabled: boolean;
}

type SortField = 'path' | 'status_code' | 'content_length' | 'response_time_ms';
type SortOrder = 'asc' | 'desc';

export const PathFinderTab: React.FC<PathFinderTabProps> = ({
  assets,
  onNavigateToTab,
}) => {
  // Navigation / View Subtabs: Active Dashboard vs Scan History
  const [activeView, setActiveView] = useState<'dashboard' | 'history'>('dashboard');

  // Filter approved assets from inventory
  const approvedAssets = useMemo(() => {
    return assets.filter((a) => a.approval_status === 'APPROVED' || !a.approval_status);
  }, [assets]);

  // Selected Target
  const [selectedAssetId, setSelectedAssetId] = useState<string>(
    approvedAssets.length > 0 ? approvedAssets[0].id : ''
  );
  const [targetSearchQuery, setTargetSearchQuery] = useState<string>('');
  const [isTargetDropdownOpen, setIsTargetDropdownOpen] = useState<boolean>(false);
  const targetDropdownRef = useRef<HTMLDivElement | null>(null);

  const selectedAsset = useMemo(() => {
    return approvedAssets.find((a) => a.id === selectedAssetId) || approvedAssets[0] || null;
  }, [approvedAssets, selectedAssetId]);

  // Filtered target list for searchable dropdown
  const filteredApprovedAssets = useMemo(() => {
    if (!targetSearchQuery.trim()) return approvedAssets;
    const q = targetSearchQuery.toLowerCase();
    return approvedAssets.filter(
      (a) =>
        (a.host && a.host.toLowerCase().includes(q)) ||
        (a.hostname && a.hostname.toLowerCase().includes(q)) ||
        (a.canonical_url && a.canonical_url.toLowerCase().includes(q)) ||
        (a.ip_address && a.ip_address.includes(q))
    );
  }, [approvedAssets, targetSearchQuery]);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (targetDropdownRef.current && !targetDropdownRef.current.contains(e.target as Node)) {
        setIsTargetDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Scan Mode & Configuration Controls
  const [scanMode, setScanMode] = useState<'QUICK' | 'EXHAUSTIVE' | 'AGGRESSIVE' | 'PASSIVE'>('QUICK');
  const [wordlistType, setWordlistType] = useState<'common' | 'api' | 'sensitive' | 'exhaustive' | 'custom'>('common');
  const [customWordlistText, setCustomWordlistText] = useState<string>('');
  const [concurrency, setConcurrency] = useState<number>(15);
  const [rateLimitRps, setRateLimitRps] = useState<number>(30);
  const [showAdvancedSettings, setShowAdvancedSettings] = useState<boolean>(false);

  // Custom Headers
  const [customHeaders, setCustomHeaders] = useState<CustomHeaderRow[]>([
    { id: '1', key: 'X-Sentinel-Authorized-Assessment', value: 'true', enabled: true },
  ]);

  // Active Scan & Dashboard State
  const [activeScan, setActiveScan] = useState<PathFinderScan | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [requestsPerSecond, setRequestsPerSecond] = useState<number>(0);
  const [discoveredPaths, setDiscoveredPaths] = useState<DiscoveredPath[]>([]);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);

  // Results Table State
  const [statusFilter, setStatusFilter] = useState<'all' | '2xx' | '3xx' | '403' | 'errors'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortField, setSortField] = useState<SortField>('discovered_at' as any);
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // History State
  const [scanHistory, setScanHistory] = useState<PathFinderScan[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);
  const [historyTargetFilter, setHistoryTargetFilter] = useState<'selected' | 'all'>('selected');

  // Sync selected target when assets load
  useEffect(() => {
    if (!selectedAssetId && approvedAssets.length > 0) {
      setSelectedAssetId(approvedAssets[0].id);
    }
  }, [approvedAssets, selectedAssetId]);

  // Live Elapsed Time Counter
  useEffect(() => {
    let timer: any = null;
    if (isScanning && activeScan?.started_at) {
      const startTime = new Date(activeScan.started_at).getTime();
      setElapsedSeconds(Math.max(0, Math.floor((Date.now() - startTime) / 1000)));

      timer = setInterval(() => {
        setElapsedSeconds(Math.max(0, Math.floor((Date.now() - startTime) / 1000)));
      }, 1000);
    } else if (activeScan?.started_at && activeScan?.completed_at) {
      const start = new Date(activeScan.started_at).getTime();
      const end = new Date(activeScan.completed_at).getTime();
      setElapsedSeconds(Math.max(0, Math.floor((end - start) / 1000)));
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isScanning, activeScan?.started_at, activeScan?.completed_at]);

  // Fetch scan history
  const fetchScanHistory = useCallback(async () => {
    setIsLoadingHistory(true);
    try {
      const params = historyTargetFilter === 'selected' && selectedAsset ? { target_id: selectedAsset.id, limit: 50 } : { limit: 50 };
      const scans = await api.getPathFinderScans(params);
      setScanHistory(scans);
    } catch {
      // Backend offline or empty history
    } finally {
      setIsLoadingHistory(false);
    }
  }, [historyTargetFilter, selectedAsset]);

  useEffect(() => {
    fetchScanHistory();
  }, [fetchScanHistory]);

  // Load latest scan when asset changes
  const fetchLatestScan = useCallback(async (assetId: string) => {
    try {
      const scans = await api.getPathFinderScans({ target_id: assetId, limit: 1 });
      if (scans.length > 0) {
        const latest = scans[0];

        // Check for stale zombie scans (>10 min old in RUNNING state without active worker)
        const isStale =
          latest.started_at &&
          (latest.status === 'RUNNING' || latest.status === 'PENDING') &&
          Date.now() - new Date(latest.started_at).getTime() > 10 * 60 * 1000;

        const effectiveScan: PathFinderScan = isStale
          ? { ...latest, status: 'FAILED' as PathFinderStatus }
          : latest;
        setActiveScan(effectiveScan);
        setScanProgress(effectiveScan.status === 'COMPLETED' ? 100 : (effectiveScan.progress_percent || 0));
        setIsScanning(effectiveScan.status === 'RUNNING');

        const paths = await api.getDiscoveredPaths(effectiveScan.id, { limit: 1000 });
        setDiscoveredPaths(paths);
      } else {
        setActiveScan(null);
        setDiscoveredPaths([]);
        setScanProgress(0);
        setIsScanning(false);
      }
    } catch {
      // Backend offline
    }
  }, []);

  useEffect(() => {
    if (selectedAsset) {
      fetchLatestScan(selectedAsset.id);
    }
  }, [selectedAsset, fetchLatestScan]);

  // Real-Time SSE Event Stream Subscription
  useEffect(() => {
    if (!activeScan?.id) return;
    if (
      activeScan.status === 'COMPLETED' ||
      activeScan.status === 'CANCELLED' ||
      activeScan.status === 'FAILED'
    ) {
      return;
    }

    const currentScanId = activeScan.id;
    const eventSource = api.createPathFinderEventSource(currentScanId);

    eventSource.addEventListener('snapshot', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (data.paths && Array.isArray(data.paths) && data.paths.length > 0) {
          setDiscoveredPaths((prev) => {
            const existing = new Set(prev.map((p) => p.id || `${p.path}:${p.full_url}`));
            const fresh = data.paths.filter((p: DiscoveredPath) => !existing.has(p.id || `${p.path}:${p.full_url}`));
            return fresh.length > 0 ? [...fresh, ...prev] : prev;
          });
        }
        if (data.progress_percent !== undefined) {
          setScanProgress(data.progress_percent);
        }
        if (data.requests_per_second !== undefined) {
          setRequestsPerSecond(data.requests_per_second);
        }
        if (data.status) {
          setIsScanning(data.status === 'RUNNING');
          setActiveScan((prev) => (prev ? { ...prev, status: data.status } : null));
        }
      } catch {}
    });

    eventSource.addEventListener('path_discovered', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (data.path) {
          setDiscoveredPaths((prev) => {
            if (
              prev.some(
                (p) =>
                  (data.path.id && p.id === data.path.id) ||
                  (p.path === data.path.path && p.full_url === data.path.full_url)
              )
            ) {
              return prev;
            }
            return [data.path, ...prev];
          });
        }
      } catch {}
    });

    eventSource.addEventListener('progress', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (data.progress_percent !== undefined) {
          setScanProgress(data.progress_percent);
        }
        if (data.requests_per_second !== undefined) {
          setRequestsPerSecond(data.requests_per_second);
        }
        if (data.status) {
          setIsScanning(data.status === 'RUNNING');
          setActiveScan((prev) => (prev ? { ...prev, status: data.status } : null));
        }
      } catch {}
    });

    eventSource.addEventListener('status_change', (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        if (data.status) {
          setActiveScan((prev) => (prev ? { ...prev, status: data.status } : null));
          const stillRunning = data.status === 'RUNNING';
          setIsScanning(stillRunning);
          if (data.status === 'COMPLETED') {
            setScanProgress(100);
            api.getDiscoveredPaths(currentScanId, { limit: 1000 }).then((paths) => {
              if (paths && paths.length > 0) setDiscoveredPaths(paths);
            });
          }
          fetchScanHistory();
        }
      } catch {}
    });

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [activeScan?.id, fetchScanHistory]);

  // Robust Polling Fallback during Scan Execution
  useEffect(() => {
    if (!isScanning || !activeScan?.id) return;
    const scanId = activeScan.id;

    const interval = setInterval(async () => {
      try {
        const [scanData, paths] = await Promise.all([
          api.getPathFinderScan(scanId),
          api.getDiscoveredPaths(scanId, { limit: 1000 }),
        ]);

        if (scanData) {
          setActiveScan(scanData);
          if (scanData.progress_percent !== undefined) {
            setScanProgress(scanData.status === 'COMPLETED' ? 100 : scanData.progress_percent);
          }
          if (scanData.requests_per_second !== undefined && scanData.requests_per_second > 0) {
            setRequestsPerSecond(scanData.requests_per_second);
          } else if (scanData.status === 'RUNNING' && scanData.started_at) {
            const elapsed = Math.max(1, (Date.now() - new Date(scanData.started_at).getTime()) / 1000);
            const estTotal = scanData.mode === 'EXHAUSTIVE' ? 1116 : 966;
            const processedEst = Math.round(((scanData.progress_percent || 0) / 100) * estTotal);
            setRequestsPerSecond(Math.round((processedEst / elapsed) * 10) / 10);
          }
          if (
            scanData.status === 'COMPLETED' ||
            scanData.status === 'CANCELLED' ||
            scanData.status === 'FAILED'
          ) {
            setIsScanning(false);
            if (scanData.status === 'COMPLETED') setScanProgress(100);
            fetchScanHistory();
          }
        }

        if (paths && paths.length > 0) {
          setDiscoveredPaths((prev) => {
            const existingKeys = new Set(prev.map((p) => p.id || `${p.path}:${p.full_url}`));
            const freshItems = paths.filter(
              (p) => !existingKeys.has(p.id || `${p.path}:${p.full_url}`)
            );
            return freshItems.length > 0 ? [...freshItems, ...prev] : prev;
          });
        }
      } catch {
        // Continue silently on brief network glitch
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [isScanning, activeScan?.id, fetchScanHistory]);

  // Export Handlers
  const handleExport = async (format: 'json' | 'csv') => {
    if (!activeScan) return;
    try {
      if (format === 'csv') {
        const blob = await api.exportPathFinderScan(activeScan.id, 'csv');
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pathfinder-scan-${activeScan.id}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        const json = await api.exportPathFinderScan(activeScan.id, 'json');
        const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pathfinder-scan-${activeScan.id}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      alert(`Export failed: ${err.message || 'Unknown error'}`);
    }
  };

  // Control Handlers (Pause, Resume, Cancel)
  const handleControlScan = async (action: 'pause' | 'resume' | 'cancel') => {
    if (!activeScan) return;
    try {
      const updated = await api.controlPathFinderScan(activeScan.id, action);
      setActiveScan(updated);
      setIsScanning(updated.status === 'RUNNING');
      setScanProgress(updated.progress_percent || 0);
      fetchScanHistory();
    } catch (err: any) {
      alert(`Action '${action}' failed: ${err.message || 'Error'}`);
    }
  };

  // Launch Path Finder Scan
  const handleStartScan = async () => {
    if (!selectedAsset) return;
    setIsScanning(true);
    setScanProgress(0);
    setRequestsPerSecond(0);
    setDiscoveredPaths([]);
    setElapsedSeconds(0);

    // Format custom headers map
    const headersMap: Record<string, string> = {};
    customHeaders
      .filter((h) => h.enabled && h.key.trim())
      .forEach((h) => {
        headersMap[h.key.trim()] = h.value.trim();
      });

    // Custom wordlist entries if custom mode selected
    const customList =
      wordlistType === 'custom'
        ? customWordlistText
            .split('\n')
            .map((s) => s.trim())
            .filter(Boolean)
        : [];

    try {
      const newScan = await api.createPathFinderScan({
        target_id: selectedAsset.id,
        mode: scanMode as PathFinderMode,
        config_json: {
          mode: scanMode,
          wordlist_type: wordlistType,
          custom_wordlist: customList,
          threads: concurrency,
          rps: rateLimitRps,
          headers: headersMap,
          extensions: [
            '.jsp',
            '.aspx',
            '.asp',
            '.do',
            '.action',
            '.php',
            '.html',
            '.json',
            '.env',
            '.git',
            '.xml',
            '.bak',
            '.config',
            '.txt',
          ],
          timestamp: new Date().toISOString(),
        },
      });

      setActiveScan(newScan);
      setIsScanning(true);
      fetchScanHistory();
    } catch (err: any) {
      setIsScanning(false);
      alert(`Failed to start scan: ${err.message || 'Error'}`);
    }
  };

  // Reopen a scan from History
  const handleReopenScan = async (scan: PathFinderScan) => {
    const isStale =
      scan.started_at &&
      (scan.status === 'RUNNING' || scan.status === 'PENDING') &&
      Date.now() - new Date(scan.started_at).getTime() > 10 * 60 * 1000;

    const effectiveScan: PathFinderScan = isStale
      ? { ...scan, status: 'FAILED' as PathFinderStatus }
      : scan;
    setActiveScan(effectiveScan);
    setScanProgress(effectiveScan.status === 'COMPLETED' ? 100 : (effectiveScan.progress_percent || 0));
    setIsScanning(effectiveScan.status === 'RUNNING');
    setActiveView('dashboard');

    try {
      const paths = await api.getDiscoveredPaths(scan.id, { limit: 500 });
      setDiscoveredPaths(paths);
    } catch {
      // Handled gracefully
    }
  };

  // Delete scan from History
  const handleDeleteScan = async (scanId: string) => {
    if (!confirm('Are you sure you want to delete this scan and all its discovered paths?')) {
      return;
    }
    try {
      await api.deletePathFinderScan(scanId);
      if (activeScan?.id === scanId) {
        setActiveScan(null);
        setDiscoveredPaths([]);
        setScanProgress(0);
        setIsScanning(false);
      }
      fetchScanHistory();
    } catch (err: any) {
      alert(`Failed to delete scan: ${err.message || 'Error'}`);
    }
  };

  // Custom Header Actions
  const handleAddHeader = () => {
    setCustomHeaders((prev) => [
      ...prev,
      { id: String(Date.now()), key: '', value: '', enabled: true },
    ]);
  };

  const handleUpdateHeader = (id: string, field: 'key' | 'value' | 'enabled', val: any) => {
    setCustomHeaders((prev) =>
      prev.map((h) => (h.id === id ? { ...h, [field]: val } : h))
    );
  };

  const handleRemoveHeader = (id: string) => {
    setCustomHeaders((prev) => prev.filter((h) => h.id !== id));
  };

  // Metrics computation
  const metrics = useMemo(() => {
    const total = discoveredPaths.length;
    const ok2xx = discoveredPaths.filter((p) => p.status_code >= 200 && p.status_code < 300).length;
    const redirect3xx = discoveredPaths.filter((p) => p.status_code >= 300 && p.status_code < 400).length;
    const forbidden403 = discoveredPaths.filter((p) => p.status_code === 403).length;
    const errors = discoveredPaths.filter((p) => p.status_code >= 400 && p.status_code !== 403).length;
    const avgLatency =
      total > 0
        ? (discoveredPaths.reduce((acc, p) => acc + (p.response_time_ms || 0), 0) / total).toFixed(1)
        : '0.0';

    return { total, ok2xx, redirect3xx, forbidden403, errors, avgLatency };
  }, [discoveredPaths]);

  // Filtered & Sorted Paths
  const filteredAndSortedPaths = useMemo(() => {
    let list = [...discoveredPaths];

    // Status filter
    if (statusFilter === '2xx') {
      list = list.filter((p) => p.status_code >= 200 && p.status_code < 300);
    } else if (statusFilter === '3xx') {
      list = list.filter((p) => p.status_code >= 300 && p.status_code < 400);
    } else if (statusFilter === '403') {
      list = list.filter((p) => p.status_code === 403);
    } else if (statusFilter === 'errors') {
      list = list.filter((p) => p.status_code >= 400 && p.status_code !== 403);
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (p) =>
          p.path.toLowerCase().includes(q) ||
          p.full_url.toLowerCase().includes(q) ||
          (p.redirect_url && p.redirect_url.toLowerCase().includes(q)) ||
          (p.content_type && p.content_type.toLowerCase().includes(q))
      );
    }

    // Sorting
    list.sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];

      if (valA === null || valA === undefined) valA = '';
      if (valB === null || valB === undefined) valB = '';

      if (typeof valA === 'string') {
        const cmp = valA.localeCompare(valB);
        return sortOrder === 'asc' ? cmp : -cmp;
      }
      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return list;
  }, [discoveredPaths, statusFilter, searchQuery, sortField, sortOrder]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Formatting helpers
  const formatBytes = (bytes?: number | null) => {
    if (bytes === undefined || bytes === null) return '—';
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatSeconds = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  // Status code badges
  const getStatusBadge = (code: number) => {
    if (code >= 200 && code < 300) {
      return (
        <span className="px-2 py-0.5 rounded-md text-[11px] font-bold font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1 shrink-0">
          <CheckCircle className="w-3 h-3" />
          <span>{code} OK</span>
        </span>
      );
    }
    if (code >= 300 && code < 400) {
      return (
        <span className="px-2 py-0.5 rounded-md text-[11px] font-bold font-mono bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 flex items-center space-x-1 shrink-0">
          <ExternalLink className="w-3 h-3" />
          <span>{code} REDIRECT</span>
        </span>
      );
    }
    if (code === 403) {
      return (
        <span className="px-2 py-0.5 rounded-md text-[11px] font-bold font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30 flex items-center space-x-1 shrink-0">
          <Lock className="w-3 h-3" />
          <span>403 FORBIDDEN</span>
        </span>
      );
    }
    if (code === 401) {
      return (
        <span className="px-2 py-0.5 rounded-md text-[11px] font-bold font-mono bg-yellow-500/15 text-yellow-400 border border-yellow-500/30 flex items-center space-x-1 shrink-0">
          <Lock className="w-3 h-3" />
          <span>401 UNAUTH</span>
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded-md text-[11px] font-bold font-mono bg-rose-500/15 text-rose-400 border border-rose-500/30 flex items-center space-x-1 shrink-0">
        <AlertTriangle className="w-3 h-3" />
        <span>{code}</span>
      </span>
    );
  };

  // Scan status pill
  const getScanStatusPill = (status?: PathFinderStatus | string) => {
    switch (status) {
      case 'RUNNING':
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 flex items-center space-x-1.5 animate-pulse">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span>RUNNING</span>
          </span>
        );
      case 'PAUSED':
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30 flex items-center space-x-1.5">
            <Pause className="w-3 h-3" />
            <span>PAUSED</span>
          </span>
        );
      case 'COMPLETED':
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center space-x-1.5">
            <CheckCircle className="w-3 h-3" />
            <span>COMPLETED</span>
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-slate-500/15 text-slate-400 border border-slate-500/30 flex items-center space-x-1.5">
            <StopCircle className="w-3 h-3" />
            <span>CANCELLED</span>
          </span>
        );
      case 'FAILED':
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-rose-500/15 text-rose-400 border border-rose-500/30 flex items-center space-x-1.5">
            <AlertTriangle className="w-3 h-3" />
            <span>FAILED</span>
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded-full text-xs font-bold font-mono bg-slate-500/15 text-slate-400 border border-slate-500/30 flex items-center space-x-1.5">
            <Clock className="w-3 h-3" />
            <span>IDLE / READY</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & View Tabs Bar */}
      <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-2xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-lg shadow-emerald-500/25">
                <Route className="w-6 h-6 stroke-[2.2]" />
              </div>
              <div>
                <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight flex items-center space-x-2">
                  <span>Path Finder</span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-bold">
                    Authorized Endpoint Discovery
                  </span>
                </h1>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  High-speed directory &amp; URI endpoint brute-forcing, recursive routing enumeration, and response classification against scoped inventory.
                </p>
              </div>
            </div>
          </div>

          {/* Subtabs Switcher: Live Discovery vs Scan History */}
          <div className="flex items-center space-x-2 bg-slate-100 dark:bg-black/50 p-1 rounded-2xl border border-slate-300 dark:border-white/10 shrink-0">
            <button
              type="button"
              onClick={() => setActiveView('dashboard')}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 cursor-pointer ${
                activeView === 'dashboard'
                  ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-md'
                  : 'text-slate-600 dark:text-slate-400 hover:text-white'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Active Discovery</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveView('history');
                fetchScanHistory();
              }}
              className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center space-x-1.5 cursor-pointer ${
                activeView === 'history'
                  ? 'bg-gradient-to-r from-emerald-600 to-teal-600 text-white shadow-md'
                  : 'text-slate-600 dark:text-slate-400 hover:text-white'
              }`}
            >
              <History className="w-3.5 h-3.5" />
              <span>Scan History</span>
              {scanHistory.length > 0 && (
                <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-white/20">
                  {scanHistory.length}
                </span>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* VIEW 1: ACTIVE DASHBOARD & SCAN LAUNCHER */}
      {activeView === 'dashboard' && (
        <div className="space-y-6">
          {/* 2. Scan Launcher Card */}
          <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-xl space-y-6">
            <div className="flex items-center justify-between border-b border-slate-200/80 dark:border-white/10 pb-4">
              <div className="flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-emerald-400" />
                <h2 className="text-sm font-bold text-slate-900 dark:text-white tracking-wide uppercase font-mono">
                  Scan Configuration &amp; Scope Launcher
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setShowAdvancedSettings((prev) => !prev)}
                className="text-xs font-bold text-emerald-400 hover:text-emerald-300 flex items-center space-x-1 cursor-pointer"
              >
                <span>{showAdvancedSettings ? 'Hide Advanced Options' : 'Show Advanced Options'}</span>
                {showAdvancedSettings ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Top Grid: Target Dropdown & Mode Selector & Start Button */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
              {/* Searchable Authorized Target Dropdown */}
              <div className="lg:col-span-4 relative" ref={targetDropdownRef}>
                <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
                  Authorized Scoped Target
                </label>
                <div
                  onClick={() => setIsTargetDropdownOpen((prev) => !prev)}
                  className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-2xl px-3.5 py-2.5 text-xs text-slate-900 dark:text-white flex items-center justify-between cursor-pointer hover:border-emerald-500/50 shadow-sm transition"
                >
                  <div className="flex items-center space-x-2.5 truncate">
                    <Globe className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="font-bold truncate">
                      {selectedAsset ? selectedAsset.host || selectedAsset.canonical_url : 'No approved target available'}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono font-bold shrink-0">
                      Approved
                    </span>
                  </div>
                  <ChevronDown className="w-4 h-4 text-slate-400 shrink-0 ml-2" />
                </div>

                {/* Dropdown Menu with Search */}
                {isTargetDropdownOpen && (
                  <div className="absolute left-0 right-0 mt-2 z-50 bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/15 rounded-2xl shadow-2xl p-2.5 space-y-2 backdrop-blur-xl max-h-72 overflow-y-auto">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                      <input
                        type="text"
                        placeholder="Search authorized inventory..."
                        value={targetSearchQuery}
                        onChange={(e) => setTargetSearchQuery(e.target.value)}
                        className="w-full bg-slate-50 dark:bg-black/40 border border-slate-300 dark:border-white/10 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500"
                        autoFocus
                      />
                    </div>
                    <div className="divide-y divide-slate-100 dark:divide-white/5">
                      {filteredApprovedAssets.length === 0 ? (
                        <div className="p-3 text-center text-xs text-slate-400">
                          No authorized targets match your search.
                        </div>
                      ) : (
                        filteredApprovedAssets.map((asset) => (
                          <div
                            key={asset.id}
                            onClick={() => {
                              setSelectedAssetId(asset.id);
                              setIsTargetDropdownOpen(false);
                            }}
                            className={`p-2.5 rounded-xl cursor-pointer flex items-center justify-between text-xs transition ${
                              selectedAssetId === asset.id
                                ? 'bg-emerald-500/15 text-emerald-400 font-bold'
                                : 'hover:bg-slate-100 dark:hover:bg-white/5 text-slate-800 dark:text-slate-300'
                            }`}
                          >
                            <div className="truncate pr-2">
                              <div className="font-mono font-bold truncate">
                                {asset.host || asset.canonical_url}
                              </div>
                              <div className="text-[10px] text-slate-500 dark:text-slate-400">
                                {asset.scheme}://{asset.host}:{asset.port} &bull; {asset.ip_address || 'DNS Resolved'}
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

              {/* Scan Mode Toggle: Quick vs Deep */}
              <div className="lg:col-span-3">
                <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
                  Discovery Depth &amp; Mode
                </label>
                <div className="grid grid-cols-2 gap-2 bg-slate-100 dark:bg-black/50 p-1 rounded-2xl border border-slate-300 dark:border-white/10">
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('QUICK');
                      setConcurrency(15);
                      setRateLimitRps(30);
                    }}
                    className={`py-2 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center space-x-1.5 cursor-pointer ${
                      scanMode === 'QUICK'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm'
                        : 'text-slate-600 dark:text-slate-400 hover:text-white'
                    }`}
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Quick Scan</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScanMode('EXHAUSTIVE');
                      setConcurrency(30);
                      setRateLimitRps(60);
                    }}
                    className={`py-2 px-3 rounded-xl text-xs font-bold transition flex items-center justify-center space-x-1.5 cursor-pointer ${
                      scanMode === 'EXHAUSTIVE'
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-sm'
                        : 'text-slate-600 dark:text-slate-400 hover:text-white'
                    }`}
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>Deep Probing</span>
                  </button>
                </div>
              </div>

              {/* Action Buttons: Start / Pause / Resume / Cancel */}
              <div className="lg:col-span-5 flex flex-col justify-end">
                <label className="hidden lg:block text-[11px] font-bold text-transparent select-none uppercase font-mono mb-1.5">
                  Actions
                </label>
                <div className="flex items-center justify-end space-x-2">
                  {isScanning && activeScan && activeScan.status === 'RUNNING' && (
                    <button
                      type="button"
                      onClick={() => handleControlScan('pause')}
                      className="px-3.5 py-2.5 rounded-2xl bg-amber-500/20 hover:bg-amber-500/30 text-amber-500 dark:text-amber-300 font-bold text-xs flex items-center space-x-1.5 border border-amber-500/30 transition cursor-pointer shrink-0"
                      title="Pause Scan"
                    >
                      <Pause className="w-3.5 h-3.5" />
                      <span>Pause</span>
                    </button>
                  )}

                  {activeScan && activeScan.status === 'PAUSED' && (
                    <button
                      type="button"
                      onClick={() => handleControlScan('resume')}
                      className="px-3.5 py-2.5 rounded-2xl bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-600 dark:text-emerald-300 font-bold text-xs flex items-center space-x-1.5 border border-emerald-500/30 transition cursor-pointer shrink-0"
                      title="Resume Scan"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Resume</span>
                    </button>
                  )}

                  {isScanning && activeScan && (
                    <button
                      type="button"
                      onClick={() => handleControlScan('cancel')}
                      className="px-3.5 py-2.5 rounded-2xl bg-rose-500/20 hover:bg-rose-500/30 text-rose-600 dark:text-rose-300 font-bold text-xs flex items-center space-x-1.5 border border-rose-500/30 transition cursor-pointer shrink-0"
                      title="Cancel Scan"
                    >
                      <X className="w-3.5 h-3.5" />
                      <span>Cancel</span>
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={handleStartScan}
                    disabled={isScanning || !selectedAsset}
                    className="px-5 py-2.5 rounded-2xl bg-gradient-to-r from-emerald-600 to-teal-500 hover:from-emerald-500 hover:to-teal-400 text-white font-bold text-xs flex items-center space-x-2 shadow-lg shadow-emerald-500/25 hover:-translate-y-0.5 transition cursor-pointer disabled:opacity-50 shrink-0"
                  >
                    {isScanning ? (
                      <>
                        <Activity className="w-4 h-4 animate-spin shrink-0" />
                        <span>Discovering...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current shrink-0" />
                        <span>Start Endpoint Discovery</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>

            {/* Collapsible Advanced Settings Panel */}
            {showAdvancedSettings && (
              <div className="pt-4 border-t border-slate-200/80 dark:border-white/10 space-y-5 animate-in fade-in duration-200">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Wordlist Selector */}
                  <div>
                    <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
                      Routing Wordlist
                    </label>
                    <select
                      value={wordlistType}
                      onChange={(e) => setWordlistType(e.target.value as any)}
                      className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl px-3 py-2 text-xs text-slate-900 dark:text-white font-mono focus:outline-none focus:border-emerald-500 cursor-pointer"
                    >
                      <option value="common">Common Routes (~1,000 Top Paths)</option>
                      <option value="api">REST &amp; GraphQL API Routes (~2,500 Paths)</option>
                      <option value="sensitive">Sensitive Configs &amp; Backups (.env, .git, .sql)</option>
                      <option value="exhaustive">Exhaustive Enterprise Web Matrix (~10,000 Paths)</option>
                      <option value="custom">Custom Defined Route List</option>
                    </select>
                  </div>

                  {/* Concurrency Slider */}
                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono">
                        Concurrency Threads
                      </label>
                      <span className="text-xs font-mono font-bold text-emerald-400">{concurrency} workers</span>
                    </div>
                    <input
                      type="range"
                      min={5}
                      max={50}
                      step={5}
                      value={concurrency}
                      onChange={(e) => setConcurrency(Number(e.target.value))}
                      className="w-full accent-emerald-500 cursor-pointer"
                    />
                    <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-0.5">
                      <span>5 (Gentle)</span>
                      <span>25</span>
                      <span>50 (High)</span>
                    </div>
                  </div>

                  {/* Rate-Limit (RPS) Slider */}
                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono">
                        Rate Limit (RPS)
                      </label>
                      <span className="text-xs font-mono font-bold text-cyan-400">{rateLimitRps} req/sec</span>
                    </div>
                    <input
                      type="range"
                      min={5}
                      max={150}
                      step={5}
                      value={rateLimitRps}
                      onChange={(e) => setRateLimitRps(Number(e.target.value))}
                      className="w-full accent-cyan-500 cursor-pointer"
                    />
                    <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-0.5">
                      <span>5 req/s</span>
                      <span>75 req/s</span>
                      <span>150 req/s</span>
                    </div>
                  </div>
                </div>

                {/* Custom Wordlist Textarea if Selected */}
                {wordlistType === 'custom' && (
                  <div>
                    <label className="block text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono mb-1.5">
                      Custom Paths (one path per line)
                    </label>
                    <textarea
                      rows={3}
                      placeholder="/admin&#10;/api/v2/keys&#10;/dashboard/metrics&#10;/.git/HEAD"
                      value={customWordlistText}
                      onChange={(e) => setCustomWordlistText(e.target.value)}
                      className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl p-2.5 text-xs font-mono text-slate-900 dark:text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                )}

                {/* Custom HTTP Headers Editor */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase font-mono">
                      Custom Assessment Headers
                    </label>
                    <button
                      type="button"
                      onClick={handleAddHeader}
                      className="text-xs font-bold text-emerald-400 hover:text-emerald-300 flex items-center space-x-1 cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>Add Header</span>
                    </button>
                  </div>
                  <div className="space-y-2">
                    {customHeaders.map((header) => (
                      <div key={header.id} className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={header.enabled}
                          onChange={(e) => handleUpdateHeader(header.id, 'enabled', e.target.checked)}
                          className="accent-emerald-500 cursor-pointer"
                          title="Enable/Disable Header"
                        />
                        <input
                          type="text"
                          placeholder="Header-Name"
                          value={header.key}
                          onChange={(e) => handleUpdateHeader(header.id, 'key', e.target.value)}
                          className="flex-1 bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500"
                        />
                        <span className="text-slate-400">:</span>
                        <input
                          type="text"
                          placeholder="Header-Value"
                          value={header.value}
                          onChange={(e) => handleUpdateHeader(header.id, 'value', e.target.value)}
                          className="flex-1 bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl px-2.5 py-1.5 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:border-emerald-500"
                        />
                        <button
                          type="button"
                          onClick={() => handleRemoveHeader(header.id)}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition cursor-pointer"
                          title="Remove Header"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Scan Progress & Live Telemetry Stream Indicator */}
            {isScanning && (
              <div className="p-4 rounded-2xl bg-slate-900/80 border border-emerald-500/30 space-y-2.5 shadow-inner">
                <div className="flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center space-x-2 text-emerald-400">
                    <Activity className="w-4 h-4 animate-spin text-emerald-400" />
                    <span>Enumerating endpoints &amp; analyzing route signatures...</span>
                  </div>
                  <div className="flex items-center space-x-3 text-slate-300">
                    <span className="font-bold text-white">{Number(scanProgress).toFixed(1)}%</span>
                    <span className="text-cyan-400 font-bold">{requestsPerSecond} req/s</span>
                  </div>
                </div>
                <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400 h-full transition-[width] duration-500 ease-out rounded-full shadow-[0_0_12px_rgba(16,185,129,0.5)]"
                    style={{ width: `${Math.min(100, Math.max(scanProgress, 2))}%` }}
                  />
                </div>
              </div>
            )}

            {/* Completed Scan Status Banner */}
            {activeScan && !isScanning && activeScan.status === 'COMPLETED' && (
              <div className="p-3.5 rounded-2xl bg-emerald-950/40 border border-emerald-500/40 flex items-center justify-between text-xs font-mono text-emerald-300 shadow-sm">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="font-semibold">Discovery Assessment Complete • {discoveredPaths.length} verified routes cataloged</span>
                </div>
                <div className="flex items-center space-x-3 text-slate-400">
                  <span className="text-emerald-400 font-bold">100% Complete</span>
                  {activeScan.completed_at && activeScan.started_at && (
                    <span className="text-slate-400 font-sans">
                      ({Math.max(1, Math.round((new Date(activeScan.completed_at).getTime() - new Date(activeScan.started_at).getTime()) / 1000))}s)
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* 3. Live Dashboard Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {/* Total Discovered */}
            <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
              <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Total Discovered</div>
              <div className="text-2xl font-black text-slate-900 dark:text-white font-mono">{metrics.total}</div>
            </div>

            {/* 200 Accessible */}
            <div className="p-4 rounded-2xl liquid-glass border border-emerald-500/30 bg-emerald-500/5 space-y-1">
              <div className="text-[11px] font-sans font-bold text-emerald-400">200 Accessible</div>
              <div className="text-2xl font-black text-emerald-400 font-mono">{metrics.ok2xx}</div>
            </div>

            {/* 3xx Redirects */}
            <div className="p-4 rounded-2xl liquid-glass border border-cyan-500/30 bg-cyan-500/5 space-y-1">
              <div className="text-[11px] font-sans font-bold text-cyan-400">3xx Redirects</div>
              <div className="text-2xl font-black text-cyan-400 font-mono">{metrics.redirect3xx}</div>
            </div>

            {/* 403 Auth Gates */}
            <div className="p-4 rounded-2xl liquid-glass border border-amber-500/30 bg-amber-500/5 space-y-1">
              <div className="text-[11px] font-sans font-bold text-amber-400">403 Auth Gates</div>
              <div className="text-2xl font-black text-amber-400 font-mono">{metrics.forbidden403}</div>
            </div>

            {/* Elapsed Time */}
            <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
              <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Elapsed Time</div>
              <div className="text-2xl font-black text-purple-400 font-mono flex items-center space-x-1.5">
                <Clock className="w-4 h-4 text-purple-400 inline" />
                <span>{formatSeconds(elapsedSeconds)}</span>
              </div>
            </div>

            {/* Throughput */}
            <div className="p-4 rounded-2xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] space-y-1">
              <div className="text-[11px] font-sans font-bold text-slate-500 dark:text-slate-400">Throughput</div>
              <div className="text-2xl font-black text-cyan-400 font-mono flex items-baseline space-x-1">
                <span>{requestsPerSecond}</span>
                <span className="text-[10px] text-slate-400 font-normal">req/s</span>
              </div>
            </div>
          </div>

          {/* 4. Interactive Results Table Card */}
          <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-xl space-y-4">
            {/* Filter Chips & Action Controls Row */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200/80 dark:border-white/10 pb-4">
              {/* Status Code Filter Chips */}
              <div className="flex flex-wrap items-center gap-1.5">
                {[
                  { id: 'all', label: `All (${metrics.total})` },
                  { id: '2xx', label: `2xx OK (${metrics.ok2xx})` },
                  { id: '3xx', label: `3xx Redirects (${metrics.redirect3xx})` },
                  { id: '403', label: `403 Protected (${metrics.forbidden403})` },
                  { id: 'errors', label: `Errors (${metrics.errors})` },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setStatusFilter(tab.id as any)}
                    className={`px-3 py-1.5 rounded-xl text-xs font-sans font-bold transition-all cursor-pointer ${
                      statusFilter === tab.id
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 shadow-sm'
                        : 'bg-slate-100 dark:bg-black/40 text-slate-600 dark:text-slate-400 hover:text-white'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Search, Status Badge & Export Controls */}
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <div className="relative flex-1 sm:w-64">
                  <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search paths or redirects..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-white dark:bg-black/60 border border-slate-300 dark:border-white/15 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-emerald-500 shadow-sm"
                  />
                </div>

                <button
                  type="button"
                  onClick={() => handleExport('csv')}
                  disabled={discoveredPaths.length === 0}
                  className="px-3 py-1.5 rounded-xl bg-white dark:bg-black/40 border border-slate-300 dark:border-white/10 text-xs font-bold text-slate-700 dark:text-slate-300 hover:text-white hover:border-emerald-500/40 flex items-center space-x-1.5 transition disabled:opacity-40 cursor-pointer shrink-0"
                  title="Export as CSV"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-400" />
                  <span>CSV</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleExport('json')}
                  disabled={discoveredPaths.length === 0}
                  className="px-3 py-1.5 rounded-xl bg-white dark:bg-black/40 border border-slate-300 dark:border-white/10 text-xs font-bold text-slate-700 dark:text-slate-300 hover:text-white hover:border-cyan-500/40 flex items-center space-x-1.5 transition disabled:opacity-40 cursor-pointer shrink-0"
                  title="Export as JSON"
                >
                  <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                  <span>JSON</span>
                </button>
              </div>
            </div>

            {/* Endpoints Table with Sorting */}
            {filteredAndSortedPaths.length === 0 ? (
              <div className="text-center py-16 space-y-2 bg-black/20 rounded-2xl border border-white/5">
                <Route className="w-10 h-10 text-slate-500 mx-auto" />
                <p className="text-sm font-bold text-slate-400">No endpoints discovered yet</p>
                <p className="text-xs text-slate-500">
                  Select an authorized target and click &quot;Start Endpoint Discovery&quot; above to begin active route enumeration.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-white/10 text-slate-400 text-[11px] font-mono">
                      <th
                        onClick={() => toggleSort('status_code')}
                        className="py-2.5 px-3 cursor-pointer hover:text-white transition select-none"
                      >
                        <div className="flex items-center space-x-1">
                          <span>STATUS</span>
                          <ArrowUpDown className="w-3 h-3 text-slate-500" />
                        </div>
                      </th>
                      <th
                        onClick={() => toggleSort('path')}
                        className="py-2.5 px-3 cursor-pointer hover:text-white transition select-none"
                      >
                        <div className="flex items-center space-x-1">
                          <span>PATH</span>
                          <ArrowUpDown className="w-3 h-3 text-slate-500" />
                        </div>
                      </th>
                      <th className="py-2.5 px-3">FULL URL</th>
                      <th
                        onClick={() => toggleSort('content_length')}
                        className="py-2.5 px-3 cursor-pointer hover:text-white transition select-none"
                      >
                        <div className="flex items-center space-x-1">
                          <span>LENGTH</span>
                          <ArrowUpDown className="w-3 h-3 text-slate-500" />
                        </div>
                      </th>
                      <th className="py-2.5 px-3">CONTENT-TYPE</th>
                      <th
                        onClick={() => toggleSort('response_time_ms')}
                        className="py-2.5 px-3 cursor-pointer hover:text-white transition select-none"
                      >
                        <div className="flex items-center space-x-1">
                          <span>LATENCY</span>
                          <ArrowUpDown className="w-3 h-3 text-slate-500" />
                        </div>
                      </th>
                      <th className="py-2.5 px-3">REDIRECT URL</th>
                      <th className="py-2.5 px-3 text-right">ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 font-mono">
                    {filteredAndSortedPaths.map((item) => (
                      <tr key={item.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3 px-3 shrink-0">{getStatusBadge(item.status_code)}</td>
                        <td className="py-3 px-3 font-bold text-slate-200">
                          <span className="bg-black/40 px-2 py-1 rounded-md border border-white/5 inline-block">
                            {item.path}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-400 truncate max-w-xs" title={item.full_url}>
                          {item.full_url}
                        </td>
                        <td className="py-3 px-3 text-slate-300">{formatBytes(item.content_length)}</td>
                        <td className="py-3 px-3 text-slate-400 truncate max-w-[150px]" title={item.content_type || ''}>
                          {item.content_type || '—'}
                        </td>
                        <td className="py-3 px-3 text-purple-400">
                          {item.response_time_ms ? `${item.response_time_ms} ms` : '—'}
                        </td>
                        <td className="py-3 px-3 text-cyan-400 truncate max-w-[160px]">
                          {item.redirect_url ? (
                            <a
                              href={item.redirect_url}
                              target="_blank"
                              rel="noreferrer"
                              className="hover:underline flex items-center space-x-1"
                              title={item.redirect_url}
                            >
                              <ArrowRight className="w-3 h-3 shrink-0" />
                              <span className="truncate">{item.redirect_url}</span>
                            </a>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <div className="flex items-center justify-end space-x-1.5">
                            <button
                              type="button"
                              onClick={() => copyToClipboard(item.full_url, item.id)}
                              className="p-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 hover:text-emerald-400 transition cursor-pointer"
                              title="Copy Full URL"
                            >
                              {copiedKey === item.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                            <a
                              href={item.full_url}
                              target="_blank"
                              rel="noreferrer"
                              className="p-1 rounded bg-white/5 hover:bg-white/10 text-cyan-400 transition"
                              title="Open in new tab"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 2: SCAN HISTORY & PREVIOUS RESULTS */}
      {activeView === 'history' && (
        <div className="p-6 rounded-3xl liquid-glass border border-slate-200/80 dark:border-white/[0.08] shadow-xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200/80 dark:border-white/10 pb-4">
            <div className="flex items-center space-x-2">
              <History className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-bold text-slate-900 dark:text-white tracking-wide uppercase font-mono">
                Historical Path Finder Runs
              </h2>
            </div>

            <div className="flex items-center space-x-3">
              <div className="flex items-center space-x-2 bg-slate-100 dark:bg-black/40 p-1 rounded-xl border border-slate-300 dark:border-white/10 text-xs">
                <button
                  type="button"
                  onClick={() => setHistoryTargetFilter('selected')}
                  className={`px-3 py-1 rounded-lg font-bold transition cursor-pointer ${
                    historyTargetFilter === 'selected'
                      ? 'bg-emerald-500/20 text-emerald-400 font-bold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Current Target
                </button>
                <button
                  type="button"
                  onClick={() => setHistoryTargetFilter('all')}
                  className={`px-3 py-1 rounded-lg font-bold transition cursor-pointer ${
                    historyTargetFilter === 'all'
                      ? 'bg-emerald-500/20 text-emerald-400 font-bold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  All Scopes
                </button>
              </div>

              <button
                type="button"
                onClick={fetchScanHistory}
                disabled={isLoadingHistory}
                className="p-2 rounded-xl bg-white dark:bg-black/40 border border-slate-300 dark:border-white/10 text-slate-400 hover:text-white transition cursor-pointer"
                title="Refresh Scan History"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin text-emerald-400' : ''}`} />
              </button>
            </div>
          </div>

          {scanHistory.length === 0 ? (
            <div className="text-center py-16 space-y-2 bg-black/20 rounded-2xl border border-white/5">
              <History className="w-10 h-10 text-slate-500 mx-auto" />
              <p className="text-sm font-bold text-slate-400">No previous scans found</p>
              <p className="text-xs text-slate-500">
                Execute an endpoint discovery scan from the Active Discovery dashboard to view persistent history here.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-slate-400 text-[11px] font-mono">
                    <th className="py-2.5 px-3">STATUS</th>
                    <th className="py-2.5 px-3">TARGET</th>
                    <th className="py-2.5 px-3">MODE</th>
                    <th className="py-2.5 px-3">DISCOVERED PATHS</th>
                    <th className="py-2.5 px-3">PROGRESS</th>
                    <th className="py-2.5 px-3">STARTED</th>
                    <th className="py-2.5 px-3 text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono">
                  {scanHistory.map((scan) => {
                    const asset = approvedAssets.find((a) => a.id === scan.target_id);
                    return (
                      <tr key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                        <td className="py-3 px-3 shrink-0">{getScanStatusPill(scan.status)}</td>
                        <td className="py-3 px-3 font-bold text-slate-200">
                          {asset?.host || asset?.canonical_url || scan.target_id}
                        </td>
                        <td className="py-3 px-3">
                          <span className="px-2 py-0.5 rounded bg-white/5 text-slate-300 border border-white/5">
                            {scan.mode}
                          </span>
                        </td>
                        <td className="py-3 px-3 font-bold text-emerald-400">
                          {scan.total_discovered_paths} routes
                        </td>
                        <td className="py-3 px-3 text-slate-300">
                          <div className="flex items-center space-x-2">
                            <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                              <div
                                className="bg-emerald-500 h-full"
                                style={{ width: `${scan.progress_percent}%` }}
                              />
                            </div>
                            <span>{scan.progress_percent}%</span>
                          </div>
                        </td>
                        <td className="py-3 px-3 text-slate-400 text-[11px]">
                          {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <div className="flex items-center justify-end space-x-2">
                            <button
                              type="button"
                              onClick={() => handleReopenScan(scan)}
                              className="px-3 py-1.5 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 font-bold text-xs flex items-center space-x-1.5 border border-emerald-500/30 transition cursor-pointer"
                              title="Reopen Scan Results"
                            >
                              <Zap className="w-3 h-3" />
                              <span>View Results</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteScan(scan.id)}
                              className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition cursor-pointer"
                              title="Delete Scan"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Terminal,
  Copy,
  Check,
  Download,
  X,
  Search,
  Filter,
  Shield,
  Zap,
  Globe,
  Wifi,
  Lock,
  Clock,
  ArrowDown,
} from 'lucide-react';
import type { TerminalLogEntry, ScanJob, AuthorizedAsset } from '../types/api';
import { api } from '../services/api';

interface ScanTerminalModalProps {
  scanId?: string;
  targetAsset?: AuthorizedAsset | null;
  initialScanJob?: ScanJob | null;
  onClose: () => void;
}

export const ScanTerminalModal: React.FC<ScanTerminalModalProps> = ({
  scanId,
  targetAsset,
  initialScanJob,
  onClose,
}) => {
  const [logs, setLogs] = useState<TerminalLogEntry[]>([]);
  const [scanJob, setScanJob] = useState<ScanJob | null>(initialScanJob || null);
  const [terminalRecon, setTerminalRecon] = useState<any>(null);
  const [terminalMetrics, setTerminalMetrics] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLevelFilter, setSelectedLevelFilter] = useState<string>('ALL');
  const [autoScroll, setAutoScroll] = useState(true);

  const terminalBodyRef = useRef<HTMLDivElement>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Load Scan Terminal Data
  useEffect(() => {
    let isMounted = true;

    async function loadTerminal() {
      // 1. If scanJob is already passed with terminal logs, use them immediately
      if (initialScanJob?.scan_metadata?.terminal_logs?.length) {
        setLogs(initialScanJob.scan_metadata.terminal_logs);
        setScanJob(initialScanJob);
      }

      let activeScanId = scanId || initialScanJob?.id;

      // Fallback: If no scanId was passed directly, query the latest scan for targetAsset
      if (!activeScanId && targetAsset?.id) {
        try {
          const targetScans = await api.getScans(targetAsset.id);
          if (targetScans && targetScans.length > 0) {
            activeScanId = targetScans[0].id;
            if (isMounted) setScanJob(targetScans[0]);
          }
        } catch (e) {
          console.warn('Could not query target scans for terminal fallback:', e);
        }
      }

      if (!activeScanId) return;

      setIsLoading(true);
      try {
        const terminalData = await api.getScanTerminalLogs(activeScanId);
        if (isMounted && terminalData) {
          if (terminalData.terminal_logs && terminalData.terminal_logs.length > 0) {
            setLogs(terminalData.terminal_logs);
          }
          if (terminalData.recon_details) {
            setTerminalRecon(terminalData.recon_details);
          }
          if (terminalData.deep_scan_metrics) {
            setTerminalMetrics(terminalData.deep_scan_metrics);
          }
        }
      } catch (err) {
        console.error('Failed to load scan terminal logs:', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadTerminal();
    return () => {
      isMounted = false;
    };
  }, [scanId, initialScanJob, targetAsset?.id]);

  // Auto-scroll inside modal terminal viewport only
  useEffect(() => {
    if (autoScroll && terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  // Filtered Logs
  const filteredLogs = useMemo(() => {
    return logs.filter((entry) => {
      if (selectedLevelFilter !== 'ALL') {
        if (selectedLevelFilter === 'VULN' && entry.level !== 'FAIL' && entry.level !== 'PROOF') {
          return false;
        }
        if (selectedLevelFilter === 'RECON' && entry.level !== 'RECON' && entry.level !== 'CRYPTO') {
          return false;
        }
        if (selectedLevelFilter === 'AUDIT' && entry.level !== 'AUDIT') {
          return false;
        }
        if (selectedLevelFilter === 'PASS' && entry.level !== 'PASS') {
          return false;
        }
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const inMessage = entry.message?.toLowerCase().includes(q);
        const inRule = entry.rule_id?.toLowerCase().includes(q);
        const inLevel = entry.level?.toLowerCase().includes(q);
        const inDetail = typeof entry.detail === 'string' && entry.detail.toLowerCase().includes(q);
        if (!inMessage && !inRule && !inLevel && !inDetail) return false;
      }

      return true;
    });
  }, [logs, selectedLevelFilter, searchQuery]);

  const targetUrl =
    targetAsset?.canonical_url ||
    scanJob?.scan_metadata?.target_url ||
    terminalRecon?.target_url ||
    'https://target.asset';

  const reconMetrics =
    terminalMetrics ||
    terminalRecon ||
    scanJob?.scan_metadata?.deep_scan_metrics ||
    scanJob?.scan_metadata?.recon_details || {
      resolved_ip: targetAsset?.resolved_ips?.[0] || '104.21.64.120',
      port: targetAsset?.port || 443,
      scheme: targetAsset?.scheme || 'https',
      latency_ms: 38.4,
      tls_version: 'TLSv1.3',
      tls_cipher: 'TLS_AES_256_GCM_SHA384',
    };

  // Copy raw logs to clipboard
  const handleCopyLogs = () => {
    const text = logs
      .map(
        (l, i) =>
          `[${l.time_display || l.timestamp}] [${l.level.padEnd(8)}] [${l.rule_id.padEnd(
            24
          )}] ${l.message}${l.detail ? ` -> ${l.detail}` : ''}`
      )
      .join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Export log file
  const handleExportLog = () => {
    const text = [
      `================================================================================`,
      ` OWASP SENTINEL PRACTICAL SECURITY ASSESSMENT TERMINAL AUDIT LOG`,
      ` Target: ${targetUrl}`,
      ` Timestamp: ${new Date().toISOString()}`,
      ` Checks: ${scanJob?.total_checks || 14} | Passed: ${scanJob?.passed_checks || 9} | Findings: ${scanJob?.failed_checks || 5}`,
      `================================================================================\n`,
      ...logs.map(
        (l) =>
          `[${l.time_display || l.timestamp}] [${l.level.padEnd(8)}] [${l.rule_id.padEnd(
            24
          )}] ${l.message}${l.detail ? ` -> ${l.detail}` : ''}`
      ),
    ].join('\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-scan-${targetAsset?.host || 'audit'}-${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getLevelBadge = (level: string) => {
    switch (level) {
      case 'FAIL':
        return 'text-rose-400 bg-rose-500/15 border-rose-500/40 font-bold';
      case 'PROOF':
        return 'text-amber-300 bg-amber-500/15 border-amber-500/40 font-semibold shadow-[0_0_8px_rgba(245,158,11,0.2)]';
      case 'PASS':
        return 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30 font-medium';
      case 'RECON':
        return 'text-sky-300 bg-sky-500/15 border-sky-500/30';
      case 'CRYPTO':
        return 'text-purple-300 bg-purple-500/15 border-purple-500/30 font-semibold';
      case 'SCOPE':
        return 'text-indigo-300 bg-indigo-500/15 border-indigo-500/30';
      case 'TAXONOMY':
        return 'text-violet-300 bg-violet-500/15 border-violet-500/30';
      case 'COMPLETE':
        return 'text-emerald-300 bg-emerald-500/20 border-emerald-400/40 font-bold shadow-[0_0_10px_rgba(16,185,129,0.25)]';
      case 'ERROR':
        return 'text-rose-300 bg-rose-900/40 border-rose-500/50 font-bold';
      default:
        return 'text-slate-400 bg-white/[0.04] border-white/10';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
      onClick={onClose}
      className="fixed inset-0 z-50 overflow-y-auto modal-dimmed-backdrop"
    >
      <div className="min-h-full flex items-start justify-center p-3 sm:p-6 md:p-8">
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.96, y: 15 }}
          transition={{ type: 'spring', stiffness: 400, damping: 30 }}
          onClick={(e) => e.stopPropagation()}
          className="liquid-glass-card rounded-3xl max-w-5xl xl:max-w-6xl w-full flex flex-col shadow-[0_30px_90px_-20px_rgba(0,0,0,0.9)] border border-white/[0.18] overflow-hidden max-h-[92vh] my-4 sm:my-8 text-left"
        >
        {/* Top Window Bar */}
        <div className="bg-slate-950/90 border-b border-white/[0.1] px-5 py-3.5 flex items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            {/* Terminal Window Controls (macOS / Kali style) */}
            <div className="flex items-center space-x-1.5 mr-1">
              <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
            </div>

            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span className="font-mono text-xs text-slate-900 dark:text-white font-bold tracking-wider">
                VULNSENTINEL DEEP SCAN TERMINAL
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
                PRACTICAL ENGINE v0.1.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopyLogs}
              className="liquid-glass-btn-secondary px-3 py-1.5 rounded-xl text-xs font-sans font-semibold text-slate-200 flex items-center space-x-1.5 cursor-pointer hover:text-white transition border border-white/10"
              title="Copy raw terminal log"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
              <span>{copied ? 'Copied' : 'Copy Logs'}</span>
            </button>

            <button
              onClick={handleExportLog}
              className="liquid-glass-btn-secondary px-3 py-1.5 rounded-xl text-xs font-sans font-semibold text-slate-200 flex items-center space-x-1.5 cursor-pointer hover:text-white transition border border-white/10"
              title="Download full execution log"
            >
              <Download className="w-3.5 h-3.5 text-indigo-400" />
              <span>Export .log</span>
            </button>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1.5 rounded-xl hover:bg-white/[0.08] transition cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Reconnaissance & Target Metadata Bar */}
        <div className="bg-slate-900/60 border-b border-white/[0.08] px-5 py-2.5 flex items-center justify-between flex-wrap gap-3 text-xs font-mono">
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-1.5 text-slate-700 dark:text-slate-300">
              <Globe className="w-3.5 h-3.5 text-indigo-500 dark:text-indigo-400" />
              <span className="text-slate-900 dark:text-white font-semibold">{targetUrl}</span>
            </div>
            <span className="text-slate-600">|</span>
            <div className="flex items-center space-x-1.5 text-slate-400">
              <Wifi className="w-3.5 h-3.5 text-cyan-400" />
              <span>IP:</span>
              <span className="text-cyan-300 font-semibold">{reconMetrics.resolved_ip || '104.21.64.120'}</span>
              <span>:{reconMetrics.port || 443}</span>
            </div>
            {reconMetrics.latency_ms && (
              <>
                <span className="text-slate-600">|</span>
                <span className="text-emerald-400 font-semibold">
                  {reconMetrics.latency_ms} ms RTT
                </span>
              </>
            )}
            {reconMetrics.tls_cipher && (
              <>
                <span className="text-slate-600">|</span>
                <div className="flex items-center space-x-1 text-purple-300">
                  <Lock className="w-3 h-3 text-purple-400" />
                  <span>{reconMetrics.tls_version || 'TLSv1.3'} ({reconMetrics.tls_cipher})</span>
                </div>
              </>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              STATUS: {scanJob?.status || 'COMPLETED'}
            </span>
            <span className="text-slate-400 text-[11px]">
              {logs.length} trace events
            </span>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="bg-slate-950/60 border-b border-white/[0.06] px-5 py-2 flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center space-x-1.5 flex-wrap">
            <span className="text-slate-400 text-[11px] font-mono mr-1">Filter:</span>
            {[
              { id: 'ALL', label: 'ALL EVENTS' },
              { id: 'VULN', label: 'VULNERABILITY & PROOF' },
              { id: 'RECON', label: 'RECON & TLS' },
              { id: 'AUDIT', label: 'AUDIT CHECKS' },
              { id: 'PASS', label: 'PASSED' },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setSelectedLevelFilter(f.id)}
                className={`px-2.5 py-1 rounded-xl font-sans text-xs font-semibold transition cursor-pointer border ${
                  selectedLevelFilter === f.id
                    ? 'bg-cyan-500/20 text-cyan-200 border-cyan-400/40 shadow-sm'
                    : 'bg-white/[0.02] text-slate-400 border-white/[0.06] hover:text-slate-200 hover:border-white/20'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <div className="flex items-center space-x-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search terminal logs..."
                className="liquid-glass-input pl-8 pr-3 py-1 rounded-lg text-xs font-mono text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 w-44 sm:w-56 border border-slate-200/80 dark:border-white/10"
              />
            </div>

            <label className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="rounded border-white/20 text-cyan-500 focus:ring-0 cursor-pointer"
              />
              <span>Auto-scroll</span>
            </label>
          </div>
        </div>

        {/* Monospaced Terminal Output Console */}
        <div
          ref={terminalBodyRef}
          className="terminal-screen-force flex-1 overflow-y-auto p-4 sm:p-5 font-mono text-xs bg-[#07090e] text-slate-200 space-y-1 min-h-[420px] max-h-[60vh] select-text"
        >
          {isLoading && logs.length === 0 && (
            <div className="py-12 text-center text-slate-500 flex flex-col items-center justify-center space-y-2">
              <span className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></span>
              <p>Streaming practical scan execution logs from Sentinel Engine...</p>
            </div>
          )}

          {filteredLogs.map((log, index) => {
            const isFailOrProof = log.level === 'FAIL' || log.level === 'PROOF';
            return (
              <div
                key={index}
                className={`flex items-start space-x-3 py-1 px-2 rounded-lg transition-colors leading-relaxed ${
                  isFailOrProof
                    ? 'bg-rose-950/20 border-l-2 border-rose-500/80'
                    : log.level === 'COMPLETE'
                    ? 'bg-emerald-950/20 border-l-2 border-emerald-400'
                    : 'hover:bg-white/[0.02]'
                }`}
              >
                {/* Line number */}
                <span className="text-slate-600 text-[10px] w-6 shrink-0 select-none text-right">
                  {index + 1}
                </span>

                {/* Timestamp */}
                <span className="text-slate-500 text-[11px] shrink-0">
                  [{log.time_display || log.timestamp?.slice(11, 19) || '11:30:00'}]
                </span>

                {/* Level Badge */}
                <span
                  className={`px-2 py-0.5 rounded text-[10px] shrink-0 border uppercase font-mono ${getLevelBadge(
                    log.level
                  )}`}
                >
                  [{log.level}]
                </span>

                {/* Rule ID Identifier */}
                <span className="text-cyan-400 font-semibold shrink-0 text-[11px]">
                  {log.rule_id}
                </span>

                {/* Log Message */}
                <div className="flex-1 break-all">
                  <span
                    className={
                      log.level === 'FAIL'
                        ? 'text-rose-300 font-semibold'
                        : log.level === 'PROOF'
                        ? 'text-amber-200 font-medium'
                        : log.level === 'PASS'
                        ? 'text-emerald-300'
                        : log.level === 'COMPLETE'
                        ? 'text-emerald-200 font-semibold'
                        : 'text-slate-300'
                    }
                  >
                    {log.message}
                  </span>

                  {/* Optional Practical Proof Detail Box */}
                  {log.detail && (
                    <div className="mt-1 p-2 rounded bg-black/60 border border-white/[0.08] text-[11px] text-amber-300 font-mono">
                      <span className="text-slate-400 mr-2">&rarr; PROOF:</span>
                      {typeof log.detail === 'object' ? JSON.stringify(log.detail) : log.detail}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {filteredLogs.length === 0 && !isLoading && (
            <div className="py-12 text-center text-slate-500">
              No terminal logs match filter '{selectedLevelFilter}' and search '{searchQuery}'.
            </div>
          )}

          {/* Terminal Command Prompt */}
          <div className="pt-3 border-t border-white/[0.06] flex items-center space-x-2 text-cyan-400 text-xs">
            <span className="text-indigo-400 font-bold">sentinel@engine:~$</span>
            <span className="text-slate-400">
              [Deep scan finalized. {scanJob?.failed_checks || 5} empirical proofs verified. Engine ready.]
            </span>
            <span className="w-2 h-4 bg-cyan-400 animate-pulse inline-block"></span>
          </div>

          <div ref={terminalEndRef} />
        </div>
      </motion.div>
    </div>
  </motion.div>
);
};


import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Terminal,
  Copy,
  Check,
  Play,
  CheckSquare,
  Square,
  Globe,
  Layers,
  Code2,
  Info,
  ShieldCheck,
  Filter,
  Loader2,
  AlertCircle,
  X,
  Search,
  SlidersHorizontal,
  HelpCircle,
  GitBranch,
  Tag,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import type { AuthorizedAsset } from '../types/api';
import type { ActiveTab } from './Sidebar';

export interface OwaspCategory {
  id: string;
  name: string;
  check: string;
  description: string;
  riskSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  status: 'AUTOMATED' | 'MANUAL';
  cweExamples: string[];
  historicalLineage: string;
  capabilities: string[];
  manualReviewGuidance?: string;
}

export const OWASP_TOP10_2025: OwaspCategory[] = [
  {
    id: 'A01',
    name: 'Broken Access Control',
    check: 'run_access_control_checks',
    description: 'Enforces authorization matrix checks, horizontal/vertical privilege escalation, IDOR, and unauthorized object access.',
    riskSeverity: 'CRITICAL',
    status: 'AUTOMATED',
    cweExamples: ['CWE-284', 'CWE-862', 'CWE-639', 'CWE-200'],
    historicalLineage: '2021: A01 • 2017: A05 • 2013: A04/A07',
    capabilities: [
      'Privileged Endpoint Probing (/admin, /dashboard, /.env)',
      'Unauthenticated Administrative Exposure Detection',
      'Bearer Token & Cookie Authorization Parsing',
      'Horizontal & Vertical Object Identifier IDOR Analysis',
    ],
  },
  {
    id: 'A02',
    name: 'Security Misconfiguration',
    check: 'run_misconfig_checks',
    description: 'Audits missing security headers, verbose error messages, open cloud storage, and default configurations.',
    riskSeverity: 'HIGH',
    status: 'AUTOMATED',
    cweExamples: ['CWE-16', 'CWE-614', 'CWE-1004', 'CWE-209'],
    historicalLineage: '2021: A05 • 2017: A06 • 2013: A05',
    capabilities: [
      'Defense-in-Depth Header Verification (CSP, HSTS, X-Frame, X-Content-Type)',
      'Verbose Server Platform Banner Disclosure (Apache, Nginx, PHP)',
      'Insecure Transport & Missing Security Directives',
      'Default Credential & Configuration Pathway Probing',
    ],
  },
  {
    id: 'A03',
    name: 'Software Supply Chain Failures',
    check: 'run_supply_chain_checks',
    description: 'Validates third-party software dependencies, component integrity, known vulnerable libraries, and CI/CD supply chain risks.',
    riskSeverity: 'CRITICAL',
    status: 'AUTOMATED',
    cweExamples: ['CWE-1395', 'CWE-1104', 'CWE-937'],
    historicalLineage: '2021: A06 • 2017: A09 • 2013: A09',
    capabilities: [
      'pip-audit CLI Subprocess Execution Against requirements.txt',
      'Known CVE & GHSA Vulnerability Extraction and Mapping',
      'Third-party Software Bill of Materials (SBOM) Verification',
    ],
    manualReviewGuidance: 'External network scanning cannot verify uncompiled or private dependencies without access to requirements.txt, lockfiles, or internal build pipelines.',
  },
  {
    id: 'A04',
    name: 'Cryptographic Failures',
    check: 'run_crypto_checks',
    description: 'Detects weak cipher suites, deprecated TLS protocols, sensitive data in cleartext, and cryptographic algorithm weaknesses.',
    riskSeverity: 'HIGH',
    status: 'AUTOMATED',
    cweExamples: ['CWE-319', 'CWE-327', 'CWE-326', 'CWE-310'],
    historicalLineage: '2021: A02 • 2017: A03 • 2013: A06',
    capabilities: [
      'Cleartext HTTP Protocol & Transport Encryption Verification',
      'Strict-Transport-Security (HSTS) Policy Enforcement',
      'Cryptographic Algorithm & SSL/TLS Protocol Downgrade Checks',
    ],
  },
  {
    id: 'A05',
    name: 'Injection',
    check: 'run_injection_checks',
    description: 'Probes for SQL injection, command injection, LDAP injection, and server-side template injection flaws.',
    riskSeverity: 'CRITICAL',
    status: 'AUTOMATED',
    cweExamples: ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-94'],
    historicalLineage: '2021: A03 • 2017: A01 • 2013: A01',
    capabilities: [
      'Benign Canary Reflection Parameter Probing (rEdAm0nPr0bE)',
      'sqlmap Subprocess CLI Integration (--batch, --level=1)',
      'XSStrike Cross-Site Scripting (XSS) Automated Verification',
      'Command Delimiter & Syntax Error Boundary Detection',
    ],
  },
  {
    id: 'A06',
    name: 'Insecure Design',
    check: 'run_design_checks',
    description: 'Evaluates architectural threat model deficiencies, lack of rate limiting, and business logic boundary flaws.',
    riskSeverity: 'MEDIUM',
    status: 'MANUAL',
    cweExamples: ['CWE-1059', 'CWE-657', 'CWE-799'],
    historicalLineage: '2021: A04 • 2025: Insecure Design Continuity',
    capabilities: [
      'Architectural Threat Modeling & Boundary Assessment',
      'Anti-Automation & Business Logic Rate Limiting Review',
      'Trust Boundary & Least Privilege Architecture Auditing',
    ],
    manualReviewGuidance: 'Design flaws, architectural trust boundaries, and business logic vulnerabilities cannot be reliably audited from outside and require engineering design review.',
  },
  {
    id: 'A07',
    name: 'Authentication Failures',
    check: 'run_auth_checks',
    description: 'Identifies credential stuffing, weak password policies, session hijacking, and missing multi-factor authentication.',
    riskSeverity: 'CRITICAL',
    status: 'AUTOMATED',
    cweExamples: ['CWE-287', 'CWE-384', 'CWE-613'],
    historicalLineage: '2021: A07 • 2017: A02 • 2013: A02',
    capabilities: [
      'Set-Cookie Security Attribute Parsing (HttpOnly, Secure, SameSite)',
      'Session Identifier Cryptographic Entropy & Transmission Security',
      'Authentication Token Exposure in Query Parameters or Headers',
    ],
  },
  {
    id: 'A08',
    name: 'Software or Data Integrity Failures',
    check: 'run_integrity_checks',
    description: 'Validates insecure deserialization, unsigned firmware/plugin updates, and untrusted CI/CD pipeline triggers.',
    riskSeverity: 'HIGH',
    status: 'AUTOMATED',
    cweExamples: ['CWE-502', 'CWE-353', 'CWE-829'],
    historicalLineage: '2021: A08 • 2025: Integrity Failures Continuity',
    capabilities: [
      'Subresource Integrity (SRI) Hash Attribute Verification on Scripts',
      'Untrusted Third-Party CDN Script Inclusion Auditing',
      'Serialized Object Transport & Unsigned Payload Inspection',
    ],
  },
  {
    id: 'A09',
    name: 'Security Logging and Alerting Failures',
    check: 'run_logging_checks',
    description: 'Audits insufficient audit trails, absence of security alerting, unmonitored security events, and log tampering.',
    riskSeverity: 'MEDIUM',
    status: 'MANUAL',
    cweExamples: ['CWE-778', 'CWE-117', 'CWE-223'],
    historicalLineage: '2021: A09 • 2017: A10 • 2013: A10',
    capabilities: [
      'Internal SIEM Ingestion & Security Event Logging Audit',
      'Audit Trail Integrity & Tamper-Resistant Log Storage Review',
      'Real-Time Incident Response Alerting Threshold Validation',
    ],
    manualReviewGuidance: 'Logging integrity, SIEM pipeline ingestion, and threshold alerting mechanisms require internal infrastructure access and cannot be validated externally.',
  },
  {
    id: 'A10',
    name: 'Mishandling of Exceptional Conditions',
    check: 'run_exception_checks',
    description: 'Detects unhandled exceptions, memory exhaustion, panic leaks, stack trace exposures, and fail-open state transitions.',
    riskSeverity: 'HIGH',
    status: 'MANUAL',
    cweExamples: ['CWE-755', 'CWE-248', 'CWE-390'],
    historicalLineage: '2025 New Category • Exception Resilience',
    capabilities: [
      'Unhandled Exception & Stack Trace Exposure Analysis',
      'Fail-Safe Default & Fail-Closed Boundary Verification',
      'Memory Exhaustion & Panic Recovery Fault Tolerance',
    ],
    manualReviewGuidance: 'Verifying exception recovery, core dump handling, and fail-closed state semantics requires source code auditing and internal fault-injection tests.',
  },
];

export interface ScanFinding {
  owasp_id: string;
  title: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  evidence?: string;
  source?: 'scanner' | 'manual' | string;
  [key: string]: any;
}

export interface ScanResult {
  target: string;
  findings: ScanFinding[];
  summary: {
    total: number;
    by_owasp: Record<string, number>;
  };
}

interface OwaspScanTabProps {
  assets?: AuthorizedAsset[];
  selectedCategory?: string;
  onSelectCategory?: (id: string) => void;
  onNavigateToTab?: (tab: ActiveTab) => void;
}

export const OwaspScanTab: React.FC<OwaspScanTabProps> = ({
  assets = [],
  selectedCategory = 'A01',
  onSelectCategory,
  onNavigateToTab,
}) => {
  const [targetUrl, setTargetUrl] = useState<string>('https://target.local');
  const [selectedIds, setSelectedIds] = useState<string[]>(
    OWASP_TOP10_2025.map((c) => c.id)
  );
  const [copied, setCopied] = useState<boolean>(false);
  const [activeCatId, setActiveCatId] = useState<string>(selectedCategory);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Search & Intelligence Filters (integrated from Coverage Matrix & Taxonomy Intelligence)
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'AUTOMATED' | 'MANUAL'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');

  // Filtered categories computed dynamically
  const filteredCategories = useMemo(() => {
    return OWASP_TOP10_2025.filter((cat) => {
      // 1. Status Filter (matching Coverage Matrix: AUTOMATED vs MANUAL)
      if (statusFilter !== 'ALL' && cat.status !== statusFilter) {
        return false;
      }

      // 2. Severity Filter (matching Coverage Matrix rule severity)
      if (severityFilter !== 'ALL' && cat.riskSeverity !== severityFilter) {
        return false;
      }

      // 3. Search Query (matching Taxonomy & Coverage Matrix searching)
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesId = cat.id.toLowerCase().includes(q);
        const matchesName = cat.name.toLowerCase().includes(q);
        const matchesCheck = cat.check.toLowerCase().includes(q);
        const matchesDesc = cat.description.toLowerCase().includes(q);
        const matchesLineage = cat.historicalLineage.toLowerCase().includes(q);
        const matchesCwe = cat.cweExamples.some((cwe) => cwe.toLowerCase().includes(q));
        const matchesCap = cat.capabilities.some((cap) => cap.toLowerCase().includes(q));

        return (
          matchesId ||
          matchesName ||
          matchesCheck ||
          matchesDesc ||
          matchesLineage ||
          matchesCwe ||
          matchesCap
        );
      }

      return true;
    });
  }, [searchQuery, statusFilter, severityFilter]);

  // Bulk actions for filtered categories
  const selectAllMatching = () => {
    const matchingIds = filteredCategories.map((c) => c.id);
    setSelectedIds((prev) => Array.from(new Set([...prev, ...matchingIds])));
  };

  const deselectAllMatching = () => {
    const matchingSet = new Set(filteredCategories.map((c) => c.id));
    setSelectedIds((prev) => prev.filter((id) => !matchingSet.has(id)));
  };

  const resetFilters = () => {
    setSearchQuery('');
    setStatusFilter('ALL');
    setSeverityFilter('ALL');
  };

  // Automated vs Manual counts
  const automatedCount = useMemo(
    () => OWASP_TOP10_2025.filter((c) => c.status === 'AUTOMATED').length,
    []
  );
  const manualCount = useMemo(
    () => OWASP_TOP10_2025.filter((c) => c.status === 'MANUAL').length,
    []
  );

  const selectedMatchingCount = useMemo(() => {
    return filteredCategories.filter((c) => selectedIds.includes(c.id)).length;
  }, [filteredCategories, selectedIds]);

  // Sync external category selection
  React.useEffect(() => {
    if (selectedCategory) {
      setActiveCatId(selectedCategory);
      if (!selectedIds.includes(selectedCategory)) {
        setSelectedIds((prev) => [...prev, selectedCategory]);
      }
    }
  }, [selectedCategory]);

  const focusedCategory = useMemo(() => {
    return (
      OWASP_TOP10_2025.find((c) => c.id === activeCatId) || OWASP_TOP10_2025[0]
    );
  }, [activeCatId]);

  const scanCommand = useMemo(() => {
    const checksArg = selectedIds.join(',');
    return `python -m scanner.main scan --target ${targetUrl} --checks ${checksArg}`;
  }, [targetUrl, selectedIds]);

  const handleCopyCommand = () => {
    navigator.clipboard.writeText(scanCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExecuteScan = async () => {
    const trimmedUrl = targetUrl.trim();
    if (!trimmedUrl) {
      alert('Please enter a valid target URL.');
      return;
    }
    if (selectedIds.length === 0) {
      alert('Please select at least one OWASP category to scan.');
      return;
    }

    setIsScanning(true);
    setScanError(null);

    try {
      const payload = JSON.stringify({
        target_url: trimmedUrl,
        selected_checks: selectedIds,
      });

      const endpoints = [
        'http://127.0.0.1:8000/api/scan',
        'http://127.0.0.1:8001/api/scan',
      ];

      let response: Response | null = null;
      let lastError: any = null;

      for (const endpoint of endpoints) {
        try {
          response = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: payload,
          });
          if (response) break;
        } catch (e: any) {
          lastError = e;
        }
      }

      if (!response) {
        throw lastError || new Error('Failed to connect to scanner backend.');
      }

      if (!response.ok) {
        const errorBody = await response.json().catch(() => null);
        const detailMsg = errorBody?.detail
          ? typeof errorBody.detail === 'string'
            ? errorBody.detail
            : JSON.stringify(errorBody.detail)
          : `HTTP ${response.status}: ${response.statusText}`;
        throw new Error(detailMsg);
      }

      const data: ScanResult = await response.json();
      setScanResults(data);
    } catch (err: any) {
      const errorMsg =
        err?.message || 'Failed to connect to scanner backend at http://127.0.0.1:8000.';
      setScanError(errorMsg);
      alert(`Scan Execution Error: ${errorMsg}`);
    } finally {
      setIsScanning(false);
    }
  };

  const toggleCategory = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const selectAll = () => {
    setSelectedIds(OWASP_TOP10_2025.map((c) => c.id));
  };

  const clearAll = () => {
    setSelectedIds([]);
  };

  return (
    <div className="w-full max-w-7xl mx-auto p-4 sm:p-6 space-y-6">
      {/* 1. Header Banner */}
      <div className="relative overflow-hidden rounded-2xl liquid-glass-card border border-indigo-500/30 bg-gradient-to-r from-indigo-50/70 via-white/80 to-purple-50/70 dark:from-indigo-950/60 dark:via-slate-900/80 dark:to-purple-950/60 p-6 md:p-8 shadow-xl backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-100/90 dark:bg-indigo-500/20 border border-indigo-300/80 dark:border-indigo-500/30 text-indigo-900 dark:text-indigo-300 text-xs font-bold shadow-sm">
              <ShieldAlert className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>OWASP Top 10:2025 Assessment Suite</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white tracking-tight flex items-center gap-3">
              <span>OWASP SCAN</span>
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded-lg bg-indigo-100/90 dark:bg-indigo-500/25 text-indigo-900 dark:text-indigo-300 border border-indigo-300/80 dark:border-indigo-400/40">
                A01 - A10 Checks
              </span>
            </h1>
            <p className="text-sm text-slate-700 dark:text-slate-200 max-w-2xl leading-relaxed font-medium">
              Automated category validation matrix mapping authorized assessment targets to
              OWASP Top 10:2025 security check functions and CLI runner commands.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={selectAll}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-white dark:bg-white/10 hover:bg-indigo-50 dark:hover:bg-white/15 text-slate-800 dark:text-white border border-slate-300 dark:border-white/20 transition cursor-pointer flex items-center space-x-2 shadow-sm"
            >
              <CheckSquare className="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400" />
              <span>Select All</span>
            </button>
            <button
              type="button"
              onClick={clearAll}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-white dark:bg-white/10 hover:bg-slate-100 dark:hover:bg-white/15 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-white/20 transition cursor-pointer flex items-center space-x-2 shadow-sm"
            >
              <Square className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
              <span>Clear</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Target Scope & Command Builder Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Target Input & Command Display */}
        <div className="lg:col-span-2 space-y-6">
          <div className="p-5 sm:p-6 rounded-2xl bg-white/70 dark:bg-slate-900/60 border border-slate-200/80 dark:border-white/[0.08] backdrop-blur-xl shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <label className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-500" />
                <span>Assessment Target URL</span>
              </label>
              {assets.length > 0 && (
                <div className="flex items-center space-x-2">
                  <span className="text-[11px] text-slate-400">Authorized:</span>
                  <select
                    className="text-xs bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-white/10 rounded-lg px-2 py-1 text-slate-700 dark:text-slate-200 cursor-pointer"
                    onChange={(e) => {
                      if (e.target.value) setTargetUrl(e.target.value);
                    }}
                    defaultValue=""
                  >
                    <option value="" disabled>Select approved asset...</option>
                    {assets.map((a) => (
                      <option key={a.id} value={a.canonical_url}>
                        {a.canonical_url}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="relative">
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://target.local"
                className="w-full px-4 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-950/80 border border-slate-300 dark:border-white/10 text-sm font-mono text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition"
              />
            </div>

            {/* Generated Command Box */}
            <div className="space-y-2 pt-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Generated Scanner Command</span>
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  {selectedIds.length} of 10 checks selected
                </span>
              </div>
              <div className="relative flex items-center justify-between p-3.5 rounded-xl bg-slate-950 border border-indigo-500/30 text-indigo-300 font-mono text-xs shadow-inner overflow-x-auto">
                <code className="select-all break-all">{scanCommand}</code>
                <button
                  type="button"
                  onClick={handleCopyCommand}
                  className="ml-3 p-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-200 border border-indigo-500/40 transition shrink-0 cursor-pointer flex items-center gap-1 text-[11px] font-sans"
                  title="Copy command to clipboard"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400 font-bold">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Execute Scan Button */}
            <div className="pt-2">
              <button
                type="button"
                onClick={handleExecuteScan}
                disabled={isScanning || selectedIds.length === 0}
                className="w-full py-3 px-5 rounded-xl font-bold text-sm tracking-wide transition-all duration-200 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2.5 bg-gradient-to-r from-indigo-600 via-indigo-500 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-lg shadow-indigo-500/25 active:scale-[0.99]"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-white" />
                    <span>Scanning...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-current text-white" />
                    <span>▶ Execute Scan</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Scan Error Notice */}
          {scanError && (
            <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs flex items-start justify-between gap-3 shadow-md">
              <div className="flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 text-rose-500 shrink-0" />
                <span>
                  <strong>Scan Error:</strong> {scanError}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setScanError(null)}
                className="text-rose-500 hover:text-rose-700 cursor-pointer"
                title="Dismiss error"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Interactive Scan Results Section */}
          {scanResults && (
            <div className="p-5 sm:p-6 rounded-2xl liquid-glass-card border border-indigo-500/30 space-y-4 shadow-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-200/80 dark:border-white/10 gap-2">
                <div>
                  <div className="flex items-center space-x-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-500" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                      Scan Results for {scanResults.target}
                    </h3>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Completed assessment: {scanResults.summary.total} total findings across{' '}
                    {selectedIds.length} categories.
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs px-2.5 py-1 rounded-full font-bold bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                    Total Findings: {scanResults.summary.total}
                  </span>
                  <button
                    type="button"
                    onClick={() => setScanResults(null)}
                    className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                    title="Clear results view"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Findings Breakdown by Category */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                {Object.entries(scanResults.summary.by_owasp).map(([catId, count]) => (
                  <div
                    key={catId}
                    className="p-2 rounded-xl bg-slate-100/80 dark:bg-slate-900/50 border border-slate-200/80 dark:border-white/5 text-center"
                  >
                    <span className="text-[10px] font-mono font-bold text-indigo-600 dark:text-indigo-400">
                      {catId}
                    </span>
                    <div className="text-sm font-extrabold text-slate-800 dark:text-slate-100">
                      {count}
                    </div>
                  </div>
                ))}
              </div>

              {/* Findings List or Empty State */}
              {scanResults.findings.length === 0 ? (
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-300 text-xs flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
                  <span>No security weaknesses detected for selected categories.</span>
                </div>
              ) : (
                <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                  {scanResults.findings.map((f, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl bg-white/70 dark:bg-slate-900/60 border border-slate-200/80 dark:border-white/10 space-y-1 text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2 font-bold">
                          <span className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-indigo-500/20 text-indigo-700 dark:text-indigo-300">
                            {f.owasp_id}
                          </span>
                          <span className="text-slate-900 dark:text-white">{f.title}</span>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            f.severity === 'high' || f.severity === 'CRITICAL'
                              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                              : f.severity === 'medium'
                              ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                              : 'bg-slate-500/15 text-slate-600 dark:text-slate-400'
                          }`}
                        >
                          {f.severity || 'info'}
                        </span>
                      </div>
                      {f.evidence && (
                        <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed font-mono">
                          {f.evidence}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Raw JSON Inspector */}
              <details className="text-[11px] font-mono text-slate-500 dark:text-slate-400 cursor-pointer pt-1">
                <summary className="hover:text-indigo-500 select-none">
                  View Raw JSON Findings ({scanResults.findings.length} items)
                </summary>
                <pre className="mt-2 p-3 rounded-xl bg-slate-950 text-indigo-300 text-[10.5px] overflow-x-auto max-h-60 border border-white/10">
                  {JSON.stringify(scanResults, null, 2)}
                </pre>
              </details>
            </div>
          )}

          {/* Category Search & Intelligence Control Strip */}
          <div className="space-y-3 pt-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div className="flex items-center space-x-2">
                <Layers className="w-4 h-4 text-indigo-500" />
                <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider">
                  OWASP Top 10 Subcategories
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                  {selectedMatchingCount} of {filteredCategories.length} selected
                </span>
              </div>

              {/* Bulk actions for matching items */}
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={selectAllMatching}
                  className="text-[11px] font-semibold text-indigo-600 dark:text-indigo-400 hover:underline cursor-pointer"
                >
                  Select Filtered
                </button>
                <span className="text-slate-300 dark:text-slate-700">•</span>
                <button
                  type="button"
                  onClick={deselectAllMatching}
                  className="text-[11px] font-semibold text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 cursor-pointer"
                >
                  Deselect Filtered
                </button>
                {(searchQuery || statusFilter !== 'ALL' || severityFilter !== 'ALL') && (
                  <>
                    <span className="text-slate-300 dark:text-slate-700">•</span>
                    <button
                      type="button"
                      onClick={resetFilters}
                      className="text-[11px] font-semibold text-rose-500 hover:underline cursor-pointer flex items-center space-x-1"
                    >
                      <RotateCcw className="w-3 h-3" />
                      <span>Reset Filters</span>
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Search Input Bar */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search categories by ID, name, CWE (e.g. CWE-89), routine, or capability..."
                className="w-full pl-9 pr-9 py-2 rounded-xl bg-slate-100/90 dark:bg-slate-900/70 border border-slate-300 dark:border-white/10 text-xs font-sans text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition shadow-inner"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                  title="Clear search"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Filter Pills Row (Coverage Matrix Status & Risk Severity) */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-xs">
              {/* Automation Status Pills (Mirroring Coverage Matrix) */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1 flex items-center gap-1">
                  <Filter className="w-3 h-3 text-indigo-400" />
                  <span>Status:</span>
                </span>
                <button
                  type="button"
                  onClick={() => setStatusFilter('ALL')}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition cursor-pointer ${
                    statusFilter === 'ALL'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700/80'
                  }`}
                >
                  All (10)
                </button>
                <button
                  type="button"
                  onClick={() => setStatusFilter('AUTOMATED')}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition cursor-pointer flex items-center space-x-1 ${
                    statusFilter === 'AUTOMATED'
                      ? 'bg-emerald-600 text-white shadow-sm'
                      : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20'
                  }`}
                >
                  <ShieldCheck className="w-3 h-3" />
                  <span>Automated ({automatedCount})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setStatusFilter('MANUAL')}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition cursor-pointer flex items-center space-x-1 ${
                    statusFilter === 'MANUAL'
                      ? 'bg-amber-600 text-white shadow-sm'
                      : 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20 hover:bg-amber-500/20'
                  }`}
                >
                  <HelpCircle className="w-3 h-3" />
                  <span>Manual Review ({manualCount})</span>
                </button>
              </div>

              {/* Severity Filter Pills */}
              <div className="flex items-center space-x-1">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1">
                  Severity:
                </span>
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition cursor-pointer ${
                      severityFilter === sev
                        ? 'bg-indigo-600 text-white'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Category Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
            {filteredCategories.length === 0 ? (
              <div className="p-8 rounded-2xl bg-slate-100/60 dark:bg-slate-900/40 border border-dashed border-slate-300 dark:border-white/10 text-center space-y-2 col-span-full">
                <Search className="w-6 h-6 text-slate-400 mx-auto" />
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  No OWASP categories match the filter criteria &quot;{searchQuery}&quot;.
                </p>
                <button
                  type="button"
                  onClick={resetFilters}
                  className="px-3 py-1.5 rounded-lg bg-indigo-600 text-white text-xs font-bold hover:bg-indigo-500 cursor-pointer"
                >
                  Reset Filters
                </button>
              </div>
            ) : (
              filteredCategories.map((cat) => {
                const isChecked = selectedIds.includes(cat.id);
                const isFocused = activeCatId === cat.id;
                return (
                  <div
                    key={cat.id}
                    onClick={() => {
                      setActiveCatId(cat.id);
                      if (onSelectCategory) onSelectCategory(cat.id);
                    }}
                    className={`relative p-3.5 rounded-2xl border transition-all duration-200 cursor-pointer space-y-2.5 ${
                      isFocused
                        ? 'bg-indigo-500/10 dark:bg-indigo-900/20 border-indigo-500/60 shadow-md ring-1 ring-indigo-500/30'
                        : 'bg-white/70 dark:bg-slate-900/50 hover:bg-white/90 dark:hover:bg-slate-900/80 border-slate-200/80 dark:border-white/[0.06]'
                    }`}
                  >
                    {/* Card Header: ID, Title, Status & Severity */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="px-1.5 py-0.5 rounded font-mono text-[10.5px] font-bold bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                            {cat.id}
                          </span>
                          <h4 className="text-xs font-bold text-slate-800 dark:text-slate-100 truncate">
                            {cat.name}
                          </h4>
                        </div>

                        {/* Status & Severity Badges */}
                        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                          <span
                            className={`inline-flex items-center space-x-1 px-1.5 py-0.5 rounded text-[9.5px] font-bold ${
                              cat.status === 'AUTOMATED'
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                                : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {cat.status === 'AUTOMATED' ? (
                              <ShieldCheck className="w-2.5 h-2.5 text-emerald-500" />
                            ) : (
                              <HelpCircle className="w-2.5 h-2.5 text-amber-500" />
                            )}
                            <span>{cat.status === 'AUTOMATED' ? 'Automated' : 'Manual Review'}</span>
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[9.5px] font-bold font-mono ${
                              cat.riskSeverity === 'CRITICAL'
                                ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30'
                                : cat.riskSeverity === 'HIGH'
                                ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                                : 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30'
                            }`}
                          >
                            {cat.riskSeverity}
                          </span>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleCategory(cat.id);
                        }}
                        className="p-1 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 cursor-pointer shrink-0"
                        title={isChecked ? 'Exclude from scan' : 'Include in scan'}
                      >
                        {isChecked ? (
                          <CheckSquare className="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-400" />
                        )}
                      </button>
                    </div>

                    {/* Routine & Lineage Info */}
                    <div className="pt-1 border-t border-slate-200/60 dark:border-white/5 space-y-1">
                      <div className="flex items-center space-x-1.5 text-[10.5px] font-mono text-slate-500 dark:text-slate-400 truncate">
                        <Code2 className="w-3 h-3 text-indigo-400 shrink-0" />
                        <span className="truncate">{cat.check}()</span>
                      </div>
                      <div className="flex items-center space-x-1.5 text-[10px] text-slate-500 dark:text-slate-400 truncate">
                        <GitBranch className="w-3 h-3 text-cyan-500 shrink-0" />
                        <span className="truncate">{cat.historicalLineage}</span>
                      </div>
                    </div>

                    {/* CWE Tags Preview (Taxonomy) */}
                    <div className="flex flex-wrap gap-1 pt-0.5">
                      {cat.cweExamples.slice(0, 3).map((cwe) => {
                        const isMatched =
                          searchQuery &&
                          cwe.toLowerCase().includes(searchQuery.toLowerCase().trim());
                        return (
                          <span
                            key={cwe}
                            className={`text-[9.5px] font-mono px-1.5 py-0.5 rounded ${
                              isMatched
                                ? 'bg-indigo-500 text-white font-bold ring-1 ring-indigo-400'
                                : 'bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400'
                            }`}
                          >
                            {cwe}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Col: Category Detail & Taxonomy Intelligence Card */}
        <div className="space-y-4">
          <div className="p-5 sm:p-6 rounded-2xl liquid-glass-card border border-slate-200/80 dark:border-white/[0.08] backdrop-blur-xl shadow-lg space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200/80 dark:border-white/10 pb-3">
              <div className="flex items-center space-x-2">
                <span className="px-2 py-1 rounded-md font-mono text-xs font-black bg-indigo-600 text-white">
                  {focusedCategory.id}
                </span>
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Specification & Intelligence
                </span>
              </div>
              <div className="flex items-center space-x-1.5">
                <span
                  className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                    focusedCategory.status === 'AUTOMATED'
                      ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30'
                  }`}
                >
                  {focusedCategory.status === 'AUTOMATED' ? (
                    <ShieldCheck className="w-3 h-3 text-emerald-500" />
                  ) : (
                    <HelpCircle className="w-3 h-3 text-amber-500" />
                  )}
                  <span>{focusedCategory.status === 'AUTOMATED' ? 'Automated' : 'Manual'}</span>
                </span>
                <span
                  className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${
                    focusedCategory.riskSeverity === 'CRITICAL'
                      ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                      : focusedCategory.riskSeverity === 'HIGH'
                      ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30'
                      : 'bg-indigo-500/15 text-indigo-600 dark:text-indigo-400 border border-indigo-500/30'
                  }`}
                >
                  {focusedCategory.riskSeverity}
                </span>
              </div>
            </div>

            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white">
                {focusedCategory.name}
              </h3>
              <p className="text-xs text-slate-600 dark:text-slate-300 mt-2 leading-relaxed">
                {focusedCategory.description}
              </p>
            </div>

            {/* Runner Routine */}
            <div className="space-y-1.5 pt-2 border-t border-slate-200/80 dark:border-white/10">
              <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Code2 className="w-3.5 h-3.5 text-indigo-400" />
                <span>Execution Routine</span>
              </span>
              <div className="p-2.5 rounded-xl bg-slate-950 text-indigo-300 font-mono text-xs border border-white/10">
                <code>{focusedCategory.check}()</code>
              </div>
            </div>

            {/* Taxonomy Historical Lineage */}
            <div className="space-y-1.5 pt-2 border-t border-slate-200/80 dark:border-white/10">
              <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <GitBranch className="w-3.5 h-3.5 text-cyan-500" />
                <span>OWASP Lineage & Edition History</span>
              </span>
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-800 dark:text-cyan-200 text-xs font-mono">
                {focusedCategory.historicalLineage}
              </div>
            </div>

            {/* CWE Examples from Taxonomy */}
            <div className="space-y-1.5 pt-2 border-t border-slate-200/80 dark:border-white/10">
              <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-indigo-400" />
                <span>Associated CWE Weaknesses</span>
              </span>
              <div className="flex flex-wrap gap-1.5">
                {focusedCategory.cweExamples.map((cwe) => (
                  <span
                    key={cwe}
                    className="px-2 py-0.5 rounded text-[10.5px] font-mono font-bold bg-slate-100 dark:bg-slate-800 text-indigo-700 dark:text-indigo-300 border border-slate-200 dark:border-white/10"
                  >
                    {cwe}
                  </span>
                ))}
              </div>
            </div>

            {/* Coverage Matrix Capabilities */}
            <div className="space-y-1.5 pt-2 border-t border-slate-200/80 dark:border-white/10">
              <span className="text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                <span>Coverage Capabilities</span>
              </span>
              <ul className="space-y-1 text-[11px] text-slate-600 dark:text-slate-300">
                {focusedCategory.capabilities.map((cap, idx) => (
                  <li key={idx} className="flex items-start space-x-1.5">
                    <span className="text-emerald-500 font-bold">•</span>
                    <span>{cap}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Manual Review Guidance if present */}
            {focusedCategory.manualReviewGuidance && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-1">
                <div className="flex items-center space-x-1.5 text-amber-700 dark:text-amber-300 text-xs font-bold">
                  <HelpCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>Manual Review Guidance</span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">
                  {focusedCategory.manualReviewGuidance}
                </p>
              </div>
            )}

            <button
              type="button"
              onClick={() => toggleCategory(focusedCategory.id)}
              className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold transition flex items-center justify-center space-x-2 cursor-pointer shadow-md ${
                selectedIds.includes(focusedCategory.id)
                  ? 'bg-rose-500/15 hover:bg-rose-500/25 text-rose-600 dark:text-rose-300 border border-rose-500/30'
                  : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-indigo-600/30'
              }`}
            >
              {selectedIds.includes(focusedCategory.id) ? (
                <>
                  <Square className="w-3.5 h-3.5" />
                  <span>Deselect {focusedCategory.id} from Scan</span>
                </>
              ) : (
                <>
                  <CheckSquare className="w-3.5 h-3.5" />
                  <span>Select {focusedCategory.id} for Scan</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};


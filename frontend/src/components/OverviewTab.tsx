import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  Activity,
  ArrowUpRight,
  AlertTriangle,
  CheckCircle2,
  CheckCircle,
  Filter,
  ArrowDownUp,
  Layers,
  Sparkles,
  TrendingUp,
  TrendingDown,
  Clock,
  Terminal,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  Line,
  ReferenceLine,
} from 'recharts';
import type { Finding, ScanJob, AuthorizedAsset, SeverityLevel } from '../types/api';
import { formatDateTimeShort, formatRelativeTime } from '../utils/formatters';

interface OverviewTabProps {
  assets: AuthorizedAsset[];
  scans: ScanJob[];
  findings: Finding[];
  onSelectTarget: (targetId: string) => void;
  onNavigateToTab: (tab: any) => void;
}

interface CategoryDefinition {
  code: string;
  shortCode: string;
  title: string;
  description: string;
}

// Authoritative OWASP Top 10 Taxonomy Definitions for 2025, 2021, and 2017
const OWASP_EDITION_CATALOG: Record<string, CategoryDefinition[]> = {
  '2025': [
    { code: 'A01:2025', shortCode: 'A01', title: 'Broken Access Control', description: 'SSRF, IDOR, authorization bypass, and missing functional access boundaries.' },
    { code: 'A02:2025', shortCode: 'A02', title: 'Security Misconfiguration', description: 'Missing defensive HTTP headers, permissive CORS, open cloud storage, and unhardened services.' },
    { code: 'A03:2025', shortCode: 'A03', title: 'Software Supply Chain Failures', description: 'Compromised third-party packages, dependency vulnerabilities, and CI/CD build chain tampering.' },
    { code: 'A04:2025', shortCode: 'A04', title: 'Cryptographic Failures', description: 'Inadequate transport encryption (TLS/SSL), weak ciphers, cleartext transmission, and sensitive data leakage.' },
    { code: 'A05:2025', shortCode: 'A05', title: 'Injection', description: 'Cross-Site Scripting (XSS), SQLi, command injection, and unsanitized untrusted inputs.' },
    { code: 'A06:2025', shortCode: 'A06', title: 'Insecure Design', description: 'Architectural omissions, missing anti-automation rate limits, and lack of threat modeling defense.' },
    { code: 'A07:2025', shortCode: 'A07', title: 'Authentication Failures', description: 'Session fixation, missing cookie HttpOnly/Secure flags, credential stuffing, and weak session timeouts.' },
    { code: 'A08:2025', shortCode: 'A08', title: 'Software or Data Integrity Failures', description: 'Missing Subresource Integrity (SRI) hashes, untrusted deserialization, and unverified software updates.' },
    { code: 'A09:2025', shortCode: 'A09', title: 'Security Logging and Alerting Failures', description: 'Missing distributed request correlation IDs, absent audit trails, and insufficient intrusion alerting.' },
    { code: 'A10:2025', shortCode: 'A10', title: 'Mishandling of Exceptional Conditions', description: 'Unhandled exceptions, verbose debugging stack traces, and fail-open state transitions.' },
  ],
  '2021': [
    { code: 'A01:2021', shortCode: 'A01', title: 'Broken Access Control', description: 'Bypassing access controls, acting as unintended users, or unauthorized metadata access.' },
    { code: 'A02:2021', shortCode: 'A02', title: 'Cryptographic Failures', description: 'Exposure of sensitive data due to weak transport cryptography or insecure cipher suites.' },
    { code: 'A03:2021', shortCode: 'A03', title: 'Injection', description: 'SQL, NoSQL, OS command injection, and Cross-Site Scripting (XSS).' },
    { code: 'A04:2021', shortCode: 'A04', title: 'Insecure Design', description: 'Risks related to design and architectural flaws, lack of rate limiting and business logic defense.' },
    { code: 'A05:2021', shortCode: 'A05', title: 'Security Misconfiguration', description: 'Default accounts, missing security headers, verbose error messages, and misconfigured permissions.' },
    { code: 'A06:2021', shortCode: 'A06', title: 'Vulnerable and Outdated Components', description: 'Operating with unsupported, unpatched, or known vulnerable software modules.' },
    { code: 'A07:2021', shortCode: 'A07', title: 'Identification and Authentication Failures', description: 'Authentication bypass, session hijacking, credential stuffing, and cookie security flag omissions.' },
    { code: 'A08:2021', shortCode: 'A08', title: 'Software and Data Integrity Failures', description: 'Insecure deserialization, unverified script inclusions, and unsigned software updates.' },
    { code: 'A09:2021', shortCode: 'A09', title: 'Security Logging and Monitoring Failures', description: 'Insufficient audit logging, unmonitored security events, and delayed incident detection.' },
    { code: 'A10:2021', shortCode: 'A10', title: 'Server-Side Request Forgery (SSRF)', description: 'Fetching remote resources without validating user-supplied destinations.' },
  ],
  '2017': [
    { code: 'A01:2017', shortCode: 'A01', title: 'Injection', description: 'SQL, NoSQL, OS command injection, and untrusted data interpreters.' },
    { code: 'A02:2017', shortCode: 'A02', title: 'Broken Authentication', description: 'Compromised passwords, session tokens, or keys allowing identity assumption.' },
    { code: 'A03:2017', shortCode: 'A03', title: 'Sensitive Data Exposure', description: 'Inadequate protection of financial, healthcare, or PII transport data.' },
    { code: 'A04:2017', shortCode: 'A04', title: 'XML External Entities (XXE)', description: 'Weakly configured XML processors parsing external entity references.' },
    { code: 'A05:2017', shortCode: 'A05', title: 'Broken Access Control', description: 'Improperly enforced restrictions on authenticated users.' },
    { code: 'A06:2017', shortCode: 'A06', title: 'Security Misconfiguration', description: 'Incomplete or ad-hoc configurations, unpatched flaws, default settings.' },
    { code: 'A07:2017', shortCode: 'A07', title: 'Cross-Site Scripting (XSS)', description: 'Execution of malicious scripts in the victim browser.' },
    { code: 'A08:2017', shortCode: 'A08', title: 'Insecure Deserialization', description: 'Tampering with serialized objects leading to remote code execution.' },
    { code: 'A09:2017', shortCode: 'A09', title: 'Using Components with Known Vulnerabilities', description: 'Libraries with known security vulnerabilities.' },
    { code: 'A10:2017', shortCode: 'A10', title: 'Insufficient Logging & Monitoring', description: 'Lack of telemetry preventing detection of active breaches.' },
  ],
};

const normalizeCategoryCode = (code: string): string => {
  return code.replace(/^A(\d):/, 'A0$1:');
};

const SEVERITY_CONFIG: Record<
  SeverityLevel,
  { label: string; color: string; gradientId: string; glow: string; textClass: string; bgClass: string; borderClass: string }
> = {
  CRITICAL: {
    label: 'Critical',
    color: '#f43f5e',
    gradientId: 'roseBarGradient',
    glow: 'rgba(244, 63, 94, 0.5)',
    textClass: 'text-rose-400',
    bgClass: 'bg-rose-500/15',
    borderClass: 'border-rose-500/30',
  },
  HIGH: {
    label: 'High',
    color: '#f97316',
    gradientId: 'orangeBarGradient',
    glow: 'rgba(249, 115, 22, 0.5)',
    textClass: 'text-orange-400',
    bgClass: 'bg-orange-500/15',
    borderClass: 'border-orange-500/30',
  },
  MEDIUM: {
    label: 'Medium',
    color: '#eab308',
    gradientId: 'amberBarGradient',
    glow: 'rgba(234, 179, 8, 0.5)',
    textClass: 'text-amber-300',
    bgClass: 'bg-amber-500/15',
    borderClass: 'border-amber-500/30',
  },
  LOW: {
    label: 'Low',
    color: '#06b6d4',
    gradientId: 'cyanBarGradient',
    glow: 'rgba(6, 182, 212, 0.5)',
    textClass: 'text-cyan-300',
    bgClass: 'bg-cyan-500/15',
    borderClass: 'border-cyan-500/30',
  },
  INFO: {
    label: 'Info',
    color: '#94a3b8',
    gradientId: 'indigoBarGradient',
    glow: 'rgba(148, 163, 184, 0.5)',
    textClass: 'text-slate-300',
    bgClass: 'bg-slate-500/15',
    borderClass: 'border-slate-500/30',
  },
};

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const OverviewTab: React.FC<OverviewTabProps> = ({
  assets,
  scans,
  findings,
  onSelectTarget,
  onNavigateToTab,
}) => {
  // Aggregate KPI stats
  const totalScans = scans.length;
  const totalAssets = assets.length;
  const activeFindings = useMemo(() => {
    return findings.filter((f) => f.validation_status === 'CONFIRMED' || f.validation_status === 'POTENTIAL');
  }, [findings]);

  // Exact severity counts
  const severityCounts = useMemo(() => {
    return {
      CRITICAL: activeFindings.filter((f) => f.severity === 'CRITICAL').length,
      HIGH: activeFindings.filter((f) => f.severity === 'HIGH').length,
      MEDIUM: activeFindings.filter((f) => f.severity === 'MEDIUM').length,
      LOW: activeFindings.filter((f) => f.severity === 'LOW').length,
      INFO: activeFindings.filter((f) => f.severity === 'INFO').length,
    };
  }, [activeFindings]);

  // Overall risk rating based on highest present active severity
  const overallRiskBadge = useMemo(() => {
    if (severityCounts.CRITICAL > 0) return { label: 'CRITICAL RISK', color: 'rose', bg: 'bg-rose-500/20 text-rose-300 border-rose-500/30' };
    if (severityCounts.HIGH > 0) return { label: 'HIGH RISK', color: 'orange', bg: 'bg-orange-500/20 text-orange-300 border-orange-500/30' };
    if (severityCounts.MEDIUM > 0) return { label: 'MODERATE RISK', color: 'amber', bg: 'bg-amber-500/20 text-amber-300 border-amber-500/30' };
    if (severityCounts.LOW > 0) return { label: 'LOW RISK', color: 'cyan', bg: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30' };
    return { label: 'CLEAN POSTURE', color: 'emerald', bg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' };
  }, [severityCounts]);

  // Severity Distribution Data for PieChart (non-zero slices for donut rendering)
  const severityPieData = useMemo(() => {
    return SEVERITY_ORDER.map((level) => {
      const cfg = SEVERITY_CONFIG[level];
      const count = severityCounts[level];
      return {
        name: cfg.label,
        key: level,
        value: count,
        color: cfg.color,
        glow: cfg.glow,
        config: cfg,
      };
    }).filter((d) => d.value > 0);
  }, [severityCounts]);

  // Hovered slice state for interactive center metric
  const [hoveredSeverity, setHoveredSeverity] = useState<{
    name: string;
    key: SeverityLevel;
    value: number;
    color: string;
  } | null>(null);

  // Edition selector for OWASP Top 10 Category distribution
  const [selectedEdition, setSelectedEdition] = useState<string>('2025');
  const [sortMode, setSortMode] = useState<'ranked' | 'canonical'>('ranked');
  const [filterMode, setFilterMode] = useState<'all' | 'flagged'>('all');

  // Aggregated OWASP Category Analytics for selected edition
  const categoryAnalytics = useMemo(() => {
    const catalog = OWASP_EDITION_CATALOG[selectedEdition] || OWASP_EDITION_CATALOG['2025'];

    // Map each catalog code to aggregated metrics
    const catMap = new Map<
      string,
      {
        def: CategoryDefinition;
        count: number;
        targetsAffected: Set<string>;
        severities: Record<SeverityLevel, number>;
        findings: Finding[];
      }
    >();

    catalog.forEach((def) => {
      catMap.set(def.code, {
        def,
        count: 0,
        targetsAffected: new Set<string>(),
        severities: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        findings: [],
      });
    });

    // Populate counts and severities from active findings
    activeFindings.forEach((f) => {
      const mappings = f.category_mappings || [];
      const matched = mappings.filter((m) => {
        const ed = m.edition_identifier || m.owasp_edition;
        return ed === selectedEdition;
      });

      matched.forEach((m) => {
        const rawCode = m.category_identifier || m.owasp_category_code || '';
        const normalized = normalizeCategoryCode(rawCode);

        let target = catMap.get(rawCode) || catMap.get(normalized);
        if (!target) {
          const prefix = rawCode.split(':')[0].replace(/^A(\d)$/, 'A0$1');
          for (const [codeKey, catObj] of catMap.entries()) {
            if (codeKey.startsWith(prefix)) {
              target = catObj;
              break;
            }
          }
        }

        if (target) {
          target.count += 1;
          if (f.target_id) target.targetsAffected.add(f.target_id);
          const sev = (f.severity?.toUpperCase() || 'INFO') as SeverityLevel;
          if (target.severities[sev] !== undefined) {
            target.severities[sev] += 1;
          }
          target.findings.push(f);
        }
      });
    });

    let list = Array.from(catMap.values()).map((entry) => {
      const { def, count, targetsAffected, severities } = entry;
      // Determine dominant severity for gradient coloring
      let dominantSeverity: SeverityLevel = 'INFO';
      for (const s of SEVERITY_ORDER) {
        if (severities[s] > 0) {
          dominantSeverity = s;
          break;
        }
      }

      return {
        categoryCode: def.code,
        shortCode: def.shortCode,
        title: def.title,
        description: def.description,
        findings: count,
        targetsCount: targetsAffected.size,
        severities,
        dominantSeverity,
        gradientId: count > 0 ? SEVERITY_CONFIG[dominantSeverity].gradientId : 'cleanBarGradient',
        barColor: count > 0 ? SEVERITY_CONFIG[dominantSeverity].color : '#10b981',
        percentage: activeFindings.length > 0 ? Math.round((count / activeFindings.length) * 1000) / 10 : 0,
      };
    });

    if (filterMode === 'flagged') {
      list = list.filter((item) => item.findings > 0);
    }

    if (sortMode === 'ranked') {
      list.sort((a, b) => b.findings - a.findings);
    } else {
      // Canonical order A01 -> A10
      list.sort((a, b) => a.shortCode.localeCompare(b.shortCode));
    }

    return list;
  }, [activeFindings, selectedEdition, sortMode, filterMode]);

  // Category counts summary
  const flaggedCategoriesCount = useMemo(() => {
    return categoryAnalytics.filter((c) => c.findings > 0).length;
  }, [categoryAnalytics]);

  const cleanCategoriesCount = useMemo(() => {
    const catalog = OWASP_EDITION_CATALOG[selectedEdition] || [];
    return Math.max(0, catalog.length - flaggedCategoriesCount);
  }, [selectedEdition, flaggedCategoriesCount]);

  // Target filter & view mode state for Assessment Posture Trend
  const [trendTargetId, setTrendTargetId] = useState<string>('');
  const [trendViewMode, setTrendViewMode] = useState<'compliance' | 'volume'>('compliance');

  // Chronologically ordered completed scans filtered by target
  const timelineData = useMemo(() => {
    let filtered = scans.filter((s) => s.status === 'COMPLETED');
    if (trendTargetId) {
      filtered = filtered.filter((s) => {
        const aId = (s as any).target_id || s.asset_id;
        return aId === trendTargetId;
      });
    }

    // Sort chronologically ascending (oldest to latest)
    const sorted = [...filtered].sort(
      (a, b) =>
        new Date(a.started_at || a.created_at || 0).getTime() -
        new Date(b.started_at || b.created_at || 0).getTime()
    );

    // Keep the most recent 10 assessment runs
    const slice = sorted.slice(-10);

    return slice.map((s, idx) => {
      const assetId = (s as any).target_id || s.asset_id;
      const targetAsset = assets.find((a) => a.id === assetId);
      const targetUrl =
        targetAsset?.canonical_url ||
        s.scan_metadata?.target_url ||
        (assetId ? `Target ${assetId.slice(0, 8)}` : 'Target');

      const totalChecks = s.total_checks || 14;
      const passed = s.passed_checks ?? Math.max(0, totalChecks - (s.failed_checks || 0));
      const failed = s.failed_checks ?? Math.max(0, totalChecks - passed);
      // Accurate findings count (using observations_count or failed_checks)
      const findingsCount = (s.observations_count !== undefined && s.observations_count > 0)
        ? s.observations_count
        : failed;
      const complianceRate = Math.round((passed / (totalChecks || 1)) * 100);

      const d = new Date(s.started_at || s.created_at || Date.now());
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const dateLabel = `${monthNames[d.getMonth()]} ${d.getDate()}`;
      const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      // Calculate execution duration if available
      let durationStr = '';
      if (s.scan_metadata?.deep_scan_metrics?.execution_time_seconds) {
        durationStr = `${s.scan_metadata.deep_scan_metrics.execution_time_seconds}s`;
      } else if (s.started_at && s.completed_at) {
        const diffMs = new Date(s.completed_at).getTime() - new Date(s.started_at).getTime();
        if (diffMs > 0) {
          durationStr = `${(diffMs / 1000).toFixed(1)}s`;
        }
      }

      return {
        id: s.id,
        runLabel: `Run #${idx + 1}`,
        axisLabel: `${dateLabel} #${idx + 1}`,
        dateLabel,
        timeStr,
        fullDate: d.toLocaleString([], {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        }),
        target: targetUrl,
        passed,
        failed,
        total: totalChecks,
        findingsCount,
        complianceRate,
        durationStr,
      };
    });
  }, [scans, assets, trendTargetId]);

  // Latest timeline summary point for quick posture metrics
  const latestTimelinePoint = timelineData.length > 0 ? timelineData[timelineData.length - 1] : null;
  const avgCompliance = timelineData.length > 0
    ? Math.round(timelineData.reduce((acc, curr) => acc + curr.complianceRate, 0) / timelineData.length)
    : 0;

  // Recent scans sorted strictly chronologically descending for the activity table
  const sortedRecentScans = useMemo(() => {
    return [...scans]
      .sort(
        (a, b) =>
          new Date(b.started_at || b.created_at || 0).getTime() -
          new Date(a.started_at || a.created_at || 0).getTime()
      )
      .slice(0, 6);
  }, [scans]);

  return (
    <div className="space-y-7">
      {/* Welcome & Quick Action Banner */}
      <div className="liquid-glass-card rounded-3xl p-7 flex flex-col md:flex-row items-start md:items-center justify-between gap-5 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-gradient-to-br from-indigo-500/10 via-cyan-500/10 to-transparent rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10">
          <div className="flex items-center space-x-2 text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1.5">
            <ShieldCheck className="w-4 h-4 drop-shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            <span>Autonomous Web Security Sentinel</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight bg-gradient-to-r from-white via-slate-100 to-indigo-200 bg-clip-text text-transparent">
            OWASP Security Posture Dashboard
          </h1>
          <p className="text-slate-400 text-xs sm:text-sm mt-1.5 max-w-2xl leading-relaxed">
            Continuous empirical assessment, multi-edition OWASP Top 10 intelligence mapping, non-destructive automated checks,
            and high-precision vulnerability telemetry.
          </p>
        </div>
        <div className="flex space-x-3 shrink-0 relative z-10">
          <button
            onClick={() => onNavigateToTab('targets')}
            className="px-5 py-2.5 liquid-glass-btn-primary text-white rounded-xl text-xs font-bold transition flex items-center space-x-2 cursor-pointer shadow-lg shadow-indigo-600/30"
          >
            <Activity className="w-4 h-4" />
            <span>Assess Target</span>
          </button>
          <button
            onClick={() => onNavigateToTab('coverage')}
            className="px-4 py-2.5 liquid-glass-btn-secondary text-slate-200 rounded-xl text-xs font-semibold transition flex items-center space-x-2 cursor-pointer"
          >
            <Layers className="w-4 h-4 text-cyan-400" />
            <span>Coverage Matrix</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4.5">
        {/* Monitored Assets */}
        <div
          onClick={() => onNavigateToTab('targets')}
          className="liquid-glass-card liquid-glass-card-interactive rounded-2xl p-5 shadow-lg cursor-pointer group hover:border-indigo-500/40 hover:shadow-indigo-500/15 transition select-none"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigateToTab('targets');
            }
          }}
          title="Click to view Authorized Target Inventory"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider group-hover:text-indigo-300 transition flex items-center gap-1.5">
              <span>Authorized Targets</span>
              <ArrowUpRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition duration-200 text-indigo-400" />
            </span>
            <div className="p-2.5 bg-indigo-500/15 rounded-xl text-indigo-400 border border-indigo-500/20 shadow-[0_0_12px_rgba(99,102,241,0.2)] group-hover:scale-110 group-hover:bg-indigo-500/25 transition">
              <Globe className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3.5 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight group-hover:text-indigo-600 dark:group-hover:text-indigo-200 transition">
              {totalAssets}
            </span>
            <span className="text-xs text-indigo-400 font-semibold px-2 py-0.5 rounded-full liquid-glass-pill group-hover:bg-indigo-500/25 group-hover:border-indigo-500/40 group-hover:text-indigo-200 transition flex items-center space-x-1">
              <span>Inventory</span>
              <ArrowUpRight className="w-3 h-3 inline-block" />
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2 group-hover:text-slate-400 transition flex items-center justify-between">
            <span>Explicitly scoped & cleared domains/IPs</span>
            <span className="text-indigo-400 text-[11px] font-semibold opacity-0 group-hover:opacity-100 transition">
              View &rarr;
            </span>
          </p>
        </div>

        {/* Total Scans Executed */}
        <div
          onClick={() => onNavigateToTab('targets')}
          className="liquid-glass-card liquid-glass-card-interactive rounded-2xl p-5 shadow-lg cursor-pointer group hover:border-cyan-500/40 hover:shadow-cyan-500/15 transition select-none"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigateToTab('targets');
            }
          }}
          title="Click to view assessment history and launch scans"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider group-hover:text-cyan-300 transition flex items-center gap-1.5">
              <span>Assessments Run</span>
              <ArrowUpRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition duration-200 text-cyan-400" />
            </span>
            <div className="p-2.5 bg-cyan-500/15 rounded-xl text-cyan-400 border border-cyan-500/20 shadow-[0_0_12px_rgba(6,182,212,0.2)] group-hover:scale-110 group-hover:bg-cyan-500/25 transition">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3.5 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight group-hover:text-cyan-600 dark:group-hover:text-cyan-200 transition">
              {totalScans}
            </span>
            <span className="text-xs text-cyan-400 font-semibold px-2 py-0.5 rounded-full liquid-glass-pill group-hover:bg-cyan-500/25 group-hover:border-cyan-500/40 group-hover:text-cyan-200 transition flex items-center space-x-1">
              <span>Completed</span>
              <ArrowUpRight className="w-3 h-3 inline-block" />
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-2 group-hover:text-slate-400 transition flex items-center justify-between">
            <span>Safe, non-destructive rule inspections</span>
            <span className="text-cyan-400 text-[11px] font-semibold opacity-0 group-hover:opacity-100 transition">
              View &rarr;
            </span>
          </p>
        </div>

        {/* Active Vulnerabilities */}
        <div
          onClick={() => onNavigateToTab('findings')}
          className="liquid-glass-card liquid-glass-card-interactive rounded-2xl p-5 shadow-lg cursor-pointer group hover:border-rose-500/40 hover:shadow-rose-500/15 transition select-none"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onNavigateToTab('findings');
            }
          }}
          title="Click to view all active OWASP findings"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider group-hover:text-rose-300 transition flex items-center gap-1.5">
              <span>Active Findings</span>
              <ArrowUpRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition duration-200 text-rose-400" />
            </span>
            <div className="p-2.5 bg-rose-500/15 rounded-xl text-rose-400 border border-rose-500/20 shadow-[0_0_12px_rgba(244,63,94,0.2)] group-hover:scale-110 group-hover:bg-rose-500/25 transition">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3.5 flex items-baseline justify-between">
            <span className="text-3xl font-extrabold text-rose-400 tracking-tight group-hover:text-rose-300 transition">
              {activeFindings.length}
            </span>
            <div className="flex items-center space-x-1.5 flex-wrap gap-1">
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${overallRiskBadge.bg}`}>
                {overallRiskBadge.label}
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-500 mt-2 group-hover:text-slate-400 transition flex items-center justify-between">
            <span>Requires technical remediation</span>
            <span className="text-rose-400 text-[11px] font-semibold opacity-0 group-hover:opacity-100 transition">
              Review &rarr;
            </span>
          </p>
        </div>
      </div>

      {/* Visual Analytics Charts: Category Distribution & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* OWASP Top 10 Category Distribution Bar Chart */}
        <div className="lg:col-span-2 liquid-glass-card rounded-2xl p-6 shadow-xl relative overflow-hidden flex flex-col justify-between">
          <div>
            {/* Header with Edition & View Controls */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-wide">OWASP Top 10 Category Distribution</h2>
                  <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                    OWASP {selectedEdition}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Verified security findings mapped across official Top 10 taxonomy categories
                </p>
              </div>

              {/* Controls Toolbar */}
              <div className="flex items-center space-x-2 flex-wrap gap-1.5">
                {/* View Mode Toggle */}
                <div className="flex items-center bg-slate-950/60 p-0.5 rounded-xl border border-white/10 text-xs">
                  <button
                    onClick={() => setSortMode('ranked')}
                    className={`px-2 py-1 rounded-lg text-[11px] font-medium transition cursor-pointer flex items-center space-x-1 ${
                      sortMode === 'ranked'
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                    title="Sort by finding volume (High to Low)"
                  >
                    <ArrowDownUp className="w-3 h-3" />
                    <span>Ranked</span>
                  </button>
                  <button
                    onClick={() => setSortMode('canonical')}
                    className={`px-2 py-1 rounded-lg text-[11px] font-medium transition cursor-pointer flex items-center space-x-1 ${
                      sortMode === 'canonical'
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                    title="Order by canonical Top 10 code (A01 - A10)"
                  >
                    <span>A01-A10</span>
                  </button>
                </div>

                {/* Edition Selector */}
                <div className="flex items-center space-x-1 bg-slate-950/60 p-0.5 rounded-xl border border-white/10">
                  {['2025', '2021', '2017'].map((ed) => (
                    <button
                      key={ed}
                      onClick={() => setSelectedEdition(ed)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-mono transition cursor-pointer ${
                        selectedEdition === ed
                          ? 'liquid-glass-nav-pill text-white shadow-sm font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {ed} {ed === '2025' ? '(Latest)' : ''}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Quick Metrics & Posture Coverage Badges */}
            <div className="flex items-center justify-between text-xs py-2 px-3 rounded-xl bg-slate-950/40 border border-white/[0.06] mb-4 flex-wrap gap-2">
              <div className="flex items-center space-x-4">
                <span className="flex items-center space-x-1.5 text-amber-300 font-medium">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>
                    <strong className="text-white">{flaggedCategoriesCount}</strong> of 10 Categories Flagged
                  </span>
                </span>
                <span className="flex items-center space-x-1.5 text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>
                    <strong className="text-white">{cleanCategoriesCount}</strong> Passing / Clean
                  </span>
                </span>
              </div>

              <div className="flex items-center space-x-2 text-[11px] text-slate-400">
                <button
                  onClick={() => setFilterMode((prev) => (prev === 'all' ? 'flagged' : 'all'))}
                  className="flex items-center space-x-1 px-2 py-0.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition cursor-pointer border border-white/10"
                >
                  <Filter className="w-3 h-3 text-cyan-400" />
                  <span>{filterMode === 'all' ? 'Showing All 10' : 'Flagged Only'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Bar Chart Container */}
          <div className="h-72 w-full mt-2">
            {categoryAnalytics.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={categoryAnalytics}
                  margin={{ top: 15, right: 10, left: -20, bottom: 25 }}
                >
                  <defs>
                    <linearGradient id="amberBarGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#fbbf24" stopOpacity={0.95} />
                      <stop offset="100%" stopColor="#d97706" stopOpacity={0.7} />
                    </linearGradient>
                    <linearGradient id="cyanBarGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.95} />
                      <stop offset="100%" stopColor="#0284c7" stopOpacity={0.7} />
                    </linearGradient>
                    <linearGradient id="indigoBarGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#818cf8" stopOpacity={0.95} />
                      <stop offset="100%" stopColor="#4f46e5" stopOpacity={0.7} />
                    </linearGradient>
                    <linearGradient id="roseBarGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#fb7185" stopOpacity={0.95} />
                      <stop offset="100%" stopColor="#e11d48" stopOpacity={0.7} />
                    </linearGradient>
                    <linearGradient id="cleanBarGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#34d399" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#059669" stopOpacity={0.2} />
                    </linearGradient>
                  </defs>

                  <XAxis
                    dataKey="shortCode"
                    stroke="#94a3b8"
                    fontSize={11}
                    tickLine={false}
                    tick={({ x, y, payload }) => {
                      const item = categoryAnalytics.find((c) => c.shortCode === payload.value);
                      const hasIssues = item && item.findings > 0;
                      return (
                        <g transform={`translate(${x},${y})`}>
                          <text
                            x={0}
                            y={12}
                            textAnchor="middle"
                            fill={hasIssues ? '#f1f5f9' : '#64748b'}
                            fontSize={11}
                            fontWeight={hasIssues ? 600 : 400}
                          >
                            {payload.value}
                          </text>
                          {hasIssues ? (
                            <circle cx={0} cy={22} r={2.5} fill="#38bdf8" />
                          ) : (
                            <circle cx={0} cy={22} r={2} fill="#10b981" opacity={0.6} />
                          )}
                        </g>
                      );
                    }}
                  />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }}
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="liquid-glass-card rounded-2xl p-4 border border-white/20 shadow-2xl text-xs space-y-2.5 backdrop-blur-2xl max-w-sm z-50">
                            <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2">
                              <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-bold bg-indigo-500/25 text-indigo-300 border border-indigo-500/30">
                                {data.categoryCode}
                              </span>
                              <span className="text-[10px] text-slate-400 font-sans">
                                OWASP {selectedEdition} Edition
                              </span>
                            </div>

                            <div>
                              <h4 className="text-sm font-bold text-slate-900 dark:text-white leading-snug">{data.title}</h4>
                              <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                                {data.description}
                              </p>
                            </div>

                            <div className="flex items-center justify-between pt-1 border-t border-slate-200/80 dark:border-white/[0.08] text-xs">
                              <span className="text-slate-700 dark:text-slate-300">Total Findings:</span>
                              <span className="font-mono font-extrabold text-slate-900 dark:text-white text-sm">
                                {data.findings}{' '}
                                <span className="text-[10px] font-normal text-cyan-300 font-sans">
                                  ({data.percentage}% of active)
                                </span>
                              </span>
                            </div>

                            {data.targetsCount > 0 && (
                              <div className="flex items-center justify-between text-[11px] text-slate-400">
                                <span>Affected Targets:</span>
                                <span className="font-mono text-slate-200">
                                  {data.targetsCount} target{data.targetsCount > 1 ? 's' : ''}
                                </span>
                              </div>
                            )}

                            {/* Severity Breakdown Badges */}
                            {data.findings > 0 ? (
                              <div className="pt-2 border-t border-white/[0.08]">
                                <div className="text-[10px] uppercase font-bold text-slate-400 mb-1.5 tracking-wider">
                                  Severity Breakdown
                                </div>
                                <div className="flex items-center space-x-1.5 flex-wrap gap-1">
                                  {data.severities.CRITICAL > 0 && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono">
                                      {data.severities.CRITICAL} Critical
                                    </span>
                                  )}
                                  {data.severities.HIGH > 0 && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-300 border border-orange-500/30 font-mono">
                                      {data.severities.HIGH} High
                                    </span>
                                  )}
                                  {data.severities.MEDIUM > 0 && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">
                                      {data.severities.MEDIUM} Medium
                                    </span>
                                  )}
                                  {data.severities.LOW > 0 && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">
                                      {data.severities.LOW} Low
                                    </span>
                                  )}
                                  {data.severities.INFO > 0 && (
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-500/20 text-slate-300 border border-slate-500/30 font-mono">
                                      {data.severities.INFO} Info
                                    </span>
                                  )}
                                </div>
                              </div>
                            ) : (
                              <div className="flex items-center space-x-1.5 text-emerald-400 text-xs pt-1">
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                <span>Zero defects detected in this category</span>
                              </div>
                            )}
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <Bar
                    dataKey="findings"
                    radius={[6, 6, 0, 0]}
                    minPointSize={2}
                  >
                    {categoryAnalytics.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={`url(#${entry.gradientId})`}
                        style={{
                          filter: entry.findings > 0 ? `drop-shadow(0 2px 6px ${entry.barColor}30)` : 'none',
                        }}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 text-sm">
                <AlertTriangle className="w-8 h-8 mb-2 opacity-40 text-slate-400" />
                <span>No findings mapped yet. Run an assessment on an authorized target.</span>
              </div>
            )}
          </div>
        </div>

        {/* Severity Breakdown Donut Chart */}
        <div className="liquid-glass-card rounded-2xl p-6 shadow-xl flex flex-col justify-between relative overflow-hidden">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-wide">Severity Breakdown</h2>
                <p className="text-xs text-slate-400">Distribution of active findings by threat level</p>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold border ${overallRiskBadge.bg}`}>
                {overallRiskBadge.label}
              </span>
            </div>
          </div>

          {/* Interactive Donut with Centered Metric Badge */}
          <div className="relative h-56 w-full flex items-center justify-center">
            {severityPieData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityPieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={64}
                      outerRadius={88}
                      paddingAngle={4}
                      dataKey="value"
                      onMouseEnter={(_, index) => {
                        const entry = severityPieData[index];
                        if (entry) {
                          setHoveredSeverity({
                            name: entry.name,
                            key: entry.key as SeverityLevel,
                            value: entry.value,
                            color: entry.color,
                          });
                        }
                      }}
                      onMouseLeave={() => setHoveredSeverity(null)}
                    >
                      {severityPieData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.color}
                          style={{
                            filter: `drop-shadow(0 2px 8px ${entry.glow})`,
                            outline: 'none',
                            cursor: 'pointer',
                          }}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          const pct =
                            activeFindings.length > 0
                              ? Math.round((data.value / activeFindings.length) * 1000) / 10
                              : 0;
                          return (
                            <div className="liquid-glass rounded-xl p-3 border border-white/20 shadow-2xl text-xs space-y-1 backdrop-blur-2xl">
                              <div className="flex items-center space-x-2">
                                <span
                                  className="w-2.5 h-2.5 rounded-full"
                                  style={{ backgroundColor: data.color }}
                                />
                                <span className="font-bold text-slate-900 dark:text-white text-xs">{data.name} Severity</span>
                              </div>
                              <div className="flex items-center justify-between gap-4 pt-1 font-mono text-slate-700 dark:text-slate-200">
                                <span>Findings:</span>
                                <span className="font-bold text-slate-900 dark:text-white">{data.value}</span>
                              </div>
                              <div className="flex items-center justify-between gap-4 font-mono text-slate-600 dark:text-slate-300">
                                <span>Share:</span>
                                <span className="font-bold text-cyan-600 dark:text-cyan-300">{pct}%</span>
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>

                {/* Center Metric Badge Overlay */}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none text-center">
                  {hoveredSeverity ? (
                    <>
                      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                        {hoveredSeverity.name}
                      </span>
                      <span
                        className="text-3xl font-black tracking-tight"
                        style={{ color: hoveredSeverity.color }}
                      >
                        {hoveredSeverity.value}
                      </span>
                      <span className="text-[11px] font-mono text-slate-300">
                        {activeFindings.length > 0
                          ? `${Math.round((hoveredSeverity.value / activeFindings.length) * 1000) / 10}%`
                          : '0%'}
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                        Total
                      </span>
                      <span className="text-3xl font-black text-slate-900 dark:text-white tracking-tight">
                        {activeFindings.length}
                      </span>
                      <span className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                        Active Risks
                      </span>
                    </>
                  )}
                </div>
              </>
            ) : (
              <div className="text-center text-slate-500 text-sm">
                <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-60" />
                <span>No active findings detected</span>
              </div>
            )}
          </div>

          {/* Interactive 5-Tier Severity Matrix Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-2 pt-3 border-t border-white/[0.08]">
            {SEVERITY_ORDER.map((level) => {
              const cfg = SEVERITY_CONFIG[level];
              const count = severityCounts[level];
              const pct = activeFindings.length > 0 ? (count / activeFindings.length) * 100 : 0;
              const isHovered = hoveredSeverity?.key === level;

              return (
                <div
                  key={level}
                  onMouseEnter={() =>
                    setHoveredSeverity({
                      name: cfg.label,
                      key: level,
                      value: count,
                      color: cfg.color,
                    })
                  }
                  onMouseLeave={() => setHoveredSeverity(null)}
                  className={`p-2 rounded-xl transition cursor-pointer border ${
                    isHovered
                      ? 'bg-white/10 border-white/30 scale-[1.02] shadow-lg'
                      : count > 0
                      ? 'bg-slate-900/50 border-white/5 hover:border-white/20'
                      : 'bg-slate-950/30 border-white/[0.03] opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-1.5">
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{
                          backgroundColor: cfg.color,
                          boxShadow: count > 0 ? `0 0 6px ${cfg.color}` : 'none',
                        }}
                      />
                      <span className="text-xs font-semibold text-slate-200">{cfg.label}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-white">{count}</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1 font-mono">
                    <span>Share</span>
                    <span className={count > 0 ? cfg.textClass : 'text-slate-500'}>
                      {pct.toFixed(1)}%
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Posture Trend & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Assessment Posture Trend */}
        <div className="liquid-glass-card rounded-2xl p-6 shadow-xl flex flex-col justify-between relative overflow-hidden">
          <div>
            {/* Header with Title and Controls */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-wide">Assessment Posture Trend</h2>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/25">
                    {trendViewMode === 'compliance' ? 'Compliance Score' : 'Checks Breakdown'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Security health trajectory across continuous assessment cycles
                </p>
              </div>

              {/* View Mode Toggle & Target Selector */}
              <div className="flex items-center space-x-2 flex-wrap gap-1.5">
                <div className="flex items-center bg-slate-950/60 p-0.5 rounded-xl border border-white/10 text-xs">
                  <button
                    onClick={() => setTrendViewMode('compliance')}
                    className={`px-2 py-1 rounded-lg text-[11px] font-medium transition cursor-pointer flex items-center space-x-1 ${
                      trendViewMode === 'compliance'
                        ? 'bg-cyan-600 text-white shadow-sm font-bold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                    title="View compliance percentage trend"
                  >
                    <TrendingUp className="w-3 h-3" />
                    <span>Compliance %</span>
                  </button>
                  <button
                    onClick={() => setTrendViewMode('volume')}
                    className={`px-2 py-1 rounded-lg text-[11px] font-medium transition cursor-pointer flex items-center space-x-1 ${
                      trendViewMode === 'volume'
                        ? 'bg-cyan-600 text-white shadow-sm font-bold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                    title="View passed vs flagged checks volume"
                  >
                    <span>Checks</span>
                  </button>
                </div>

                <select
                  value={trendTargetId}
                  onChange={(e) => setTrendTargetId(e.target.value)}
                  className="liquid-glass-input text-xs rounded-xl px-2.5 py-1 text-slate-200 border border-white/10 max-w-[180px] truncate"
                >
                  <option value="" className="bg-slate-900">All Targets (Chronological)</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id} className="bg-slate-900">
                      {a.canonical_url}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Quick Metrics Sub-Banner */}
            {latestTimelinePoint && (
              <div className="flex items-center justify-between text-xs py-2 px-3 rounded-xl bg-slate-950/40 border border-white/[0.06] mb-3 flex-wrap gap-2">
                <div className="flex items-center space-x-3">
                  <span className="flex items-center space-x-1.5 text-slate-300">
                    <span className="text-slate-400">Latest Run:</span>
                    <span
                      className={`font-mono font-bold px-2 py-0.5 rounded-full text-[11px] border ${
                        latestTimelinePoint.complianceRate >= 80
                          ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                          : latestTimelinePoint.complianceRate >= 50
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                      }`}
                    >
                      {latestTimelinePoint.complianceRate}% Compliance
                    </span>
                  </span>
                  <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
                    {latestTimelinePoint.passed}/{latestTimelinePoint.total} checks passed
                  </span>
                </div>
                <div className="flex items-center space-x-2 text-[11px] text-slate-400 font-mono">
                  <span>Avg: <strong className="text-white">{avgCompliance}%</strong></span>
                  <span className="text-slate-600">•</span>
                  <span>{timelineData.length} runs</span>
                </div>
              </div>
            )}
          </div>

          {/* Chart Canvas */}
          <div className="h-56 w-full">
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                {trendViewMode === 'compliance' ? (
                  <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 5 }}>
                    <defs>
                      <linearGradient id="complianceGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.45} />
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="axisLabel"
                      stroke="#64748b"
                      fontSize={11}
                      tickLine={false}
                    />
                    <YAxis
                      stroke="#64748b"
                      fontSize={11}
                      domain={[0, 100]}
                      ticks={[0, 25, 50, 75, 100]}
                      tickFormatter={(v) => `${v}%`}
                      allowDecimals={false}
                      tickLine={false}
                    />
                    <ReferenceLine
                      y={80}
                      stroke="#10b981"
                      strokeDasharray="3 3"
                      strokeOpacity={0.7}
                    />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          return (
                            <div className="liquid-glass rounded-xl p-3 border border-white/20 shadow-2xl text-xs space-y-2 backdrop-blur-2xl max-w-xs">
                              <div className="flex items-center space-x-1.5 font-semibold text-slate-900 dark:text-white truncate max-w-[240px]">
                                <Globe className="w-3.5 h-3.5 text-cyan-500 dark:text-cyan-400 shrink-0" />
                                <span className="truncate">{data.target}</span>
                              </div>
                              <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono pb-1.5 border-b border-slate-200/80 dark:border-white/10 flex items-center justify-between">
                                <span>{data.fullDate}</span>
                                {data.durationStr && (
                                  <span className="text-cyan-600 dark:text-cyan-400 flex items-center space-x-1">
                                    <Clock className="w-2.5 h-2.5" />
                                    <span>{data.durationStr}</span>
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center justify-between gap-4">
                                <span className="text-cyan-700 dark:text-cyan-300 font-medium">Compliance Score:</span>
                                <span className="font-extrabold text-slate-900 dark:text-white font-mono text-sm">{data.complianceRate}%</span>
                              </div>
                              <div className="flex items-center justify-between gap-4 text-[11px] text-slate-700 dark:text-slate-300">
                                <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                                  <CheckCircle className="w-3 h-3 text-emerald-600 dark:text-emerald-400" /> Checks Passed:
                                </span>
                                <span className="font-mono text-slate-900 dark:text-white">{data.passed} of {data.total}</span>
                              </div>
                              <div className="flex items-center justify-between gap-4 text-[11px] text-slate-300">
                                <span className="text-amber-400 flex items-center gap-1">
                                  <AlertTriangle className="w-3 h-3 text-amber-400" /> Vulnerabilities:
                                </span>
                                <span className="font-mono text-amber-300 font-bold">{data.findingsCount} findings</span>
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="complianceRate"
                      name="Compliance Score"
                      stroke="#06b6d4"
                      strokeWidth={2.5}
                      fillOpacity={1}
                      fill="url(#complianceGradient)"
                      activeDot={{ r: 5, fill: '#38bdf8', stroke: '#ffffff', strokeWidth: 2 }}
                    />
                  </AreaChart>
                ) : (
                  <BarChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 5 }}>
                    <XAxis
                      dataKey="axisLabel"
                      stroke="#64748b"
                      fontSize={11}
                      tickLine={false}
                    />
                    <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} tickLine={false} />
                    <Tooltip
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          return (
                            <div className="liquid-glass rounded-xl p-3 border border-white/20 shadow-2xl text-xs space-y-1.5 backdrop-blur-2xl">
                              <div className="font-semibold text-slate-900 dark:text-white truncate max-w-[240px]">
                                {data.target}
                              </div>
                              <div className="text-[10px] text-slate-500 dark:text-slate-400 font-mono pb-1 border-b border-slate-200/80 dark:border-white/10">
                                {data.fullDate}
                              </div>
                              <div className="flex items-center justify-between gap-4 text-emerald-600 dark:text-emerald-400">
                                <span>Passed Rules:</span>
                                <span className="font-bold text-slate-900 dark:text-white font-mono">{data.passed}</span>
                              </div>
                              <div className="flex items-center justify-between gap-4 text-rose-400">
                                <span>Failed Rules:</span>
                                <span className="font-bold text-rose-300 font-mono">{data.failed}</span>
                              </div>
                              <div className="flex items-center justify-between gap-4 text-amber-300 pt-1 border-t border-white/10 font-mono text-[11px]">
                                <span>Total Bugs Found:</span>
                                <span className="font-bold">{data.findingsCount}</span>
                              </div>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Bar dataKey="passed" name="Passed Checks" fill="#10b981" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="failed" name="Failed Checks" fill="#f43f5e" radius={[4, 4, 0, 0]} />
                  </BarChart>
                )}
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs text-center">
                <span>No scan runs recorded for this selection.</span>
              </div>
            )}
          </div>

          {/* Chart Legend / Posture Guidance */}
          <div className="mt-3 pt-3 border-t border-white/10 flex items-center justify-center space-x-6 text-xs text-slate-400 flex-wrap gap-2">
            {trendViewMode === 'compliance' ? (
              <>
                <span className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.6)]" />
                  <span>Compliance Trajectory</span>
                </span>
                <span className="flex items-center space-x-1.5">
                  <span className="w-4 border-b border-dashed border-emerald-400 inline-block" />
                  <span className="text-emerald-400 font-medium">80% Target Benchmark</span>
                </span>
              </>
            ) : (
              <>
                <span className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.6)]" />
                  <span>Passed Checks</span>
                </span>
                <span className="flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]" />
                  <span>Failed Checks</span>
                </span>
              </>
            )}
          </div>
        </div>

        {/* Recent Scan Jobs Table */}
        <div className="lg:col-span-2 liquid-glass-card rounded-2xl p-6 shadow-xl overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-base font-bold text-slate-900 dark:text-white tracking-wide">Recent Assessment Activity</h2>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-700 dark:text-indigo-300 border border-indigo-500/30">
                    Latest {sortedRecentScans.length} Scans
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">Execution status and real vulnerability yields of latest security audits</p>
              </div>
              <button
                onClick={() => onNavigateToTab('targets')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center space-x-1 cursor-pointer transition px-2.5 py-1 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20"
              >
                <span>View All Targets</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-white/[0.08] text-slate-400 font-semibold text-[11px] uppercase tracking-wider">
                    <th className="pb-2.5">Target Asset</th>
                    <th className="pb-2.5">Status</th>
                    <th className="pb-2.5">Checks Passed</th>
                    <th className="pb-2.5">Vulnerabilities</th>
                    <th className="pb-2.5">Executed At</th>
                    <th className="pb-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {sortedRecentScans.map((scan) => {
                    const assetId = (scan as any).target_id || scan.asset_id;
                    const targetAsset = assets.find((a) => a.id === assetId);
                    const displayTarget =
                      targetAsset?.canonical_url ||
                      scan.scan_metadata?.target_url ||
                      (assetId ? `Asset ${assetId.slice(0, 8)}...` : 'Unknown Target');

                    const totalChecks = scan.total_checks || 14;
                    const passed = scan.passed_checks ?? Math.max(0, totalChecks - (scan.failed_checks || 0));
                    const failed = scan.failed_checks ?? Math.max(0, totalChecks - passed);
                    const findingsCount = (scan.observations_count !== undefined && scan.observations_count > 0)
                      ? scan.observations_count
                      : failed;

                    // Duration string if available
                    let durationStr = '';
                    if (scan.scan_metadata?.deep_scan_metrics?.execution_time_seconds) {
                      durationStr = `${scan.scan_metadata.deep_scan_metrics.execution_time_seconds}s`;
                    } else if (scan.started_at && scan.completed_at) {
                      const diffMs = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime();
                      if (diffMs > 0) durationStr = `${(diffMs / 1000).toFixed(1)}s`;
                    }

                    const resolvedIp = scan.scan_metadata?.deep_scan_metrics?.resolved_ip;

                    return (
                      <tr key={scan.id} className="hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.04] transition group">
                        <td className="py-3 text-slate-900 dark:text-white font-medium max-w-xs truncate" title={displayTarget}>
                          <div className="flex items-center space-x-2">
                            <Globe className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400 shrink-0" />
                            <div className="truncate">
                              <div className="truncate text-slate-800 dark:text-slate-200 font-semibold group-hover:text-cyan-600 dark:group-hover:text-cyan-300 transition">
                                {displayTarget}
                              </div>
                              <div className="flex items-center space-x-1.5 text-[10px] text-slate-500 font-mono mt-0.5">
                                <span>{scan.id.slice(0, 8)}</span>
                                {resolvedIp && (
                                  <>
                                    <span>•</span>
                                    <span className="text-slate-400">{resolvedIp}</span>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="py-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold ${
                              scan.status === 'COMPLETED'
                                ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-[0_0_8px_rgba(16,185,129,0.2)]'
                                : scan.status === 'RUNNING'
                                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 animate-pulse'
                                : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 font-mono">
                          <div className="flex items-center space-x-1.5">
                            <span className="text-emerald-400 font-bold">{passed}</span>
                            <span className="text-slate-500">/</span>
                            <span className="text-slate-400">{totalChecks}</span>
                          </div>
                          <div className="text-[10px] text-slate-500 font-sans">
                            {Math.round((passed / totalChecks) * 100)}% pass rate
                          </div>
                        </td>
                        <td className="py-3 font-semibold">
                          {findingsCount > 0 ? (
                            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30 font-sans">
                              <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                              <span>{findingsCount} vulnerabilities</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-sans">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                              <span>0 Clean</span>
                            </span>
                          )}
                        </td>
                        <td className="py-3 text-slate-400 font-sans text-[11px] whitespace-nowrap">
                          <div className="text-slate-200 font-medium">
                            {formatDateTimeShort(scan.started_at)}
                          </div>
                          <div className="flex items-center space-x-1.5 text-[10px] text-cyan-400/80 font-sans">
                            <span>{formatRelativeTime(scan.started_at)}</span>
                            {durationStr && (
                              <>
                                <span>•</span>
                                <span className="font-mono text-slate-400">{durationStr}</span>
                              </>
                            )}
                          </div>
                        </td>
                        <td className="py-3 text-right">
                          <button
                            onClick={() => {
                              if (assetId) onSelectTarget(assetId);
                              onNavigateToTab('findings');
                            }}
                            className="text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer transition text-xs px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/25 inline-flex items-center space-x-1"
                          >
                            <span>Review</span>
                            <ArrowUpRight className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {sortedRecentScans.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        No scan jobs executed yet. Register an authorized target and start an assessment.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

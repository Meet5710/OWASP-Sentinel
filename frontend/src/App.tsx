import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Sidebar, type ActiveTab } from './components/Sidebar';
import { Menu, Shield, Moon, Sun } from 'lucide-react';
import { OverviewTab } from './components/OverviewTab';
import { TargetAssessmentTab } from './components/TargetAssessmentTab';
import { SubdomainFinderTab } from './components/SubdomainFinderTab';
import { PathFinderTab } from './components/PathFinderTab';
import { KaliPentesterTab } from './components/KaliPentesterTab';
import { FindingsTab } from './components/FindingsTab';
import { TaxonomyTab } from './components/TaxonomyTab';
import { CoverageMatrixTab } from './components/CoverageMatrixTab';
import { SchedulesTab } from './components/SchedulesTab';
import { ProofOfConceptTab } from './components/ProofOfConceptTab';
import { SettingsAndAuditTab } from './components/SettingsAndAuditTab';
import { api } from './services/api';
import type { AuthorizedAsset, ScopeGrant, ScanJob, Finding } from './types/api';

// Labeled Simulated Fixtures for Sandbox / Benchmark evaluation
const SIMULATED_ASSETS: AuthorizedAsset[] = [
  {
    id: 'sim-asset-01',
    scope_grant_id: 'sim-scope-01',
    canonical_url: 'https://sandbox.vuln-bank.test [SIMULATED LAB]',
    hostname: 'sandbox.vuln-bank.test',
    port: 443,
    scheme: 'https',
    is_subdomain: false,
    approval_status: 'APPROVED',
    approval_notes: 'Authorized simulated sandbox fixture',
    first_discovered_at: new Date(Date.now() - 7 * 86400000).toISOString(),
    last_assessed_at: new Date().toISOString(),
  },
  {
    id: 'sim-asset-02',
    scope_grant_id: 'sim-scope-01',
    canonical_url: 'https://api.sandbox.vuln-bank.test [SIMULATED LAB]',
    hostname: 'api.sandbox.vuln-bank.test',
    port: 443,
    scheme: 'https',
    is_subdomain: true,
    approval_status: 'APPROVED',
    approval_notes: 'Authorized simulated API target',
    first_discovered_at: new Date(Date.now() - 5 * 86400000).toISOString(),
    last_assessed_at: new Date().toISOString(),
  },
];

const SIMULATED_FINDINGS: Finding[] = [
  {
    id: 'sim-fnd-01',
    target_id: 'sim-asset-01',
    initial_scan_id: 'sim-scan-01',
    last_scan_id: 'sim-scan-02',
    rule_id: 'RULE-SEC-001',
    technical_issue_type: 'MISSING_SECURITY_HEADERS',
    title: '[SIMULATED] Missing Strict-Transport-Security (HSTS) Header',
    description: 'The simulated web server does not supply the Strict-Transport-Security header.',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    validation_status: 'CONFIRMED',
    remediation_guidance: 'Enforce HSTS with max-age=31536000; includeSubDomains.',
    references: ['https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/'],
    evidence: { missing_header: 'Strict-Transport-Security', simulated_fixture: true },
    status_history: [
      {
        from_status: 'POTENTIAL',
        to_status: 'CONFIRMED',
        timestamp: new Date(Date.now() - 86400000).toISOString(),
        actor: 'Simulated Engine',
        note: 'Validated simulated rule behavior',
      },
    ],
    first_seen_at: new Date(Date.now() - 3 * 86400000).toISOString(),
    last_seen_at: new Date().toISOString(),
    category_mappings: [
      {
        id: 'sim-map-01',
        finding_id: 'sim-fnd-01',
        edition_identifier: '2021',
        category_identifier: 'A05:2021',
        justification: 'Security Misconfiguration: Transport layer encryption not enforced via policy.',
      },
    ],
  },
  {
    id: 'sim-fnd-02',
    target_id: 'sim-asset-01',
    initial_scan_id: 'sim-scan-01',
    last_scan_id: 'sim-scan-02',
    rule_id: 'RULE-SEC-004',
    technical_issue_type: 'VERBOSE_SERVER_BANNER',
    title: '[SIMULATED] Detailed Server Banner Information Disclosure',
    description: 'The target returns Apache/2.4.41 (Ubuntu) exposing version and platform specifics.',
    severity: 'LOW',
    confidence: 'CONFIRMED',
    validation_status: 'CONFIRMED',
    remediation_guidance: 'Configure ServerTokens Prod and ServerSignature Off.',
    references: ['https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/'],
    evidence: { banner: 'Apache/2.4.41 (Ubuntu)', header: 'Server', simulated_fixture: true },
    status_history: [],
    first_seen_at: new Date(Date.now() - 3 * 86400000).toISOString(),
    last_seen_at: new Date().toISOString(),
    category_mappings: [
      {
        id: 'sim-map-02',
        finding_id: 'sim-fnd-02',
        edition_identifier: '2021',
        category_identifier: 'A05:2021',
        justification: 'Security Misconfiguration: Verbose software banners assist targeted exploitation.',
      },
    ],
  },
  {
    id: 'sim-fnd-03',
    target_id: 'sim-asset-02',
    initial_scan_id: 'sim-scan-01',
    last_scan_id: 'sim-scan-02',
    rule_id: 'RULE-SEC-005',
    technical_issue_type: 'CORS_ORIGIN_REFLECTION',
    title: '[SIMULATED] Arbitrary CORS Origin Reflection with Credentials',
    description: 'The API endpoint reflects untrusted Origin headers with Access-Control-Allow-Credentials: true.',
    severity: 'HIGH',
    confidence: 'HIGH',
    validation_status: 'CONFIRMED',
    remediation_guidance: 'Enforce strict whitelist of trusted partner origins.',
    references: ['https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control/'],
    evidence: { reflected_origin: 'https://evil-attacker.example.com', simulated_fixture: true },
    status_history: [],
    first_seen_at: new Date(Date.now() - 2 * 86400000).toISOString(),
    last_seen_at: new Date().toISOString(),
    category_mappings: [
      {
        id: 'sim-map-03',
        finding_id: 'sim-fnd-03',
        edition_identifier: '2021',
        category_identifier: 'A01:2021',
        justification: 'Broken Access Control: Cross-origin data theft allowed via credentialed reflection.',
      },
      {
        id: 'sim-map-04',
        finding_id: 'sim-fnd-03',
        edition_identifier: '2021',
        category_identifier: 'A05:2021',
        justification: 'Security Misconfiguration: CORS headers incorrectly configured.',
      },
    ],
  },
];

const SIMULATED_SCANS: ScanJob[] = [
  {
    id: 'sim-scan-01',
    asset_id: 'sim-asset-01',
    status: 'COMPLETED',
    started_at: new Date(Date.now() - 3 * 86400000).toISOString(),
    completed_at: new Date(Date.now() - 3 * 86400000 + 4000).toISOString(),
    observations_count: 2,
    scan_metadata: { simulated: true },
  },
  {
    id: 'sim-scan-02',
    asset_id: 'sim-asset-01',
    status: 'COMPLETED',
    started_at: new Date(Date.now() - 86400000).toISOString(),
    completed_at: new Date(Date.now() - 86400000 + 3500).toISOString(),
    observations_count: 2,
    scan_metadata: { simulated: true },
  },
];

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [systemHealth, setSystemHealth] = useState<{ status: string; version: string } | null>(null);
  const [isSimulatedMode, setIsSimulatedMode] = useState<boolean>(false);
  const [isMobileNavOpen, setIsMobileNavOpen] = useState<boolean>(false);

  // Theme State with System Preference & LocalStorage persistence
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      const saved = localStorage.getItem('sentinel_theme');
      if (saved === 'light' || saved === 'dark') return saved;
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'light') {
      root.classList.add('light');
      root.classList.remove('dark');
    } else {
      root.classList.add('dark');
      root.classList.remove('light');
    }
    try {
      localStorage.setItem('sentinel_theme', theme);
    } catch {
      // storage unavailable
    }
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  }, []);

  // Core Live Data Collections
  const [liveAssets, setLiveAssets] = useState<AuthorizedAsset[]>([]);
  const [liveScopes, setLiveScopes] = useState<ScopeGrant[]>([]);
  const [liveScans, setLiveScans] = useState<ScanJob[]>([]);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Active dataset depending on mode (live vs simulated benchmark)
  const displayAssets = useMemo(() => {
    return isSimulatedMode ? SIMULATED_ASSETS : liveAssets;
  }, [isSimulatedMode, liveAssets]);

  const displayFindings = useMemo(() => {
    const raw = isSimulatedMode ? SIMULATED_FINDINGS : liveFindings;
    const grouped = new Map<string, Finding>();

    for (const f of raw) {
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
  }, [isSimulatedMode, liveFindings]);

  const displayScans = useMemo(() => {
    return isSimulatedMode ? SIMULATED_SCANS : liveScans;
  }, [isSimulatedMode, liveScans]);

  // Fetch all core live datasets
  const loadAllData = useCallback(async () => {
    try {
      const [healthRes, assetsRes, scopesRes, scansRes, findingsRes] = await Promise.all([
        api.getHealth().catch(() => null),
        api.getAssets().catch(() => null),
        api.getScopes().catch(() => null),
        api.getScans().catch(() => null),
        api.getFindings().catch(() => null),
      ]);

      if (healthRes) {
        setSystemHealth(healthRes);
        setErrorMsg(null);
      }

      if (assetsRes && Array.isArray(assetsRes)) {
        setLiveAssets(assetsRes);
      }
      if (scopesRes && Array.isArray(scopesRes)) {
        setLiveScopes(scopesRes);
      }
      if (scansRes && Array.isArray(scansRes)) {
        setLiveScans(scansRes);
      }
      if (findingsRes && Array.isArray(findingsRes)) {
        setLiveFindings(findingsRes);
      }
    } catch (err: any) {
      console.error('Error fetching live data:', err);
    }
  }, []);

  // Global Live Scanning Process State (Persists seamlessly across all tabs)
  const [activeScanningTargetId, setActiveScanningTargetId] = useState<string | null>(null);
  const [scanStatusMessage, setScanStatusMessage] = useState<string | null>(null);
  const [latestScanRunInfo, setLatestScanRunInfo] = useState<{
    scanId: string;
    targetId: string;
    time: string;
    count: number;
  } | null>(null);

  // Centralized scan execution that runs in App and NEVER restarts/aborts when switching tabs
  const executeGlobalScan = useCallback(
    async (assetId: string) => {
      if (!assetId || assetId === '__ALL__' || activeScanningTargetId) return;

      const targetAsset = displayAssets.find((a) => a.id === assetId);
      const targetName = targetAsset?.canonical_url || targetAsset?.hostname || 'target';

      setActiveScanningTargetId(assetId);
      setSelectedTargetId(assetId);
      setScanStatusMessage(`Running natural live scan from scratch against ${targetName} across all 19 OWASP detection rules...`);

      try {
        const scanJob = await api.triggerScan(assetId);
        setScanStatusMessage(`Auditing live responses and collecting empirical evidence from ${targetName}...`);

        // Refresh live data to pull all newly observed findings and scans
        await loadAllData();

        setLatestScanRunInfo({
          scanId: scanJob.id,
          targetId: assetId,
          time: new Date().toLocaleTimeString(),
          count: scanJob.failed_checks ?? 0,
        });

        setScanStatusMessage(`Live scan completed successfully! Verified empirical telemetry across all rules.`);

        setTimeout(() => {
          setScanStatusMessage(null);
          setActiveScanningTargetId(null);
        }, 3500);
      } catch (err: any) {
        console.error('Global scan execution failed:', err);
        setScanStatusMessage(`Scan failed: ${err.message || 'Unknown error'}`);
        setTimeout(() => {
          setScanStatusMessage(null);
          setActiveScanningTargetId(null);
        }, 4000);
      }
    },
    [displayAssets, activeScanningTargetId, loadAllData]
  );

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 20000); // refresh every 20s
    return () => clearInterval(interval);
  }, [loadAllData]);

  // Main scroll container ref to reset scroll to top on tab transitions
  const mainScrollRef = useRef<HTMLDivElement>(null);

  // Automatically reset scroll position to the top whenever activeTab changes
  useEffect(() => {
    if (mainScrollRef.current) {
      mainScrollRef.current.scrollTop = 0;
    }
    window.scrollTo(0, 0);

    const rafId = requestAnimationFrame(() => {
      if (mainScrollRef.current) {
        mainScrollRef.current.scrollTop = 0;
      }
      window.scrollTo(0, 0);
    });
    return () => cancelAnimationFrame(rafId);
  }, [activeTab]);

  return (
    <div className="min-h-screen spatial-bg-mesh text-slate-100 flex flex-col md:flex-row relative selection:bg-cyan-500 selection:text-black overflow-x-hidden">
      {/* 3D Spatial Ambient Glowing Lighting Orbs with smooth transitions */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden -z-10">
        <div className="orb-primary absolute -top-32 -left-32 w-96 h-96 bg-indigo-600/20 rounded-full blur-3xl animate-float-slow transition-all duration-700" />
        <div className="orb-secondary absolute top-1/4 -right-32 w-[32rem] h-[32rem] bg-cyan-500/15 rounded-full blur-[100px] animate-float-reverse transition-all duration-700" />
        <div className="orb-tertiary absolute -bottom-32 left-1/3 w-[36rem] h-[36rem] bg-purple-600/15 rounded-full blur-[120px] animate-float-slow transition-all duration-700" />
      </div>

      {/* Persistent Spatial Liquid Glass Left Sidebar & Mobile Drawer */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          if (tab === 'findings') {
            setSelectedTargetId('');
          }
          setActiveTab(tab);
        }}
        systemHealth={systemHealth}
        isSimulatedMode={isSimulatedMode}
        setIsSimulatedMode={setIsSimulatedMode}
        theme={theme}
        onToggleTheme={toggleTheme}
        isOpenMobile={isMobileNavOpen}
        onCloseMobile={() => setIsMobileNavOpen(false)}
      />

      {/* Main Content Area Container with Independent Scroll */}
      <div
        ref={mainScrollRef}
        className="flex-1 flex flex-col min-w-0 md:h-screen md:overflow-y-auto relative"
      >
        {/* Mobile Top Bar (Header on small screens < md) */}
        <div className="md:hidden sticky top-0 z-40 liquid-glass border-b border-white/[0.08] px-4 py-3 flex items-center justify-between shadow-lg">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 rounded-xl bg-gradient-to-br from-indigo-600 via-indigo-700 to-cyan-600 text-white shadow-md border border-white/20">
              <Shield className="w-4 h-4 fill-cyan-400/20 text-cyan-200 stroke-[2.2] drop-shadow" />
            </div>
            <span className="sentinel-brand-logo-text font-black text-sm tracking-wide">
              OWASP Sentinel
            </span>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full liquid-glass-pill text-cyan-600 dark:text-cyan-300 border border-cyan-500/30">
              v{systemHealth?.version || '0.1.0'}
            </span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={toggleTheme}
              className="p-1.5 rounded-lg liquid-glass-pill text-slate-300 hover:text-white cursor-pointer"
              aria-label="Toggle theme"
            >
              {theme === 'light' ? (
                <Moon className="w-4 h-4 text-indigo-500" />
              ) : (
                <Sun className="w-4 h-4 text-amber-300" />
              )}
            </button>
            <button
              type="button"
              onClick={() => setIsMobileNavOpen(true)}
              className="p-2 rounded-xl liquid-glass text-slate-300 hover:text-white border border-white/10 cursor-pointer"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5 text-cyan-400" />
            </button>
          </div>
        </div>

        {/* Top Simulation Warning Banner across main area if active */}
        {isSimulatedMode && (
          <div className="bg-amber-500/10 border-b border-amber-500/25 px-4 py-2 text-center text-xs text-amber-300 flex items-center justify-center space-x-2 backdrop-blur-md shrink-0">
            <span className="font-semibold uppercase tracking-wider text-[10px] px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/30">
              SIMULATION ACTIVE
            </span>
            <span>
              Displaying safe sandbox and benchmark fixtures. All technical findings in this mode are strictly simulated.
            </span>
          </div>
        )}

        {/* Main Content Area with Silky-Smooth Tab Transition */}
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
          {errorMsg && (
            <div className="mb-6 p-4 rounded-2xl liquid-glass border border-rose-500/30 text-rose-200 text-xs flex items-center justify-between shadow-lg shadow-rose-950/40">
              <span>
                <strong className="text-rose-400">Connection Warning:</strong> {errorMsg}
              </span>
              <button
                onClick={() => loadAllData()}
                className="px-3 py-1.5 liquid-glass-btn-secondary text-white rounded-lg text-xs transition cursor-pointer"
              >
                Retry
              </button>
            </div>
          )}

          {/* Persistent Global Scan Banner (Active across ALL tabs) */}
          {activeScanningTargetId && (
            <div className="mb-5 px-4 py-3 rounded-2xl bg-cyan-950/70 border border-cyan-500/40 shadow-xl backdrop-blur-md flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-cyan-200 font-mono animate-pulse">
              <div className="flex items-center space-x-3">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping shrink-0" />
                <span className="font-bold text-white tracking-wide shrink-0">ACTIVE LIVE SCAN:</span>
                <span className="text-cyan-100 truncate">{scanStatusMessage}</span>
              </div>
              <span className="shrink-0 text-[11px] text-cyan-300/90 bg-cyan-900/60 px-2.5 py-1 rounded-lg border border-cyan-500/30">
                ⚡ Running in background • Continues across tabs
              </span>
            </div>
          )}

          {/* Persistent Keep-Alive Tab Hierarchy (Preserves All Running Scans, Terminal Commands, Form State & Async Tasks Across Tab Navigation) */}
          <div className="w-full">
            <div
              className={`w-full ${activeTab === 'overview' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'overview'}
            >
              <OverviewTab
                assets={displayAssets}
                scans={displayScans}
                findings={displayFindings}
                onSelectTarget={(tId) => setSelectedTargetId(tId)}
                onNavigateToTab={(tab) => setActiveTab(tab)}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'targets' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'targets'}
            >
              <TargetAssessmentTab
                assets={displayAssets}
                scopes={liveScopes}
                onRefreshData={loadAllData}
                onScanCompleted={(scanJob, asset) => {
                  const targetId = asset?.id || scanJob.target_id || scanJob.asset_id;
                  if (targetId) {
                    setSelectedTargetId(targetId);
                  }
                }}
                onNavigateToTab={(tab) => setActiveTab(tab)}
                onSelectTarget={(tId) => setSelectedTargetId(tId)}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'subdomains' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'subdomains'}
            >
              <SubdomainFinderTab
                assets={displayAssets}
                scopes={liveScopes}
                onRefreshData={loadAllData}
                onNavigateToTab={(tab) => setActiveTab(tab)}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'pathfinder' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'pathfinder'}
            >
              <PathFinderTab
                assets={displayAssets}
                onRefreshData={loadAllData}
                onNavigateToTab={(tab) => setActiveTab(tab)}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'kali_pentester' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'kali_pentester'}
            >
              <KaliPentesterTab
                assets={displayAssets}
                onNavigateToTab={(tab) => setActiveTab(tab)}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'findings' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'findings'}
            >
              <FindingsTab
                findings={displayFindings}
                assets={displayAssets}
                selectedTargetId={selectedTargetId}
                onSelectTarget={(tId) => setSelectedTargetId(tId)}
                onRefreshData={loadAllData}
                activeScanningTargetId={activeScanningTargetId}
                scanStatusMessage={scanStatusMessage}
                latestScanRunInfo={latestScanRunInfo}
                onTriggerScan={executeGlobalScan}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'taxonomy' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'taxonomy'}
            >
              <TaxonomyTab />
            </div>

            <div
              className={`w-full ${activeTab === 'coverage' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'coverage'}
            >
              <CoverageMatrixTab />
            </div>

            <div
              className={`w-full ${activeTab === 'schedules' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'schedules'}
            >
              <SchedulesTab assets={displayAssets} onRefreshData={loadAllData} />
            </div>

            <div
              className={`w-full ${activeTab === 'poc' || activeTab === 'reports' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'poc' && activeTab !== 'reports'}
            >
              <ProofOfConceptTab
                assets={displayAssets}
                findings={displayFindings}
                scans={displayScans}
                selectedTargetId={selectedTargetId}
                onSelectTarget={(tId) => setSelectedTargetId(tId)}
                onRefreshData={loadAllData}
                activeScanningTargetId={activeScanningTargetId}
                scanStatusMessage={scanStatusMessage}
                onTriggerScan={executeGlobalScan}
              />
            </div>

            <div
              className={`w-full ${activeTab === 'audit' ? 'spatial-tab-pane block' : 'hidden'}`}
              aria-hidden={activeTab !== 'audit'}
            >
              <SettingsAndAuditTab scopes={liveScopes} onRefreshData={loadAllData} />
            </div>
          </div>
        </main>

        {/* Global Spatial Footer */}
        <footer className="border-t border-white/[0.07] liquid-glass py-6 text-center text-xs text-slate-400 mt-auto shrink-0">
          <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-medium text-slate-300">OWASP Sentinel Spatial Glass Platform</span>
              <span>&bull;</span>
              <span>Continuous Posture & Taxonomy Intelligence</span>
            </div>
            <span className="text-slate-500">
              OWASP Top 10 is an official publication of OWASP Foundation. Authorized assessment use only.
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default App;

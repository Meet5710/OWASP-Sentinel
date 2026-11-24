import React, { useState } from 'react';
import {
  Shield,
  Activity,
  Globe,
  Database,
  Clock,
  FileCheck,
  FileText,
  Settings,
  Layers,
  Sun,
  Moon,
  X,
  Sparkles,
  Radar,
  Share2,
  Route,
  Code,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export type ActiveTab =
  | 'overview'
  | 'targets'
  | 'subdomains'
  | 'pathfinder'
  | 'sql'
  | 'xssspect'
  | 'owasp_scan'
  | 'findings'
  | 'taxonomy'
  | 'coverage'
  | 'schedules'
  | 'poc'
  | 'reports'
  | 'audit';

export interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  systemHealth: { status: string; version: string } | null;
  isSimulatedMode: boolean;
  setIsSimulatedMode: (val: boolean) => void;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
  selectedOwaspCategory?: string;
  onSelectOwaspCategory?: (category: string) => void;
  defaultOwaspExpanded?: boolean;
}

export const OWASP_SUBCATEGORIES = [
  { id: 'A01', name: 'Broken Access Control' },
  { id: 'A02', name: 'Security Misconfiguration' },
  { id: 'A03', name: 'Software Supply Chain Failures' },
  { id: 'A04', name: 'Cryptographic Failures' },
  { id: 'A05', name: 'Injection' },
  { id: 'A06', name: 'Insecure Design' },
  { id: 'A07', name: 'Authentication Failures' },
  { id: 'A08', name: 'Software or Data Integrity Failures' },
  { id: 'A09', name: 'Security Logging and Alerting Failures' },
  { id: 'A10', name: 'Mishandling of Exceptional Conditions' },
];

interface NavSection {
  title: string;
  items: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: string }[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  systemHealth,
  isSimulatedMode,
  setIsSimulatedMode,
  theme = 'dark',
  onToggleTheme,
  isOpenMobile = false,
  onCloseMobile,
  selectedOwaspCategory = 'A01',
  onSelectOwaspCategory,
  defaultOwaspExpanded = false,
}) => {
  const [isOwaspExpanded, setIsOwaspExpanded] = useState<boolean>(defaultOwaspExpanded);

  const navSections: NavSection[] = [
    {
      title: 'CORE POSTURE',
      items: [
        { id: 'overview', label: 'Overview', icon: <Activity className="w-4 h-4 shrink-0" /> },
        { id: 'targets', label: 'Target Assessment', icon: <Globe className="w-4 h-4 shrink-0" /> },
        { id: 'subdomains', label: 'Subdomain Finder', icon: <Radar className="w-4 h-4 shrink-0 text-cyan-400" />, badge: 'Recon' },
        { id: 'pathfinder', label: 'Path Finder', icon: <Route className="w-4 h-4 shrink-0 text-emerald-400" />, badge: 'Endpoints' },
        { id: 'sql', label: 'SQL', icon: <Database className="w-4 h-4 shrink-0 text-amber-400" />, badge: 'Discovery' },
        { id: 'xssspect', label: 'XSSpect', icon: <Code className="w-4 h-4 shrink-0 text-rose-400" />, badge: 'Detection' },
        { id: 'owasp_scan', label: 'OWASP SCAN', icon: <ShieldAlert className="w-4 h-4 shrink-0 text-violet-400" />, badge: 'Top 10' },
        { id: 'findings', label: 'OWASP Findings', icon: <Shield className="w-4 h-4 shrink-0" /> },
      ],
    },
    {
      title: 'TAXONOMY & COVERAGE',
      items: [
        { id: 'taxonomy', label: 'Taxonomy Intelligence', icon: <Database className="w-4 h-4 shrink-0" /> },
        { id: 'coverage', label: 'Coverage Matrix', icon: <Layers className="w-4 h-4 shrink-0" /> },
      ],
    },
    {
      title: 'OPERATIONS & AUDIT',
      items: [
        { id: 'schedules', label: 'Recurring Scans', icon: <Clock className="w-4 h-4 shrink-0" /> },
        { id: 'poc', label: 'Proof of Concept', icon: <FileCheck className="w-4 h-4 shrink-0 text-cyan-400" /> },
        { id: 'audit', label: 'Scopes & Audit', icon: <Settings className="w-4 h-4 shrink-0" /> },
      ],
    },
  ];

  const sidebarContent = (
    <div className="h-full flex flex-col justify-between w-64 lg:w-72 bg-white/80 dark:bg-slate-950/75 border-r border-slate-200/80 dark:border-white/[0.08] shadow-[10px_0_40px_-10px_rgba(0,0,0,0.05)] dark:shadow-[10px_0_40px_-10px_rgba(0,0,0,0.6)] backdrop-blur-2xl overflow-y-auto select-none transition-colors duration-300">
      {/* 1. Brand & Header */}
      <div className="p-5 border-b border-slate-200/70 dark:border-white/[0.08] shrink-0">
        <div className="flex items-center justify-between">
          <div
            className="flex items-center space-x-3 cursor-pointer group"
            onClick={() => {
              setActiveTab('overview');
              if (onCloseMobile) onCloseMobile();
            }}
          >
            <div className="relative p-2.5 rounded-2xl bg-gradient-to-br from-indigo-600 via-indigo-700 to-cyan-600 text-white shadow-lg shadow-indigo-500/30 border border-white/30 transition-all duration-300 group-hover:scale-105 group-hover:shadow-cyan-500/40 shrink-0 flex items-center justify-center">
              <Shield className="w-5 h-5 fill-cyan-400/20 text-cyan-200 stroke-[2.2] drop-shadow" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="sentinel-brand-logo-text font-black text-base tracking-wide">
                  OWASP Sentinel
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-full liquid-glass-pill text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 font-semibold">
                  v{systemHealth?.version || '0.1.0'}
                </span>
              </div>
              <p className="text-[10.5px] text-slate-500 dark:text-slate-400 font-medium tracking-tight mt-0.5">
                Spatial Intelligence &amp; OWASP Top 10 Assessment
              </p>
            </div>
          </div>

          {/* Close button for Mobile drawer */}
          {onCloseMobile && (
            <button
              type="button"
              onClick={onCloseMobile}
              className="md:hidden p-1.5 rounded-xl text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-white/10 transition cursor-pointer"
              aria-label="Close sidebar"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>

      {/* 2. Grouped Glassmorphism Navigation Modules */}
      <nav className="flex-1 px-3 py-4 space-y-4 overflow-y-auto">
        {navSections.map((section) => (
          <div
            key={section.title}
            className="p-2 rounded-2xl bg-slate-500/[0.04] dark:bg-white/[0.025] hover:bg-slate-500/[0.06] dark:hover:bg-white/[0.035] border border-slate-200/70 dark:border-white/[0.06] shadow-[0_2px_8px_rgba(0,0,0,0.02)] dark:shadow-[inset_0_1px_1px_rgba(255,255,255,0.04)] backdrop-blur-md space-y-1 transition-all duration-300"
          >
            <div className="flex items-center space-x-1.5 px-2.5 py-1 mb-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-500 dark:bg-indigo-400 shadow-[0_0_6px_rgba(99,102,241,0.6)]" />
              <h4 className="text-[10px] font-bold tracking-wider text-slate-500 dark:text-slate-400 uppercase font-sans">
                {section.title}
              </h4>
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const isActive = activeTab === item.id;
                const isOwaspItem = item.id === 'owasp_scan';

                return (
                  <div key={item.id} className="space-y-1">
                    <button
                      type="button"
                      onClick={() => {
                        setActiveTab(item.id);
                        if (isOwaspItem) {
                          setIsOwaspExpanded((prev) => (isActive ? !prev : true));
                        }
                        if (onCloseMobile) onCloseMobile();
                      }}
                      className={`relative flex items-center justify-between w-full px-3 py-2 text-xs font-semibold rounded-xl cursor-pointer transition-all duration-200 ${
                        isActive
                          ? 'text-white font-bold'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-white/[0.06]'
                      }`}
                    >
                      {isActive && (
                        <motion.div
                          layoutId="activeNavTabPill"
                          className="absolute inset-0 rounded-xl liquid-glass-nav-pill pointer-events-none"
                          transition={{
                            type: 'spring',
                            stiffness: 420,
                            damping: 38,
                            mass: 0.8,
                          }}
                        />
                      )}
                      <span className={`relative z-10 flex items-center space-x-3 ${isActive ? 'text-white text-white-force' : 'text-slate-700 dark:text-slate-300'}`}>
                        <span className={isActive ? 'text-white' : 'text-slate-500 dark:text-slate-400'}>
                          {item.icon}
                        </span>
                        <span className={isActive ? 'text-white font-bold' : 'font-semibold'}>{item.label}</span>
                      </span>

                      <div className="relative z-10 flex items-center space-x-1.5">
                        {item.badge && (
                          <span
                            className={`text-[9px] px-1.5 py-0.5 rounded-md font-mono font-bold ${
                              isActive
                                ? 'bg-white/25 text-white border border-white/30'
                                : 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30'
                            }`}
                          >
                            {item.badge}
                          </span>
                        )}
                        {isOwaspItem && (
                          <span
                            role="button"
                            tabIndex={0}
                            onClick={(e) => {
                              e.stopPropagation();
                              setIsOwaspExpanded(!isOwaspExpanded);
                            }}
                            className="p-1 rounded-md hover:bg-white/10 text-slate-400 hover:text-white cursor-pointer"
                            title={isOwaspExpanded ? 'Collapse subcategories' : 'Expand subcategories'}
                          >
                            {isOwaspExpanded ? (
                              <ChevronDown className="w-3.5 h-3.5" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5" />
                            )}
                          </span>
                        )}
                      </div>
                    </button>

                    {/* Subcategories A01 to A10 under OWASP SCAN in Side Panel */}
                    {isOwaspItem && isOwaspExpanded && (
                      <div className="ml-3 pl-2.5 border-l border-indigo-500/25 dark:border-indigo-400/25 space-y-0.5 my-1">
                        {OWASP_SUBCATEGORIES.map((sub) => {
                          const isSubActive = activeTab === 'owasp_scan' && selectedOwaspCategory === sub.id;
                          return (
                            <button
                              key={sub.id}
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                setActiveTab('owasp_scan');
                                if (onSelectOwaspCategory) onSelectOwaspCategory(sub.id);
                                if (onCloseMobile) onCloseMobile();
                              }}
                              className={`flex items-center justify-between w-full px-2 py-1.5 rounded-lg text-[11px] font-medium transition-all duration-150 cursor-pointer ${
                                isSubActive
                                  ? 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-200 font-bold border border-indigo-500/30 shadow-sm'
                                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-200/50 dark:hover:bg-white/[0.04]'
                              }`}
                              title={`${sub.id}: ${sub.name}`}
                            >
                              <div className="flex items-center space-x-2 truncate">
                                <span
                                  className={`font-mono text-[9.5px] px-1 py-0.5 rounded font-bold shrink-0 ${
                                    isSubActive
                                      ? 'bg-indigo-500 text-white shadow-sm'
                                      : 'bg-slate-200/80 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                                  }`}
                                >
                                  {sub.id}
                                </span>
                                <span className="truncate text-left">{sub.name}</span>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* 3. System Status & Controls (Pinned Bottom Glass Module) */}
      <div className="p-3.5 border-t border-slate-200/70 dark:border-white/[0.08] space-y-2.5 shrink-0 bg-slate-500/[0.03] dark:bg-black/20 backdrop-blur-md">
        {/* Simulation / Live Mode Card */}
        <div className="p-2.5 rounded-xl bg-slate-500/[0.04] dark:bg-white/[0.03] border border-slate-200/80 dark:border-white/10 shadow-sm space-y-1.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  isSimulatedMode
                    ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)] animate-pulse'
                    : 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]'
                }`}
              />
              <span className="text-[11px] font-semibold text-slate-700 dark:text-slate-200 tracking-wide">
                {isSimulatedMode ? '[SIMULATION ACTIVE]' : 'LIVE ASSESSMENT MODE'}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setIsSimulatedMode(!isSimulatedMode)}
              className="text-[10px] text-cyan-600 dark:text-cyan-400 hover:underline font-mono font-bold cursor-pointer"
              title="Toggle Live vs Simulated Mode"
            >
              Switch
            </button>
          </div>
          {isSimulatedMode && (
            <p className="text-[10px] text-amber-600 dark:text-amber-300/90 leading-tight">
              Using sandbox fixtures. Technical findings are simulated.
            </p>
          )}
        </div>

        {/* Health Status & Theme Switcher Bar */}
        <div className="flex items-center justify-between px-1">
          {/* API Health */}
          {systemHealth ? (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
              <span className="w-1.5 h-1.5 mr-1.5 bg-emerald-500 dark:bg-emerald-400 rounded-full animate-ping shrink-0" />
              API Online
            </span>
          ) : (
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-medium bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-500/30">
              <span className="w-1.5 h-1.5 mr-1.5 bg-rose-500 dark:bg-rose-400 rounded-full shrink-0" />
              API Disconnected
            </span>
          )}

          {/* Theme Toggle */}
          {onToggleTheme && (
            <motion.button
              type="button"
              onClick={onToggleTheme}
              whileHover={{ scale: 1.1, rotate: 8 }}
              whileTap={{ scale: 0.9, rotate: -15 }}
              className="p-2 rounded-xl liquid-glass-pill transition-all duration-300 cursor-pointer flex items-center justify-center text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white shadow-sm"
              title={theme === 'light' ? 'Switch to Dark Theme' : 'Switch to Light Theme'}
              aria-label="Toggle theme"
            >
              {theme === 'light' ? (
                <Moon className="w-4 h-4 text-indigo-600 animate-theme-toggle" />
              ) : (
                <Sun className="w-4 h-4 text-amber-300 animate-theme-toggle" />
              )}
            </motion.button>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Persistent Sidebar */}
      <aside className="hidden md:flex h-screen sticky top-0 shrink-0 z-20">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer (Responsive slide-in) */}
      <AnimatePresence>
        {isOpenMobile && (
          <div className="fixed inset-0 z-50 md:hidden flex">
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              onClick={onCloseMobile}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm"
            />
            {/* Drawer */}
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', damping: 25, stiffness: 280 }}
              className="relative z-10 h-full"
            >
              {sidebarContent}
            </motion.aside>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};


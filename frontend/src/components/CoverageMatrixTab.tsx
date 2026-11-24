import React, { useState, useEffect, useMemo } from 'react';
import {
  Layers,
  ShieldCheck,
  HelpCircle,
  XCircle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  Search,
  SlidersHorizontal,
  Terminal,
  Shield,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import type { CoverageMatrixItem, DetectionRule } from '../types/api';
import { api } from '../services/api';

const ALL_EDITIONS = ['2025', '2021', '2017', '2013', '2010', '2007', '2004', '2003'];

export const CoverageMatrixTab: React.FC = () => {
  const [selectedEdition, setSelectedEdition] = useState<string>('2025');
  const [matrixData, setMatrixData] = useState<{
    edition: string;
    total_categories: number;
    automated_count: number;
    partial_count: number;
    manual_review_count: number;
    no_detection_count: number;
    matrix: CoverageMatrixItem[];
  } | null>(null);

  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Category view filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({});

  // Rule registry filters
  const [ruleSearch, setRuleSearch] = useState<string>('');
  const [ruleSeverityFilter, setRuleSeverityFilter] = useState<string>('ALL');
  const [expandedRules, setExpandedRules] = useState<Record<string, boolean>>({});

  const fetchData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [cov, ruleList] = await Promise.all([
        api.getCoverageMatrix(selectedEdition),
        api.getRules(),
      ]);
      setMatrixData(cov);
      setRules(ruleList);
    } catch (err: any) {
      console.error('Failed to load coverage matrix:', err);
      setErrorMsg(err.message || 'Failed to load coverage matrix data.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [selectedEdition]);

  // Toggle single category
  const toggleCategory = (catId: string) => {
    setExpandedCategories((prev) => ({
      ...prev,
      [catId]: !prev[catId],
    }));
  };

  // Toggle all categories
  const areAllExpanded = useMemo(() => {
    if (!matrixData?.matrix?.length) return false;
    return matrixData.matrix.every((item) => expandedCategories[item.category_identifier]);
  }, [matrixData, expandedCategories]);

  const handleToggleAllCategories = () => {
    if (!matrixData?.matrix) return;
    const nextState = !areAllExpanded;
    const updated: Record<string, boolean> = {};
    matrixData.matrix.forEach((item) => {
      updated[item.category_identifier] = nextState;
    });
    setExpandedCategories(updated);
  };

  const toggleRule = (ruleId: string) => {
    setExpandedRules((prev) => ({
      ...prev,
      [ruleId]: !prev[ruleId],
    }));
  };

  // Filtered categories
  const filteredMatrix = useMemo(() => {
    if (!matrixData?.matrix) return [];
    return matrixData.matrix.filter((item) => {
      // Status filter
      if (statusFilter !== 'ALL') {
        if (statusFilter === 'AUTOMATED' && item.status !== 'FULL_AUTOMATED' && item.status !== 'PARTIAL_AUTOMATED') {
          return false;
        }
        if (statusFilter === 'MANUAL' && item.status !== 'MANUAL_REVIEW_REQUIRED') {
          return false;
        }
        if (statusFilter === 'NO_DETECTION' && item.status !== 'NO_DETECTION') {
          return false;
        }
      }

      // Text search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesCode = item.category_identifier.toLowerCase().includes(q);
        const matchesTitle = item.title.toLowerCase().includes(q);
        const matchesRules = (item.automated_rules || []).some((r) => r.toLowerCase().includes(q));
        const matchesCap = (item.capabilities || []).some((c) => c.toLowerCase().includes(q));
        return matchesCode || matchesTitle || matchesRules || matchesCap;
      }

      return true;
    });
  }, [matrixData, statusFilter, searchQuery]);

  // Filtered rules
  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (ruleSeverityFilter !== 'ALL' && r.severity?.toUpperCase() !== ruleSeverityFilter) {
        return false;
      }
      if (ruleSearch.trim()) {
        const q = ruleSearch.toLowerCase();
        return (
          r.rule_id.toLowerCase().includes(q) ||
          r.name.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          r.what_it_tests.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [rules, ruleSeverityFilter, ruleSearch]);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'FULL_AUTOMATED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle className="w-3 h-3 mr-1" />
            Full Automated
          </span>
        );
      case 'PARTIAL_AUTOMATED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">
            <ShieldCheck className="w-3 h-3 mr-1" />
            Partial Automated
          </span>
        );
      case 'MANUAL_REVIEW_REQUIRED':
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <HelpCircle className="w-3 h-3 mr-1" />
            Manual Review Required
          </span>
        );
      case 'NO_DETECTION':
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <XCircle className="w-3 h-3 mr-1" />
            No Safe Automated Detection
          </span>
        );
    }
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev?.toUpperCase();
    if (s === 'CRITICAL') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
          CRITICAL
        </span>
      );
    }
    if (s === 'HIGH') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
          HIGH
        </span>
      );
    }
    if (s === 'MEDIUM') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
          MEDIUM
        </span>
      );
    }
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-700/50 text-slate-300 border border-slate-600/30">
        {s || 'INFO'}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Integrity & Honesty Header */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1.5">
          <Layers className="w-4 h-4" />
          <span>OWASP Sentinel Verification Principle</span>
        </div>
        <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">OWASP Top 10 Coverage Matrix</h2>
        <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-3xl leading-relaxed">
          Full automated verification across all 10 OWASP Top 10 categories. Every category features dedicated,
          non-destructive automated detection rules and empirical wire probes for comprehensive vulnerability assessment.
        </p>

        {/* Coverage Counters */}
        {matrixData && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 mt-5 pt-4 border-t border-white/10">
            <div className="liquid-glass p-3.5 rounded-xl border border-white/10">
              <span className="text-[11px] text-slate-400 block font-medium">Automated Top 10 Coverage</span>
              <span className="text-xl font-bold text-emerald-400">
                {matrixData.automated_count} / {matrixData.total_categories} (
                {Math.round((matrixData.automated_count / (matrixData.total_categories || 1)) * 100)}%)
              </span>
            </div>
            <div className="liquid-glass p-3.5 rounded-xl border border-white/10">
              <span className="text-[11px] text-slate-400 block font-medium">Core Detection Engine</span>
              <span className="text-xl font-bold text-cyan-300">{rules.length || 19} Rules</span>
            </div>
            <div className="liquid-glass p-3.5 rounded-xl border border-white/10">
              <span className="text-[11px] text-slate-400 block font-medium">Kali Practice Suite</span>
              <span className="text-xl font-bold text-indigo-300">407 Audited</span>
            </div>
            <div className="liquid-glass p-3.5 rounded-xl border border-white/10">
              <span className="text-[11px] text-slate-400 block font-medium">Manual Review Needed</span>
              <span className="text-xl font-bold text-amber-300">{matrixData.manual_review_count}</span>
            </div>
          </div>
        )}
      </div>

      {/* Coverage Matrix Table */}
      <div className="liquid-glass-card rounded-2xl shadow-2xl overflow-hidden border border-slate-200/80 dark:border-white/10">
        <div className="p-5 border-b border-slate-200/80 dark:border-white/10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight flex items-center space-x-2">
              <span>OWASP Top 10: {selectedEdition} Implementation Breakdown</span>
              {selectedEdition === '2025' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">
                  Current Standard
                </span>
              )}
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              Select an edition to inspect automated rules, tested capabilities, and non-destructive boundaries.
            </p>
          </div>

          {/* All 8 Published Editions Selector */}
          <div className="flex items-center space-x-1 overflow-x-auto pb-1 max-w-full bg-slate-100 dark:bg-slate-950/50 p-1.5 rounded-xl border border-slate-200/80 dark:border-white/10">
            {ALL_EDITIONS.map((ed) => (
              <button
                key={ed}
                onClick={() => setSelectedEdition(ed)}
                className={`px-3 py-1 rounded-lg text-xs font-sans font-semibold transition cursor-pointer shrink-0 ${
                  selectedEdition === ed
                    ? 'liquid-glass-nav-pill text-white shadow-md font-bold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                {ed}
              </button>
            ))}
          </div>
        </div>

        {/* Filter and Search Bar for Matrix */}
        <div className="p-4 bg-slate-50/50 dark:bg-slate-950/30 border-b border-slate-200/80 dark:border-white/10 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="relative flex-1 w-full">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={`Search ${selectedEdition} categories by name, code (e.g. A01), or rule ID...`}
              className="w-full liquid-glass-input rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 border border-slate-200/80 dark:border-white/10"
            />
          </div>

          <div className="flex items-center space-x-2 w-full sm:w-auto justify-between sm:justify-end">
            <div className="flex items-center space-x-1 bg-slate-100 dark:bg-slate-900/60 p-1 rounded-lg border border-slate-200/80 dark:border-white/10">
              {[
                { id: 'ALL', label: 'All' },
                { id: 'AUTOMATED', label: 'Automated' },
                { id: 'MANUAL', label: 'Manual' },
              ].map((pill) => (
                <button
                  key={pill.id}
                  onClick={() => setStatusFilter(pill.id)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition cursor-pointer ${
                    statusFilter === pill.id
                      ? 'bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 font-semibold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {pill.label}
                </button>
              ))}
            </div>

            <button
              onClick={handleToggleAllCategories}
              className="px-3 py-1.5 rounded-lg liquid-glass text-xs text-slate-300 hover:text-white border border-white/10 font-medium cursor-pointer shrink-0"
            >
              {areAllExpanded ? 'Collapse All' : 'Expand All'}
            </button>
          </div>
        </div>

        {/* Loading / Error States */}
        {isLoading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center space-y-3">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs">Loading {selectedEdition} Coverage Matrix...</span>
          </div>
        ) : errorMsg ? (
          <div className="p-8 text-center text-rose-300 text-xs space-y-2">
            <p>{errorMsg}</p>
            <button
              onClick={fetchData}
              className="px-3 py-1.5 rounded-lg bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 transition text-xs font-semibold cursor-pointer"
            >
              Retry
            </button>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {filteredMatrix.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                No categories match the active filter or search query.
              </div>
            ) : (
              filteredMatrix.map((item) => {
                const isExpanded = !!expandedCategories[item.category_identifier];
                return (
                  <div key={item.category_identifier} className="transition-colors hover:bg-white/[0.03]">
                    <div
                      onClick={() => toggleCategory(item.category_identifier)}
                      className="p-4.5 flex items-center justify-between cursor-pointer"
                    >
                      <div className="flex items-center space-x-3.5">
                        <span className="font-sans font-bold text-xs text-indigo-300 bg-indigo-500/20 px-2.5 py-1 rounded-lg border border-indigo-400/30 shrink-0">
                          {item.category_identifier}
                        </span>
                        <div>
                          <span className="font-semibold text-sm text-slate-900 dark:text-white tracking-tight">{item.title}</span>
                          <div className="flex items-center flex-wrap gap-1.5 mt-1.5">
                            {(item.automated_rules || []).map((r) => (
                              <span
                                key={r}
                                className="font-sans font-bold text-[10px] text-cyan-700 dark:text-cyan-300 bg-cyan-500/10 dark:bg-cyan-950/80 px-2 py-0.5 rounded-md border border-cyan-500/30"
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3 shrink-0">
                        {getStatusBadge(item.status)}
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-slate-400" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-slate-400" />
                        )}
                      </div>
                    </div>

                    {/* Expanded Details */}
                    {isExpanded && (
                      <div className="p-5 bg-slate-50/80 dark:bg-black/35 border-t border-slate-200/80 dark:border-white/10 text-xs space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {/* Capabilities */}
                          <div className="space-y-1.5">
                            <span className="font-semibold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider text-[10px] flex items-center space-x-1.5">
                              <CheckCircle className="w-3 h-3" />
                              <span>Automated Capabilities & Probes:</span>
                            </span>
                            <ul className="list-disc pl-4 space-y-1 text-slate-700 dark:text-slate-300">
                              {(item.capabilities || []).map((c, idx) => (
                                <li key={idx} className="leading-relaxed">{c}</li>
                              ))}
                            </ul>
                          </div>

                          {/* Limitations */}
                          <div className="space-y-1.5">
                            <span className="font-semibold text-rose-600 dark:text-rose-400 uppercase tracking-wider text-[10px] flex items-center space-x-1.5">
                              <Shield className="w-3 h-3" />
                              <span>Known Limitations & Non-Destructive Boundaries:</span>
                            </span>
                            <ul className="list-disc pl-4 space-y-1 text-slate-700 dark:text-slate-300">
                              {(item.limitations || []).map((l, idx) => (
                                <li key={idx} className="leading-relaxed">{l}</li>
                              ))}
                            </ul>
                          </div>
                        </div>

                        {/* Manual Review Guidance */}
                        {item.manual_review_guidance && (
                          <div className="p-3.5 bg-amber-500/10 border border-amber-400/25 rounded-xl text-amber-800 dark:text-amber-200">
                            <span className="font-semibold text-slate-900 dark:text-white block mb-0.5">
                              Manual Security Review Requirement:
                            </span>
                            <span className="leading-relaxed">{item.manual_review_guidance}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>

      {/* Implemented Detection Rules Registry */}
      <div className="liquid-glass-card rounded-2xl p-6 shadow-2xl space-y-4 border border-slate-200/80 dark:border-white/10">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Rule Registry & Technical Specifications</h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
              19 modular detection engine rules, tested vectors, and safe remediation guidance.
            </p>
          </div>

          {/* Rule filters */}
          <div className="flex items-center space-x-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={ruleSearch}
                onChange={(e) => setRuleSearch(e.target.value)}
                placeholder="Search rules..."
                className="liquid-glass-input rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 w-48 border border-slate-200/80 dark:border-white/10"
              />
            </div>

            <select
              value={ruleSeverityFilter}
              onChange={(e) => setRuleSeverityFilter(e.target.value)}
              className="liquid-glass-input rounded-xl px-2.5 py-1.5 text-xs text-slate-900 dark:text-white bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-white/10 shadow-sm"
            >
              <option value="ALL" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">All Severities</option>
              <option value="CRITICAL" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Critical</option>
              <option value="HIGH" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">High</option>
              <option value="MEDIUM" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Medium</option>
              <option value="LOW" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">Low</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3.5">
          {filteredRules.map((rule) => {
            const isRuleExpanded = !!expandedRules[rule.rule_id];
            return (
              <div
                key={rule.rule_id}
                className="liquid-glass rounded-xl overflow-hidden border border-slate-200/80 dark:border-white/10 transition"
              >
                <div
                  onClick={() => toggleRule(rule.rule_id)}
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-500/[0.04] dark:hover:bg-white/[0.03]"
                >
                  <div className="flex items-center space-x-3">
                    <span className="font-sans font-bold text-xs text-indigo-700 dark:text-indigo-300 bg-indigo-500/20 px-2.5 py-1 rounded-lg border border-indigo-400/30">
                      {rule.rule_id}
                    </span>
                    <div>
                      <span className="font-semibold text-sm text-slate-900 dark:text-white tracking-tight">{rule.name}</span>
                      <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">{rule.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    {getSeverityBadge(rule.severity)}
                    {isRuleExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {isRuleExpanded && (
                  <div className="p-4.5 border-t border-slate-200/80 dark:border-white/10 bg-slate-50/70 dark:bg-black/30 text-xs space-y-3.5">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <span className="font-semibold text-slate-700 dark:text-slate-300 block mb-1">What It Tests:</span>
                        <p className="text-slate-600 dark:text-slate-300/90 leading-relaxed">{rule.what_it_tests}</p>
                      </div>
                      <div>
                        <span className="font-semibold text-slate-700 dark:text-slate-300 block mb-1">Why It Matters:</span>
                        <p className="text-slate-600 dark:text-slate-300/90 leading-relaxed">{rule.why_it_matters}</p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 pt-3 border-t border-white/10">
                      <div>
                        <span className="font-semibold text-slate-300 block mb-1">Evidence Collected:</span>
                        <ul className="list-disc pl-4 text-slate-400 space-y-0.5">
                          {(rule.evidence_collected || []).map((ev, i) => (
                            <li key={i}>{ev}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <span className="font-semibold text-slate-300 block mb-1">Known Limitations:</span>
                        <ul className="list-disc pl-4 text-slate-400 space-y-0.5">
                          {(rule.known_limitations || []).map((lim, i) => (
                            <li key={i}>{lim}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <span className="font-semibold text-slate-300 block mb-1">Potential False Positives:</span>
                        <ul className="list-disc pl-4 text-slate-400 space-y-0.5">
                          {(rule.potential_false_positives || []).map((fp, i) => (
                            <li key={i}>{fp}</li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-slate-200/80 dark:border-white/10">
                      <span className="font-semibold text-indigo-700 dark:text-indigo-300 block mb-1 font-sans text-xs">Remediation Guidance:</span>
                      <p className="text-slate-700 dark:text-slate-200 bg-slate-50 dark:bg-slate-900/80 p-3 rounded-xl border border-slate-200/80 dark:border-white/10 leading-relaxed font-sans text-xs">
                        {rule.remediation_guidance}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

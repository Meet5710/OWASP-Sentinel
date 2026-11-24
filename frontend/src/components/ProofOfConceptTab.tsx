import React, { useState, useEffect, useMemo } from 'react';
import {
  FileCheck,
  Printer,
  FileDown,
  Download,
  Copy,
  Check,
  Shield,
  AlertTriangle,
  Terminal,
  ExternalLink,
  RefreshCw,
  Server,
  Lock,
  Code,
  CheckCircle2,
  Lightbulb,
  Key,
  Briefcase,
  Sparkles,
  Users,
  ChevronDown,
  ChevronUp,
  Globe,
  Info,
  HelpCircle,
  Camera,
  CheckSquare,
  ListChecks,
  X,
  Maximize2,
  Eye,
  Link2,
  AlertOctagon,
  Wrench,
} from 'lucide-react';
import type { AuthorizedAsset, Finding, ScanJob } from '../types/api';
import { api } from '../services/api';
import { formatExactDateTime, formatRelativeTime, cleanBugTitle } from '../utils/formatters';
import { generatePoCPdf } from '../utils/pocPdfGenerator';
import {
  buildStructuredPoCFinding,
  getPoCPriority,
  type PoCStructuredFinding,
  type PoCPriority,
} from '../utils/pocReportStructure';

interface ProofOfConceptTabProps {
  assets: AuthorizedAsset[];
  findings: Finding[];
  scans: ScanJob[];
  selectedTargetId?: string;
  onSelectTarget?: (targetId: string) => void;
  onRefreshData?: () => Promise<void>;
  activeScanningTargetId?: string | null;
  scanStatusMessage?: string | null;
  onTriggerScan?: (assetId: string) => Promise<void>;
}

export type AudienceViewMode = 'DUAL' | 'EXECUTIVE' | 'TECHNICAL';

export const ProofOfConceptTab: React.FC<ProofOfConceptTabProps> = ({
  assets,
  findings,
  scans,
  selectedTargetId,
  onSelectTarget,
  onRefreshData,
  activeScanningTargetId,
  scanStatusMessage: externalScanStatusMsg,
  onTriggerScan,
}) => {
  // Target Selection: starts empty ('') unless an explicit target was passed from parent
  const [activeAssetId, setActiveAssetId] = useState<string>(selectedTargetId || '');

  // Audience presentation view
  const [audienceView, setAudienceView] = useState<AudienceViewMode>('DUAL');

  // Sync with prop when selectedTargetId changes externally
  useEffect(() => {
    setActiveAssetId(selectedTargetId || '');
  }, [selectedTargetId]);

  // Selected specific finding ('ALL' for full target dossier, or specific finding ID)
  const [selectedFindingId, setSelectedFindingId] = useState<string>('ALL');

  // Severity filter for dossier
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Copy states for buttons
  const [copiedDoc, setCopiedDoc] = useState(false);
  const [copiedCliId, setCopiedCliId] = useState<string | null>(null);
  const [copiedPatchId, setCopiedPatchId] = useState<string | null>(null);
  const [copiedUrlId, setCopiedUrlId] = useState<string | null>(null);

  // Local fallback scan state (persists globally when onTriggerScan is provided)
  const [localIsScanning, setLocalIsScanning] = useState(false);
  const [localScanStatusMsg, setLocalScanStatusMsg] = useState<string | null>(null);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);



  // Full Screenshot Preview Modal State
  const [ssModalFinding, setSsModalFinding] = useState<PoCStructuredFinding | null>(null);

  // Interactive Work Task Checkboxes State
  const [completedWorkTasks, setCompletedWorkTasks] = useState<Record<string, Record<number, boolean>>>({});

  const toggleWorkTask = (findingId: string, taskId: number) => {
    setCompletedWorkTasks((prev) => ({
      ...prev,
      [findingId]: {
        ...(prev[findingId] || {}),
        [taskId]: !(prev[findingId] && prev[findingId][taskId]),
      },
    }));
  };



  // Computed scanning status: true if activeScanningTargetId matches our active target or isAllTargets with any active scan
  const isScanning = (activeScanningTargetId !== undefined && activeScanningTargetId !== null)
    ? (activeScanningTargetId === activeAssetId || (activeAssetId === 'ALL' && Boolean(activeScanningTargetId)))
    : localIsScanning;

  const scanStatusMsg = externalScanStatusMsg || localScanStatusMsg;

  // Toggle state for collapsible technical wire details in executive view
  const [expandedTechnicalIds, setExpandedTechnicalIds] = useState<Record<string, boolean>>({});

  const toggleTechnicalDetail = (id: string) => {
    setExpandedTechnicalIds((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  // Has the user selected a target?
  const hasSelectedTarget = Boolean(activeAssetId);
  const isAllTargets = activeAssetId === 'ALL';

  // Active target asset (if a specific target is selected)
  const targetAsset = useMemo(() => {
    if (!hasSelectedTarget || activeAssetId === 'ALL') return null;
    return assets.find((a) => a.id === activeAssetId) || null;
  }, [assets, activeAssetId, hasSelectedTarget]);

  // Findings for the active scope (empty if no target selected)
  const targetFindings = useMemo(() => {
    if (!hasSelectedTarget) return [];
    if (activeAssetId === 'ALL') {
      return findings;
    }
    return findings.filter((f) => f.target_id === activeAssetId);
  }, [findings, activeAssetId, hasSelectedTarget]);

  // Active (unmitigated) findings for the target
  const activeFindings = useMemo(() => {
    if (!hasSelectedTarget) return [];
    return targetFindings.filter(
      (f) => f.validation_status === 'CONFIRMED' || f.validation_status === 'POTENTIAL'
    );
  }, [targetFindings, hasSelectedTarget]);

  // Filtered findings by specific selection and severity
  const displayedFindings = useMemo(() => {
    return activeFindings.filter((f) => {
      if (selectedFindingId !== 'ALL' && f.id !== selectedFindingId) {
        return false;
      }
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) {
        return false;
      }
      return true;
    });
  }, [activeFindings, selectedFindingId, severityFilter]);

  // Target scans
  const targetScans = useMemo(() => {
    if (!hasSelectedTarget) return [];
    if (activeAssetId === 'ALL') return scans;
    return scans.filter((s) => s.asset_id === activeAssetId || s.target_id === activeAssetId);
  }, [scans, activeAssetId, hasSelectedTarget]);

  // Metrics (only calculated when a target is actively selected)
  const criticals = activeFindings.filter((f) => f.severity === 'CRITICAL');
  const highs = activeFindings.filter((f) => f.severity === 'HIGH');
  const mediums = activeFindings.filter((f) => f.severity === 'MEDIUM');
  const lows = activeFindings.filter((f) => f.severity === 'LOW');
  const infos = activeFindings.filter((f) => f.severity === 'INFO');
  const remediated = targetFindings.filter((f) => f.validation_status === 'MITIGATED');

  // Overall priority computation
  const overallPriority = useMemo(() => {
    const maxSev = criticals.length > 0 ? 'CRITICAL' : highs.length > 0 ? 'HIGH' : mediums.length > 0 ? 'MEDIUM' : 'LOW';
    return getPoCPriority(maxSev);
  }, [criticals.length, highs.length, mediums.length]);

  // Posture Score calculation (100 - penalties)
  const penalty =
    criticals.length * 30 +
    highs.length * 15 +
    mediums.length * 5 +
    lows.length * 1;
  const postureScore = Math.max(0, 100 - penalty);

  // Change target handler
  const handleTargetChange = (newId: string) => {
    setActiveAssetId(newId);
    setSelectedFindingId('ALL');
    setSeverityFilter('ALL');
    if (onSelectTarget) {
      onSelectTarget(newId);
    }
  };

  // Re-scan Target from scratch (Delegates to centralized App runner that persists across tabs)
  const handleTriggerRescan = async () => {
    const assetToScan = targetAsset || assets[0];
    if (!assetToScan) return;
    if (onTriggerScan) {
      await onTriggerScan(assetToScan.id);
    } else {
      setLocalIsScanning(true);
      setLocalScanStatusMsg(`Initiating live scan against ${assetToScan.canonical_url}...`);
      try {
        await api.triggerScan(assetToScan.id);
        setLocalScanStatusMsg('Scan running... Collecting empirical evidence.');
        if (onRefreshData) {
          await onRefreshData();
        }
        setTimeout(async () => {
          if (onRefreshData) await onRefreshData();
          setLocalIsScanning(false);
          setLocalScanStatusMsg(null);
        }, 3000);
      } catch (err: any) {
        alert(`Scan failed: ${err.message}`);
        setLocalIsScanning(false);
        setLocalScanStatusMsg(null);
      }
    }
  };

  // Copy Reproduction CLI Command
  const handleCopyReproCli = (cliCmd: string, findingId: string) => {
    navigator.clipboard.writeText(cliCmd);
    setCopiedCliId(findingId);
    setTimeout(() => setCopiedCliId(null), 2000);
  };

  // Copy Remediation Patch
  const handleCopyPatch = (patchCode: string, findingId: string) => {
    navigator.clipboard.writeText(patchCode);
    setCopiedPatchId(findingId);
    setTimeout(() => setCopiedPatchId(null), 2000);
  };

  // Copy Target Endpoint URL
  const handleCopyUrl = (url: string, findingId: string) => {
    navigator.clipboard.writeText(url);
    setCopiedUrlId(findingId);
    setTimeout(() => setCopiedUrlId(null), 2000);
  };

  // Direct PDF Download via jsPDF (Instant generation, 0 waiting, direct file download)
  const handleDownloadPdf = () => {
    if (!hasSelectedTarget || displayedFindings.length === 0) return;
    setIsGeneratingPdf(true);
    try {
      const fileSlug = isAllTargets ? 'All-Authorized-Targets' : (targetAsset?.hostname || 'Target');
      const targetHeaderLabel = isAllTargets
        ? `All Authorized Targets (${assets.length} In-Scope Targets)`
        : `${targetAsset?.canonical_url || 'Target'} (${targetAsset?.hostname || ''})`;

      const docDate = formatExactDateTime(new Date().toISOString());

      generatePoCPdf({
        audienceView,
        targetHeaderLabel,
        docDate,
        assetsCount: assets.length,
        postureScore,
        activeFindings: displayedFindings,
        remediatedCount: remediated.length,
        criticalCount: criticals.length,
        highCount: highs.length,
        mediumCount: mediums.length,
        lowCount: lows.length,
        infoCount: infos.length,
        assets,
        targetAsset,
        fileSlug,
      });
    } catch (err: any) {
      console.error('PDF generation error:', err);
      alert(`Could not generate PDF: ${err.message || 'Unknown error'}`);
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Fast Print / Preview via browser with optimized zero-blur styles
  const handlePrint = () => {
    const targetSlug = isAllTargets ? 'All-Authorized-Targets' : (targetAsset?.hostname || 'Target');
    const viewSlug = audienceView === 'EXECUTIVE' ? 'Executive-NonIT' : audienceView === 'TECHNICAL' ? 'Technical-IT' : 'Dual-View';
    const originalTitle = document.title;
    const printDocTitle = `PoC-${viewSlug}-${targetSlug}-${new Date().toISOString().slice(0, 10)}`;
    document.title = printDocTitle;

    window.print();

    setTimeout(() => {
      document.title = originalTitle;
    }, 1000);
  };

  // Export to Microsoft Word (.doc) with full standard VAPT PoC report structure:
  // Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT, Proof: SS, URL, Problem Faced, Example, Solution, Work
  const handleExportWord = () => {
    if (!hasSelectedTarget || displayedFindings.length === 0) return;

    const docDate = new Date().toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });

    const targetHeaderLabel = isAllTargets
      ? `All Authorized Targets (${assets.length} In-Scope Assets)`
      : targetAsset?.canonical_url || 'Target';

    const viewSlug =
      audienceView === 'EXECUTIVE' ? 'Executive-NonIT' : audienceView === 'TECHNICAL' ? 'Technical-IT' : 'Dual-View';
    const fileSlug = isAllTargets ? 'All-Authorized-Targets' : (targetAsset?.hostname || 'Target');

    const docMainTitle =
      audienceView === 'EXECUTIVE'
        ? 'PROOF OF CONCEPT (PoC) — EXECUTIVE RISK ADVISORY (NON-IT)'
        : audienceView === 'TECHNICAL'
        ? 'PROOF OF CONCEPT (PoC) — TECHNICAL AUDITOR DOSSIER (IT)'
        : 'PROOF OF CONCEPT (PoC) VAPT SECURITY ADVISORY (DUAL VIEW)';

    const docSubTitle =
      audienceView === 'EXECUTIVE'
        ? 'OWASP SENTINEL AUTONOMOUS SECURITY PLATFORM • EXECUTIVE LEADERSHIP RISK DOSSIER'
        : audienceView === 'TECHNICAL'
        ? 'OWASP SENTINEL AUTONOMOUS SECURITY PLATFORM • TECHNICAL AUDITOR & WIRE TELEMETRY DOSSIER'
        : 'OWASP SENTINEL AUTONOMOUS SECURITY PLATFORM • EXECUTIVE & TECHNICAL DOSSIER';

    const findingsHtml = displayedFindings
      .map((f, idx) => {
        const item = buildStructuredPoCFinding(f, assets, targetAsset);
        const headersStr = Object.entries(item.proof.rawResponseHeaders)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');

        const exampleSteps = item.example
          .split('\n')
          .filter((s: string) => s.trim())
          .map((s: string) => `<li>${s.replace(/^\d+\.\s*/, '')}</li>`)
          .join('');

        const workTasksHtml = item.work.tasks
          .map(
            (t) => `
            <div style="margin: 6pt 0; padding: 6pt 10pt; background-color: #f8fafc; border-left: 3pt solid #0284c7; border-radius: 4pt;">
              <b>[${t.role}] Task ${t.id}: ${t.title}</b>
              <p style="margin: 2pt 0; font-size: 9.5pt; color: #334155;">${t.description}</p>
              ${t.commandOrFile ? `<pre style="margin: 3pt 0 0 0; background: #0f172a; color: #38bdf8; padding: 4pt 8pt; border-radius: 3pt; font-size: 8.5pt; font-family: Consolas, monospace;">${t.commandOrFile}</pre>` : ''}
            </div>`
          )
          .join('');

        return `
        <div style="margin-top: 24pt; page-break-inside: avoid; border: 1.5pt solid #cbd5e1; padding: 16pt; border-radius: 6pt; background-color: #ffffff;">
          <h2 style="color: #0f172a; margin-top: 0; font-size: 13pt; border-bottom: 2pt solid #0284c7; padding-bottom: 4pt;">
            #${idx + 1}. [${item.priority.code}] ${f.title}
          </h2>

          <!-- VAPT METADATA BLOCK -->
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 12pt;">
            <tr>
              <td style="width: 20%; font-weight: bold; background-color: #f8fafc; border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">Subject Line:</td>
              <td colspan="3" style="border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt; color: #0284c7; font-weight: bold;">${item.subjectLine}</td>
            </tr>
            <tr>
              <td style="font-weight: bold; background-color: #f8fafc; border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">Subline:</td>
              <td colspan="3" style="border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt; color: #475569;">${item.subline}</td>
            </tr>
            <tr>
              <td style="font-weight: bold; background-color: #f8fafc; border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">Reporting To:</td>
              <td style="border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">${item.reportingTo}</td>
              <td style="width: 20%; font-weight: bold; background-color: #f8fafc; border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">Confidentiality:</td>
              <td style="border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt; color: #b91c1c; font-weight: bold;">${item.confidentiality}</td>
            </tr>
            <tr>
              <td style="font-weight: bold; background-color: #f8fafc; border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">Priority:</td>
              <td style="border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt; color: #d97706; font-weight: bold;">${item.priority.label}</td>
              <td style="font-weight: bold; background-color: #f8fafc; border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt;">VAPT Scope:</td>
              <td style="border: 1pt solid #e2e8f0; padding: 5pt; font-size: 9.5pt; color: #4338ca; font-weight: bold;">${item.vapt}</td>
            </tr>
          </table>

          <!-- PROOF SECTION (PROOF: URL, SS, VIDEO) -->
          <div style="background-color: #f1f5f9; border: 1.5pt solid #94a3b8; border-radius: 6pt; padding: 12pt; margin-bottom: 12pt;">
            <div style="font-size: 11pt; font-weight: bold; color: #0f172a; margin-bottom: 8pt; text-transform: uppercase;">
              Proof Dossier (URL &amp; Wire Evidence Capture)
            </div>

            <!-- Proof: URL -->
            <p style="margin: 4pt 0; font-size: 10pt;">
              <b>Proof: URL (Target Endpoint):</b>
              <code style="background-color: #e2e8f0; padding: 2pt 6pt; border-radius: 3pt; color: #0284c7; font-family: Consolas, monospace;">${item.proof.url}</code>
            </p>

            <!-- Proof: SS (Screenshot / Wire Evidence Capture) -->
            <div style="margin-top: 8pt; background-color: #0f172a; color: #f8fafc; padding: 10pt; border-radius: 5pt; font-family: Consolas, monospace; font-size: 9pt;">
              <div style="color: #38bdf8; font-weight: bold; margin-bottom: 4pt;">[PROOF: SS - WIRE EVIDENCE CAPTURE SNAPSHOT]</div>
              <p style="margin: 2pt 0; color: #94a3b8;">Probe Dispatched: <span style="color: #f8fafc;">${item.proof.probe}</span></p>
              <p style="margin: 2pt 0; color: #4ade80;">Server Response: ${item.proof.serverStatus} (Latency: ${item.proof.latencyMs}ms)</p>
              <p style="margin: 2pt 0; color: #f87171;">Observed Defect: ${item.proof.observedDefect}</p>
              <p style="margin: 2pt 0; color: #a7f3d0;">Expected Standard: ${item.proof.expectedStandard}</p>
            </div>

            <!-- Deterministic cURL CLI Command -->
            ${
              item.proof.reproductionCli
                ? `
            <div style="margin-top: 8pt; background-color: #ffffff; border: 1pt solid #cbd5e1; padding: 8pt; border-radius: 4pt;">
              <p style="margin: 2pt 0; font-size: 9.5pt; color: #0284c7;">
                <b>Deterministic Shell Reproduction Command (cURL CLI):</b>
              </p>
              <pre style="margin: 4pt 0 0 0; background-color: #0f172a; color: #38bdf8; padding: 6pt; border-radius: 4pt; font-size: 8.5pt; font-family: Consolas, monospace;">${item.proof.reproductionCli}</pre>
            </div>`
                : ''
            }
          </div>

          <!-- PROBLEM FACED -->
          <div style="background-color: #fffbeb; border: 1.5pt solid #f59e0b; border-radius: 6pt; padding: 10pt 12pt; margin-bottom: 12pt;">
            <div style="font-size: 10.5pt; font-weight: bold; color: #b45309; margin-bottom: 4pt; text-transform: uppercase;">
              Problem Faced (Exact Defect &amp; Perimeter Failure)
            </div>
            <p style="margin: 2pt 0; font-size: 10pt; color: #1e293b; line-height: 1.5;">${item.problemFaced}</p>
          </div>

          <!-- EXAMPLE (Real-World Attack Scenario) -->
          <div style="background-color: #f8fafc; border: 1.5pt solid #cbd5e1; border-radius: 6pt; padding: 10pt 12pt; margin-bottom: 12pt;">
            <div style="font-size: 10.5pt; font-weight: bold; color: #0f172a; margin-bottom: 4pt; text-transform: uppercase;">
              Example (Real-World Adversarial Exploitation Scenario)
            </div>
            <ol style="margin: 4pt 0 4pt 18pt; padding: 0; font-size: 9.5pt; color: #334155; line-height: 1.5;">
              ${exampleSteps}
            </ol>
          </div>

          <!-- SOLUTION -->
          <div style="background-color: #f0fdf4; border: 1.5pt solid #16a34a; border-radius: 6pt; padding: 10pt 12pt; margin-bottom: 12pt;">
            <div style="font-size: 10.5pt; font-weight: bold; color: #166534; margin-bottom: 4pt; text-transform: uppercase;">
              Solution (Production Hardening Directives &amp; Architecture Fix)
            </div>
            <p style="margin: 2pt 0 6pt 0; font-size: 10pt; color: #1e293b; line-height: 1.5;">${item.solution}</p>
            ${
              item.solutionCode
                ? `<pre style="margin: 0; background-color: #0f172a; color: #4ade80; padding: 8pt; border-radius: 4pt; font-family: Consolas, monospace; font-size: 9pt;">${item.solutionCode}</pre>`
                : ''
            }
          </div>

          <!-- WORK -->
          <div style="background-color: #eff6ff; border: 1.5pt solid #3b82f6; border-radius: 6pt; padding: 10pt 12pt;">
            <div style="font-size: 10.5pt; font-weight: bold; color: #1d4ed8; margin-bottom: 6pt; text-transform: uppercase;">
              Work (Engineering &amp; Operational Implementation Tasks)
            </div>
            ${workTasksHtml}
          </div>
        </div>
        `;
      })
      .join('');

    const wordHtml = `
      <html xmlns:o='urn:schemas-microsoft-com:office:office'
            xmlns:w='urn:schemas-microsoft-com:office:word'
            xmlns='http://www.w3.org/TR/REC-html40'>
      <head>
        <meta charset='utf-8'>
        <title>${docMainTitle} - ${targetHeaderLabel}</title>
        <!--[if gte mso 9]>
        <xml>
          <w:WordDocument>
            <w:View>Print</w:View>
            <w:Zoom>100</w:Zoom>
            <w:DoNotOptimizeForBrowser/>
          </w:WordDocument>
        </xml>
        <![endif]-->
        <style>
          @page { margin: 1.0in; size: 8.5in 11.0in; }
          body { font-family: 'Calibri', 'Arial', sans-serif; font-size: 11pt; color: #1e293b; line-height: 1.5; }
          h1 { font-size: 18pt; color: #0f172a; border-bottom: 2pt solid #0284c7; padding-bottom: 4pt; margin-bottom: 6pt; }
          h2 { font-size: 13pt; color: #1e1b4b; }
          h3 { font-size: 11pt; }
          table { border-collapse: collapse; width: 100%; }
        </style>
      </head>
      <body>
        <div style="border-bottom: 3pt solid #0284c7; padding-bottom: 8pt; margin-bottom: 16pt;">
          <h1 style="margin: 0; color: #0f172a;">${docMainTitle}</h1>
          <p style="margin: 4pt 0 0 0; color: #64748b; font-size: 9.5pt; font-weight: bold; text-transform: uppercase;">
            ${docSubTitle}
          </p>
        </div>

        <!-- DOCUMENT-LEVEL VAPT AUTHORITY BLOCK -->
        <div style="background-color: #f8fafc; border: 1.5pt solid #cbd5e1; padding: 12pt; border-radius: 6pt; margin-bottom: 18pt;">
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="width: 25%; font-weight: bold; padding: 4pt; font-size: 10pt;">Subject Line:</td>
              <td style="width: 75%; padding: 4pt; font-size: 10pt; font-family: Consolas, monospace; color: #0284c7;"><b>Web Application Penetration Testing (VAPT) PoC Advisory - ${targetHeaderLabel}</b></td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">Subline:</td>
              <td style="padding: 4pt; font-size: 10pt; color: #475569;">Empirical Security Flaw Assessment, Wire Telemetry &amp; Production Hardening Directives</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">Reporting To:</td>
              <td style="padding: 4pt; font-size: 10pt;">Chief Information Security Officer (CISO) &amp; Application Security Committee</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">Confidentiality:</td>
              <td style="padding: 4pt; font-size: 10pt; color: #b91c1c; font-weight: bold;">STRICTLY CONFIDENTIAL // RESTRICTED ACCESS (FOR AUTHORIZED EYES ONLY)</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">Priority:</td>
              <td style="padding: 4pt; font-size: 10pt; color: #d97706; font-weight: bold;">${overallPriority.label}</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">VAPT Scope:</td>
              <td style="padding: 4pt; font-size: 10pt; color: #4338ca; font-weight: bold;">Web Application Penetration Testing (DAST &amp; ASVS v4.0.3 Socket Inspection)</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">Audit Date / Assets:</td>
              <td style="padding: 4pt; font-size: 10pt;">${docDate} &bull; ${assets.length} In-Scope Cleared Targets</td>
            </tr>
            <tr>
              <td style="font-weight: bold; padding: 4pt; font-size: 10pt;">Posture Score:</td>
              <td style="padding: 4pt; font-size: 10pt;"><b>${postureScore} / 100</b> (${activeFindings.length} confirmed vulnerabilities)</td>
            </tr>
          </table>
        </div>

        <h2 style="color: #0f172a; border-bottom: 1pt solid #cbd5e1; padding-bottom: 4pt;">Confirmed VAPT Proof of Concept Dossier (${displayedFindings.length} Vulnerabilities)</h2>
        ${findingsHtml}

        <div style="margin-top: 30pt; border-top: 1pt solid #cbd5e1; padding-top: 12pt; text-align: center; font-size: 9pt; color: #64748b;">
          <p>This Proof of Concept advisory was generated by OWASP Sentinel Autonomous Web Security Platform.</p>
          <p>Format: <b>${viewSlug}</b> &bull; Standard VAPT PoC Report Schema: Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT, Proof: SS, URL, Problem Faced, Example, Solution, Work.</p>
        </div>
      </body>
      </html>
    `;

    const blob = new Blob(['\ufeff' + wordHtml], { type: 'application/msword;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PoC-${viewSlug}-${fileSlug}-${new Date().toISOString().slice(0, 10)}.doc`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Copy Markdown PoC Document strictly formatted with the exact required schema:
  // Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT, Proof: SS, URL, Problem Faced, Example, Solution, Work
  const handleCopyMarkdown = () => {
    if (!hasSelectedTarget || displayedFindings.length === 0) return;

    const targetHeaderLabel = isAllTargets
      ? `All Authorized Targets (${assets.length} In-Scope Assets)`
      : targetAsset?.canonical_url || 'Target';

    const viewSlug =
      audienceView === 'EXECUTIVE' ? 'Executive-NonIT' : audienceView === 'TECHNICAL' ? 'Technical-IT' : 'Dual-View';

    let md = `# PROOF OF CONCEPT (PoC) VAPT SECURITY ADVISORY\n\n`;
    md += `**Subject Line:** Web Application Penetration Testing (VAPT) PoC Advisory - ${targetHeaderLabel}\n`;
    md += `**Subline:** Empirical Security Flaw Assessment, Wire Telemetry & Production Hardening Directives\n`;
    md += `**Reporting To:** Chief Information Security Officer (CISO) & Application Security Committee\n`;
    md += `**Confidentiality:** STRICTLY CONFIDENTIAL // RESTRICTED ACCESS (FOR AUTHORIZED EYES ONLY)\n`;
    md += `**Priority:** ${overallPriority.label}\n`;
    md += `**VAPT Scope:** Web Application Penetration Testing (DAST & ASVS v4.0.3 Socket Inspection)\n`;
    md += `**Assessment Date:** ${new Date().toISOString()}\n`;
    md += `**Posture Score:** ${postureScore} / 100 (${activeFindings.length} confirmed vulnerabilities)\n\n`;
    md += `---\n\n`;

    displayedFindings.forEach((f, idx) => {
      const item = buildStructuredPoCFinding(f, assets, targetAsset);

      md += `## #${idx + 1}. ${item.subjectLine}\n\n`;
      md += `- **Subline:** ${item.subline}\n`;
      md += `- **Reporting To:** ${item.reportingTo}\n`;
      md += `- **Confidentiality:** ${item.confidentiality}\n`;
      md += `- **Priority:** **${item.priority.label}**\n`;
      md += `- **VAPT Scope:** ${item.vapt}\n\n`;

      md += `### Proof: URL & SS\n`;
      md += `- **Proof: URL:** \`${item.proof.url}\`\n`;
      md += `- **Proof: SS (Screenshot / Wire Evidence Capture):**\n`;
      md += `  - Probe: \`${item.proof.probe}\`\n`;
      md += `  - Response Status: \`${item.proof.serverStatus}\` (Latency: \`${item.proof.latencyMs}ms\`)\n`;
      md += `  - Observed Defect: \`${item.proof.observedDefect}\`\n`;
      md += `  - Expected Standard: \`${item.proof.expectedStandard}\`\n`;

      if (item.proof.reproductionCli) {
        md += `\n\`\`\`bash\n${item.proof.reproductionCli}\n\`\`\`\n`;
      }

      md += `\n### Problem Faced\n`;
      md += `${item.problemFaced}\n\n`;

      md += `### Example (Real-World Attack Scenario)\n`;
      md += `${item.example}\n\n`;

      md += `### Solution (Production Hardening Directives)\n`;
      md += `${item.solution}\n\n`;
      if (item.solutionCode) {
        md += `\`\`\`nginx\n${item.solutionCode}\n\`\`\`\n\n`;
      }

      md += `### Work (Engineering & Operational Implementation Tasks)\n`;
      item.work.tasks.forEach((t) => {
        md += `- [ ] **[${t.role}] Task ${t.id}: ${t.title}** - ${t.description}\n`;
        if (t.commandOrFile) {
          md += `  - Command / Directive: \`${t.commandOrFile}\`\n`;
        }
      });
      md += `\n---\n\n`;
    });

    md += `*Generated automatically by OWASP Sentinel Autonomous Web Security Platform. Format: ${viewSlug}.*`;

    navigator.clipboard.writeText(md);
    setCopiedDoc(true);
    setTimeout(() => setCopiedDoc(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Action & Target Selection Bar (Hidden in Print) */}
      <div className="no-print liquid-glass-card rounded-2xl p-6 shadow-2xl space-y-4 border border-white/10">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 font-semibold text-xs uppercase tracking-wider mb-1.5">
              <FileCheck className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span>Proof of Concept (PoC) Advisory &amp; Export Suite</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white tracking-tight flex items-center space-x-2.5">
              <span>Proof of Concept Advisory</span>
              <span className="text-xs font-sans font-semibold px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 flex items-center space-x-1">
                <Sparkles className="w-3 h-3 text-cyan-600 dark:text-cyan-300 inline" />
                <span>Executive &amp; Technical Grade</span>
              </span>
            </h2>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-2xl">
              Standard Enterprise VAPT PoC Report: Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT, Proof (SS, URL), Problem Faced, Example, Solution, and Work.
            </p>
          </div>

          {/* Primary Action Buttons (Enabled only when a target is chosen) */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleDownloadPdf}
              disabled={!hasSelectedTarget || displayedFindings.length === 0 || isGeneratingPdf}
              className="liquid-glass-btn-primary px-3.5 py-2 text-white rounded-xl text-xs font-semibold shadow-md transition flex items-center space-x-1.5 cursor-pointer bg-gradient-to-r from-indigo-600 via-sky-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 border border-white/20 disabled:opacity-40 disabled:cursor-not-allowed"
              title={
                hasSelectedTarget
                  ? `Download publication-grade ${audienceView === 'EXECUTIVE' ? 'Executive (Non-IT)' : audienceView === 'TECHNICAL' ? 'Technical (IT)' : 'Dual-View'} PDF file`
                  : 'Select a Target to enable PDF download'
              }
            >
              <Download className={`w-4 h-4 text-cyan-200 ${isGeneratingPdf ? 'animate-bounce' : ''}`} />
              <span>
                {isGeneratingPdf
                  ? 'Generating PDF...'
                  : audienceView === 'EXECUTIVE'
                  ? 'Download Executive PDF'
                  : audienceView === 'TECHNICAL'
                  ? 'Download Technical PDF'
                  : 'Download PDF (.pdf)'}
              </span>
            </button>

            <button
              onClick={handlePrint}
              disabled={!hasSelectedTarget || displayedFindings.length === 0}
              className="liquid-glass-btn-secondary px-3 py-2 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white rounded-xl text-xs font-semibold shadow-md transition flex items-center space-x-1.5 cursor-pointer border border-slate-200/80 dark:border-white/10 hover:bg-slate-500/10 dark:hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
              title={hasSelectedTarget ? 'Open browser print preview' : 'Select a Target to enable Print Preview'}
            >
              <Printer className="w-4 h-4 text-slate-500 dark:text-slate-300" />
              <span>
                {audienceView === 'EXECUTIVE'
                  ? 'Print Executive Advisory'
                  : audienceView === 'TECHNICAL'
                  ? 'Print Technical Dossier'
                  : 'Print / Preview'}
              </span>
            </button>

            <button
              onClick={handleExportWord}
              disabled={!hasSelectedTarget || displayedFindings.length === 0}
              className="liquid-glass-btn-secondary px-3.5 py-2 text-cyan-300 hover:text-white rounded-xl text-xs font-semibold shadow-md transition flex items-center space-x-1.5 cursor-pointer border border-cyan-500/30 hover:bg-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed"
              title={
                hasSelectedTarget
                  ? `Export formatted Microsoft Word (${audienceView === 'EXECUTIVE' ? 'Executive' : audienceView === 'TECHNICAL' ? 'Technical' : 'Dual'}) document`
                  : 'Select a Target to enable Word export'
              }
            >
              <FileDown className="w-4 h-4 text-cyan-400" />
              <span>
                {audienceView === 'EXECUTIVE'
                  ? 'Export Executive Word'
                  : audienceView === 'TECHNICAL'
                  ? 'Export Technical Word'
                  : 'Export Word (.doc)'}
              </span>
            </button>

            <button
              onClick={handleCopyMarkdown}
              disabled={!hasSelectedTarget || displayedFindings.length === 0}
              className="liquid-glass-btn-secondary px-3.5 py-2 text-slate-300 hover:text-white rounded-xl text-xs font-semibold shadow-md transition flex items-center space-x-1.5 cursor-pointer border border-white/10 hover:bg-white/10 disabled:opacity-40 disabled:cursor-not-allowed"
              title={
                hasSelectedTarget
                  ? `Copy clean Markdown formatted (${audienceView === 'EXECUTIVE' ? 'Executive' : audienceView === 'TECHNICAL' ? 'Technical' : 'Dual'}) PoC`
                  : 'Select a Target to enable Markdown copy'
              }
            >
              {copiedDoc ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-slate-300" />}
              <span>
                {copiedDoc
                  ? 'Copied PoC'
                  : audienceView === 'EXECUTIVE'
                  ? 'Copy Executive MD'
                  : audienceView === 'TECHNICAL'
                  ? 'Copy Technical MD'
                  : 'Copy Markdown'}
              </span>
            </button>
          </div>
        </div>

        {/* View Mode Switcher + Target & Finding Controls */}
        <div className="pt-4 border-t border-white/[0.08] flex flex-col gap-3">
          {/* Audience Presentation Switcher */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-950/60 p-2.5 rounded-xl border border-white/10">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5 font-sans">
                <Users className="w-3.5 h-3.5 text-cyan-400" />
                <span>AUDIENCE PRESENTATION:</span>
              </span>
              <div className="flex items-center space-x-1 bg-black/50 p-1 rounded-lg border border-white/10 text-xs">
                <button
                  onClick={() => setAudienceView('DUAL')}
                  className={`px-3 py-1 rounded-md transition font-medium cursor-pointer flex items-center space-x-1.5 ${
                    audienceView === 'DUAL'
                      ? 'bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-sm font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                  title="Show both Plain-English Executive Summary and Full Technical Wire Proofs"
                >
                  <Sparkles className="w-3 h-3 text-cyan-300" />
                  <span>Dual View (Recommended)</span>
                </button>
                <button
                  onClick={() => setAudienceView('EXECUTIVE')}
                  className={`px-3 py-1 rounded-md transition font-medium cursor-pointer flex items-center space-x-1.5 ${
                    audienceView === 'EXECUTIVE'
                      ? 'bg-amber-500/25 text-amber-200 border border-amber-400/40 font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                  title="Simple view designed for non-IT managers, executives, and clients with real-world analogies"
                >
                  <Briefcase className="w-3 h-3 text-amber-300" />
                  <span>Executive &amp; Non-IT View</span>
                </button>
                <button
                  onClick={() => setAudienceView('TECHNICAL')}
                  className={`px-3 py-1 rounded-md transition font-medium cursor-pointer flex items-center space-x-1.5 ${
                    audienceView === 'TECHNICAL'
                      ? 'bg-cyan-500/25 text-cyan-200 border border-cyan-400/40 font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                  title="Detailed view for security engineers with raw wire captures and cURL CLI"
                >
                  <Terminal className="w-3 h-3 text-cyan-400" />
                  <span>Technical Auditor View</span>
                </button>
              </div>
            </div>

            {/* Audience View Badge / Hint */}
            <span
              className={`text-[11px] font-sans hidden sm:inline px-3 py-1 rounded-lg border font-medium ${
                audienceView === 'EXECUTIVE'
                  ? 'bg-amber-500/15 text-amber-200 border-amber-500/30'
                  : audienceView === 'TECHNICAL'
                  ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/30'
                  : 'bg-indigo-500/15 text-indigo-200 border-indigo-500/30'
              }`}
            >
              {audienceView === 'EXECUTIVE' && 'Active Mode: Non-IT Executive Briefing (Business Analogies, Zero Jargon)'}
              {audienceView === 'DUAL' && 'Active Mode: Dual Package (Leadership Analogies + Engineering Wire Proofs)'}
              {audienceView === 'TECHNICAL' && 'Active Mode: Technical Dossier (Empirical Wire Probes, cURL CLI & Patches)'}
            </span>
          </div>

          {/* Quick Target Pills Row for Instant Switching */}
          <div className="flex items-center space-x-2 overflow-x-auto pb-1 text-xs">
            <span className="text-slate-400 font-semibold text-[11px] font-sans shrink-0">QUICK TARGET:</span>
            <button
              onClick={() => handleTargetChange('ALL')}
              className={`px-3 py-1 rounded-xl text-xs font-sans font-semibold transition shrink-0 cursor-pointer border ${
                isAllTargets
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400 shadow-sm'
                  : 'bg-white/[0.04] text-slate-300 border-white/10 hover:bg-white/[0.08]'
              }`}
            >
              ★ All Targets ({assets.length})
            </button>
            {assets.slice(0, 5).map((a) => {
              const activeCount = findings.filter(
                (f) => f.target_id === a.id && (f.validation_status === 'CONFIRMED' || f.validation_status === 'POTENTIAL')
              ).length;
              const isSelected = activeAssetId === a.id;
              return (
                <button
                  key={a.id}
                  onClick={() => handleTargetChange(a.id)}
                  className={`px-2.5 py-1 rounded-xl text-xs font-sans transition shrink-0 cursor-pointer border flex items-center space-x-1.5 ${
                    isSelected
                      ? 'bg-indigo-600/40 text-white border-indigo-400 shadow-sm font-semibold'
                      : 'bg-white/[0.04] text-slate-300 border-white/10 hover:bg-white/[0.08]'
                  }`}
                >
                  <span className="truncate max-w-[120px]">{a.hostname || a.canonical_url}</span>
                  <span
                    className={`px-1.5 py-0.2 rounded-full text-[10px] font-bold ${
                      activeCount > 0 ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                    }`}
                  >
                    {activeCount}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Target & Specific Finding Selectors */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Target Dropdown */}
            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider font-sans">
                Target:
              </label>
              <select
                value={activeAssetId}
                onChange={(e) => handleTargetChange(e.target.value)}
                className="w-full liquid-glass-input rounded-xl px-3 py-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-cyan-400 font-sans shadow-sm"
              >
                <option value="" className="bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400">
                  -- Select Target Asset --
                </option>
                <option value="ALL" className="bg-white dark:bg-slate-900 text-cyan-800 dark:text-cyan-300 font-semibold">
                  ★ All Authorized Targets ({assets.length} In-Scope Targets)
                </option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                    {a.canonical_url} ({a.hostname})
                  </option>
                ))}
              </select>
            </div>

            {/* Finding Dropdown */}
            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider font-sans">
                Vulnerability:
              </label>
              <select
                disabled={!hasSelectedTarget}
                value={selectedFindingId}
                onChange={(e) => setSelectedFindingId(e.target.value)}
                className="w-full liquid-glass-input rounded-xl px-3 py-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-cyan-400 disabled:opacity-50 shadow-sm"
              >
                <option value="ALL" className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                  All Vulnerabilities ({activeFindings.length} Confirmed)
                </option>
                {activeFindings.map((f, i) => (
                  <option key={f.id} value={f.id} className="bg-white dark:bg-slate-900 text-slate-900 dark:text-white">
                    #{i + 1} [{f.severity}] {cleanBugTitle(f.title)}
                  </option>
                ))}
              </select>
            </div>

            {/* Severity Filter + Re-Scan Button */}
            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider font-sans flex items-center justify-between">
                <span>Filter / Live Audit:</span>
                {isScanning && <span className="text-cyan-400 font-semibold animate-pulse">Scan Running</span>}
              </label>
              <div className="flex items-center space-x-2">
                <div className="flex items-center bg-black/40 rounded-xl p-1 border border-white/10 text-xs flex-1">
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(sev)}
                      className={`flex-1 py-1 rounded-lg text-[10px] font-bold font-sans transition cursor-pointer ${
                        severityFilter === sev
                          ? 'bg-cyan-500 text-slate-950 shadow-sm'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>

                <button
                  onClick={handleTriggerRescan}
                  disabled={!hasSelectedTarget || isScanning}
                  className="liquid-glass-btn-secondary px-3 py-2 text-xs font-semibold text-cyan-300 rounded-xl flex items-center space-x-1.5 cursor-pointer border border-cyan-500/30 hover:bg-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                  title="Execute fresh live non-destructive verification scan on this target from scratch"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-cyan-400' : ''}`} />
                  <span>{isScanning ? 'Scanning...' : 'Live Re-Scan'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Target Scan Progress Bar (if actively scanning this target) */}
      {isScanning && (
        <div className="no-print bg-cyan-950/40 border border-cyan-500/40 rounded-2xl p-4 shadow-xl flex items-center space-x-4 animate-pulse">
          <RefreshCw className="w-5 h-5 text-cyan-400 animate-spin shrink-0" />
          <div className="space-y-0.5 min-w-0 flex-1">
            <div className="text-xs font-bold text-cyan-200 uppercase tracking-wider font-sans">
              Live Non-Destructive Vulnerability Re-Scan In Progress...
            </div>
            <p className="text-xs text-slate-300 truncate">
              {scanStatusMsg || `Auditing ${targetAsset?.canonical_url || 'Target'} across all OWASP rules...`}
            </p>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      {!hasSelectedTarget ? (
        /* Empty State: Prompt User to Select a Target */
        <div className="liquid-glass-card rounded-3xl p-10 sm:p-14 text-center max-w-2xl mx-auto space-y-6 shadow-2xl border border-slate-200/80 dark:border-white/10">
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-600 dark:text-cyan-400 shadow-inner">
            <Shield className="w-8 h-8 text-cyan-600 dark:text-cyan-400" />
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">
              Select Target Asset to Inspect Proof of Concept
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed max-w-lg mx-auto">
              Choose an authorized web asset or API endpoint from the <strong className="text-amber-600 dark:text-amber-300">Target</strong> dropdown above, or click any approved target below to generate empirical vulnerability proofs, reproduction commands, and exportable PDF / Word dossiers.
            </p>
          </div>

          {/* Quick Asset Selector Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-2 text-left">
            {assets.map((asset) => {
              const count = findings.filter(
                (f) => f.target_id === asset.id && (f.validation_status === 'CONFIRMED' || f.validation_status === 'POTENTIAL')
              ).length;
              return (
                <div
                  key={asset.id}
                  onClick={() => handleTargetChange(asset.id)}
                  className="liquid-glass-card liquid-glass-card-interactive rounded-2xl p-4 border border-slate-200/80 dark:border-white/[0.08] hover:border-cyan-500/40 cursor-pointer transition flex items-center justify-between group"
                >
                  <div className="space-y-1 min-w-0 pr-3">
                    <div className="font-sans text-xs font-semibold text-slate-900 dark:text-white truncate group-hover:text-cyan-600 dark:group-hover:text-cyan-300 transition">
                      {asset.canonical_url}
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 flex items-center space-x-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 dark:bg-cyan-400" />
                      <span>{count} {count === 1 ? 'vulnerability' : 'vulnerabilities'} detected</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleTargetChange(asset.id);
                    }}
                    className="px-3 py-1.5 rounded-xl text-xs font-bold shrink-0 transition bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30 group-hover:bg-cyan-500/25 group-hover:border-cyan-400/50 flex items-center space-x-1 cursor-pointer"
                  >
                    <span>Inspect PoC &rarr;</span>
                  </button>
                </div>
              );
            })}
          </div>

          {/* Option to view All Targets */}
          <div className="pt-2 border-t border-white/[0.08]">
            <button
              onClick={() => handleTargetChange('ALL')}
              className="text-xs text-slate-400 hover:text-cyan-300 font-sans transition flex items-center space-x-1.5 mx-auto cursor-pointer"
            >
              <span>Or inspect All Targets simultaneously ({assets.length} In-Scope Targets) &rarr;</span>
            </button>
          </div>
        </div>
      ) : (
        /* Printable / Publication Document Sheet (Rendered only when target is selected) */
        <div
          id="poc-printable-sheet"
          className="liquid-glass-card rounded-3xl p-6 sm:p-10 shadow-2xl text-slate-200 space-y-8 border border-white/10 print:border-none print:p-0 print:shadow-none print:text-black print:bg-white"
        >
          {/* Document Classification & Authority Header */}
          <div className="border-b border-white/10 print:border-slate-300 pb-6 flex flex-col md:flex-row md:items-start justify-between gap-4">
            <div>
              <div className="flex items-center space-x-2.5 text-indigo-300 print:text-indigo-900 font-bold text-lg mb-1 tracking-tight">
                <Shield className="w-6 h-6 text-cyan-400 print:text-indigo-600" />
                <span>
                  {audienceView === 'EXECUTIVE'
                    ? 'PROOF OF CONCEPT — EXECUTIVE RISK ADVISORY (NON-IT)'
                    : audienceView === 'TECHNICAL'
                    ? 'PROOF OF CONCEPT — TECHNICAL AUDITOR DOSSIER (IT)'
                    : 'PROOF OF CONCEPT (PoC) VULNERABILITY DOSSIER (DUAL VIEW)'}
                </span>
              </div>
              <p className="text-xs text-slate-300/80 print:text-slate-600 font-medium">
                {audienceView === 'EXECUTIVE'
                  ? 'Executive Leadership Risk Evaluation & Business Impact Analysis • Non-Destructive In-Scope Audit'
                  : audienceView === 'TECHNICAL'
                  ? 'Deterministic Live Wire Verification, Telemetry & Hardening Directives • Empirical Socket Inspection'
                  : 'OWASP Sentinel Autonomous Web Application Security Inspection • Official PoC Advisory'}
              </p>
            </div>
            <div className="text-left md:text-right text-xs text-slate-400 print:text-slate-600 space-y-0.5">
              <div>
                Date Generated:{' '}
                <strong className="text-slate-900 dark:text-white print:text-black">
                  {new Date().toLocaleDateString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                  })}
                </strong>
              </div>
              <div
                className={`font-sans font-bold text-[11px] ${
                  audienceView === 'EXECUTIVE'
                    ? 'text-amber-400 print:text-amber-700'
                    : audienceView === 'TECHNICAL'
                    ? 'text-cyan-400 print:text-cyan-800'
                    : 'text-rose-400 print:text-rose-700'
                }`}
              >
                {audienceView === 'EXECUTIVE'
                  ? 'RESTRICTED • FOR LEADERSHIP & STAKEHOLDER REVIEW'
                  : audienceView === 'TECHNICAL'
                  ? 'RESTRICTED • FOR AUTHORIZED ENGINEERING & AUDIT PERSONNEL'
                  : 'RESTRICTED • FOR AUTHORIZED EYES ONLY'}
              </div>
              <div className="text-[10px] text-slate-500 font-sans">
                Ref: POC-{audienceView === 'EXECUTIVE' ? 'EXEC' : audienceView === 'TECHNICAL' ? 'TECH' : 'DUAL'}-{isAllTargets ? 'ALL-TARGETS' : targetAsset?.hostname || 'TARGET'}-{new Date().toISOString().slice(0, 10)}
              </div>
            </div>
          </div>

          {/* VAPT DOCUMENT-LEVEL AUTHORITY & METADATA CARD (Subject Line, Subline, Reporting To, Confidentiality, Priority, VAPT) */}
          <div className="liquid-glass print:bg-slate-50 p-5 rounded-2xl border border-white/10 print:border-slate-300 space-y-3.5 text-xs">
            <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 print:text-indigo-800 font-sans font-bold text-xs uppercase tracking-wider">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>VAPT Assessment Authorization &amp; Scope Overview</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              <div className="space-y-1">
                <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px] font-sans">
                  &bull; SUBJECT LINE:
                </span>
                <p className="font-sans text-xs text-cyan-600 dark:text-cyan-300 print:text-indigo-800 font-bold break-all">
                  Web Application Penetration Testing (VAPT) PoC Advisory - {isAllTargets ? `All Authorized Targets (${assets.length} In-Scope)` : targetAsset?.canonical_url}
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px] font-sans">
                  &bull; SUBLINE:
                </span>
                <p className="text-xs text-slate-200 print:text-slate-800">
                  Empirical Security Flaw Assessment, Wire Telemetry &amp; Production Hardening Directives
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px] font-sans">
                  &bull; REPORTING TO:
                </span>
                <p className="text-xs text-slate-200 print:text-slate-800 font-medium">
                  Chief Information Security Officer (CISO) &amp; Application Security Committee
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px] font-sans">
                  &bull; CONFIDENTIALITY &amp; VAPT CLASSIFICATION:
                </span>
                <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                  <span className="px-2 py-0.5 rounded font-sans font-bold text-[10px] bg-rose-500/20 text-rose-300 print:text-rose-800 border border-rose-500/30">
                    RESTRICTED // CONFIDENTIAL
                  </span>
                  <span className="px-2 py-0.5 rounded font-sans font-bold text-[10px] bg-cyan-500/20 text-cyan-300 print:text-sky-800 border border-cyan-500/30">
                    VAPT DAST ASVS v4.0.3
                  </span>
                  <span className={`px-2 py-0.5 rounded font-sans font-bold text-[10px] border ${overallPriority.badgeClass}`}>
                    {overallPriority.label}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Executive Briefing Banner (Dual & Executive view) */}
          {(audienceView === 'DUAL' || audienceView === 'EXECUTIVE') && (
            <div className="bg-emerald-950/20 print:bg-emerald-50 border border-emerald-500/30 print:border-emerald-300 rounded-2xl p-5 space-y-2 text-xs">
              <div className="flex items-center space-x-2 text-emerald-600 dark:text-emerald-400 print:text-emerald-800 font-bold text-xs uppercase tracking-wider font-sans">
                <Briefcase className="w-4 h-4 text-emerald-400 print:text-emerald-700" />
                <span>Executive Briefing: What Non-Technical Leadership Needs to Know</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1 text-slate-300 print:text-slate-800">
                <div>
                  <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px]">&bull; Threat Exposure:</span>
                  <p className="text-slate-200 print:text-slate-900 mt-0.5">{cleanBugTitle(activeFindings[0]?.title) || 'Missing transport hardening, exposed server signatures, or insufficient browser controls.'}</p>
                </div>
                <div>
                  <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px]">&bull; Business Consequence:</span>
                  <p className="text-slate-200 print:text-slate-900 mt-0.5">Reputational erosion, interception on public Wi-Fi, and regulatory compliance audit findings.</p>
                </div>
                <div>
                  <span className="text-slate-400 print:text-slate-600 font-semibold block text-[11px]">&bull; Recommended Action:</span>
                  <p className="text-slate-200 print:text-slate-900 mt-0.5">Instruct infrastructure &amp; web engineering to apply the verified configuration patches below.</p>
                </div>
              </div>
            </div>
          )}

          {/* Technical Scope Banner (Technical view) */}
          {audienceView === 'TECHNICAL' && (
            <div className="bg-cyan-950/20 print:bg-cyan-50 border border-cyan-500/30 print:border-cyan-300 rounded-2xl p-5 space-y-2 text-xs">
              <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 print:text-cyan-800 font-bold text-xs uppercase tracking-wider font-sans">
                <Terminal className="w-4 h-4 text-cyan-400 print:text-cyan-700" />
                <span>Technical Scope &amp; Empirical Verification Parameters (IT Auditor)</span>
              </div>
              <p className="text-slate-300 print:text-slate-800">
                Empirical wire trace verification conforming to OWASP Top 10 standards with deterministic reproduction payloads.
              </p>
            </div>
          )}

          {/* Posture Score Banner */}
          <div className="liquid-glass print:bg-slate-50 border border-white/10 print:border-slate-300 rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-xs font-sans font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 print:text-slate-600">
                Overall Target Defenses Score:
              </span>
              <div className="text-sm text-slate-700 dark:text-slate-300 print:text-slate-700">
                Evaluated against <strong className="text-slate-900 dark:text-white print:text-black">{activeFindings.length} confirmed vulnerabilities</strong> across in-scope assets.
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <div
                className={`text-3xl sm:text-4xl font-extrabold font-sans ${
                  postureScore >= 80
                    ? 'text-emerald-400 print:text-emerald-700'
                    : postureScore >= 50
                    ? 'text-amber-400 print:text-amber-700'
                    : 'text-rose-400 print:text-rose-700'
                }`}
              >
                {postureScore} / 100
              </div>
              <span className="text-xs px-2.5 py-1 rounded-xl bg-white/[0.04] print:bg-white border border-white/10 print:border-slate-300 font-semibold font-sans text-slate-300 print:text-slate-800">
                {postureScore >= 80 ? 'Hardened Defenses' : postureScore >= 50 ? 'Elevated Risk' : 'Critical Action Required'}
              </span>
            </div>
          </div>

          {/* Severity Metrics Bar (Rendered ONLY when target is selected) */}
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-3.5 print:grid-cols-6">
            <div className="liquid-glass print:bg-slate-50 border border-rose-500/30 print:border-rose-400 p-3.5 rounded-xl text-center">
              <span className="text-rose-400 print:text-rose-700 text-xs font-semibold uppercase block">Critical (P1)</span>
              <span className="text-2xl font-bold text-rose-300 print:text-rose-900">{criticals.length}</span>
            </div>
            <div className="liquid-glass print:bg-slate-50 border border-orange-500/30 print:border-orange-400 p-3.5 rounded-xl text-center">
              <span className="text-orange-400 print:text-orange-700 text-xs font-semibold uppercase block">High (P2)</span>
              <span className="text-2xl font-bold text-orange-300 print:text-orange-900">{highs.length}</span>
            </div>
            <div className="liquid-glass print:bg-slate-50 border border-yellow-500/30 print:border-yellow-500 p-3.5 rounded-xl text-center">
              <span className="text-yellow-400 print:text-amber-700 text-xs font-semibold uppercase block">Medium (P3)</span>
              <span className="text-2xl font-bold text-yellow-300 print:text-amber-900">{mediums.length}</span>
            </div>
            <div className="liquid-glass print:bg-slate-50 border border-blue-500/30 print:border-blue-400 p-3.5 rounded-xl text-center">
              <span className="text-blue-400 print:text-sky-700 text-xs font-semibold uppercase block">Low (P4)</span>
              <span className="text-2xl font-bold text-blue-300 print:text-sky-900">{lows.length}</span>
            </div>
            <div className="liquid-glass print:bg-slate-50 border border-purple-500/30 print:border-purple-400 p-3.5 rounded-xl text-center">
              <span className="text-purple-400 print:text-purple-700 text-xs font-semibold uppercase block">Info (P5)</span>
              <span className="text-2xl font-bold text-purple-300 print:text-purple-900">{infos.length}</span>
            </div>
            <div className="liquid-glass print:bg-slate-50 border border-emerald-500/30 print:border-emerald-400 p-3.5 rounded-xl text-center">
              <span className="text-emerald-400 print:text-emerald-700 text-xs font-semibold uppercase block">Remediated</span>
              <span className="text-2xl font-bold text-emerald-300 print:text-emerald-900">{remediated.length}</span>
            </div>
          </div>

          {/* Detailed Findings & Proof of Concept Sections */}
          <div className="space-y-8">
            <div className="border-b border-white/10 print:border-slate-300 pb-2 flex items-center justify-between">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 dark:text-slate-200 print:text-black font-sans flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400 print:text-black" />
                <span>
                  {audienceView === 'EXECUTIVE'
                    ? `Executive Findings & Management Action Plans (${displayedFindings.length} Findings)`
                    : audienceView === 'TECHNICAL'
                    ? `Empirical Wire Telemetry & Hardening Dossier (${displayedFindings.length} Vulnerabilities)`
                    : `Technical Proof of Concept Dossier (${displayedFindings.length} Vulnerabilities)`}
                </span>
              </h3>
              <span className="text-xs text-slate-400 print:text-slate-600 font-sans">
                {audienceView === 'EXECUTIVE'
                  ? 'Plain-English Explanations & Action Plans'
                  : 'Live Wire Proofs &amp; Deterministic CLI Reproduction'}
              </span>
            </div>

            <div className="space-y-8">
              {displayedFindings.map((f, idx) => {
                const item = buildStructuredPoCFinding(f, assets, targetAsset);
                const showTechDetails = audienceView !== 'EXECUTIVE' || expandedTechnicalIds[f.id];

                return (
                  <div
                    key={f.id}
                    className="liquid-glass print:bg-white print:border-slate-300 rounded-2xl p-6 sm:p-7 space-y-6 border border-white/10 shadow-lg print:shadow-none print:break-inside-avoid"
                    style={{ breakInside: 'avoid', pageBreakInside: 'avoid' }}
                  >
                    {/* Plain-English Explanation (For Non-Technical Stakeholders) - Dual & Executive View */}
                    {(audienceView === 'DUAL' || audienceView === 'EXECUTIVE') && (
                      <div className="bg-amber-950/20 print:bg-amber-50 border border-amber-500/40 print:border-amber-300 rounded-xl p-4 text-xs space-y-2">
                        <div className="flex items-center space-x-2 text-amber-300 print:text-amber-800 font-bold font-sans">
                          <Lightbulb className="w-4 h-4 text-amber-400 print:text-amber-600" />
                          <span>Plain-English Explanation (For Non-Technical Stakeholders)</span>
                        </div>
                        <p className="text-slate-200 print:text-slate-800 leading-relaxed font-sans">{item.nonTech.whatItMeans}</p>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1 text-slate-300 print:text-slate-700 text-[11px]">
                          <div>
                            <strong className="text-amber-400 print:text-amber-800 block">&bull; Real-World Analogy:</strong>
                            <p className="text-slate-200 print:text-slate-900">{item.nonTech.analogy}</p>
                          </div>
                          <div>
                            <strong className="text-amber-400 print:text-amber-800 block">&bull; Business &amp; Reputation Risk:</strong>
                            <p className="text-slate-200 print:text-slate-900">{item.nonTech.businessRisk}</p>
                          </div>
                          <div>
                            <strong className="text-amber-400 print:text-amber-800 block">&bull; What Management Should Do:</strong>
                            <p className="text-slate-200 print:text-slate-900">{item.nonTech.managementAction}</p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Executive View Toggle for Technical Details */}
                    {audienceView === 'EXECUTIVE' && (
                      <div className="no-print flex items-center justify-between border-t border-b border-white/10 py-2.5">
                        <span className="text-xs text-slate-400 font-sans">Deep Technical Telemetry &amp; Reproduction Command:</span>
                        <button
                          onClick={() => toggleTechnicalDetail(f.id)}
                          className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center space-x-1 cursor-pointer bg-white/[0.04] px-3 py-1.5 rounded-xl border border-white/10 font-sans"
                        >
                          <span>{showTechDetails ? 'Hide Technical Wire Telemetry' : 'View Deep Technical Wire Telemetry'}</span>
                          {showTechDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    )}

                    {/* 1. SUBJECT LINE & SUBLINE HEADER STRIP */}
                    <div className="border-b border-white/[0.08] print:border-slate-200 pb-4 space-y-2">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className="text-xs font-sans font-bold text-slate-400 print:text-slate-700">
                          #{idx + 1}
                        </span>

                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${item.priority.badgeClass}`}>
                          {item.priority.code}
                        </span>

                        <span className="px-2.5 py-0.5 rounded-lg bg-cyan-500/15 text-cyan-300 print:text-cyan-900 border border-cyan-500/30 text-xs font-sans font-semibold flex items-center space-x-1">
                          <Globe className="w-3 h-3 text-cyan-400 inline" />
                          <span>{item.assetHost}</span>
                        </span>

                        <span className="font-sans text-xs text-indigo-300 print:text-indigo-900 bg-indigo-500/10 print:bg-indigo-100 px-2 py-0.5 rounded-lg border border-indigo-500/30 font-semibold">
                          {item.ruleId}
                        </span>

                        <span className="text-xs font-sans font-semibold text-emerald-400 print:text-emerald-800 bg-emerald-500/10 print:bg-emerald-100 px-2 py-0.5 rounded border border-emerald-500/30">
                          {f.validation_status}
                        </span>
                      </div>

                      {/* Subject Line */}
                      <div>
                        <span className="text-[11px] font-sans font-bold text-cyan-600 dark:text-cyan-400 print:text-indigo-800 uppercase tracking-wider block">
                          SUBJECT LINE:
                        </span>
                        <h4 className="text-lg font-bold text-slate-900 dark:text-white print:text-black tracking-tight">
                          {item.subjectLine}
                        </h4>
                      </div>

                      {/* Subline */}
                      <div>
                        <span className="text-[10px] font-sans font-semibold text-slate-500 dark:text-slate-400 print:text-slate-600 uppercase tracking-wider block">
                          SUBLINE:
                        </span>
                        <p className="text-xs text-slate-700 dark:text-slate-300 print:text-slate-700 leading-relaxed font-sans">
                          {item.subline}
                        </p>
                      </div>

                      {/* Reporting To, Confidentiality, Priority & VAPT Meta Grid */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 pt-2 text-[11px]">
                        <div className="bg-black/30 print:bg-slate-100 p-2 rounded-lg border border-white/10 print:border-slate-300">
                          <span className="text-slate-400 print:text-slate-600 block font-sans text-[10px] font-semibold">REPORTING TO:</span>
                          <span className="font-semibold text-slate-200 print:text-slate-800 truncate block">{item.reportingTo}</span>
                        </div>
                        <div className="bg-black/30 print:bg-slate-100 p-2 rounded-lg border border-white/10 print:border-slate-300">
                          <span className="text-slate-400 print:text-slate-600 block font-sans text-[10px] font-semibold">CONFIDENTIALITY:</span>
                          <span className="font-bold text-rose-300 print:text-rose-800 truncate block">RESTRICTED // AUDIT ONLY</span>
                        </div>
                        <div className="bg-black/30 print:bg-slate-100 p-2 rounded-lg border border-white/10 print:border-slate-300">
                          <span className="text-slate-400 print:text-slate-600 block font-sans text-[10px] font-semibold">PRIORITY:</span>
                          <span className="font-bold text-amber-300 print:text-amber-800 truncate block">{item.priority.label}</span>
                        </div>
                        <div className="bg-black/30 print:bg-slate-100 p-2 rounded-lg border border-white/10 print:border-slate-300">
                          <span className="text-slate-400 print:text-slate-600 block font-sans text-[10px] font-semibold">VAPT CLASSIFICATION:</span>
                          <span className="font-semibold text-indigo-300 print:text-indigo-800 truncate block">{item.vapt}</span>
                        </div>
                      </div>
                    </div>

                    {/* 2. PROOF SECTION (PROOF: SS, VIDEO, URL) */}
                    <div className="space-y-4 bg-slate-950/40 print:bg-slate-50 p-5 rounded-2xl border border-cyan-500/30 print:border-slate-300 shadow-md">
                      <div className="flex items-center justify-between flex-wrap gap-2 border-b border-white/10 print:border-slate-200 pb-3">
                        <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-400 print:text-indigo-800 font-bold text-xs uppercase tracking-wider font-sans">
                          <Shield className="w-4 h-4 text-cyan-400" />
                          <span>PROOF DOSSIER: PROOF: SS &amp; URL</span>
                        </div>
                        <span className="px-2.5 py-0.5 rounded text-[10px] font-sans font-bold bg-cyan-500/20 text-cyan-300 print:text-cyan-900 border border-cyan-500/30">
                          VERIFIED EMPIRICAL PROOF
                        </span>
                      </div>

                      {/* A. Proof: URL */}
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-sans font-bold text-cyan-300 print:text-slate-900 flex items-center space-x-1.5">
                            <Link2 className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Proof: URL (Target Endpoint):</span>
                          </span>
                          <button
                            onClick={() => handleCopyUrl(item.proof.url, f.id)}
                            className="no-print text-[11px] font-sans text-cyan-400 hover:text-white flex items-center space-x-1 cursor-pointer bg-white/[0.04] px-2 py-0.5 rounded border border-white/10 font-semibold"
                            title="Copy target URL"
                          >
                            {copiedUrlId === f.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-cyan-400" />}
                            <span>{copiedUrlId === f.id ? 'Copied' : 'Copy URL'}</span>
                          </button>
                        </div>
                        <div className="bg-black/40 print:bg-white p-2.5 rounded-xl border border-white/10 print:border-slate-300 flex items-center justify-between flex-wrap gap-2">
                          <a
                            href={item.proof.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-sans text-xs text-cyan-300 print:text-indigo-700 hover:underline break-all font-semibold flex items-center space-x-1"
                          >
                            <span>{item.proof.url}</span>
                            <ExternalLink className="w-3 h-3 inline text-cyan-400" />
                          </a>
                          <div className="flex items-center space-x-2 text-[10px] font-sans font-medium">
                            <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded">Port {item.proof.port}</span>
                            <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded">{item.proof.scheme.toUpperCase()}</span>
                            <span className="bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30">{item.proof.latencyMs}ms Latency</span>
                          </div>
                        </div>
                      </div>

                      {showTechDetails && (
                        <>
{/* B. Proof: SS (Screenshot / Wire Telemetry Capture) */}
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-sans font-bold text-emerald-300 print:text-slate-900 flex items-center space-x-1.5">
                            <Camera className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Proof: SS (Screenshot / Wire Evidence Capture):</span>
                          </span>
                          <button
                            onClick={() => setSsModalFinding(item)}
                            className="no-print text-[11px] font-sans font-semibold text-emerald-400 hover:text-white flex items-center space-x-1 cursor-pointer bg-emerald-500/10 px-2.5 py-0.5 rounded-lg border border-emerald-500/30"
                            title="Expand full-size wire evidence screenshot preview"
                          >
                            <Maximize2 className="w-3 h-3 text-emerald-400" />
                            <span>View Full Screenshot Preview</span>
                          </button>
                        </div>

                        {/* Styled Screenshot Simulation Frame */}
                        <div className="bg-slate-950/90 print:bg-white border-2 border-emerald-500/30 print:border-slate-400 rounded-xl p-4 font-mono text-xs space-y-3 shadow-inner">
                          <div className="flex items-center justify-between border-b border-white/10 print:border-slate-300 pb-2 text-[11px]">
                            <div className="flex items-center space-x-2">
                              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
                              <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
                              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                              <span className="text-slate-400 print:text-slate-600 pl-2">WIRE CAPTURE SNAPSHOT &bull; {item.proof.probe}</span>
                            </div>
                            <span className="text-emerald-400 font-bold bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-500/30">
                              {item.proof.serverStatus}
                            </span>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                            <div className="space-y-1">
                              <span className="text-rose-400 print:text-rose-700 font-bold text-[10px] block uppercase">
                                Observed Defect:
                              </span>
                              <p className="text-rose-200 print:text-rose-900 text-[11px] leading-relaxed">
                                {item.proof.observedDefect}
                              </p>
                            </div>
                            <div className="space-y-1">
                              <span className="text-emerald-400 print:text-emerald-700 font-bold text-[10px] block uppercase">
                                Expected Baseline Standard:
                              </span>
                              <p className="text-emerald-200 print:text-emerald-900 text-[11px] leading-relaxed">
                                {item.proof.expectedStandard}
                              </p>
                            </div>
                          </div>

                          {/* Raw headers preview */}
                          <div className="pt-2 border-t border-white/[0.08] print:border-slate-200 text-[10px] text-slate-300 print:text-slate-800 space-y-0.5">
                            <div className="text-cyan-400 print:text-sky-800 font-bold">&larr; Response Headers Captured on Wire:</div>
                            {Object.entries(item.proof.rawResponseHeaders).slice(0, 4).map(([k, v]) => (
                              <div key={k} className="truncate">
                                <span className="text-slate-400 print:text-slate-600">{k}:</span> {v}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Deterministic Shell Reproduction Command */}
                      {item.proof.reproductionCli && (
                        <div className="bg-black/60 print:bg-slate-900 p-3 rounded-xl border border-cyan-500/30 text-emerald-300 text-xs space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="text-cyan-400 font-sans text-[11px] font-bold flex items-center space-x-1">
                              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                              <span>Deterministic Shell Reproduction Command (cURL CLI):</span>
                            </span>
                            <button
                              onClick={() => handleCopyReproCli(item.proof.reproductionCli, f.id)}
                              className="no-print text-[10px] text-cyan-300 hover:text-white flex items-center space-x-1 cursor-pointer bg-white/[0.05] px-2 py-0.5 rounded border border-white/10"
                              title="Copy cURL CLI"
                            >
                              {copiedCliId === f.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-cyan-400" />}
                              <span>{copiedCliId === f.id ? 'Copied' : 'Copy cURL'}</span>
                            </button>
                          </div>
                          <code className="block select-all break-all font-semibold font-mono text-cyan-200 bg-slate-950 p-2 rounded border border-white/10">
                            {item.proof.reproductionCli}
                          </code>
                        </div>
                      )}
                    </>
                  )}
                </div>

                    {/* 3. PROBLEM FACED */}
                    <div className="bg-gradient-to-r from-amber-950/30 via-slate-900/60 to-amber-950/20 print:bg-amber-50/50 border border-amber-500/40 print:border-amber-300 rounded-2xl p-5 space-y-2.5 shadow-md">
                      <div className="flex items-center space-x-2 text-amber-600 dark:text-amber-300 print:text-amber-900 font-bold text-xs uppercase tracking-wider font-sans">
                        <AlertOctagon className="w-4 h-4 text-amber-400 print:text-amber-700" />
                        <span>Problem Faced (Exact Defect &amp; Control Deficiency)</span>
                      </div>
                      <p className="text-xs sm:text-sm text-slate-200 print:text-slate-800 leading-relaxed font-sans">
                        {item.problemFaced}
                      </p>

                      {/* In Simple Words callout */}
                      <div className="bg-black/30 print:bg-white p-3 rounded-xl border border-white/10 print:border-amber-200 text-xs text-amber-200 print:text-amber-900 space-y-1">
                        <strong className="text-amber-300 print:text-amber-800 block text-[11px] font-sans font-bold">
                          💡 In Simple Words &amp; Business Impact:
                        </strong>
                        <p className="leading-relaxed font-sans">{item.nonTech.whatItMeans}</p>
                        <p className="text-amber-300/80 print:text-amber-800 text-[11px] pt-1">
                          <strong>Real-World Analogy:</strong> {item.nonTech.analogy}
                        </p>
                      </div>
                    </div>

                    {/* 4. EXAMPLE (Real-World Attack Scenario) */}
                    <div className="bg-gradient-to-r from-slate-900/70 to-rose-950/20 print:bg-slate-50 border border-white/10 print:border-slate-300 rounded-2xl p-5 space-y-2.5 shadow-md">
                      <div className="flex items-center space-x-2 text-rose-600 dark:text-rose-300 print:text-rose-900 font-bold text-xs uppercase tracking-wider font-sans">
                        <AlertTriangle className="w-4 h-4 text-rose-400 print:text-rose-700" />
                        <span>Example (Real-World Adversarial Exploitation Scenario)</span>
                      </div>

                      <div className="bg-black/30 print:bg-white p-3.5 rounded-xl border border-white/10 print:border-slate-200 space-y-2 text-xs text-slate-200 print:text-slate-800">
                        {item.example
                          .split('\n')
                          .filter((s: string) => s.trim())
                          .map((step: string, sIdx: number) => (
                            <div key={sIdx} className="flex items-start space-x-2 py-0.5">
                              <span className="text-rose-400 print:text-rose-700 font-sans font-bold shrink-0">
                                {sIdx + 1}.
                              </span>
                              <span className="leading-relaxed">{step.replace(/^\d+\.\s*/, '')}</span>
                            </div>
                          ))}
                      </div>
                    </div>

                    {/* 5. SOLUTION (Production Hardening & Architecture Fix) */}
                    <div className="bg-gradient-to-r from-emerald-950/30 via-slate-900/60 to-emerald-950/20 print:bg-emerald-50/50 border border-emerald-500/40 print:border-emerald-300 rounded-2xl p-5 space-y-3 shadow-md">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center space-x-2 text-emerald-600 dark:text-emerald-300 print:text-emerald-900 font-bold text-xs uppercase tracking-wider font-sans">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 print:text-emerald-700" />
                          <span>Solution (Production Hardening Directives &amp; Architecture Fix)</span>
                        </div>
                        {item.solutionCode && (
                          <button
                            onClick={() => handleCopyPatch(item.solutionCode, f.id)}
                            className="no-print text-[11px] font-sans font-semibold text-emerald-300 hover:text-white flex items-center space-x-1 cursor-pointer bg-emerald-500/15 px-2.5 py-1 rounded-lg border border-emerald-500/30"
                            title="Copy production patch directive"
                          >
                            {copiedPatchId === f.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-emerald-400" />}
                            <span>{copiedPatchId === f.id ? 'Copied Patch' : 'Copy Patch'}</span>
                          </button>
                        )}
                      </div>

                      <p className="text-xs sm:text-sm text-slate-200 print:text-slate-800 leading-relaxed font-sans">
                        {item.solution}
                      </p>

                      {item.solutionCode && (
                        <div className="bg-slate-950/90 print:bg-slate-900 text-emerald-300 p-3 rounded-xl border border-white/10 print:border-slate-400 font-mono text-xs overflow-x-auto select-all">
                          <pre className="whitespace-pre-wrap">{item.solutionCode}</pre>
                        </div>
                      )}
                    </div>

                    {/* 6. WORK (Engineering & Operational Implementation Tasks) */}
                    <div className="bg-gradient-to-r from-blue-950/30 via-slate-900/60 to-indigo-950/30 print:bg-blue-50/50 border border-blue-500/40 print:border-blue-300 rounded-2xl p-5 space-y-3 shadow-md">
                      <div className="flex items-center space-x-2 text-cyan-600 dark:text-cyan-300 print:text-blue-900 font-bold text-xs uppercase tracking-wider font-sans">
                        <CheckSquare className="w-4 h-4 text-cyan-400 print:text-blue-700" />
                        <span>Work (Engineering &amp; Operational Implementation Tasks)</span>
                      </div>

                      <div className="space-y-2.5">
                        {item.work.tasks.map((task) => {
                          const isDone = Boolean(completedWorkTasks[f.id] && completedWorkTasks[f.id][task.id]);
                          return (
                            <div
                              key={task.id}
                              onClick={() => toggleWorkTask(f.id, task.id)}
                              className={`p-3 rounded-xl border transition cursor-pointer flex items-start space-x-3 ${
                                isDone
                                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                                  : 'bg-black/30 print:bg-white border-white/10 print:border-slate-300 text-slate-200'
                              }`}
                            >
                              <div className="pt-0.5 shrink-0">
                                <input
                                  type="checkbox"
                                  checked={isDone}
                                  onChange={() => {}} // handled by parent onClick
                                  className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
                                />
                              </div>
                              <div className="space-y-1 min-w-0 flex-1">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs font-bold font-sans text-cyan-300 print:text-blue-800">
                                    [{task.role}] Task {task.id}: {task.title}
                                  </span>
                                  {isDone && <span className="text-[10px] font-sans font-bold text-emerald-400">COMPLETED</span>}
                                </div>
                                <p className="text-xs text-slate-300 print:text-slate-700">{task.description}</p>
                                {task.commandOrFile && (
                                  <code className="text-[11px] font-mono text-slate-400 print:text-slate-800 bg-black/40 print:bg-slate-100 px-2 py-0.5 rounded block truncate">
                                    {task.commandOrFile}
                                  </code>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* --- MODAL 2: FULL SCREENSHOT PREVIEW MODAL --- */}
      {ssModalFinding && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-emerald-500/40 rounded-3xl max-w-3xl w-full p-6 space-y-4 shadow-2xl text-slate-200">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <div className="flex items-center space-x-2 text-emerald-600 dark:text-emerald-300 font-sans font-bold text-sm uppercase">
                <Camera className="w-5 h-5 text-emerald-400" />
                <span>Proof: SS (Wire Evidence Capture Snapshot)</span>
              </div>
              <button
                onClick={() => setSsModalFinding(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-white/10 cursor-pointer"
                aria-label="Close Screenshot"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-1">
              <h4 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">
                {cleanBugTitle(ssModalFinding.finding.title)}
              </h4>
              <p className="text-xs text-slate-400 font-sans">
                Target: {ssModalFinding.proof.url} &bull; Rule: {ssModalFinding.ruleId}
              </p>
            </div>

            {/* Enlarged Screenshot Container */}
            <div className="bg-slate-950 rounded-2xl p-5 border-2 border-emerald-500/30 font-mono text-xs space-y-4 shadow-inner max-h-[70vh] overflow-y-auto">
              <div className="flex items-center justify-between border-b border-white/10 pb-2">
                <span className="text-cyan-400 font-bold">SNAPSHOT TELEMETRY OVERVIEW</span>
                <span className="text-emerald-400 font-bold bg-emerald-950 px-2 py-0.5 rounded border border-emerald-500/30">
                  {ssModalFinding.proof.serverStatus}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="space-y-1 bg-black/40 p-3 rounded-xl border border-white/10">
                  <span className="text-slate-400 text-[10px] uppercase font-bold block">Probe Dispatched:</span>
                  <p className="text-cyan-300 break-all">{ssModalFinding.proof.probe}</p>
                </div>
                <div className="space-y-1 bg-black/40 p-3 rounded-xl border border-white/10">
                  <span className="text-slate-400 text-[10px] uppercase font-bold block">Server Telemetry:</span>
                  <p className="text-emerald-300">
                    Host: {ssModalFinding.proof.resolvedIp}:{ssModalFinding.proof.port} | Latency: {ssModalFinding.proof.latencyMs}ms
                  </p>
                </div>
              </div>

              <div className="space-y-1 bg-rose-950/30 p-3 rounded-xl border border-rose-500/40">
                <span className="text-rose-400 font-bold uppercase text-[10px] block">Observed Defect on Wire:</span>
                <p className="text-rose-200">{ssModalFinding.proof.observedDefect}</p>
              </div>

              <div className="space-y-1 bg-emerald-950/30 p-3 rounded-xl border border-emerald-500/40">
                <span className="text-emerald-400 font-bold uppercase text-[10px] block">Baseline Standard Required:</span>
                <p className="text-emerald-200">{ssModalFinding.proof.expectedStandard}</p>
              </div>

              {/* Full Headers Captured */}
              <div className="space-y-1 bg-black/60 p-3.5 rounded-xl border border-white/10">
                <span className="text-slate-400 text-[10px] uppercase font-bold block">&larr; Live Response Headers Captured:</span>
                <pre className="text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {Object.entries(ssModalFinding.proof.rawResponseHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
